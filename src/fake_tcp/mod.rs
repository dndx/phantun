pub mod packet;

use bytes::{Bytes, BytesMut};
use packet::*;
use pnet::packet::{tcp, Packet};
use rand::prelude::*;
use std::cell::RefCell;
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::io::{Error, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, error::TrySendError, Receiver, Sender};
use tokio::sync::Mutex as AsyncMutex;
use tokio::{io, time};
use tokio_tun::Tun;

const TIMEOUT: time::Duration = time::Duration::from_secs(5);
const MPSC_BUFFER_LEN: usize = 128;

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct AddrTuple {
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
}

impl AddrTuple {
    fn new(local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

#[derive(Debug)]
struct Shared {
    tuples: Mutex<HashMap<AddrTuple, Arc<Sender<Bytes>>>>,
    listening: Mutex<HashSet<u16>>,
    outgoing: Sender<Bytes>,
    ready: Sender<Socket>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    ready: Receiver<Socket>,
}

#[derive(Debug)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

#[derive(Debug)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug)]
pub struct Socket {
    mode: Mode,
    shared: Arc<Shared>,
    incoming: AsyncMutex<Receiver<Bytes>>,
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
    seq: AtomicU32,
    ack: AtomicU32,
    state: State,
}

impl Socket {
    fn new(
        mode: Mode,
        shared: Arc<Shared>,
        local_addr: SocketAddrV4,
        remote_addr: SocketAddrV4,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MPSC_BUFFER_LEN);

        (
            Socket {
                mode,
                shared,
                incoming: AsyncMutex::new(incoming_rx),
                local_addr,
                remote_addr,
                seq: AtomicU32::new(0),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                state,
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u16, payload: Option<&[u8]>) -> Bytes {
        return build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            self.ack.load(Ordering::Relaxed),
            flags,
            payload,
        );
    }

    pub async fn send(&self, payload: &[u8]) {
        match self.state {
            State::Established => {
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(buf.len() as u32, Ordering::Relaxed);
                self.shared.outgoing.send(buf).await.unwrap();
            }
            _ => unreachable!(),
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> usize {
        match self.state {
            State::Established => {
                let raw_buf = self.incoming.lock().await.recv().await.unwrap();
                let (_v4_packet, tcp_packet) = parse_ipv4_packet(&raw_buf);
                let payload = tcp_packet.payload();

                self.ack
                    .fetch_max(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                buf[..payload.len()].copy_from_slice(payload);

                payload.len()
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        loop {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.shared.outgoing.send(buf).await.unwrap();
                    self.state = State::SynReceived;
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.lock().await.recv()).await;
                    if let Ok(buf) = res {
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ipv4_packet(&buf);

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed) + 1
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            self.state = State::Established;

                            println!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            ready.send(self).await.unwrap();
                            return;
                        }
                    } else {
                        println!("waiting for SYN + ACK timed out, dropping connection");
                        return;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) {
        loop {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.shared.outgoing.send(buf).await.unwrap();
                    self.state = State::SynSent;
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.lock().await.recv()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ipv4_packet(&buf);

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.shared.outgoing.send(buf).await.unwrap();

                                self.state = State::Established;

                                println!("Connection to {:?} established", self.remote_addr);
                                return;
                            }
                        }
                        Err(_) => {
                            println!("waiting for SYN + ACK timed out, going back to Idle");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // dissociates ourself from the dispatch map
        assert!(self
            .shared
            .tuples
            .lock()
            .unwrap()
            .remove(&AddrTuple::new(self.local_addr, self.remote_addr))
            .is_some());

        let buf = self.build_tcp_packet(tcp::TcpFlags::RST, None);
        self.shared.outgoing.try_send(buf).unwrap();
    }
}

impl Stack {
    pub fn new(tun: Tun) -> Stack {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let shared = Arc::new(Shared {
            tuples: Mutex::new(HashMap::new()),
            outgoing: outgoing_tx,
            listening: Mutex::new(HashSet::new()),
            ready: ready_tx,
        });
        let local_ip = tun.destination().unwrap();

        tokio::spawn(Stack::dispatch(tun, outgoing_rx, shared.clone()));
        Stack {
            shared,
            local_ip,
            ready: ready_rx,
        }
    }

    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.lock().unwrap().insert(port));
    }

    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    pub async fn connect(&mut self, addr: SocketAddrV4) -> Socket {
        let mut rng = SmallRng::from_entropy();
        let local_port: u16 = rng.gen_range(1024..65535);
        let local_addr = SocketAddrV4::new(self.local_ip, local_port);
        let tuple = AddrTuple::new(local_addr, addr);
        let (mut sock, incoming) = Socket::new(
            Mode::Client,
            self.shared.clone(),
            local_addr,
            addr,
            None,
            State::Idle,
        );

        {
            let mut tuples = self.shared.tuples.lock().unwrap();
            assert!(tuples.insert(tuple, Arc::new(incoming.clone())).is_none());
        }

        sock.connect().await;
        sock
    }

    async fn dispatch(tun: Tun, mut outgoing: Receiver<Bytes>, shared: Arc<Shared>) {
        let (mut tun_r, mut tun_w) = io::split(tun);

        loop {
            let mut buf = BytesMut::with_capacity(MAX_PACKET_LEN);

            tokio::select! {
                buf = outgoing.recv() => {
                    let buf = buf.unwrap();
                    tun_w.write_all(&buf).await.unwrap();
                },
                s = tun_r.read_buf(&mut buf) => {
                    s.unwrap();
                    let buf = buf.freeze();
                    if buf[0] >> 4 != 4 {
                        // not an IPv4 packet
                        continue;
                    }

                    let (ip_packet, tcp_packet) = parse_ipv4_packet(&buf);
                    let local_addr = SocketAddrV4::new(ip_packet.get_destination(), tcp_packet.get_destination());
                    let remote_addr = SocketAddrV4::new(ip_packet.get_source(), tcp_packet.get_source());

                    let tuple = AddrTuple::new(local_addr, remote_addr);

                    let sender;
                    {
                        let mut tuples = shared.tuples.lock().unwrap();
                        sender = tuples.get(&tuple).map(|c| c.clone());
                    }

                    if let Some(c) = sender {
                        c.send(buf).await.unwrap();
                        continue;
                    }

                    if tcp_packet.get_flags() == tcp::TcpFlags::SYN && shared.listening.lock().unwrap().contains(&tcp_packet.get_destination()) {
                        // SYN seen on listening socket
                        if tcp_packet.get_sequence() == 0 {
                            let (sock, incoming) = Socket::new(Mode::Server, shared.clone(), local_addr, remote_addr, Some(tcp_packet.get_sequence() + 1), State::Idle);
                            assert!(shared.tuples.lock().unwrap().insert(tuple, Arc::new(incoming)).is_none());
                            tokio::spawn(sock.accept());
                        } else {
                            let buf = build_tcp_packet(
                                local_addr,
                                remote_addr,
                                0,
                                tcp_packet.get_acknowledgement() + 1,
                                tcp::TcpFlags::RST,
                                None,
                            );
                            shared.outgoing.try_send(buf).unwrap();
                        }
                    }
                }
            }
        }
    }
}
