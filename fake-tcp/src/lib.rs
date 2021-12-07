#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{tcp, Packet};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time;
use tokio_tun::Tun;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPSC_BUFFER_LEN: usize = 512;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
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

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, Sender<Bytes>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    ready: Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<Tun>,
    incoming: AsyncMutex<Receiver<Bytes>>,
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
    seq: AtomicU32,
    ack: AtomicU32,
    state: State,
}

impl Socket {
    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddrV4,
        remote_addr: SocketAddrV4,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MPSC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
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
        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            self.ack.load(Ordering::Relaxed),
            flags,
            payload,
        )
    }

    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        match self.state {
            State::Established => {
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);

                tokio::select! {
                    res = self.tun.send(&buf) => {
                        res.ok().and(Some(()))
                    },
                }
            }
            _ => unreachable!(),
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => {
                let mut incoming = self.incoming.lock().await;
                incoming.recv().await.and_then(|raw_buf| {
                    let (_v4_packet, tcp_packet) = parse_ipv4_packet(&raw_buf);

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    let payload = tcp_packet.payload();

                    self.ack
                        .store(tcp_packet.get_sequence().wrapping_add(1), Ordering::Relaxed);

                    buf[..payload.len()].copy_from_slice(payload);

                    Some(payload.len())
                })
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
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

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.lock().await.recv()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ipv4_packet(&buf);

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
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
                                self.tun.send(&buf).await.unwrap();

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        self.shared.tuples_purge.send(tuple).unwrap();

        let buf = self.build_tcp_packet(tcp::TcpFlags::RST, None);
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

impl Stack {
    pub fn new(tun: Vec<Tun>) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
        });
        let local_ip = tun[0].destination().unwrap();

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            ready: ready_rx,
        }
    }

    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    pub async fn connect(&mut self, addr: SocketAddrV4) -> Option<Socket> {
        let mut rng = SmallRng::from_entropy();
        let local_port: u16 = rng.gen_range(1024..65535);
        let local_addr = SocketAddrV4::new(self.local_ip, local_port);
        let tuple = AddrTuple::new(local_addr, addr);
        let (mut sock, incoming) = Socket::new(
            self.shared.clone(),
            self.shared.tun.choose(&mut rng).unwrap().clone(),
            local_addr,
            addr,
            None,
            State::Idle,
        );

        {
            let mut tuples = self.shared.tuples.write().unwrap();
            assert!(tuples.insert(tuple, incoming.clone()).is_none());
        }

        sock.connect().await.map(|_| sock)
    }

    async fn reader_task(
        tun: Arc<Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::with_capacity(MAX_PACKET_LEN);
            buf.resize(MAX_PACKET_LEN, 0);

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = size.unwrap();
                    buf.truncate(size);
                    let buf = buf.freeze();

                    if buf[0] >> 4 != 4 {
                        // not an IPv4 packet
                        continue;
                    }

                    let (ip_packet, tcp_packet) = parse_ipv4_packet(&buf);
                    let local_addr =
                        SocketAddrV4::new(ip_packet.get_destination(), tcp_packet.get_destination());
                    let remote_addr = SocketAddrV4::new(ip_packet.get_source(), tcp_packet.get_source());

                    let tuple = AddrTuple::new(local_addr, remote_addr);
                    if let Some(c) = tuples.get(&tuple) {
                        if c.send(buf).await.is_err() {
                            trace!("Cache hit, but receiver already closed, dropping packet");
                        }

                        continue;

                        // If not Ok, receiver has been closed and just fall through to the slow
                        // path below

                    } else {
                        trace!("Cache miss, checking the shared tuples table for connection");
                        let sender = {
                            let tuples = shared.tuples.read().unwrap();
                            tuples.get(&tuple).cloned()
                        };

                        if let Some(c) = sender {
                            trace!("Storing connection information into local tuples");
                            tuples.insert(tuple, c.clone());
                            c.send(buf).await.unwrap();
                            continue;
                        }
                    }

                    if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                        && shared
                            .listening
                            .read()
                            .unwrap()
                            .contains(&tcp_packet.get_destination())
                    {
                        // SYN seen on listening socket
                        if tcp_packet.get_sequence() == 0 {
                            let (sock, incoming) = Socket::new(
                                shared.clone(),
                                tun.clone(),
                                local_addr,
                                remote_addr,
                                Some(tcp_packet.get_sequence() + 1),
                                State::Idle,
                            );
                            assert!(shared
                                .tuples
                                .write()
                                .unwrap()
                                .insert(tuple, incoming)
                                .is_none());
                            tokio::spawn(sock.accept());
                        } else {
                            trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                            let buf = build_tcp_packet(
                                local_addr,
                                remote_addr,
                                0,
                                tcp_packet.get_sequence() + 1,
                                tcp::TcpFlags::RST,
                                None,
                            );
                            shared.tun[0].try_send(&buf).unwrap();
                        }
                    } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                        info!("Unknown TCP packet from {}, sending RST", remote_addr);
                        let buf = build_tcp_packet(
                            local_addr,
                            remote_addr,
                            tcp_packet.get_acknowledgement(),
                            0,
                            tcp::TcpFlags::RST,
                            None,
                        );
                        shared.tun[0].try_send(&buf).unwrap();
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    trace!("Removed cached tuple");
                }
            }
        }
    }
}
