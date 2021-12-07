use clap::{crate_version, App, Arg};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time;
use tokio_tun::TunBuilder;

const UDP_TTL: Duration = Duration::from_secs(180);

fn new_udp_reuseport(addr: SocketAddr) -> UdpSocket {
    let udp_sock = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )
    .unwrap();
    udp_sock.set_reuse_port(true).unwrap();
    // from tokio-rs/mio/blob/master/src/sys/unix/net.rs
    udp_sock.set_cloexec(true).unwrap();
    udp_sock.set_nonblocking(true).unwrap();
    udp_sock.bind(&socket2::SockAddr::from(addr)).unwrap();
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into().unwrap()
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let matches = App::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::with_name("local")
                .short("l")
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote")
                .short("r")
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.200.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("192.168.200.2")
                .takes_value(true),
        )
        .get_matches();

    let local_addr: SocketAddr = matches
        .value_of("local")
        .unwrap()
        .parse()
        .expect("bad local address");

    let remote_addr = tokio::net::lookup_host(matches.value_of("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");
    let remote_addr = if let SocketAddr::V4(addr) = remote_addr {
        addr
    } else {
        panic!("only IPv4 remote address is supported");
    };
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .value_of("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .value_of("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let tun = TunBuilder::new()
        .name(matches.value_of("tun").unwrap()) // if name is empty, then it is set by kernel.
        .tap(false) // false (default): TUN, true: TAP.
        .packet_info(false) // false: IFF_NO_PI, default is true.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .try_build_mq(num_cpus::get())
        .unwrap();

    info!("Created TUN device {}", tun[0].name());

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));

    let mut stack = Stack::new(tun);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            tokio::select! {
                Ok((size, addr)) = udp_sock.recv_from(&mut buf_r) => {
                    // seen UDP packet to listening socket, this means:
                    // 1. It is a new UDP connection, or
                    // 2. It is some extra packets not filtered by more specific
                    //    connected UDP socket yet
                    if let Some(sock) = connections.read().await.get(&addr) {
                        sock.send(&buf_r[..size]).await;
                        continue;
                    }

                    info!("New UDP client from {}", addr);
                    let sock = stack.connect(remote_addr).await;
                    if sock.is_none() {
                        error!("Unable to connect to remote {}", remote_addr);
                        continue;
                    }

                    let sock = Arc::new(sock.unwrap());
                    // send first packet
                    let res = sock.send(&buf_r[..size]).await;
                    if res.is_none() {
                        continue;
                    }

                    assert!(connections.write().await.insert(addr, sock.clone()).is_none());
                    debug!("inserted fake TCP socket into connection table");

                    let connections = connections.clone();

                    // spawn "fastpath" UDP socket and task, this will offload main task
                    // from forwarding UDP packets
                    tokio::spawn(async move {
                        let mut buf_udp = [0u8; MAX_PACKET_LEN];
                        let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                        let udp_sock = new_udp_reuseport(local_addr);
                        udp_sock.connect(addr).await.unwrap();

                        loop {
                            let read_timeout = time::sleep(UDP_TTL);

                            tokio::select! {
                                Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                    if sock.send(&buf_udp[..size]).await.is_none() {
                                        connections.write().await.remove(&addr);
                                        debug!("removed fake TCP socket from connections table");
                                        return;
                                    }
                                },
                                res = sock.recv(&mut buf_tcp) => {
                                    match res {
                                        Some(size) => {
                                            if size > 0 {
                                                if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                    connections.write().await.remove(&addr);
                                                    error!("Unable to send UDP packet to {}: {}, closing connection", e, addr);
                                                    return;
                                                }
                                            }
                                        },
                                        None => {
                                            connections.write().await.remove(&addr);
                                            debug!("removed fake TCP socket from connections table");
                                            return;
                                        },
                                    }
                                },
                                _ = read_timeout => {
                                    info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                                    connections.write().await.remove(&addr);
                                    debug!("removed fake TCP socket from connections table");
                                    return;
                                }
                            };
                        }
                    });
                },
            }
        }
    });

    tokio::join!(main_loop).0.unwrap();
}
