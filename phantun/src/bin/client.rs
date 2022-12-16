use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info, trace, warn};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::time::{self, Instant};
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("keepalive_time")
                .long("keepalive-time")
                .short('k')
                .required(false)
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64).range(1..86400))
                .help("Specify the interval between the last packet received and the first keepalive probe.\
                If not specified, no keepalive probe will be sent.")
        )
        .arg(
            Arg::new("keepalive_interval")
                .long("keepalive-interval")
                .required(false)
                .default_value("5")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64).range(1..3600))
                .help("Specify the interval between keepalive probes.")
        )
        .arg(
            Arg::new("keepalive_retries")
                .long("keepalive-retries")
                .required(false)
                .default_value("3")
                .value_name("N")
                .value_parser(clap::value_parser!(i32).range(1..20))
                .help("Specify the number of keepalive probe retries before a connection reset.")
        )
        .get_matches();

    let local_addr: SocketAddr = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local address");

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;

    let tcp_keepalive_intvl = Duration::from_secs(*matches.get_one::<u64>("keepalive_interval").unwrap());
    let tcp_keepalive_time = matches.get_one::<u64>("keepalive_time").map(|s| Duration::from_secs(*s));
    let tcp_keepalive_retries = *matches.get_one::<i32>("keepalive_retries").unwrap();

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .tap(false) // false (default): TUN, true: TAP.
        .packet_info(false) // false: IFF_NO_PI, default is true.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .try_build_mq(num_cpus)
        .unwrap();

    if remote_addr.is_ipv6() {
        assign_ipv6_address(tun[0].name(), tun_local6.unwrap(), tun_peer6.unwrap());
    }

    info!("Created TUN device {}", tun[0].name());

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));

    let mut stack = Stack::new(tun, tun_peer, tun_peer6);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            let (size, addr) = udp_sock.recv_from(&mut buf_r).await?;
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
            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            // send first packet
            if sock.send(&buf_r[..size]).await.is_none() {
                continue;
            }

            assert!(connections
                .write()
                .await
                .insert(addr, sock.clone())
                .is_none());
            debug!("inserted fake TCP socket into connection table");

            // spawn "fastpath" UDP socket and task, this will offload main task
            // from forwarding UDP packets

            let data_received = Arc::new(Notify::new());
            let tcp_packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let data_received = data_received.clone();
                let tcp_packet_received = tcp_packet_received.clone();

                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                    let udp_sock = new_udp_reuseport(local_addr);
                    udp_sock.connect(addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                if sock.send(&buf_udp[..size]).await.is_none() {
                                    debug!("removed fake TCP socket from connections table");
                                    quit.cancel();
                                    return;
                                }

                                data_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", e, addr);
                                                quit.cancel();
                                                return;
                                            }
                                            data_received.notify_one();
                                        } else {
                                            trace!("Empty TCP packet received");
                                        }
                                    },
                                    None => {
                                        debug!("removed fake TCP socket from connections table");
                                        quit.cancel();
                                        return;
                                    },
                                }

                                tcp_packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            let connections = connections.clone();
            tokio::spawn(async move {
                let mut last_tcp_recv = Instant::now();
                let mut last_data_recv = Instant::now();
                let mut probe_sent = 0;
                let mut last_tcp_keepalive_sent = Instant::now();
                loop {
                    let tm0 = time::sleep(Duration::from_secs(1));
                    let data_received_fut = data_received.notified();
                    let tcp_packet_received_fut = tcp_packet_received.notified();

                    tokio::select! {
                        _ = tm0 => {
                            
                            if tcp_keepalive_time.is_some() {
                                let tcp_idle = last_tcp_recv.elapsed();
                                if tcp_idle > tcp_keepalive_time.unwrap() {
                                    if last_tcp_keepalive_sent.elapsed() >= tcp_keepalive_intvl {
                                        if probe_sent >= tcp_keepalive_retries {
                                            info!("Connection {} TCP keep-alive retry exceeded", sock);
                                            break;
                                        }
                                        trace!("Connection {} sending keep-alive {} / {}", sock, probe_sent + 1, tcp_keepalive_retries);
                                        let result = sock.send_keepalive().await;
                                        if result.is_none() {
                                            warn!("Failed to send keep-alive!");
                                        }
                                        probe_sent += 1;
                                        last_tcp_keepalive_sent = Instant::now();
                                    }
                                }
                            }

                            if last_data_recv.elapsed() > UDP_TTL {
                                // Execute every 1 sec, unless there's traffic
                                info!("Connection {} No traffic seen in the last {:?}, closing connection", sock, UDP_TTL);
                                break;
                            }
                        },
                        _ = quit.cancelled() => {
                            break;
                        },
                        _ = data_received_fut => {
                            last_data_recv = Instant::now();
                        },
                        _ = tcp_packet_received_fut => {
                            last_tcp_recv = Instant::now();
                            probe_sent = 0;
                        },
                    }
                }
                debug!("removed fake TCP socket {} from connections table", sock);
                connections.write().await.remove(&addr);
                quit.cancel();
            });
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
