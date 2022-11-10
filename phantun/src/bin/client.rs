use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::Stack;
use log::{debug, error, info};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use phantun::Encryption;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time;
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
            Arg::new("tcp_connections")
                .long("tcp-connections")
                .required(false)
                .value_name("number")
                .help("Number of TCP connections per each client.")
                .default_value("8")
        )
        .arg(
            Arg::new("udp_connections")
                .long("udp-connections")
                .required(false)
                .value_name("number")
                .help("Number of UDP connections per each client.")
                .default_value("8")
        )
        .arg(
            Arg::new("encryption")
                .long("encryption")
                .required(false)
                .value_name("encryption")
                .help("Specify an encryption algorithm for using in TCP connections. \n\
                       Server and client should use the same encryption. \n\
                       Currently XOR is only supported and the format should be 'xor:key'.")
        )
        .get_matches();

    let local_addr: Arc<SocketAddr> = Arc::new(
        matches
            .get_one::<String>("local")
            .unwrap()
            .parse()
            .expect("bad local address"),
    );

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

    let (tun_local6, tun_peer6) = if ipv4_only {
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

    let tcp_socks_amount: usize = matches
        .get_one::<String>("tcp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of TCP connections per each client");
    if tcp_socks_amount == 0 {
        panic!("TCP connections should be greater than or equal to 1");
    }

    let udp_socks_amount: usize = matches
        .get_one::<String>("udp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of UDP connections per each client");
    if udp_socks_amount == 0 {
        panic!("UDP connections should be greater than or equal to 1");
    }

    let encryption = matches
        .get_one::<String>("encryption")
        .map(Encryption::from);
    debug!("Encryption in use: {:?}", encryption);
    let encryption = Arc::new(encryption);

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Arc<Option<Vec<u8>>> = Arc::new(
        matches
            .get_one::<String>("handshake_packet")
            .map(fs::read)
            .transpose()?,
    );

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

    let stack = Arc::new(Stack::new(tun, tun_peer, tun_peer6));

    let local_addr = local_addr.clone();
    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];
        let udp_sock = new_udp_reuseport(*local_addr);

        'main_loop: loop {
            let (size, addr) = udp_sock.recv_from(&mut buf_r).await.unwrap();

            info!("New UDP client from {}", addr);
            let stack = stack.clone();
            let local_addr = local_addr.clone();
            let handshake_packet = handshake_packet.clone();
            let encryption = encryption.clone();

            let udp_socks: Vec<_> = {
                let mut socks = Vec::with_capacity(udp_socks_amount);
                for _ in 0..udp_socks_amount {
                    let udp_sock = new_udp_reuseport(*local_addr);
                    if let Err(err) = udp_sock.connect(addr).await {
                        error!("Unable to connect to {addr} over udp: {err}");
                        continue 'main_loop;
                    }
                    socks.push(Arc::new(udp_sock));
                }
                socks
            };
            tokio::spawn(async move {
                let udp_socks = Arc::new(udp_socks);
                let cancellation = CancellationToken::new();
                let packet_received = Arc::new(Notify::new());
                let mut tcp_socks = Vec::with_capacity(tcp_socks_amount);
                let udp_sock_index = Arc::new(AtomicUsize::new(0));
                let tcp_sock_index = Arc::new(AtomicUsize::new(0));

                for sock_index in 0..tcp_socks_amount {
                    debug!("Creating tcp stream number {sock_index} for {addr} to {remote_addr}.");
                    let tcp_sock = match stack.connect(remote_addr).await {
                        Some(tcp_sock) => Arc::new(tcp_sock),
                        None => {
                            error!("Unable to connect to remote {}", remote_addr);
                            cancellation.cancel();
                            return;
                        }
                    };

                    if let Some(ref p) = *handshake_packet {
                        if tcp_sock.send(p).await.is_none() {
                            error!(
                                "Failed to send handshake packet to remote, closing connection."
                            );
                            cancellation.cancel();
                            return;
                        }

                        debug!("Sent handshake packet to: {}", tcp_sock);
                    }

                    // send first packet
                    if sock_index == 0 {
                        if let Some(ref enc) = *encryption {
                            enc.encrypt(&mut buf_r[..size]);
                        }
                        if tcp_sock.send(&buf_r[..size]).await.is_none() {
                            cancellation.cancel();
                            return;
                        }
                    }

                    tcp_socks.push(tcp_sock.clone());

                    // spawn "fastpath" UDP socket and task, this will offload main task
                    // from forwarding UDP packets
                    let packet_received = packet_received.clone();
                    let cancellation = cancellation.clone();
                    let udp_socks = udp_socks.clone();
                    let udp_sock_index = udp_sock_index.clone();
                    let encryption = encryption.clone();
                    tokio::spawn(async move {
                        let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                        loop {
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => {
                                    debug!("Closing connection requested for {addr}, closing connection {sock_index}");
                                    break;
                                },
                                res = tcp_sock.recv(&mut buf_tcp) => {
                                    match res {
                                        Some(size) => {
                                            let udp_sock_index = udp_sock_index.fetch_add(1, Ordering::Relaxed) % udp_socks_amount;
                                            let udp_sock = unsafe { udp_socks.get_unchecked(udp_sock_index) };
                                            if let Some(ref enc) = *encryption {
                                                enc.decrypt(&mut buf_tcp[..size]);
                                            }
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                debug!("Unable to send UDP packet to {}: {}, closing connection {sock_index}", e, addr);
                                                break;
                                            }
                                        },
                                        None => {
                                            debug!("TCP connection closed on {addr}, closing connection {sock_index}");
                                            break;
                                        },
                                    }
                                    packet_received.notify_waiters();
                                },
                            };
                        }
                        cancellation.cancel();
                    });
                    debug!(
                        "inserted fake TCP socket into connection table {remote_addr} {sock_index}"
                    );
                }

                for (sock_index, udp_sock) in udp_socks.iter().enumerate() {
                    let udp_sock = udp_sock.clone();
                    let packet_received = packet_received.clone();
                    let cancellation = cancellation.clone();
                    let tcp_socks = tcp_socks.clone();
                    let tcp_sock_index = tcp_sock_index.clone();
                    let encryption = encryption.clone();
                    tokio::spawn(async move {
                        let mut buf_udp = [0u8; MAX_PACKET_LEN];
                        loop {
                            let read_timeout = time::sleep(UDP_TTL);
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => {
                                    debug!("Closing connection requested for {addr}, closing connection UDP {sock_index}");
                                    break;
                                },
                                _ = packet_received.notified() => {},
                                res = udp_sock.recv(&mut buf_udp) => {
                                    match res {
                                        Ok(size) => {
                                            let tcp_sock_index = tcp_sock_index.fetch_add(1, Ordering::Relaxed) % tcp_socks_amount;
                                            let tcp_sock = unsafe { tcp_socks.get_unchecked(tcp_sock_index) };
                                            if let Some(ref enc) = *encryption {
                                                enc.encrypt(&mut buf_udp[..size]);
                                            }
                                            if tcp_sock.send(&buf_udp[..size]).await.is_none() {
                                                debug!("Unable to send TCP traffic to {addr}, closing connection {sock_index}");
                                                break;
                                            }
                                        },
                                        Err(e) => {
                                            debug!("UDP connection closed on {addr}: {e}, closing connection {sock_index}");
                                            break;
                                        }
                                    };

                                },
                                _ = read_timeout => {
                                    debug!("No traffic seen in the last {:?} on {addr}, closing connection {sock_index}", UDP_TTL);
                                    break;
                                },
                            };
                        }
                        cancellation.cancel();
                        info!("Connention {addr} to {remote_addr} closed {sock_index}");
                    });
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap();
    Ok(())
}
