use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::Stack;
use log::{debug, error, info};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use phantun::Encryption;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
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
        .arg(
            Arg::new("udp_connections")
                .long("udp-connections")
                .required(false)
                .value_name("number")
                .help("Number of UDP connections per each TCP connections.")
                .default_value(num_cpus.to_string())
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
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

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .tap(false) // false (default): TUN, true: TAP.
        .packet_info(false) // false: IFF_NO_PI, default is true.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .try_build_mq(num_cpus)
        .unwrap();

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let main_loop = tokio::spawn(async move {
        'main_loop: loop {
            let tcp_sock = Arc::new(stack.accept().await);
            info!("New connection: {}", tcp_sock);
            if let Some(ref p) = handshake_packet {
                if tcp_sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", tcp_sock);
            }

            let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await;

            let udp_sock = match udp_sock {
                Ok(udp_sock) => udp_sock,
                Err(err) => {
                    error!("No more UDP address is available: {err}");
                    continue;
                }
            };

            let local_addr = udp_sock.local_addr().unwrap();
            drop(udp_sock);

            let cancellation = CancellationToken::new();
            let packet_received = Arc::new(Notify::new());
            let udp_socks: Vec<_> = {
                let mut socks = Vec::with_capacity(udp_socks_amount);
                for _ in 0..udp_socks_amount {
                    let udp_sock = new_udp_reuseport(local_addr);
                    if let Err(err) = udp_sock.connect(remote_addr).await {
                        error!("UDP couldn't connect to {remote_addr}: {err}, closing connection");
                        continue 'main_loop;
                    }
                    socks.push(Arc::new(udp_sock));
                }
                socks
            };

            for udp_sock in &udp_socks {
                let tcp_sock = tcp_sock.clone();
                let cancellation = cancellation.clone();
                let encryption = encryption.clone();
                let packet_received = packet_received.clone();
                let udp_sock = udp_sock.clone();
                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    loop {
                        let read_timeout = time::sleep(UDP_TTL);
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                debug!("Closing connection requested for {local_addr}, closing connection");
                                break;
                            },
                            _ = read_timeout => {
                                debug!("No traffic seen in the last {:?}, closing connection {local_addr}", UDP_TTL);
                                break;
                            },
                            _ = packet_received.notified() => {},
                            res = udp_sock.recv(&mut buf_udp) => {
                                match res {
                                    Ok(size) => {
                                        if let Some(ref enc) = *encryption {
                                            enc.encrypt(&mut buf_udp[..size]);
                                        }
                                        if tcp_sock.send(&buf_udp[..size]).await.is_none() {
                                            debug!("Unable to send TCP packet to {remote_addr}, closing connection");
                                            break;
                                        }
                                    },
                                    Err(err) => {
                                        debug!("UDP connection closed on {remote_addr}: {err}, closing connection");
                                        break;

                                    }
                                };
                            },
                        };
                    }
                    cancellation.cancel();
                });
            }
            let tcp_sock = tcp_sock.clone();
            let encryption = encryption.clone();
            let packet_received = packet_received.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                let mut udp_sock_index = 0;

                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            debug!("Closing connection requested for {local_addr}, closing connection");
                            break;
                        },
                        res = tcp_sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    udp_sock_index = (udp_sock_index + 1) % udp_socks_amount;
                                    let udp_sock = udp_socks[udp_sock_index].clone();
                                    if let Some(ref enc) = *encryption {
                                        enc.decrypt(&mut buf_tcp[..size]);
                                    }
                                    if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                        debug!("Unable to send UDP packet to {local_addr}: {e}, closing connection");
                                        break;
                                    }
                                },
                                None => {
                                    debug!("TCP connection closed on {local_addr}");
                                    break;
                                },
                            };
                            packet_received.notify_waiters();
                        },
                    };
                }
                cancellation.cancel();
                info!("Connention {local_addr} closed");
            });
        }
    });

    tokio::join!(main_loop).0.unwrap();
    Ok(())
}
