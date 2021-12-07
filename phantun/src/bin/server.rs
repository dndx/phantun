use clap::{crate_version, App, Arg};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::Stack;
use log::{error, info};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use tokio_tun::TunBuilder;
const UDP_TTL: Duration = Duration::from_secs(180);

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let matches = App::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::with_name("local")
                .short("l")
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote")
                .short("r")
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .default_value("192.168.201.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
                .takes_value(true),
        )
        .get_matches();

    let local_port: u16 = matches
        .value_of("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.value_of("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");
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

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let main_loop = tokio::spawn(async move {
        let mut buf_udp = [0u8; MAX_PACKET_LEN];
        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        loop {
            let sock = stack.accept().await;
            info!("New connection: {}", sock);

            tokio::spawn(async move {
                let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .await
                .unwrap();
                udp_sock.connect(remote_addr).await.unwrap();

                loop {
                    let read_timeout = time::sleep(UDP_TTL);

                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            if sock.send(&buf_udp[..size]).await.is_none() {
                                return;
                            }
                        },
                        res = sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    if size > 0 {
                                        if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                            error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                            return;
                                        }
                                    }
                                },
                                None => { return; },
                            }
                        },
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                            return;
                        }
                    };
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap();
}
