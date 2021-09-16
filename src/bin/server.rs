use clap::{App, Arg};
use log::info;
use phantom::fake_tcp::packet::MAX_PACKET_LEN;
use phantom::fake_tcp::Stack;
use std::net::SocketAddrV4;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use tokio_tun::TunBuilder;
const UDP_TTL: Duration = Duration::from_secs(180);

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let matches = App::new("Phantom Server")
        .version("1.0")
        .author("Dndx")
        .arg(
            Arg::with_name("local")
                .short("l")
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the listening port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote")
                .short("r")
                .long("remote")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the connecting socket address")
                .takes_value(true),
        )
        .get_matches();

    let local_port: u16 = matches
        .value_of("local")
        .unwrap()
        .parse()
        .expect("bad local port");
    let remote_addr: SocketAddrV4 = matches
        .value_of("remote")
        .unwrap()
        .parse()
        .expect("bad remote address");

    let tun = TunBuilder::new()
        .name("") // if name is empty, then it is set by kernel.
        .tap(false) // false (default): TUN, true: TAP.
        .packet_info(false) // false: IFF_NO_PI, default is true.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address("192.168.201.1".parse().unwrap())
        .destination("192.168.201.2".parse().unwrap())
        .try_build()
        .unwrap();

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
                let udp_sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                udp_sock.connect(remote_addr).await.unwrap();

                loop {
                    let read_timeout = time::sleep(UDP_TTL);

                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            if let None = sock.send(&buf_udp[..size]).await {
                                return;
                            }
                        },
                        res = sock.recv(&mut buf_tcp) => {
                            match res {
                                Some(size) => {
                                    if size > 0 {
                                        udp_sock.send(&buf_tcp[..size]).await.unwrap();
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
