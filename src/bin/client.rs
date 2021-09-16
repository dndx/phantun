use clap::{App, Arg};
use lru_time_cache::LruCache;
use phantom::fake_tcp::packet::MAX_PACKET_LEN;
use phantom::fake_tcp::{Socket, Stack};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;
use tokio_tun::TunBuilder;

const UDP_TTL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() {
    let matches = App::new("Phantom Client")
        .version("1.0")
        .author("Dndx")
        .arg(
            Arg::with_name("local")
                .short("l")
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the listening socket address")
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

    let local_addr: SocketAddrV4 = matches
        .value_of("local")
        .unwrap()
        .parse()
        .expect("bad local address");
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
        .address("192.168.200.1".parse().unwrap())
        .destination("192.168.200.2".parse().unwrap())
        .try_build()
        .unwrap();

    let udp_sock = Arc::new(UdpSocket::bind(local_addr).await.unwrap());
    let connections = Mutex::new(LruCache::<SocketAddrV4, Arc<Socket>>::with_expiry_duration(
        UDP_TTL,
    ));

    thread::sleep(Duration::from_secs(5));
    let mut stack = Stack::new(tun);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];
        let mut cleanup_timer = time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                Ok((size, SocketAddr::V4(addr))) = udp_sock.recv_from(&mut buf_r) => {
                    if let Some(sock) = connections.lock().await.get_mut(&addr) {
                        sock.send(&buf_r[..size]).await;
                        continue;
                    }

                    let mut sock = Arc::new(stack.connect(remote_addr).await);
                    sock.send(&buf_r[..size]).await;
                    assert!(connections.lock().await.insert(addr, sock.clone()).is_none());
                    let udp_sock = udp_sock.clone();

                    tokio::spawn(async move {
                        loop {
                            let mut buf_r = [0u8; MAX_PACKET_LEN];
                            let size = sock.recv(&mut buf_r).await;

                            if size > 0 {
                                udp_sock.send_to(&buf_r[..size], addr).await.unwrap();
                            }
                        }
                    });
                },
                _ = cleanup_timer.tick() => {
                    connections.lock().await.iter();
                },
            }
        }
    });

    tokio::join!(main_loop);
}
