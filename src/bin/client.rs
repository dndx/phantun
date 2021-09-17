use clap::{App, Arg};
use log::{debug, error, info};
use lru_time_cache::{LruCache, TimedEntry};
use phantom::fake_tcp::packet::MAX_PACKET_LEN;
use phantom::fake_tcp::{Socket, Stack};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;
use tokio_tun::TunBuilder;

const UDP_TTL: Duration = Duration::from_secs(180);

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

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

    info!("Created TUN device {}", tun.name());

    let udp_sock = Arc::new(UdpSocket::bind(local_addr).await.unwrap());
    let connections = Arc::new(Mutex::new(
        LruCache::<SocketAddrV4, Arc<Socket>>::with_expiry_duration(UDP_TTL),
    ));

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

                    info!("New UDP client from {}", addr);
                    let sock = stack.connect(remote_addr).await;
                    if sock.is_none() {
                        error!("Unable to connect to remote {}", remote_addr);
                        continue;
                    }

                    let sock = Arc::new(sock.unwrap());
                    let res = sock.send(&buf_r[..size]).await;
                    if res.is_none() {
                        continue;
                    }

                    assert!(connections.lock().await.insert(addr, sock.clone()).is_none());
                    debug!("inserted fake TCP socket into LruCache");
                    let udp_sock = udp_sock.clone();

                    let connections = connections.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut buf_r = [0u8; MAX_PACKET_LEN];
                            match sock.recv(&mut buf_r).await {
                                Some(size) => {
                                    udp_sock.send_to(&buf_r[..size], addr).await.unwrap();
                                },
                                None => {
                                    connections.lock().await.remove(&addr);
                                    debug!("removed fake TCP socket from LruCache");
                                    return;
                                },
                            }
                        }
                    });
                },
                _ = cleanup_timer.tick() => {
                    let mut total = 0;

                    for c in connections.lock().await.notify_iter() {
                        if let TimedEntry::Expired(_addr, sock) = c {
                            sock.close();
                            total += 1;
                        }
                    }

                    debug!("Cleaned {} stale connections", total);
                },
            }
        }
    });

    tokio::join!(main_loop).0.unwrap();
}
