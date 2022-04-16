use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Ifa, IfaFFlags, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifaddrmsg, Rtattr},
    socket::NlSocketHandle,
    types::RtBuffer,
};
use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

pub fn new_udp_reuseport(local_addr: SocketAddr) -> UdpSocket {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
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
    udp_sock.bind(&socket2::SockAddr::from(local_addr)).unwrap();
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into().unwrap()
}

pub fn assign_ipv6_address(device_name: &str, local: Ipv6Addr, peer: Ipv6Addr) {
    let index = nix::net::if_::if_nametoindex(device_name).unwrap();

    let mut rtnl = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();
    let mut rtattrs = RtBuffer::new();
    rtattrs.push(Rtattr::new(None, Ifa::Local, &local.octets()[..]).unwrap());
    rtattrs.push(Rtattr::new(None, Ifa::Address, &peer.octets()[..]).unwrap());

    let ifaddrmsg = Ifaddrmsg {
        ifa_family: RtAddrFamily::Inet6,
        ifa_prefixlen: 128,
        ifa_flags: IfaFFlags::empty(),
        ifa_scope: 0,
        ifa_index: index as i32,
        rtattrs,
    };
    let nl_header = Nlmsghdr::new(
        None,
        Rtm::Newaddr,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(ifaddrmsg),
    );
    rtnl.send(nl_header).unwrap();
}
