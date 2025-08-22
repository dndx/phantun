use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Ifa, IfaF, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    nl::{NlPayload, NlmsghdrBuilder},
    rtnl::{IfaddrmsgBuilder, RtattrBuilder},
    socket::synchronous::NlSocketHandle,
    types::RtBuffer,
    utils::Groups,
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

    let rtnl = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty()).unwrap();
    let mut rtattrs = RtBuffer::new();
    rtattrs.push(
        RtattrBuilder::default()
            .rta_type(Ifa::Local)
            .rta_payload(&local.octets()[..])
            .build()
            .unwrap(),
    );
    rtattrs.push(
        RtattrBuilder::default()
            .rta_type(Ifa::Address)
            .rta_payload(&peer.octets()[..])
            .build()
            .unwrap(),
    );

    let ifaddrmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet6)
        .ifa_prefixlen(128)
        .ifa_flags(IfaF::empty())
        .ifa_scope(RtScope::Universe)
        .ifa_index(index)
        .rtattrs(rtattrs)
        .build()
        .unwrap();
    let nl_header = NlmsghdrBuilder::default()
        .nl_type(Rtm::Newaddr)
        .nl_flags(NlmF::REQUEST)
        .nl_payload(NlPayload::Payload(ifaddrmsg))
        .build()
        .unwrap();
    rtnl.send(&nl_header).unwrap();
}
