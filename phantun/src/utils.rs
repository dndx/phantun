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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

pub async fn lookup_host(domain: &str, ip4p_resolve: bool, ipv4_only: bool) -> std::net::SocketAddr {
    if ip4p_resolve {
        return resolve_ip4p_domain(domain);
    }
    return tokio::net::lookup_host(domain)
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
        .expect("unable to resolve remote host name");
}

fn resolve_ip4p_domain(domain: &str) -> std::net::SocketAddr {
    let ip4p_addr = dns_lookup::lookup_host(domain).unwrap();
    let ip4p_addr = ip4p_addr[0].to_string();
    let ip4p_resolve: Vec<&str> = ip4p_addr.split(':').collect();
    if ip4p_resolve.len() != 5 {
        panic!("Invalid IP4P values: {:?}", ip4p_resolve);
    }
    let port = u16::from_str_radix(ip4p_resolve[2], 16).expect("Invalid port value");
    let ipab = u16::from_str_radix(ip4p_resolve[3], 16).expect("Invalid ipab value");
    let ipcd = u16::from_str_radix(ip4p_resolve[4], 16).expect("Invalid ipcd value");
    
    let ipa = ipab >> 8;
    let ipb = ipab & 0xff;
    let ipc = ipcd >> 8;
    let ipd = ipcd & 0xff;

    let remote_addr = SocketAddr::new(
        Ipv4Addr::new(ipa.try_into().unwrap(), ipb.try_into().unwrap(), ipc.try_into().unwrap(), ipd.try_into().unwrap()).into(),
        port.try_into().unwrap()
    );
    return remote_addr;
}