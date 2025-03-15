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
use nix::sys::socket::{CmsgIterator, ControlMessageOwned, SockaddrLike as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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

    // enable IP_PKTINFO/IPV6_PKTINFO delivery so we know the destination address of incoming
    // packets
    if local_addr.is_ipv4() {
        nix::sys::socket::setsockopt(&udp_sock, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)
            .unwrap();
    } else {
        nix::sys::socket::setsockopt(
            &udp_sock,
            nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
            &true,
        )
        .unwrap();
    }

    udp_sock.bind(&socket2::SockAddr::from(local_addr)).unwrap();
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into().unwrap()
}

pub async fn udp_recv_pktinfo(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, std::net::IpAddr)> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    sock.async_io(Interest::READABLE, || {
        // FIXME this is somewhat excessive, we actually need only
        // max(sizeof(in_pktinfo), sizeof(in6_pktinfo))
        let mut control_buffer = nix::cmsg_space!(nix::libc::in_pktinfo, nix::libc::in6_pktinfo);
        let iov = &mut [std::io::IoSliceMut::new(buf)];
        let res = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
            sock.as_raw_fd(),
            iov,
            Some(&mut control_buffer),
            nix::sys::socket::MsgFlags::empty(),
        )?;

        let src_addr = res.address.expect("missing source address");
        let src_addr: SocketAddr = {
            if let Some(inaddr) = src_addr.as_sockaddr_in() {
                SocketAddrV4::new(inaddr.ip(), inaddr.port()).into()
            } else if let Some(in6addr) = src_addr.as_sockaddr_in6() {
                SocketAddrV6::new(
                    in6addr.ip(),
                    in6addr.port(),
                    in6addr.flowinfo(),
                    in6addr.scope_id(),
                )
                .into()
            } else {
                panic!("unexpected source address family {:#?}", src_addr.family());
            }
        };

        let dst_addr = dst_addr_from_cmsgs(res.cmsgs()?).expect("didn't receive pktinfo");

        Ok((res.bytes, src_addr, dst_addr))
    })
    .await
}

fn dst_addr_from_cmsgs(cmsgs: CmsgIterator) -> Option<IpAddr> {
    for cmsg in cmsgs {
        if let ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
            return Some(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()).into());
        }
        if let ControlMessageOwned::Ipv6PacketInfo(pktinfo) = cmsg {
            return Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr).into());
        }
    }
    None
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
