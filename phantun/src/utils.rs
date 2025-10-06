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
use nix::sys::socket::{
    CmsgIterator, ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, cmsg_space,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use tokio::io::Interest;
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

/// Similiar to `UdpSocket::recv_from()`, but returns a 3rd value `IPAddr`
/// which corresponds to where the UDP datagram was destined to, this is useful
/// for disambigous when socket can receive on multiple IP address
/// or interfaces.
pub async fn udp_recv_pktinfo(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, IpAddr)> {
    sock.async_io(Interest::READABLE, || {
        const CONTROL_MESSAGE_BUFFER_SIZE: usize = max_usize(
            cmsg_space::<nix::libc::in_pktinfo>(),
            cmsg_space::<nix::libc::in6_pktinfo>(),
        );
        let mut control_message_buffer = [0u8; CONTROL_MESSAGE_BUFFER_SIZE];
        let iov = &mut [std::io::IoSliceMut::new(buf)];
        let res = nix::sys::socket::recvmsg::<SockaddrStorage>(
            sock.as_raw_fd(),
            iov,
            Some(&mut control_message_buffer),
            MsgFlags::empty(),
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

const fn max_usize(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}
