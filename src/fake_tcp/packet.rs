use bytes::{Bytes, BytesMut};
use pnet::packet::{ip, ipv4, tcp};
use std::convert::TryInto;
use std::net::SocketAddrV4;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 1500;

pub fn build_tcp_packet(
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: Option<&[u8]>,
) -> Bytes {
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_total_len = TCP_HEADER_LEN + if wscale {4} else {0} // nop + wscale
                        + payload.map_or(0, |payload| payload.len());
    let total_len = IPV4_HEADER_LEN + tcp_total_len;
    let mut buf = BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    let mut v4_buf = buf.split_to(IPV4_HEADER_LEN);
    let mut tcp_buf = buf.split_to(tcp_total_len);
    assert_eq!(0, buf.len());

    let mut v4 = ipv4::MutableIpv4Packet::new(&mut v4_buf).unwrap();
    v4.set_version(4);
    v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
    v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
    v4.set_ttl(32);
    v4.set_source(*local_addr.ip());
    v4.set_destination(*remote_addr.ip());
    v4.set_total_length(total_len.try_into().unwrap());
    v4.set_flags(ipv4::Ipv4Flags::DontFragment);
    v4.set_checksum(ipv4::checksum(&v4.to_immutable()));

    let mut tcp = tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_window(0xffff);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset(TCP_HEADER_LEN as u8 / 4 + if wscale { 1 } else { 0 });
    if wscale {
        let wscale = tcp::TcpOption::wscale(14);
        tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
    }

    if let Some(payload) = payload {
        tcp.set_payload(payload);
    }

    let checksum = tcp::ipv4_checksum(&tcp.to_immutable(), local_addr.ip(), remote_addr.ip());
    tcp.set_checksum(checksum);

    v4_buf.unsplit(tcp_buf);

    v4_buf.freeze()
}

pub fn parse_ipv4_packet(buf: &Bytes) -> (ipv4::Ipv4Packet, tcp::TcpPacket) {
    let v4 = ipv4::Ipv4Packet::new(buf).unwrap();
    let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..]).unwrap();

    (v4, tcp)
}
