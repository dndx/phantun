use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::Packet;
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
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
    let tcp_total_len = tcp_header_len + payload.map_or(0, |payload| payload.len());
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
    v4.set_ttl(64);
    v4.set_source(*local_addr.ip());
    v4.set_destination(*remote_addr.ip());
    v4.set_total_length(total_len.try_into().unwrap());
    v4.set_flags(ipv4::Ipv4Flags::DontFragment);
    let mut cksm = Checksum::new();
    cksm.add_bytes(v4.packet());
    v4.set_checksum(u16::from_be_bytes(cksm.checksum()));

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

    let mut cksm = Checksum::new();
    cksm.add_bytes(&local_addr.ip().octets());
    cksm.add_bytes(&remote_addr.ip().octets());
    let ip::IpNextHeaderProtocol(tcp_protocol) = ip::IpNextHeaderProtocols::Tcp;
    let mut pseudo = [0u8, tcp_protocol, 0, 0];
    pseudo[2..].copy_from_slice(&(tcp_total_len as u16).to_be_bytes());
    cksm.add_bytes(&pseudo);
    cksm.add_bytes(tcp.packet());
    tcp.set_checksum(u16::from_be_bytes(cksm.checksum()));

    v4_buf.unsplit(tcp_buf);
    v4_buf.freeze()
}

pub fn parse_ipv4_packet(buf: &Bytes) -> (ipv4::Ipv4Packet, tcp::TcpPacket) {
    let v4 = ipv4::Ipv4Packet::new(buf).unwrap();
    let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..]).unwrap();

    (v4, tcp)
}

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_build_tcp_packet_1460(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 1460]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_512(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 512]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_128(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 128]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }
}
