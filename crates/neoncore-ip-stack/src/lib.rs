use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: TransportProtocol,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: TransportProtocol,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportPacket<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub source: SocketEndpoint,
    pub destination: SocketEndpoint,
    pub protocol: FlowProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, thiserror::Error)]
pub enum IpStackError {
    #[error("packet is too short")]
    PacketTooShort,
    #[error("unsupported IP version: {0}")]
    UnsupportedIpVersion(u8),
    #[error("invalid IPv4 header")]
    InvalidIpv4Header,
    #[error("invalid IPv6 header")]
    InvalidIpv6Header,
    #[error("unsupported transport protocol")]
    UnsupportedTransportProtocol,
    #[error("invalid transport header")]
    InvalidTransportHeader,
}

pub fn parse_ip_packet(packet: &[u8]) -> Result<IpPacket<'_>, IpStackError> {
    let first = *packet.first().ok_or(IpStackError::PacketTooShort)?;
    match first >> 4 {
        4 => parse_ipv4(packet).map(IpPacket::V4),
        6 => parse_ipv6(packet).map(IpPacket::V6),
        version => Err(IpStackError::UnsupportedIpVersion(version)),
    }
}

pub fn flow_from_packet(packet: &[u8]) -> Result<Flow, IpStackError> {
    match parse_ip_packet(packet)? {
        IpPacket::V4(ip) => match parse_transport(ip.protocol, ip.payload)? {
            TransportPacket::Tcp(tcp) => Ok(Flow {
                source: SocketEndpoint {
                    address: IpAddr::V4(ip.source),
                    port: tcp.source_port,
                },
                destination: SocketEndpoint {
                    address: IpAddr::V4(ip.destination),
                    port: tcp.destination_port,
                },
                protocol: FlowProtocol::Tcp,
            }),
            TransportPacket::Udp(udp) => Ok(Flow {
                source: SocketEndpoint {
                    address: IpAddr::V4(ip.source),
                    port: udp.source_port,
                },
                destination: SocketEndpoint {
                    address: IpAddr::V4(ip.destination),
                    port: udp.destination_port,
                },
                protocol: FlowProtocol::Udp,
            }),
        },
        IpPacket::V6(ip) => match parse_transport(ip.next_header, ip.payload)? {
            TransportPacket::Tcp(tcp) => Ok(Flow {
                source: SocketEndpoint {
                    address: IpAddr::V6(ip.source),
                    port: tcp.source_port,
                },
                destination: SocketEndpoint {
                    address: IpAddr::V6(ip.destination),
                    port: tcp.destination_port,
                },
                protocol: FlowProtocol::Tcp,
            }),
            TransportPacket::Udp(udp) => Ok(Flow {
                source: SocketEndpoint {
                    address: IpAddr::V6(ip.source),
                    port: udp.source_port,
                },
                destination: SocketEndpoint {
                    address: IpAddr::V6(ip.destination),
                    port: udp.destination_port,
                },
                protocol: FlowProtocol::Udp,
            }),
        },
    }
}

pub fn parse_transport(
    protocol: TransportProtocol,
    payload: &[u8],
) -> Result<TransportPacket<'_>, IpStackError> {
    match protocol {
        TransportProtocol::Tcp => parse_tcp(payload).map(TransportPacket::Tcp),
        TransportProtocol::Udp => parse_udp(payload).map(TransportPacket::Udp),
        _ => Err(IpStackError::UnsupportedTransportProtocol),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet<'_>, IpStackError> {
    if packet.len() < 20 {
        return Err(IpStackError::PacketTooShort);
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(IpStackError::InvalidIpv4Header);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || packet.len() < total_len {
        return Err(IpStackError::InvalidIpv4Header);
    }
    Ok(Ipv4Packet {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: protocol_from_number(packet[9]),
        payload: &packet[ihl..total_len],
    })
}

fn parse_ipv6(packet: &[u8]) -> Result<Ipv6Packet<'_>, IpStackError> {
    if packet.len() < 40 {
        return Err(IpStackError::PacketTooShort);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if packet.len() < 40 + payload_len {
        return Err(IpStackError::InvalidIpv6Header);
    }
    Ok(Ipv6Packet {
        source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
        destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
        next_header: protocol_from_number(packet[6]),
        payload: &packet[40..40 + payload_len],
    })
}

fn parse_tcp(payload: &[u8]) -> Result<TcpSegment<'_>, IpStackError> {
    if payload.len() < 20 {
        return Err(IpStackError::InvalidTransportHeader);
    }
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if data_offset < 20 || payload.len() < data_offset {
        return Err(IpStackError::InvalidTransportHeader);
    }
    let flag_byte = payload[13];
    Ok(TcpSegment {
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        flags: TcpFlags {
            fin: flag_byte & 0x01 != 0,
            syn: flag_byte & 0x02 != 0,
            rst: flag_byte & 0x04 != 0,
            psh: flag_byte & 0x08 != 0,
            ack: flag_byte & 0x10 != 0,
            urg: flag_byte & 0x20 != 0,
        },
        payload: &payload[data_offset..],
    })
}

fn parse_udp(payload: &[u8]) -> Result<UdpDatagram<'_>, IpStackError> {
    if payload.len() < 8 {
        return Err(IpStackError::InvalidTransportHeader);
    }
    let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if len < 8 || payload.len() < len {
        return Err(IpStackError::InvalidTransportHeader);
    }
    Ok(UdpDatagram {
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: &payload[8..len],
    })
}

fn protocol_from_number(value: u8) -> TransportProtocol {
    match value {
        1 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        58 => TransportProtocol::Icmpv6,
        other => TransportProtocol::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp_flow() {
        let packet = ipv4_packet(17, &[0x12, 0x34, 0x00, 0x35, 0, 12, 0, 0, 1, 2, 3, 4]);
        let flow = flow_from_packet(&packet).unwrap();

        assert_eq!(flow.source.address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(flow.destination.port, 53);
        assert_eq!(flow.protocol, FlowProtocol::Udp);
    }

    #[test]
    fn parses_ipv6_tcp_flow() {
        let mut tcp = vec![
            0x01, 0xbb, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
        ];
        let packet = ipv6_packet(6, &mut tcp);
        let flow = flow_from_packet(&packet).unwrap();

        assert!(flow.source.address.is_ipv6());
        assert_eq!(flow.source.port, 443);
        assert_eq!(flow.destination.port, 80);
        assert_eq!(flow.protocol, FlowProtocol::Tcp);
    }

    pub fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + payload.len()) as u16;
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    pub fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, next_header, 64];
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        packet.extend_from_slice(payload);
        packet
    }
}
