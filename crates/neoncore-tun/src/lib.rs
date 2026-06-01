use neoncore_dns::{looks_like_dns_query, DnsHijackConfig, DnsInterception};
use neoncore_ip_stack::{
    flow_from_packet, parse_ip_packet, parse_transport, Flow, FlowProtocol, IpPacket,
    TransportPacket,
};
use neoncore_routing::{RouteAction, RoutingTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    #[serde(default)]
    pub routing: RoutingTable,
    #[serde(default)]
    pub dns_hijack: DnsHijackConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDecision {
    ForwardTcp { flow: Flow, action: RouteAction },
    ForwardUdp { flow: Flow, action: RouteAction },
    InterceptDns { flow: Flow },
    Drop { reason: DropReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    UnsupportedPacket,
    RouteRejected,
    UnsupportedTransport,
}

#[derive(Debug, Clone)]
pub struct TunEngine {
    config: TunConfig,
}

impl TunEngine {
    pub fn new(config: TunConfig) -> Self {
        Self { config }
    }

    pub fn inspect_packet(&self, packet: &[u8]) -> TunDecision {
        let flow = match flow_from_packet(packet) {
            Ok(flow) => flow,
            Err(_) => {
                return TunDecision::Drop {
                    reason: DropReason::UnsupportedPacket,
                }
            }
        };
        if self.is_dns_hijack(packet, &flow) {
            return TunDecision::InterceptDns { flow };
        }
        let action = self.config.routing.decide(&flow);
        if action == RouteAction::Reject {
            return TunDecision::Drop {
                reason: DropReason::RouteRejected,
            };
        }
        match flow.protocol {
            FlowProtocol::Tcp => TunDecision::ForwardTcp { flow, action },
            FlowProtocol::Udp => TunDecision::ForwardUdp { flow, action },
        }
    }

    fn is_dns_hijack(&self, packet: &[u8], flow: &Flow) -> bool {
        if !matches!(
            self.config.dns_hijack.inspect(flow),
            DnsInterception::Hijack { .. }
        ) {
            return false;
        }
        let Ok(ip) = parse_ip_packet(packet) else {
            return false;
        };
        let transport = match ip {
            IpPacket::V4(ip) => parse_transport(ip.protocol, ip.payload),
            IpPacket::V6(ip) => parse_transport(ip.next_header, ip.payload),
        };
        match transport {
            Ok(TransportPacket::Udp(datagram)) => looks_like_dns_query(datagram.payload),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neoncore_routing::{RouteMatcher, RoutingMode, RoutingRule};

    #[test]
    fn intercepts_ipv4_dns_query() {
        let engine = TunEngine::new(TunConfig::default());
        let packet = ipv4_udp_packet(53, &[0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        assert!(matches!(
            engine.inspect_packet(&packet),
            TunDecision::InterceptDns { .. }
        ));
    }

    #[test]
    fn forwards_ipv6_tcp_by_rule() {
        let engine = TunEngine::new(TunConfig {
            routing: RoutingTable {
                mode: RoutingMode::Rule,
                rules: vec![RoutingRule {
                    id: "tcp-direct".to_string(),
                    matcher: RouteMatcher::Port { value: 443 },
                    action: RouteAction::Direct,
                    enabled: true,
                }],
            },
            dns_hijack: DnsHijackConfig::default(),
        });
        let packet = ipv6_tcp_packet(443);

        assert!(matches!(
            engine.inspect_packet(&packet),
            TunDecision::ForwardTcp {
                action: RouteAction::Direct,
                ..
            }
        ));
    }

    #[test]
    fn forwards_ipv4_udp_when_not_dns() {
        let engine = TunEngine::new(TunConfig::default());
        let packet = ipv4_udp_packet(123, b"time");

        assert!(matches!(
            engine.inspect_packet(&packet),
            TunDecision::ForwardUdp {
                action: RouteAction::Proxy,
                ..
            }
        ));
    }

    fn ipv4_udp_packet(destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&53_000_u16.to_be_bytes());
        udp.extend_from_slice(&destination_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&0_u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let total_len = (20 + udp.len()) as u16;
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8,
        ];
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet.extend_from_slice(&udp);
        packet
    }

    fn ipv6_tcp_packet(destination_port: u16) -> Vec<u8> {
        let mut tcp = vec![0x01, 0xbb];
        tcp.extend_from_slice(&destination_port.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0]);
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, 6, 64];
        packet[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        packet.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
        packet.extend_from_slice(&tcp);
        packet
    }
}
