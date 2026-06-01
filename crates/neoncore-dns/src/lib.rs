use neoncore_ip_stack::{Flow, FlowProtocol};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHijackConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default)]
    pub ipv4_servers: Vec<IpAddr>,
    #[serde(default)]
    pub ipv6_servers: Vec<IpAddr>,
}

impl Default for DnsHijackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_dns_port(),
            ipv4_servers: Vec::new(),
            ipv6_servers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsInterception {
    Hijack { destination: IpAddr, port: u16 },
    Pass,
}

impl DnsHijackConfig {
    pub fn inspect(&self, flow: &Flow) -> DnsInterception {
        if !self.enabled || flow.protocol != FlowProtocol::Udp || flow.destination.port != self.port
        {
            return DnsInterception::Pass;
        }
        if self.ipv4_servers.is_empty() && self.ipv6_servers.is_empty() {
            return DnsInterception::Hijack {
                destination: flow.destination.address,
                port: flow.destination.port,
            };
        }
        let servers = if flow.destination.address.is_ipv4() {
            &self.ipv4_servers
        } else {
            &self.ipv6_servers
        };
        if servers.contains(&flow.destination.address) {
            DnsInterception::Hijack {
                destination: flow.destination.address,
                port: flow.destination.port,
            }
        } else {
            DnsInterception::Pass
        }
    }
}

pub fn looks_like_dns_query(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    flags & 0x8000 == 0 && question_count > 0
}

fn default_enabled() -> bool {
    true
}

fn default_dns_port() -> u16 {
    53
}

#[cfg(test)]
mod tests {
    use super::*;
    use neoncore_ip_stack::{Flow, FlowProtocol, SocketEndpoint};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn hijacks_ipv4_dns_flow() {
        let config = DnsHijackConfig::default();
        let flow = udp_flow(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        assert!(matches!(
            config.inspect(&flow),
            DnsInterception::Hijack { .. }
        ));
    }

    #[test]
    fn hijacks_ipv6_dns_flow() {
        let config = DnsHijackConfig::default();
        let flow = udp_flow(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);

        assert!(matches!(
            config.inspect(&flow),
            DnsInterception::Hijack { .. }
        ));
    }

    #[test]
    fn detects_basic_dns_query_wire_shape() {
        let query = [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];

        assert!(looks_like_dns_query(&query));
    }

    fn udp_flow(destination: IpAddr, port: u16) -> Flow {
        Flow {
            source: SocketEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 53_000,
            },
            destination: SocketEndpoint {
                address: destination,
                port,
            },
            protocol: FlowProtocol::Udp,
        }
    }
}
