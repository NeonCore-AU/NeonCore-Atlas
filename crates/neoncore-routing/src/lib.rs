use neoncore_ip_stack::{Flow, FlowProtocol};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTable {
    #[serde(default)]
    pub mode: RoutingMode,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    Global,
    #[default]
    Rule,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub id: String,
    pub matcher: RouteMatcher,
    pub action: RouteAction,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteMatcher {
    Ip { value: IpAddr },
    Cidr { value: String },
    Port { value: u16 },
    Protocol { value: RouteProtocol },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Proxy,
    Direct,
    Reject,
}

impl RoutingTable {
    pub fn decide(&self, flow: &Flow) -> RouteAction {
        match self.mode {
            RoutingMode::Direct => return RouteAction::Direct,
            RoutingMode::Global => return RouteAction::Proxy,
            RoutingMode::Rule => {}
        }
        self.rules
            .iter()
            .filter(|rule| rule.enabled)
            .find(|rule| matches_rule(&rule.matcher, flow))
            .map(|rule| rule.action.clone())
            .unwrap_or(RouteAction::Proxy)
    }
}

fn matches_rule(matcher: &RouteMatcher, flow: &Flow) -> bool {
    match matcher {
        RouteMatcher::Ip { value } => flow.destination.address == *value,
        RouteMatcher::Cidr { value } => matches_cidr(flow.destination.address, value),
        RouteMatcher::Port { value } => flow.destination.port == *value,
        RouteMatcher::Protocol { value } => matches!(
            (value, flow.protocol),
            (RouteProtocol::Tcp, FlowProtocol::Tcp) | (RouteProtocol::Udp, FlowProtocol::Udp)
        ),
    }
}

fn matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (ip, base.parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(base))) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(ip), Ok(IpAddr::V6(base))) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use neoncore_ip_stack::{Flow, FlowProtocol, SocketEndpoint};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn routes_ipv4_cidr_to_direct() {
        let table = RoutingTable {
            mode: RoutingMode::Rule,
            rules: vec![RoutingRule {
                id: "local".to_string(),
                matcher: RouteMatcher::Cidr {
                    value: "10.0.0.0/8".to_string(),
                },
                action: RouteAction::Direct,
                enabled: true,
            }],
        };

        assert_eq!(
            table.decide(&flow(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))),
            RouteAction::Direct
        );
    }

    #[test]
    fn routes_ipv6_cidr_to_reject() {
        let table = RoutingTable {
            mode: RoutingMode::Rule,
            rules: vec![RoutingRule {
                id: "loopback".to_string(),
                matcher: RouteMatcher::Cidr {
                    value: "::1/128".to_string(),
                },
                action: RouteAction::Reject,
                enabled: true,
            }],
        };

        assert_eq!(
            table.decide(&flow(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            RouteAction::Reject
        );
    }

    fn flow(destination: IpAddr) -> Flow {
        Flow {
            source: SocketEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 50_000,
            },
            destination: SocketEndpoint {
                address: destination,
                port: 443,
            },
            protocol: FlowProtocol::Tcp,
        }
    }
}
