use crate::session::{
    KernelNode, KernelRouteAction, KernelRoutingConfig, KernelRoutingMode, KernelRuleMatcher,
    KernelSession, TargetAddress,
};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum RouteDecision {
    Proxy(KernelNode),
    Direct,
    Reject,
}

#[derive(Debug, Clone)]
pub struct Router {
    selected_node: KernelNode,
    nodes: Vec<KernelNode>,
    config: KernelRoutingConfig,
}

impl Router {
    pub fn new(session: &KernelSession) -> Self {
        Self {
            selected_node: session.selected_node.clone(),
            nodes: session.nodes.clone(),
            config: session.routing.clone(),
        }
    }

    pub fn decide(&self, target: &TargetAddress) -> anyhow::Result<RouteDecision> {
        match self.config.mode {
            KernelRoutingMode::Direct => return Ok(RouteDecision::Direct),
            KernelRoutingMode::Global => {
                return Ok(RouteDecision::Proxy(self.selected_node.clone()))
            }
            KernelRoutingMode::Rule => {}
        }
        for rule in self.config.rules.iter().filter(|rule| rule.enabled) {
            if !matches_rule(&rule.matcher, target) {
                continue;
            }
            return match &rule.action {
                KernelRouteAction::Direct => Ok(RouteDecision::Direct),
                KernelRouteAction::Reject => Ok(RouteDecision::Reject),
                KernelRouteAction::Proxy { node_id } => {
                    Ok(RouteDecision::Proxy(self.node_for(node_id.as_deref())?))
                }
            };
        }
        Ok(RouteDecision::Proxy(self.selected_node.clone()))
    }

    fn node_for(&self, node_id: Option<&str>) -> anyhow::Result<KernelNode> {
        let Some(node_id) = node_id else {
            return Ok(self.selected_node.clone());
        };
        self.nodes
            .iter()
            .chain(std::iter::once(&self.selected_node))
            .find(|node| node.id.as_deref() == Some(node_id))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("route references unknown node: {node_id}"))
    }
}

fn matches_rule(matcher: &KernelRuleMatcher, target: &TargetAddress) -> bool {
    match matcher {
        KernelRuleMatcher::Domain { value } => target.host.eq_ignore_ascii_case(value),
        KernelRuleMatcher::DomainSuffix { value } => target
            .host
            .to_ascii_lowercase()
            .ends_with(&value.to_ascii_lowercase()),
        KernelRuleMatcher::DomainKeyword { value } => target
            .host
            .to_ascii_lowercase()
            .contains(&value.to_ascii_lowercase()),
        KernelRuleMatcher::Cidr { value } => matches_cidr(&target.host, value),
    }
}

fn matches_cidr(host: &str, cidr: &str) -> bool {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{KernelRouteRule, KernelSession};
    use serde_json::json;

    fn session_with_rule(action: KernelRouteAction) -> KernelSession {
        KernelSession {
            listen_host: "127.0.0.1".to_string(),
            listen_port: 0,
            selected_node: KernelNode {
                id: Some("proxy".to_string()),
                protocol: "direct".to_string(),
                server: "unused".to_string(),
                server_port: 1,
                user_id: "".to_string(),
                parameters: json!({}),
            },
            nodes: Vec::new(),
            routing: KernelRoutingConfig {
                mode: KernelRoutingMode::Rule,
                rules: vec![KernelRouteRule {
                    id: "r1".to_string(),
                    matcher: KernelRuleMatcher::DomainSuffix {
                        value: ".local".to_string(),
                    },
                    action,
                    enabled: true,
                }],
            },
            dns: Default::default(),
        }
    }

    #[test]
    fn suffix_rule_can_select_direct() {
        let router = Router::new(&session_with_rule(KernelRouteAction::Direct));
        let decision = router
            .decide(&TargetAddress {
                host: "service.local".to_string(),
                port: 80,
            })
            .unwrap();

        assert!(matches!(decision, RouteDecision::Direct));
    }
}
