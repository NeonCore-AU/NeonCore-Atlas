use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSession {
    pub listen_host: String,
    pub listen_port: u16,
    pub selected_node: KernelNode,
    #[serde(default)]
    pub nodes: Vec<KernelNode>,
    #[serde(default)]
    pub routing: KernelRoutingConfig,
    #[serde(default)]
    pub dns: KernelDnsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelNode {
    #[serde(default)]
    pub id: Option<String>,
    pub protocol: String,
    pub server: String,
    pub server_port: u16,
    pub user_id: String,
    pub parameters: serde_json::Value,
}

impl KernelNode {
    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters.get(key).and_then(|value| value.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelRoutingConfig {
    #[serde(default)]
    pub mode: KernelRoutingMode,
    #[serde(default)]
    pub rules: Vec<KernelRouteRule>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelRoutingMode {
    Global,
    #[default]
    Rule,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRouteRule {
    pub id: String,
    pub matcher: KernelRuleMatcher,
    pub action: KernelRouteAction,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KernelRuleMatcher {
    Domain { value: String },
    DomainSuffix { value: String },
    DomainKeyword { value: String },
    Cidr { value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KernelRouteAction {
    Proxy { node_id: Option<String> },
    Direct,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelDnsConfig {
    #[serde(default)]
    pub hosts: Vec<KernelHostMapping>,
    #[serde(default)]
    pub prefer_ipv6: bool,
    #[serde(default = "default_proxy_bootstrap_nameservers")]
    pub proxy_bootstrap_nameservers: Vec<String>,
    #[serde(default = "default_fake_ip_cidrs")]
    pub fake_ip_cidrs: Vec<String>,
}

impl Default for KernelDnsConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            prefer_ipv6: false,
            proxy_bootstrap_nameservers: default_proxy_bootstrap_nameservers(),
            fake_ip_cidrs: default_fake_ip_cidrs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelHostMapping {
    pub hostname: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddress {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}

fn default_enabled() -> bool {
    true
}

fn default_proxy_bootstrap_nameservers() -> Vec<String> {
    vec![
        "https://1.1.1.1/dns-query".to_string(),
        "https://1.0.0.1/dns-query".to_string(),
        "https://8.8.8.8/resolve".to_string(),
    ]
}

fn default_fake_ip_cidrs() -> Vec<String> {
    vec!["198.18.0.0/15".to_string()]
}
