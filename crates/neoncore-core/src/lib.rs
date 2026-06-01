use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub nodes: Vec<Node>,
    pub subscriptions: Vec<Subscription>,
    pub routing_mode: RoutingMode,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub rewrites: Vec<RewriteRule>,
}

impl Profile {
    pub fn empty(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            nodes: Vec::new(),
            subscriptions: Vec::new(),
            routing_mode: RoutingMode::Rule,
            routing_rules: Vec::new(),
            dns: DnsConfig::default(),
            rewrites: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub protocol: ProtocolKind,
    pub tags: Vec<String>,
    pub udp_supported: bool,
    pub tls_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    #[serde(default)]
    pub update_strategy: SubscriptionUpdateStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionUpdateStrategy {
    Replace,
    Merge,
    KeepExisting,
}

impl Default for SubscriptionUpdateStrategy {
    fn default() -> Self {
        Self::Merge
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Http,
    Https,
    Socks5,
    WireGuard,
    OpenConnect,
    Custom { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    Global,
    Rule,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub id: String,
    pub name: String,
    pub matcher: RuleMatcher,
    pub action: RuleAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleMatcher {
    Domain { value: String },
    DomainSuffix { value: String },
    DomainKeyword { value: String },
    Cidr { value: String },
    GeoIp { country_code: String },
    UserAgent { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    Proxy { node_id: Option<String> },
    Direct,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    pub mode: DnsMode,
    pub servers: Vec<DnsServer>,
    pub hosts: Vec<HostMapping>,
    pub prefer_ipv6: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::System,
            servers: Vec::new(),
            hosts: Vec::new(),
            prefer_ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    System,
    Remote,
    ParallelFastest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServer {
    pub id: String,
    pub endpoint: String,
    pub protocol: DnsProtocol,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Https,
    Tls,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMapping {
    pub hostname: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub replacement: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyTestResult {
    pub node_id: String,
    pub latency_ms: Option<u32>,
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficStats {
    pub direct_rx_bytes: u64,
    pub direct_tx_bytes: u64,
    pub proxy_rx_bytes: u64,
    pub proxy_tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub checks: Vec<DiagnosticCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub id: String,
    pub status: DiagnosticStatus,
    pub message_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error { message_key: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AtlasCoreError {
    #[error("invalid profile configuration")]
    InvalidProfile,
    #[error("invalid subscription URL")]
    InvalidSubscriptionUrl,
}

pub fn parse_profile_config(_source: &str) -> Result<Profile, AtlasCoreError> {
    // Future work: parse native Atlas profiles and imported engine configs.
    Ok(Profile::empty("default", "Default"))
}

pub fn import_subscription(url: &str) -> Result<Subscription, AtlasCoreError> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(AtlasCoreError::InvalidSubscriptionUrl);
    }

    Ok(Subscription {
        id: "subscription.default".to_string(),
        name: "Default Subscription".to_string(),
        url: url.to_string(),
        enabled: true,
        update_strategy: SubscriptionUpdateStrategy::Merge,
    })
}

pub fn sample_diagnostic_report() -> DiagnosticReport {
    DiagnosticReport {
        checks: vec![
            DiagnosticCheck {
                id: "daemon.reachable".to_string(),
                status: DiagnosticStatus::Warn,
                message_key: "diagnostics.daemon_unavailable".to_string(),
            },
            DiagnosticCheck {
                id: "profile.loaded".to_string(),
                status: DiagnosticStatus::Pass,
                message_key: "diagnostics.profile_loaded".to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_defaults_to_rule_mode() {
        let profile = Profile::empty("p1", "Personal");
        assert_eq!(profile.routing_mode, RoutingMode::Rule);
        assert!(profile.nodes.is_empty());
        assert_eq!(profile.dns.mode, DnsMode::System);
    }

    #[test]
    fn subscription_import_accepts_http_urls() {
        let subscription = import_subscription("https://example.com/sub.txt").unwrap();
        assert!(subscription.enabled);
        assert_eq!(subscription.url, "https://example.com/sub.txt");
        assert_eq!(
            subscription.update_strategy,
            SubscriptionUpdateStrategy::Merge
        );
    }

    #[test]
    fn subscription_import_rejects_non_urls() {
        let err = import_subscription("not-a-url").unwrap_err();
        assert!(matches!(err, AtlasCoreError::InvalidSubscriptionUrl));
    }

    #[test]
    fn diagnostic_report_contains_stable_message_keys() {
        let report = sample_diagnostic_report();
        assert_eq!(report.checks.len(), 2);
        assert_eq!(
            report.checks[0].message_key,
            "diagnostics.daemon_unavailable"
        );
    }
}
