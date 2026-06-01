use neoncore_core::{
    DiagnosticReport, DnsConfig, LatencyTestResult, Node, Profile, RewriteRule, RoutingMode,
    RoutingRule, TrafficStats,
};
use neoncore_engine::EngineStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum NeonCoreRequest {
    Status,
    Connect { node: Option<String> },
    Disconnect,
    ListNodes,
    ListProfiles,
    ListRules,
    ListRewrites,
    ImportSubscription { url: String },
    UpdateSubscription { subscription_id: String },
    SetMode { mode: RoutingMode },
    SetDns { config: DnsConfig },
    TestLatency { node: Option<String> },
    TrafficStats,
    Diagnostics,
    ExportProfile { profile_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NeonCoreResponse {
    Status { status: EngineStatus },
    Connected { node: Option<String> },
    Disconnected,
    Nodes { nodes: Vec<Node> },
    Profiles { profiles: Vec<Profile> },
    Rules { rules: Vec<RoutingRule> },
    Rewrites { rewrites: Vec<RewriteRule> },
    SubscriptionImported { subscription_id: String },
    SubscriptionUpdated { subscription_id: String },
    ModeSet { mode: RoutingMode },
    DnsUpdated,
    Latency { results: Vec<LatencyTestResult> },
    TrafficStats { stats: TrafficStats },
    Diagnostics { report: DiagnosticReport },
    ProfileExported { profile_id: String, content: String },
    Error { message_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub service: String,
    pub healthy: bool,
    pub version: String,
}
