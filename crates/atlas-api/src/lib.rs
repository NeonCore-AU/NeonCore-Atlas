use atlas_core::{Node, RoutingMode};
use atlas_engine::EngineStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AtlasRequest {
    Status,
    Connect { node: Option<String> },
    Disconnect,
    ListNodes,
    ImportSubscription { url: String },
    SetMode { mode: RoutingMode },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AtlasResponse {
    Status { status: EngineStatus },
    Connected { node: Option<String> },
    Disconnected,
    Nodes { nodes: Vec<Node> },
    SubscriptionImported { subscription_id: String },
    ModeSet { mode: RoutingMode },
    Error { message_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub service: String,
    pub healthy: bool,
    pub version: String,
}
