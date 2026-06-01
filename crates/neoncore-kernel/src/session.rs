use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSession {
    pub listen_host: String,
    pub listen_port: u16,
    pub selected_node: KernelNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelNode {
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

#[derive(Debug, Clone)]
pub struct TargetAddress {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}
