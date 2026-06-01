use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub nodes: Vec<Node>,
    pub subscriptions: Vec<Subscription>,
    pub routing_mode: RoutingMode,
}

impl Profile {
    pub fn empty(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            nodes: Vec::new(),
            subscriptions: Vec::new(),
            routing_mode: RoutingMode::Rule,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub protocol: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    Global,
    Rule,
    Direct,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_defaults_to_rule_mode() {
        let profile = Profile::empty("p1", "Personal");
        assert_eq!(profile.routing_mode, RoutingMode::Rule);
        assert!(profile.nodes.is_empty());
    }

    #[test]
    fn subscription_import_accepts_http_urls() {
        let subscription = import_subscription("https://example.com/sub.txt").unwrap();
        assert!(subscription.enabled);
        assert_eq!(subscription.url, "https://example.com/sub.txt");
    }

    #[test]
    fn subscription_import_rejects_non_urls() {
        let err = import_subscription("not-a-url").unwrap_err();
        assert!(matches!(err, AtlasCoreError::InvalidSubscriptionUrl));
    }
}
