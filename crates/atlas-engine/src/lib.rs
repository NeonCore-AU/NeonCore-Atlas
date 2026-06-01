use atlas_core::{ConnectionState, Profile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatus {
    pub state: ConnectionState,
    pub active_node_id: Option<String>,
}

impl Default for EngineStatus {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            active_node_id: None,
        }
    }
}

pub trait Engine {
    fn start(&mut self, profile: &Profile, node_id: Option<&str>) -> anyhow::Result<()>;
    fn stop(&mut self) -> anyhow::Result<()>;
    fn status(&self) -> EngineStatus;
    fn reload_config(&mut self, profile: &Profile) -> anyhow::Result<()>;
}

#[derive(Debug, Default)]
pub struct MockEngine {
    status: EngineStatus,
    loaded_profile_id: Option<String>,
}

impl Engine for MockEngine {
    fn start(&mut self, profile: &Profile, node_id: Option<&str>) -> anyhow::Result<()> {
        self.loaded_profile_id = Some(profile.id.clone());
        self.status = EngineStatus {
            state: ConnectionState::Connected,
            active_node_id: node_id.map(str::to_string),
        };
        Ok(())
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        self.status = EngineStatus::default();
        Ok(())
    }

    fn status(&self) -> EngineStatus {
        self.status.clone()
    }

    fn reload_config(&mut self, profile: &Profile) -> anyhow::Result<()> {
        self.loaded_profile_id = Some(profile.id.clone());
        Ok(())
    }
}
