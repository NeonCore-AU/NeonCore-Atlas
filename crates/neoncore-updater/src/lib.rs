use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub update_available: bool,
}

pub fn check_for_updates(current_version: impl Into<String>) -> UpdateCheck {
    UpdateCheck {
        current_version: current_version.into(),
        update_available: false,
    }
}
