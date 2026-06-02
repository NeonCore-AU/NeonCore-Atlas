use std::{collections::HashMap, sync::Arc};

use serde::Deserialize;
use url::Url;

use crate::{error::HysteriaError, network::neoncore_congestion::NeonCoreHy2CongestionState};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
  pub auth: String,
  pub server_addr: String,
  pub server_name: String,
  pub insecure: bool,
  pub obfs: Option<ObfsConfig>,
  pub port_hopping_range: Option<(u16, u16)>,
  #[serde(default)]
  pub fast_open: bool,
  #[serde(default = "default_udp_timeout_ms")]
  pub udp_timeout_ms: u64,
  #[serde(default)]
  pub bbr_profile: BbrProfile,
  #[serde(skip)]
  pub congestion: Option<Arc<NeonCoreHy2CongestionState>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObfsConfig {
  pub kind: String,
  pub password: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BbrProfile {
  Conservative,
  #[default]
  Standard,
  Aggressive,
}

const fn default_udp_timeout_ms() -> u64 {
  15_000
}

impl Config {
  pub fn from_url(url_str: &str) -> Result<Self, HysteriaError> {
    let url = Url::parse(&url_str.replace("hysteria2://", "http://"))?;

    let host = url
      .host_str()
      .ok_or_else(|| HysteriaError::UrlParseError(url::ParseError::EmptyHost))?;
    let port = url
      .port()
      .ok_or_else(|| HysteriaError::UrlParseError(url::ParseError::InvalidPort))?;

    let query_params: HashMap<String, String> = url.query_pairs().into_owned().collect();

    let server_name = query_params
      .get("sni")
      .cloned()
      .unwrap_or_else(|| host.to_string());

    let insecure = query_params.get("insecure").is_some_and(|v| v == "1");

    let port_hopping_range = query_params
      .get("mport")
      .and_then(|v| Self::parse_port_range(v));

    let obfs = match query_params.get("obfs").map(String::as_str) {
      Some("salamander") => query_params.get("obfs-password").map(|password| ObfsConfig {
        kind: "salamander".to_string(),
        password: password.clone(),
      }),
      Some("gecko") => query_params.get("obfs-password").map(|password| ObfsConfig {
        kind: "gecko".to_string(),
        password: password.clone(),
      }),
      _ => None,
    };

    Ok(Config {
      auth: if let Some(password) = url.password() {
        format!("{}:{password}", url.username())
      } else {
        url.username().to_string()
      },
      server_addr: format!("{}:{}", host, port),
      server_name,
      insecure,
      obfs,
      port_hopping_range,
      fast_open: query_params
        .get("fast-open")
        .or_else(|| query_params.get("fast_open"))
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes")),
      udp_timeout_ms: default_udp_timeout_ms(),
      bbr_profile: BbrProfile::Standard,
      congestion: None,
    })
  }

  /// Parse port range, which can be a single port or "start-end".
  fn parse_port_range(range_str: &str) -> Option<(u16, u16)> {
    if let Some((start_str, end_str)) = range_str.split_once('-') {
      let start = start_str.trim().parse().ok()?;
      let end = end_str.trim().parse().ok()?;
      if start > end {
        None
      } else {
        Some((start, end))
      }
    } else {
      let port = range_str.trim().parse().ok()?;
      Some((port, port))
    }
  }
}
