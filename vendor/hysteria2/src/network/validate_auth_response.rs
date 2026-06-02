use crate::HysteriaError;

const HYSTERIA_AUTH_STATUS: u16 = 233;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CcRx {
  Brutal(u64),
  Bbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthResponse {
  pub cc_rx: CcRx,
  pub udp_enabled: bool,
}

pub(crate) fn validate_auth_response(
  resp: &http::Response<()>,
) -> Result<AuthResponse, HysteriaError> {
  if resp.status() != HYSTERIA_AUTH_STATUS {
    return Err(HysteriaError::AuthFailed);
  }

  let udp_enabled = resp
    .headers()
    .get("Hysteria-UDP")
    .and_then(|v| v.to_str().ok())
    == Some("true");
  if !udp_enabled {
    tracing::warn!("Server does not explicitly support UDP relay.");
  }

  Ok(AuthResponse {
    cc_rx: parse_cc_rx(resp),
    udp_enabled,
  })
}

fn parse_cc_rx(resp: &http::Response<()>) -> CcRx {
  let Some(value) = resp
    .headers()
    .get("Hysteria-CC-RX")
    .and_then(|value| value.to_str().ok())
  else {
    return CcRx::Bbr;
  };
  if value.eq_ignore_ascii_case("auto") {
    return CcRx::Bbr;
  }
  match value.parse::<u64>() {
    Ok(0) | Err(_) => CcRx::Bbr,
    Ok(bytes_per_second) => CcRx::Brutal(bytes_per_second),
  }
}
