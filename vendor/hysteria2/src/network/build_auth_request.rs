use std::io;

use http::Request;

use crate::{HysteriaError, config::Config};

/// Build authentication request.
pub(crate) fn build_auth_request(
  config: &Config,
  padding: &str,
) -> Result<Request<()>, HysteriaError> {
  Request::builder()
    .method("POST")
    .uri("https://hysteria/auth")
    .header("Host", "hysteria")
    .header("Hysteria-Auth", &config.auth)
    .header("Hysteria-CC-RX", "0")
    .header("Hysteria-Padding", padding)
    .body(())
    .map_err(|e| HysteriaError::IoError(io::Error::new(io::ErrorKind::InvalidInput, e)))
}
