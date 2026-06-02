use super::{
  build_auth_request::build_auth_request, generate_padding::generate_padding,
  neoncore_congestion::NeonCoreHy2CongestionState,
  validate_auth_response::{AuthResponse, CcRx, validate_auth_response},
};
use crate::{HysteriaError, config::Config};
use std::sync::Arc;

pub(crate) type AuthH3Connection = h3::client::Connection<h3_quinn::Connection, bytes::Bytes>;

pub(crate) async fn authenticate_connection(
  conn: &quinn::Connection,
  config: &Config,
  congestion_state: Arc<NeonCoreHy2CongestionState>,
) -> Result<(AuthH3Connection, AuthResponse), HysteriaError> {
  let (h3_connection, mut request_stream) =
    h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;

  let padding = generate_padding();
  let req = build_auth_request(config, &padding)?;

  let mut stream = request_stream.send_request(req).await?;
  stream.finish().await?;

  let resp = stream.recv_response().await?;

  let auth = validate_auth_response(&resp)?;
  match auth.cc_rx {
    CcRx::Brutal(bytes_per_second) => {
      tracing::debug!("Hysteria2 congestion mode switched to NeonCore Brutal-compatible control");
      congestion_state.enable_brutal(bytes_per_second);
    }
    CcRx::Bbr => {
      tracing::debug!("Hysteria2 congestion mode using BBR fallback");
      congestion_state.use_bbr();
    }
  }
  Ok((h3_connection, auth))
}
