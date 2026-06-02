use super::{
  authenticate_connection::authenticate_connection, create_quic_endpoint::create_quic_endpoint,
  create_tls_config::create_tls_config, hysteria_client::HysteriaClient,
  neoncore_congestion::NeonCoreHy2CongestionState,
  port_hopping::try_port_hopping_connection, resolve_server_address::resolve_server_address,
};
use crate::{Result, config::Config};
use std::sync::Arc;

/// Connect to the Hysteria server and perform the authentication handshake.
pub async fn connect(config: &Config) -> Result<HysteriaClient> {
  let server_addr = resolve_server_address(&config.server_addr).await?;
  let server_ip = server_addr.ip();
  let congestion_state = config
    .congestion
    .clone()
    .unwrap_or_else(|| Arc::new(NeonCoreHy2CongestionState::default()));

  let client_crypto = create_tls_config(config.insecure)?;
  let endpoint = create_quic_endpoint(client_crypto, config, congestion_state.clone())?;

  let conn = try_port_hopping_connection(&endpoint, config, server_addr, server_ip).await?;

  let (h3_connection, auth) = authenticate_connection(&conn, config, congestion_state).await?;

  Ok(HysteriaClient::new(
    conn,
    h3_connection,
    auth.udp_enabled,
    config,
  ))
}
