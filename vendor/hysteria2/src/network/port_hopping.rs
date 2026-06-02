use std::net::{IpAddr, SocketAddr};

use quinn::{Connection, Endpoint};
use rand::Rng;
use tracing::warn;

use crate::{Result, config::Config};

/// Attempts to establish a QUIC connection using port hopping if configured.
/// If a port range is specified in the config, it tries a random port within that range first.
/// If that fails, it falls back to the default port.
pub(super) async fn try_port_hopping_connection(
  endpoint: &Endpoint,
  config: &Config,
  server_addr: SocketAddr,
  server_ip: IpAddr,
) -> Result<Connection> {
  if let Some((start, end)) = config.port_hopping_range {
    let port = rand::rng().random_range(start..=end);
    let random_remote_addr = SocketAddr::new(server_ip, port);
    // Try connecting to the random port
    match endpoint.connect(random_remote_addr, &config.server_name) {
      Ok(connecting) => match connecting.await {
        Ok(c) => return Ok(c),
        Err(e) => {
          // Failure, fall back to the default port
          warn!("connect {random_remote_addr} error {e}, fallback to default port");
        }
      },
      Err(e) => {
        // Failure, fall back to the default port
        warn!("connect {random_remote_addr} error {e}, fallback to default port");
      }
    }
  }
  // No port range, just use the default.
  Ok(endpoint.connect(server_addr, &config.server_name)?.await?)
}
