use super::{
  authenticate_connection::AuthH3Connection, duplex_stream::DuplexStream,
  udp_session_manager::UdpSessionManager,
};
use crate::{
  config::Config,
  HysteriaError,
  protocol::{read_tcp_response, tcp_request_with_official_padding, TCPResponseStatus},
};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};

pub struct HysteriaClient {
  pub(crate) quic_connection: quinn::Connection,
  pub(crate) _h3_connection: AuthH3Connection,
  pub(crate) udp_manager: Option<Arc<UdpSessionManager>>,
  pub(crate) udp_timeout: Duration,
  pub(crate) fast_open: bool,
}

impl HysteriaClient {
  pub(crate) fn new(
    quic_connection: quinn::Connection,
    h3_connection: AuthH3Connection,
    udp_enabled: bool,
    config: &Config,
  ) -> Self {
    Self {
      udp_manager: udp_enabled.then(|| UdpSessionManager::new(quic_connection.clone())),
      quic_connection,
      _h3_connection: h3_connection,
      udp_timeout: Duration::from_millis(config.udp_timeout_ms),
      fast_open: config.fast_open,
    }
  }

  /// Establish a proxied TCP connection to the given address.
  pub async fn tcp_connect(&self, address: impl AsRef<str>) -> Result<DuplexStream, HysteriaError> {
    if self.fast_open {
      return self.tcp_connect_fast_open(address).await;
    }
    let (mut send, mut recv) = self.quic_connection.open_bi().await?;

    send.write_all(&tcp_request_with_official_padding(address)).await?;

    let (status, msg) = read_tcp_response(&mut recv).await?;
    if status != TCPResponseStatus::Ok {
      return Err(HysteriaError::TcpConnectError(msg));
    }

    Ok(DuplexStream { send, recv })
  }

  pub async fn tcp_connect_fast_open(
    &self,
    address: impl AsRef<str>,
  ) -> Result<DuplexStream, HysteriaError> {
    let (mut send, recv) = self.quic_connection.open_bi().await?;
    send.write_all(&tcp_request_with_official_padding(address)).await?;
    Ok(DuplexStream { send, recv })
  }

  pub async fn udp_exchange(
    &self,
    address: impl Into<String>,
    payload: impl Into<Bytes>,
  ) -> Result<Bytes, HysteriaError> {
    let manager = self
      .udp_manager
      .as_ref()
      .ok_or(HysteriaError::UdpNotSupported)?;
    manager
      .exchange(address.into(), payload.into(), self.udp_timeout)
      .await
  }
}
