use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{connect, config::Config, DuplexStream, HysteriaClient, HysteriaError};

pub struct ReconnectableClient {
  config: Config,
  client: Mutex<Option<Arc<HysteriaClient>>>,
}

impl ReconnectableClient {
  pub fn new(config: Config) -> Self {
    Self {
      config,
      client: Mutex::new(None),
    }
  }

  pub async fn tcp_connect(
    &self,
    address: impl AsRef<str>,
  ) -> Result<DuplexStream, HysteriaError> {
    let address = address.as_ref().to_string();
    let client = self.client().await?;
    match client.tcp_connect(&address).await {
      Ok(stream) => Ok(stream),
      Err(error) if is_reconnectable(&error) => {
        self.clear_if_same(&client).await;
        self.client().await?.tcp_connect(address).await
      }
      Err(error) => Err(error),
    }
  }

  pub async fn udp_exchange(
    &self,
    address: impl Into<String>,
    payload: impl Into<Bytes>,
  ) -> Result<Bytes, HysteriaError> {
    let address = address.into();
    let payload = payload.into();
    let client = self.client().await?;
    match client.udp_exchange(address.clone(), payload.clone()).await {
      Ok(reply) => Ok(reply),
      Err(error) if is_reconnectable(&error) => {
        self.clear_if_same(&client).await;
        self.client().await?.udp_exchange(address, payload).await
      }
      Err(error) => Err(error),
    }
  }

  async fn client(&self) -> Result<Arc<HysteriaClient>, HysteriaError> {
    let mut guard = self.client.lock().await;
    if let Some(client) = guard.as_ref() {
      return Ok(Arc::clone(client));
    }
    let client = Arc::new(connect(&self.config).await?);
    *guard = Some(Arc::clone(&client));
    Ok(client)
  }

  async fn clear_if_same(&self, client: &Arc<HysteriaClient>) {
    let mut guard = self.client.lock().await;
    if guard.as_ref().is_some_and(|current| Arc::ptr_eq(current, client)) {
      *guard = None;
    }
  }
}

fn is_reconnectable(error: &HysteriaError) -> bool {
  matches!(
    error,
    HysteriaError::QuicConnectionError(_)
      | HysteriaError::QuicConnectError(_)
      | HysteriaError::QuicWriteError(_)
      | HysteriaError::QuicStreamClosed(_)
      | HysteriaError::H3ConnectionError(_)
      | HysteriaError::QuicDatagramSendError(_)
      | HysteriaError::UdpSessionClosed
  )
}
