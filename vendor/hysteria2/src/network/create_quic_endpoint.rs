use std::{
  io,
  net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
  sync::Arc,
  time::Duration,
};

use quinn::{ClientConfig, Endpoint, EndpointConfig, TokioRuntime, TransportConfig, VarInt};

use crate::{config::Config, HysteriaError};

use super::{
  gecko_socket::GeckoUdpSocket,
  neoncore_congestion::{NeonCoreHy2CongestionState, NeonCoreHy2ControllerFactory},
  salamander_socket::SalamanderUdpSocket,
};

/// Create a QUIC endpoint.
pub(crate) fn create_quic_endpoint(
  client_crypto: Arc<rustls::ClientConfig>,
  config: &Config,
  congestion_state: Arc<NeonCoreHy2CongestionState>,
) -> Result<Endpoint, HysteriaError> {
  let mut client_config = ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
      .map_err(|e| HysteriaError::IoError(io::Error::new(io::ErrorKind::InvalidInput, e)))?,
  ));
  let mut transport = TransportConfig::default();
  transport
    .stream_receive_window(VarInt::from_u32(8 * 1024 * 1024))
    .receive_window(VarInt::from_u32(20 * 1024 * 1024))
    .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(|e| {
      HysteriaError::IoError(io::Error::new(io::ErrorKind::InvalidInput, e))
    })?))
    .keep_alive_interval(Some(Duration::from_secs(10)));
  transport.congestion_controller_factory(Arc::new(NeonCoreHy2ControllerFactory::new(
    congestion_state,
    config.bbr_profile,
  )));
  client_config.transport_config(Arc::new(transport));

  let mut endpoint = if let Some(obfs) = &config.obfs {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    socket.set_nonblocking(true)?;
    let socket: Arc<dyn quinn::AsyncUdpSocket> = match obfs.kind.as_str() {
      "salamander" => Arc::new(SalamanderUdpSocket::new(socket, obfs.password.clone())?),
      "gecko" => Arc::new(GeckoUdpSocket::new(socket, obfs.password.clone())?),
      other => {
        return Err(HysteriaError::IoError(io::Error::new(
          io::ErrorKind::Unsupported,
          format!("unsupported Hysteria2 obfuscation mode: {other}"),
        )));
      }
    };
    Endpoint::new_with_abstract_socket(
      EndpointConfig::default(),
      None,
      socket,
      Arc::new(TokioRuntime),
    )?
  } else {
    Endpoint::client("0.0.0.0:0".parse()?)?
  };
  endpoint.set_default_client_config(client_config);
  Ok(endpoint)
}
