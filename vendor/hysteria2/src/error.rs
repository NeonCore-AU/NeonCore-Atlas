use thiserror::Error;

#[derive(Debug, Error)]
pub enum HysteriaError {
  #[error("invalid address: {0}")]
  InvalidAddress(String),
  #[error("QUIC connection error: {0}")]
  QuicConnectionError(#[from] quinn::ConnectionError),
  #[error("QUIC connect error: {0}")]
  QuicConnectError(#[from] quinn::ConnectError),
  #[error("I/O error: {0}")]
  IoError(#[from] std::io::Error),
  #[error("URL parse error: {0}")]
  UrlParseError(#[from] url::ParseError),
  #[error("address parse error: {0}")]
  AddressParseError(#[from] std::net::AddrParseError),
  #[error("authentication failed")]
  AuthFailed,
  #[error("server does not support UDP")]
  UdpNotSupported,
  #[error("UDP relay timed out")]
  UdpTimeout,
  #[error("UDP session closed")]
  UdpSessionClosed,
  #[error("QUIC datagram send error: {0}")]
  QuicDatagramSendError(#[from] quinn::SendDatagramError),
  #[error("QUIC write error: {0}")]
  QuicWriteError(#[from] quinn::WriteError),
  #[error("QUIC stream closed")]
  QuicStreamClosed(#[from] quinn::ClosedStream),
  #[error("H3 connection error: {0}")]
  H3ConnectionError(#[from] h3::error::ConnectionError),
  #[error("H3 stream error: {0}")]
  H3StreamError(#[from] h3::error::StreamError),
  #[error("TCP connect error: {0}")]
  TcpConnectError(String),
}
