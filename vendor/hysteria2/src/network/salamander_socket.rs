use std::{
  fmt,
  io::{self, IoSliceMut},
  net::SocketAddr,
  pin::Pin,
  sync::Arc,
  task::{ready, Context, Poll},
};

use blake2::{
  digest::{consts::U32, FixedOutput},
  Blake2b, Digest,
};
use quinn::{
  udp::{RecvMeta, Transmit},
  AsyncUdpSocket, UdpPoller,
};
use rand::RngCore;
use tokio::io::Interest;

const SALAMANDER_SALT_LEN: usize = 8;

pub struct SalamanderUdpSocket {
  io: tokio::net::UdpSocket,
  password: Vec<u8>,
}

impl SalamanderUdpSocket {
  pub fn new(socket: std::net::UdpSocket, password: String) -> io::Result<Self> {
    Ok(Self {
      io: tokio::net::UdpSocket::from_std(socket)?,
      password: password.into_bytes(),
    })
  }
}

impl fmt::Debug for SalamanderUdpSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SalamanderUdpSocket")
      .field("local_addr", &self.io.local_addr().ok())
      .finish_non_exhaustive()
  }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
  fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
    Box::pin(SalamanderUdpPoller { socket: self })
  }

  fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
    if transmit.segment_size.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "segmented UDP transmit is not supported with Hysteria2 Salamander obfs",
      ));
    }
    let encoded = salamander_obfuscate(transmit.contents, &self.password);
    match self
      .io
      .try_send_to(&encoded, transmit.destination)
      .map(|_| ())
    {
      Ok(()) => Ok(()),
      Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(err),
      Err(err) => Err(err),
    }
  }

  fn poll_recv(
    &self,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    if bufs.is_empty() || meta.is_empty() {
      return Poll::Ready(Ok(0));
    }
    loop {
      ready!(self.io.poll_recv_ready(cx))?;
      let capacity = bufs[0].len() + SALAMANDER_SALT_LEN;
      let mut encoded = vec![0_u8; capacity];
      match self
        .io
        .try_io(Interest::READABLE, || self.io.try_recv_from(&mut encoded))
      {
        Ok((n, addr)) => {
          let decoded = salamander_deobfuscate(&encoded[..n], &self.password)?;
          if decoded.len() > bufs[0].len() {
            return Poll::Ready(Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "decoded Hysteria2 datagram exceeds receive buffer",
            )));
          }
          bufs[0][..decoded.len()].copy_from_slice(&decoded);
          meta[0] = RecvMeta {
            addr,
            len: decoded.len(),
            stride: decoded.len(),
            ecn: None,
            dst_ip: None,
          };
          return Poll::Ready(Ok(1));
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
        Err(err) => return Poll::Ready(Err(err)),
      }
    }
  }

  fn local_addr(&self) -> io::Result<SocketAddr> {
    self.io.local_addr()
  }

  fn may_fragment(&self) -> bool {
    false
  }
}

#[derive(Debug)]
struct SalamanderUdpPoller {
  socket: Arc<SalamanderUdpSocket>,
}

impl UdpPoller for SalamanderUdpPoller {
  fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.socket.io.poll_send_ready(cx)
  }
}

pub(crate) fn salamander_obfuscate(packet: &[u8], key: &[u8]) -> Vec<u8> {
  let mut salt = [0_u8; SALAMANDER_SALT_LEN];
  rand::rng().fill_bytes(&mut salt);
  let mut output = Vec::with_capacity(SALAMANDER_SALT_LEN + packet.len());
  output.extend_from_slice(&salt);
  output.extend_from_slice(&salamander_xor(packet, key, &salt));
  output
}

pub(crate) fn salamander_deobfuscate(packet: &[u8], key: &[u8]) -> io::Result<Vec<u8>> {
  if packet.len() < SALAMANDER_SALT_LEN {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "Hysteria2 Salamander datagram is too short",
    ));
  }
  Ok(salamander_xor(
    &packet[SALAMANDER_SALT_LEN..],
    key,
    &packet[..SALAMANDER_SALT_LEN],
  ))
}

fn salamander_xor(packet: &[u8], key: &[u8], salt: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(packet.len());
  let mut hasher = Blake2b::<U32>::new();
  hasher.update(key);
  hasher.update(salt);
  let key_stream = hasher.finalize_fixed();
  for (index, byte) in packet.iter().enumerate() {
    out.push(byte ^ key_stream[index % key_stream.len()]);
  }
  out
}
