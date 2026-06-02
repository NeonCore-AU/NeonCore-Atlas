use std::{
  collections::HashMap,
  fmt,
  io::{self, IoSliceMut},
  net::SocketAddr,
  pin::Pin,
  sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
  },
  task::{ready, Context, Poll},
  time::{Duration, Instant},
};

use quinn::{
  udp::{RecvMeta, Transmit},
  AsyncUdpSocket, UdpPoller,
};
use rand::{Rng, RngCore};
use tokio::io::Interest;

use super::salamander_socket::{salamander_deobfuscate, salamander_obfuscate};

const GECKO_FLAG_FRAGMENT: u8 = 0x80;
const GECKO_HEADER_SIZE: usize = 5;
const GECKO_MIN_FRAGMENTS: usize = 2;
const GECKO_MAX_FRAGMENTS: usize = 8;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_BUFFER_SIZE: usize = 2048;
const GECKO_MIN_PACKET: usize = 512;
const GECKO_MAX_PACKET: usize = 1200;

pub struct GeckoUdpSocket {
  io: tokio::net::UdpSocket,
  password: Vec<u8>,
  msg_id: AtomicU32,
  read_state: Mutex<GeckoReadState>,
}

#[derive(Default)]
struct GeckoReadState {
  reassembly: HashMap<(String, u8), ReassemblyEntry>,
}

struct ReassemblyEntry {
  chunks: Vec<Option<Vec<u8>>>,
  received: usize,
  deadline: Instant,
}

impl GeckoUdpSocket {
  pub fn new(socket: std::net::UdpSocket, password: String) -> io::Result<Self> {
    Ok(Self {
      io: tokio::net::UdpSocket::from_std(socket)?,
      password: password.into_bytes(),
      msg_id: AtomicU32::new(1),
      read_state: Mutex::new(GeckoReadState::default()),
    })
  }
}

impl fmt::Debug for GeckoUdpSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("GeckoUdpSocket")
      .field("local_addr", &self.io.local_addr().ok())
      .finish_non_exhaustive()
  }
}

impl AsyncUdpSocket for GeckoUdpSocket {
  fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
    Box::pin(GeckoUdpPoller { socket: self })
  }

  fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
    if transmit.segment_size.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "segmented UDP transmit is not supported with Hysteria2 Gecko obfs",
      ));
    }
    if transmit.contents.first().is_some_and(|byte| byte & 0x80 != 0) {
      self.send_fragmented(transmit.contents, transmit.destination)
    } else {
      let encoded = salamander_obfuscate(transmit.contents, &self.password);
      self.io.try_send_to(&encoded, transmit.destination).map(|_| ())
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
      let mut encoded = vec![0_u8; bufs[0].len() + 128];
      match self
        .io
        .try_io(Interest::READABLE, || self.io.try_recv_from(&mut encoded))
      {
        Ok((n, addr)) => {
          let decoded = salamander_deobfuscate(&encoded[..n], &self.password)?;
          if decoded.first().is_some_and(|byte| byte & GECKO_FLAG_FRAGMENT != 0) {
            if let Some(packet) = self.accept_fragment(addr, &decoded)? {
              return Poll::Ready(Ok(fill_recv(&packet, addr, bufs, meta)));
            }
            continue;
          }
          return Poll::Ready(Ok(fill_recv(&decoded, addr, bufs, meta)));
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

impl GeckoUdpSocket {
  fn send_fragmented(&self, packet: &[u8], destination: SocketAddr) -> io::Result<()> {
    let fragments = rand::rng().random_range(GECKO_MIN_FRAGMENTS..=GECKO_MAX_FRAGMENTS);
    let chunk_size = packet.len().div_ceil(fragments);
    let msg_id = self.msg_id.fetch_add(1, Ordering::Relaxed) as u8;
    for (index, chunk) in packet.chunks(chunk_size).enumerate() {
      let frame = encode_frame(msg_id, index as u8, fragments as u8, chunk)?;
      let encoded = salamander_obfuscate(&frame, &self.password);
      self.io.try_send_to(&encoded, destination)?;
    }
    Ok(())
  }

  fn accept_fragment(&self, addr: SocketAddr, frame: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let (msg_id, index, total, payload) = decode_frame(frame)?;
    let mut state = self
      .read_state
      .lock()
      .map_err(|_| io::Error::other("Gecko reassembly lock poisoned"))?;
    let now = Instant::now();
    state.reassembly.retain(|_, entry| entry.deadline > now);
    let key = (addr.to_string(), msg_id);
    let entry = state
      .reassembly
      .entry(key.clone())
      .or_insert_with(|| ReassemblyEntry {
        chunks: vec![None; total as usize],
        received: 0,
        deadline: now + GECKO_REASSEMBLY_TTL,
      });
    if entry.chunks.len() != total as usize || index >= total {
      state.reassembly.remove(&key);
      return Ok(None);
    }
    let slot = &mut entry.chunks[index as usize];
    if slot.is_none() {
      *slot = Some(payload.to_vec());
      entry.received += 1;
    }
    if entry.received != entry.chunks.len() {
      return Ok(None);
    }
    let entry = state.reassembly.remove(&key).expect("entry exists");
    let size = entry
      .chunks
      .iter()
      .filter_map(Option::as_ref)
      .map(Vec::len)
      .sum();
    let mut out = Vec::with_capacity(size);
    for chunk in entry.chunks.into_iter().flatten() {
      out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
  }
}

#[derive(Debug)]
struct GeckoUdpPoller {
  socket: Arc<GeckoUdpSocket>,
}

impl UdpPoller for GeckoUdpPoller {
  fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.socket.io.poll_send_ready(cx)
  }
}

fn encode_frame(msg_id: u8, chunk_index: u8, total: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
  let base = 8 + GECKO_HEADER_SIZE + payload.len();
  let pad_len = if base >= GECKO_MAX_PACKET {
    0
  } else {
    let min = GECKO_MIN_PACKET.max(base);
    rand::rng().random_range(min - base..=GECKO_MAX_PACKET - base)
  };
  let mut out = vec![0_u8; GECKO_HEADER_SIZE + pad_len + payload.len()];
  out[0] = GECKO_FLAG_FRAGMENT;
  out[1] = msg_id;
  out[2] = (chunk_index << 4) | (total & 0x0f);
  out[3..5].copy_from_slice(&(pad_len as u16).to_be_bytes());
  rand::rng().fill_bytes(&mut out[GECKO_HEADER_SIZE..GECKO_HEADER_SIZE + pad_len]);
  out[GECKO_HEADER_SIZE + pad_len..].copy_from_slice(payload);
  Ok(out)
}

fn decode_frame(input: &[u8]) -> io::Result<(u8, u8, u8, &[u8])> {
  if input.len() < GECKO_HEADER_SIZE || input[0] & GECKO_FLAG_FRAGMENT == 0 {
    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Gecko frame"));
  }
  let msg_id = input[1];
  let chunk_index = input[2] >> 4;
  let total = input[2] & 0x0f;
  if !(GECKO_MIN_FRAGMENTS as u8..=GECKO_MAX_FRAGMENTS as u8).contains(&total)
    || chunk_index >= total
  {
    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Gecko fragment metadata"));
  }
  let pad_len = u16::from_be_bytes([input[3], input[4]]) as usize;
  if input.len() < GECKO_HEADER_SIZE + pad_len {
    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Gecko frame is truncated"));
  }
  Ok((msg_id, chunk_index, total, &input[GECKO_HEADER_SIZE + pad_len..]))
}

fn fill_recv(
  packet: &[u8],
  addr: SocketAddr,
  bufs: &mut [IoSliceMut<'_>],
  meta: &mut [RecvMeta],
) -> usize {
  let len = packet.len().min(bufs[0].len()).min(GECKO_BUFFER_SIZE);
  bufs[0][..len].copy_from_slice(&packet[..len]);
  meta[0] = RecvMeta {
    addr,
    len,
    stride: len,
    ecn: None,
    dst_ip: None,
  };
  1
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gecko_frame_round_trips_payload() {
    let payload = b"client hello bytes";
    let frame = encode_frame(3, 1, 3, payload).unwrap();
    let (msg_id, chunk_index, total, decoded) = decode_frame(&frame).unwrap();

    assert_eq!(msg_id, 3);
    assert_eq!(chunk_index, 1);
    assert_eq!(total, 3);
    assert_eq!(decoded, payload);
  }
}
