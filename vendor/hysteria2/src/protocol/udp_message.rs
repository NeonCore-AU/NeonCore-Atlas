use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use std::{collections::HashMap, io};

use super::{get_varint::read_varint_from_slice, put_varint::put_varint};

pub const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
const UDP_HEADER_FIXED_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
  pub session_id: u32,
  pub packet_id: u16,
  pub fragment_id: u8,
  pub fragment_count: u8,
  pub address: String,
  pub payload: Bytes,
}

impl UdpMessage {
  pub fn header_size(&self) -> usize {
    UDP_HEADER_FIXED_SIZE + varint_len(self.address.len() as u64) + self.address.len()
  }

  pub fn encoded_size(&self) -> usize {
    self.header_size() + self.payload.len()
  }

  pub fn encode(&self) -> Bytes {
    let mut out = BytesMut::with_capacity(self.encoded_size());
    out.put_u32(self.session_id);
    out.put_u16(self.packet_id);
    out.put_u8(self.fragment_id);
    out.put_u8(self.fragment_count);
    put_varint(self.address.len() as u64, &mut out);
    out.put_slice(self.address.as_bytes());
    out.put_slice(&self.payload);
    out.freeze()
  }

  pub fn decode(input: &[u8]) -> io::Result<Self> {
    if input.len() < UDP_HEADER_FIXED_SIZE {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Hysteria2 UDP message is too short",
      ));
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice length"));
    let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice length"));
    let fragment_id = input[6];
    let fragment_count = input[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Hysteria2 UDP fragment metadata is invalid",
      ));
    }
    let mut offset = UDP_HEADER_FIXED_SIZE;
    let address_len = read_varint_from_slice(input, &mut offset)? as usize;
    if input.len() < offset + address_len {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Hysteria2 UDP address is truncated",
      ));
    }
    let address = String::from_utf8(input[offset..offset + address_len].to_vec())
      .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    offset += address_len;
    Ok(Self {
      session_id,
      packet_id,
      fragment_id,
      fragment_count,
      address,
      payload: Bytes::copy_from_slice(&input[offset..]),
    })
  }
}

#[derive(Default)]
pub struct Defragger {
  packet_id: u16,
  fragments: Vec<Option<UdpMessage>>,
  received: u8,
  size: usize,
}

impl Defragger {
  pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
    if message.fragment_count <= 1 {
      return Some(message);
    }
    if message.fragment_id >= message.fragment_count {
      return None;
    }
    if message.packet_id != self.packet_id
      || self.fragments.len() != message.fragment_count as usize
    {
      self.packet_id = message.packet_id;
      self.fragments = vec![None; message.fragment_count as usize];
      self.received = 0;
      self.size = 0;
    }
    let index = message.fragment_id as usize;
    if self.fragments[index].is_some() {
      return None;
    }
    self.size += message.payload.len();
    self.fragments[index] = Some(message);
    self.received += 1;
    if self.received as usize != self.fragments.len() {
      return None;
    }
    let mut parts = std::mem::take(&mut self.fragments)
      .into_iter()
      .collect::<Option<Vec<_>>>()?;
    let mut first = parts.remove(0);
    let mut payload = BytesMut::with_capacity(self.size);
    payload.put_slice(&first.payload);
    for part in parts {
      payload.put_slice(&part.payload);
    }
    first.fragment_id = 0;
    first.fragment_count = 1;
    first.payload = payload.freeze();
    Some(first)
  }
}

#[derive(Default)]
pub struct SessionDefraggers {
  sessions: HashMap<u32, Defragger>,
}

impl SessionDefraggers {
  pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
    self
      .sessions
      .entry(message.session_id)
      .or_default()
      .feed(message)
  }
}

pub fn fragment_message(message: UdpMessage, max_size: usize) -> Vec<UdpMessage> {
  if message.encoded_size() <= max_size {
    return vec![message];
  }
  let header_size = message.header_size();
  if max_size <= header_size {
    return Vec::new();
  }
  let max_payload = max_size - header_size;
  let fragment_count = message.payload.len().div_ceil(max_payload);
  if fragment_count == 0 || fragment_count > u8::MAX as usize {
    return Vec::new();
  }
  let packet_id = rand::rng().random_range(1..=u16::MAX);
  message
    .payload
    .chunks(max_payload)
    .enumerate()
    .map(|(index, payload)| UdpMessage {
      session_id: message.session_id,
      packet_id,
      fragment_id: index as u8,
      fragment_count: fragment_count as u8,
      address: message.address.clone(),
      payload: Bytes::copy_from_slice(payload),
    })
    .collect()
}

fn varint_len(value: u64) -> usize {
  match value {
    0..=63 => 1,
    64..=16_383 => 2,
    16_384..=1_073_741_823 => 4,
    _ => 8,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn udp_message_round_trips() {
    let message = UdpMessage {
      session_id: 7,
      packet_id: 9,
      fragment_id: 0,
      fragment_count: 1,
      address: "example.com:443".to_string(),
      payload: Bytes::from_static(b"hello"),
    };

    let decoded = UdpMessage::decode(&message.encode()).unwrap();

    assert_eq!(decoded, message);
  }

  #[test]
  fn defragger_reassembles_fragmented_payload() {
    let message = UdpMessage {
      session_id: 7,
      packet_id: 0,
      fragment_id: 0,
      fragment_count: 1,
      address: "example.com:443".to_string(),
      payload: Bytes::from(vec![42; 200]),
    };

    let fragments = fragment_message(message, 64);
    let mut defragger = Defragger::default();
    let mut output = None;
    for fragment in fragments {
      output = defragger.feed(fragment).or(output);
    }

    assert_eq!(output.unwrap().payload, Bytes::from(vec![42; 200]));
  }
}
