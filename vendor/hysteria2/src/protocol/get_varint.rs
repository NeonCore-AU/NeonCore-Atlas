use std::io;

use tokio::io::AsyncReadExt;

pub(crate) async fn get_varint<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
  let first_byte = reader.read_u8().await?;
  let tag = first_byte >> 6;
  let val = match tag {
    0 => u64::from(first_byte & 0x3F),
    1 => {
      let second_byte = reader.read_u8().await?;
      u64::from(u16::from_be_bytes([first_byte, second_byte]) & 0x3FFF)
    }
    2 => {
      let mut bytes = [0u8; 4];
      bytes[0] = first_byte;
      reader.read_exact(&mut bytes[1..]).await?;
      u64::from(u32::from_be_bytes(bytes) & 0x3FFFFFFF)
    }
    3 => {
      let mut bytes = [0u8; 8];
      bytes[0] = first_byte;
      reader.read_exact(&mut bytes[1..]).await?;
      u64::from_be_bytes(bytes) & 0x3FFFFFFFFFFFFFFF
    }
    _ => unreachable!(),
  };
  Ok(val)
}

pub(crate) fn read_varint_from_slice(input: &[u8], offset: &mut usize) -> io::Result<u64> {
  if *offset >= input.len() {
    return Err(io::Error::new(
      io::ErrorKind::UnexpectedEof,
      "QUIC varint is truncated",
    ));
  }
  let first_byte = input[*offset];
  let tag = first_byte >> 6;
  let len = match tag {
    0 => 1,
    1 => 2,
    2 => 4,
    _ => 8,
  };
  if input.len() < *offset + len {
    return Err(io::Error::new(
      io::ErrorKind::UnexpectedEof,
      "QUIC varint is truncated",
    ));
  }
  let value = match len {
    1 => u64::from(first_byte & 0x3f),
    2 => {
      let raw = u16::from_be_bytes(input[*offset..*offset + 2].try_into().expect("fixed length"));
      u64::from(raw & 0x3fff)
    }
    4 => {
      let raw = u32::from_be_bytes(input[*offset..*offset + 4].try_into().expect("fixed length"));
      u64::from(raw & 0x3fff_ffff)
    }
    _ => {
      let raw = u64::from_be_bytes(input[*offset..*offset + 8].try_into().expect("fixed length"));
      raw & 0x3fff_ffff_ffff_ffff
    }
  };
  *offset += len;
  Ok(value)
}
