use bytes::{BufMut, Bytes, BytesMut};
use rand::{Rng, RngCore};

use super::put_varint::put_varint;

const TCP_REQUEST_PADDING_MIN: usize = 64;
const TCP_REQUEST_PADDING_MAX: usize = 512;

pub fn tcp_request_with_official_padding(address: impl AsRef<str>) -> Bytes {
  let padding_len = rand::rng().random_range(TCP_REQUEST_PADDING_MIN..TCP_REQUEST_PADDING_MAX);
  tcp_request(address, padding_len)
}

pub fn tcp_request(address: impl AsRef<str>, padding_len: usize) -> Bytes {
  let address = address.as_ref();
  let estimated_size = 8 + address.len() + padding_len + 16;
  let mut buf = BytesMut::with_capacity(estimated_size);

  put_varint(0x401, &mut buf);
  put_varint(address.len() as u64, &mut buf);
  buf.put(address.as_bytes());
  put_varint(padding_len as u64, &mut buf);
  if padding_len > 0 {
    let mut padding = vec![0u8; padding_len];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut padding);
    buf.put(padding.as_slice());
  }
  buf.freeze()
}
