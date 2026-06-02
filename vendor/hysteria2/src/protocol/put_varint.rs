use bytes::BufMut;

// Write a QUIC variable-length integer with a branch table optimized for the common sizes.
pub(crate) fn put_varint(val: u64, buf: &mut bytes::BytesMut) {
  match val {
    0..=63 => buf.put_u8(val as u8),
    64..=16383 => buf.put_u16(((val & 0x3FFF) | 0x4000) as u16),
    16384..=1073741823 => buf.put_u32(((val & 0x3FFFFFFF) | 0x80000000) as u32),
    _ => buf.put_u64((val & 0x3FFFFFFFFFFFFFFF) | 0xC000000000000000),
  }
}
