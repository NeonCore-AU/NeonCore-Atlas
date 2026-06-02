// Constant definition to avoid magic numbers.
const PADDING_MIN_LEN: usize = 256;
const PADDING_MAX_LEN: usize = 2048;
const PADDING_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) fn generate_padding() -> String {
  use rand::Rng;
  let mut rng = rand::rng();
  let padding_len = rng.random_range(PADDING_MIN_LEN..PADDING_MAX_LEN);
  let mut padding = String::with_capacity(padding_len);

  for _ in 0..padding_len {
    let idx = rng.random_range(0..PADDING_CHARS.len());
    padding.push(PADDING_CHARS[idx] as char);
  }

  padding
}
