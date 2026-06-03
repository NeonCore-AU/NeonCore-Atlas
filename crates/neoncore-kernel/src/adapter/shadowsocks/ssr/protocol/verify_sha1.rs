struct VerifySha1Codec {
    key: Vec<u8>,
    iv: Vec<u8>,
    sent_header: bool,
    send_chunk_id: u32,
    recv_chunk_id: u32,
    recv_buffer: BytesMut,
    raw_recv: bool,
}

impl VerifySha1Codec {
    fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self {
            key,
            iv,
            sent_header: false,
            send_chunk_id: 0,
            recv_chunk_id: 0,
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        const UNIT_LEN: usize = 4096;
        let mut output = Vec::with_capacity(payload.len() + payload.len() / UNIT_LEN * 12 + 32);
        let mut remaining = payload;
        if !self.sent_header {
            let head_len = get_ssr_head_size(remaining, 30).min(remaining.len());
            let mut header = remaining[..head_len].to_vec();
            if !header.is_empty() {
                header[0] |= 0x10;
            }
            let mut mac_key = self.iv.clone();
            mac_key.extend_from_slice(&self.key);
            output.extend_from_slice(&header);
            let tag = hmac_sha1(&mac_key, &header);
            output.extend_from_slice(&tag);
            remaining = &remaining[head_len..];
            self.sent_header = true;
        }
        for chunk in remaining.chunks(UNIT_LEN) {
            self.pack_chunk(&mut output, chunk);
        }
        output
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 12 {
            let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if length > 8192 {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR verify_sha1 response length is invalid",
                ));
            }
            let frame_len = 2 + 10 + length;
            if frame_len > self.recv_buffer.len() {
                break;
            }
            let frame = self.recv_buffer.split_to(frame_len);
            let chunk_id = self.recv_chunk_id;
            self.recv_chunk_id = self.recv_chunk_id.wrapping_add(1);
            let expected = with_appended_u32_be(&self.iv, chunk_id, |mac_key| {
                hmac_sha1(mac_key, &frame[12..])
            });
            if expected[..10] != frame[2..12] {
                self.raw_recv = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR verify_sha1 response HMAC mismatch",
                ));
            }
            output.extend_from_slice(&frame[12..]);
        }
        Ok(())
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn decode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn pack_chunk(&mut self, output: &mut Vec<u8>, payload: &[u8]) {
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let tag = with_appended_u32_be(&self.iv, self.send_chunk_id, |mac_key| {
            hmac_sha1(mac_key, payload)
        });
        self.send_chunk_id = self.send_chunk_id.wrapping_add(1);
        output.extend_from_slice(&tag[..10]);
        output.extend_from_slice(payload);
    }
}
