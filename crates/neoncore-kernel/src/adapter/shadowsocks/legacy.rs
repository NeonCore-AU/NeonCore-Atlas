struct NeonLegacyCryptoStream<S> {
    inner: S,
    method: NeonLegacyCipherKind,
    key: Vec<u8>,
    write_iv: Vec<u8>,
    sent_iv: bool,
    encryptor: NeonLegacyCipher,
    decryptor: Option<NeonLegacyCipher>,
    read_iv: Vec<u8>,
    read_buffer: BytesMut,
    pending_write: Option<PendingWrite>,
}

impl<S> Unpin for NeonLegacyCryptoStream<S> {}

impl<S> NeonLegacyCryptoStream<S> {
    fn new(inner: S, method: NeonLegacyCipherKind, password: &str) -> anyhow::Result<Self> {
        let key = legacy_evp_bytes_to_key(password.as_bytes(), method.key_len());
        let mut write_iv = vec![0_u8; method.iv_len()];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut write_iv);
        let encryptor = NeonLegacyCipher::new(method, &key, &write_iv)?;
        Ok(Self {
            inner,
            method,
            key,
            write_iv,
            sent_iv: false,
            encryptor,
            decryptor: None,
            read_iv: Vec::new(),
            read_buffer: BytesMut::new(),
            pending_write: None,
        })
    }

    fn sent_nonce(&self) -> &[u8] {
        &self.write_iv
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NeonLegacyCryptoStream<S> {
    fn poll_read_decrypted(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }

        while self.decryptor.is_none() {
            let need = self.method.iv_len() - self.read_iv.len();
            if need == 0 {
                let decryptor = NeonLegacyCipher::new_with_direction(
                    self.method,
                    &self.key,
                    &self.read_iv,
                    false,
                )
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                self.decryptor = Some(decryptor);
                break;
            }
            let mut scratch = [0_u8; 32];
            let mut read_buf = ReadBuf::new(&mut scratch[..need]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => self.read_iv.extend_from_slice(read_buf.filled()),
            }
        }

        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) if buf.filled().len() == filled_before => Poll::Ready(Ok(())),
            Poll::Ready(Ok(())) => {
                if let Some(decryptor) = &mut self.decryptor {
                    decryptor.apply(&mut buf.filled_mut()[filled_before..]);
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_write_encrypted(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }

        let mut out =
            BytesMut::with_capacity((!self.sent_iv as usize) * self.write_iv.len() + buf.len());
        if !self.sent_iv {
            out.extend_from_slice(&self.write_iv);
            self.sent_iv = true;
        }
        let encrypted_start = out.len();
        out.extend_from_slice(buf);
        self.encryptor.apply(&mut out[encrypted_start..]);
        self.pending_write = Some(PendingWrite::new(out.freeze(), buf.len()));
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum NeonLegacyCipher {
    BlowfishCfbEnc(BlowfishCfbEnc),
    BlowfishCfbDec(BlowfishCfbDec),
    Cast5CfbEnc(Cast5CfbEnc),
    Cast5CfbDec(Cast5CfbDec),
    DesCfbEnc(DesCfbEnc),
    DesCfbDec(DesCfbDec),
    IdeaCfbEnc(IdeaCfbEnc),
    IdeaCfbDec(IdeaCfbDec),
    Rc2CfbEnc(Rc2CfbEnc),
    Rc2CfbDec(Rc2CfbDec),
    SeedCfb(SeedCfbCipher),
    Salsa20(Salsa20),
    Rc4(Rc4),
}

impl NeonLegacyCipher {
    fn new(method: NeonLegacyCipherKind, key: &[u8], iv: &[u8]) -> anyhow::Result<Self> {
        Self::new_with_direction(method, key, iv, true)
    }

    fn new_with_direction(
        method: NeonLegacyCipherKind,
        key: &[u8],
        iv: &[u8],
        encrypt: bool,
    ) -> anyhow::Result<Self> {
        let cipher = match (method, encrypt) {
            (NeonLegacyCipherKind::BlowfishCfb, true) => {
                Self::BlowfishCfbEnc(BlowfishCfbEnc::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::BlowfishCfb, false) => {
                Self::BlowfishCfbDec(BlowfishCfbDec::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::Cast5Cfb, true) => {
                Self::Cast5CfbEnc(Cast5CfbEnc::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::Cast5Cfb, false) => {
                Self::Cast5CfbDec(Cast5CfbDec::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::DesCfb, true) => {
                Self::DesCfbEnc(DesCfbEnc::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::DesCfb, false) => {
                Self::DesCfbDec(DesCfbDec::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::IdeaCfb, true) => {
                Self::IdeaCfbEnc(IdeaCfbEnc::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::IdeaCfb, false) => {
                Self::IdeaCfbDec(IdeaCfbDec::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::Rc2Cfb, true) => {
                Self::Rc2CfbEnc(Rc2CfbEnc::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::Rc2Cfb, false) => {
                Self::Rc2CfbDec(Rc2CfbDec::new_from_slices(key, iv)?)
            }
            (NeonLegacyCipherKind::SeedCfb, encrypt) => {
                Self::SeedCfb(SeedCfbCipher::new(key, iv, encrypt)?)
            }
            (NeonLegacyCipherKind::Salsa20, _) => Self::Salsa20(Salsa20::new_from_slices(key, iv)?),
            (NeonLegacyCipherKind::Rc4Md5_6, _) => {
                let mut rc4_key_data = Vec::with_capacity(key.len() + iv.len());
                rc4_key_data.extend_from_slice(key);
                rc4_key_data.extend_from_slice(iv);
                let rc4_key = md5::compute(&rc4_key_data);
                Self::Rc4(Rc4::new_from_slice(&rc4_key.0)?)
            }
        };
        Ok(cipher)
    }

    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::BlowfishCfbEnc(cipher) => cipher.encrypt(data),
            Self::BlowfishCfbDec(cipher) => cipher.decrypt(data),
            Self::Cast5CfbEnc(cipher) => cipher.encrypt(data),
            Self::Cast5CfbDec(cipher) => cipher.decrypt(data),
            Self::DesCfbEnc(cipher) => cipher.encrypt(data),
            Self::DesCfbDec(cipher) => cipher.decrypt(data),
            Self::IdeaCfbEnc(cipher) => cipher.encrypt(data),
            Self::IdeaCfbDec(cipher) => cipher.decrypt(data),
            Self::Rc2CfbEnc(cipher) => cipher.encrypt(data),
            Self::Rc2CfbDec(cipher) => cipher.decrypt(data),
            Self::SeedCfb(cipher) => cipher.apply(data),
            Self::Salsa20(cipher) => cipher.apply_keystream(data),
            Self::Rc4(cipher) => cipher.apply_keystream(data),
        }
    }
}

struct SeedCfbCipher {
    cipher: SEED,
    encrypt: bool,
    feedback: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
}

impl SeedCfbCipher {
    fn new(key: &[u8], iv: &[u8], encrypt: bool) -> anyhow::Result<Self> {
        if iv.len() != 16 {
            anyhow::bail!("SEED-CFB requires a 16-byte IV");
        }
        let cipher = SEED::new_from_slice(key)?;
        let mut feedback = [0_u8; 16];
        feedback.copy_from_slice(iv);
        Ok(Self {
            cipher,
            encrypt,
            feedback,
            keystream: [0_u8; 16],
            pos: 16,
        })
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pos == 16 {
                let mut block = cipher04::Block::<SEED>::clone_from_slice(&self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(&block);
                self.feedback = [0_u8; 16];
                self.pos = 0;
            }
            let input = *byte;
            let output = input ^ self.keystream[self.pos];
            self.feedback[self.pos] = if self.encrypt { output } else { input };
            *byte = output;
            self.pos += 1;
        }
    }
}

fn legacy_evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut data = Vec::with_capacity(previous.len() + password.len());
        data.extend_from_slice(&previous);
        data.extend_from_slice(password);
        previous = md5::compute(&data).0.to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn encrypt_legacy_udp_packet(
    method: NeonLegacyCipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut body = BytesMut::with_capacity(addr.serialized_len() + payload.len());
    addr.write_to_buf(&mut body);
    body.extend_from_slice(payload);
    encrypt_legacy_udp_body(method, key, &body)
}

fn decrypt_legacy_udp_packet(
    method: NeonLegacyCipherKind,
    key: &[u8],
    packet: &mut [u8],
) -> anyhow::Result<(Address, Vec<u8>)> {
    let iv_len = method.iv_len();
    if packet.len() < iv_len {
        anyhow::bail!("Shadowsocks legacy UDP packet is too short");
    }
    let (iv, body) = packet.split_at_mut(iv_len);
    let mut cipher = NeonLegacyCipher::new_with_direction(method, key, iv, false)?;
    cipher.apply(body);
    let mut cursor = std::io::Cursor::new(&body[..]);
    let address = Address::read_cursor(&mut cursor)?;
    let payload_start = cursor.position() as usize;
    Ok((address, body[payload_start..].to_vec()))
}

fn encrypt_legacy_udp_body(
    method: NeonLegacyCipherKind,
    key: &[u8],
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let iv_len = method.iv_len();
    let mut packet = vec![0_u8; iv_len + body.len()];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet[..iv_len]);
    packet[iv_len..].copy_from_slice(body);
    let (iv, encrypted) = packet.split_at_mut(iv_len);
    let mut cipher = NeonLegacyCipher::new(method, key, iv)?;
    cipher.apply(encrypted);
    Ok(packet)
}

fn decrypt_legacy_udp_body(
    method: NeonLegacyCipherKind,
    key: &[u8],
    packet: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    let iv_len = method.iv_len();
    if packet.len() < iv_len {
        anyhow::bail!("Shadowsocks legacy UDP packet is too short");
    }
    let (iv, body) = packet.split_at_mut(iv_len);
    let mut cipher = NeonLegacyCipher::new_with_direction(method, key, iv, false)?;
    cipher.apply(body);
    Ok(body.to_vec())
}

fn encrypt_builtin_stream_udp_body(
    method: CipherKind,
    key: &[u8],
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if method.category() != CipherCategory::Stream && method.category() != CipherCategory::None {
        anyhow::bail!("ShadowsocksR native UDP requires a stream cipher");
    }
    let iv_len = method.iv_len();
    let mut packet = vec![0_u8; iv_len + body.len()];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet[..iv_len]);
    packet[iv_len..].copy_from_slice(body);
    let (iv, encrypted) = packet.split_at_mut(iv_len);
    let mut cipher = SsV1Cipher::new(method, key, iv);
    cipher.encrypt_packet(encrypted);
    Ok(packet)
}

fn decrypt_builtin_stream_udp_body(
    method: CipherKind,
    key: &[u8],
    packet: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    if method.category() != CipherCategory::Stream && method.category() != CipherCategory::None {
        anyhow::bail!("ShadowsocksR native UDP requires a stream cipher");
    }
    let iv_len = method.iv_len();
    if packet.len() < iv_len {
        anyhow::bail!("Shadowsocks stream UDP packet is too short");
    }
    let (iv, body) = packet.split_at_mut(iv_len);
    let mut cipher = SsV1Cipher::new(method, key, iv);
    if !cipher.decrypt_packet(body) {
        anyhow::bail!("Shadowsocks stream UDP packet decryption failed");
    }
    Ok(body.to_vec())
}

fn build_ssr_udp_body(addr: &Address, payload: &[u8]) -> BytesMut {
    let mut body = BytesMut::with_capacity(addr.serialized_len() + payload.len());
    addr.write_to_buf(&mut body);
    body.extend_from_slice(payload);
    body
}

fn parse_ssr_udp_body(body: Vec<u8>) -> anyhow::Result<(Address, Vec<u8>)> {
    let mut cursor = std::io::Cursor::new(&body[..]);
    let address = Address::read_cursor(&mut cursor)?;
    let payload_start = cursor.position() as usize;
    Ok((address, body[payload_start..].to_vec()))
}

fn ssr_udp_codec(protocol: &SsrProtocol, key: &[u8], protocol_param: &str) -> SsrProtocolCodec {
    SsrProtocolCodec::new(
        protocol.clone(),
        key.to_vec(),
        Vec::new(),
        protocol_param.to_string(),
    )
}

fn encrypt_ssr_udp_builtin_packet(
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    protocol: &SsrProtocol,
    protocol_param: &str,
) -> anyhow::Result<Vec<u8>> {
    let body = build_ssr_udp_body(addr, payload);
    let wrapped = ssr_udp_codec(protocol, key, protocol_param).encode_packet(&body)?;
    encrypt_builtin_stream_udp_body(method, key, &wrapped)
}

fn decrypt_ssr_udp_builtin_packet(
    method: CipherKind,
    key: &[u8],
    packet: &mut [u8],
    protocol: &SsrProtocol,
    protocol_param: &str,
) -> anyhow::Result<(Address, Vec<u8>)> {
    let body = decrypt_builtin_stream_udp_body(method, key, packet)?;
    let unwrapped = ssr_udp_codec(protocol, key, protocol_param).decode_packet(&body)?;
    parse_ssr_udp_body(unwrapped)
}

fn encrypt_ssr_udp_legacy_packet(
    method: NeonLegacyCipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    protocol: &SsrProtocol,
    protocol_param: &str,
) -> anyhow::Result<Vec<u8>> {
    let body = build_ssr_udp_body(addr, payload);
    let wrapped = ssr_udp_codec(protocol, key, protocol_param).encode_packet(&body)?;
    encrypt_legacy_udp_body(method, key, &wrapped)
}

fn decrypt_ssr_udp_legacy_packet(
    method: NeonLegacyCipherKind,
    key: &[u8],
    packet: &mut [u8],
    protocol: &SsrProtocol,
    protocol_param: &str,
) -> anyhow::Result<(Address, Vec<u8>)> {
    let body = decrypt_legacy_udp_body(method, key, packet)?;
    let unwrapped = ssr_udp_codec(protocol, key, protocol_param).decode_packet(&body)?;
    parse_ssr_udp_body(unwrapped)
}
