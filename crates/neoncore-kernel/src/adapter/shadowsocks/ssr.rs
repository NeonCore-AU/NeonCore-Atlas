struct SsrClientStream {
    inner: ShadowCryptoStream,
    crypto_context: Context,
    codec: SsrProtocolCodec,
    target: Option<Address>,
    read_buffer: BytesMut,
    pending_write: Option<PendingWrite>,
}

impl SsrClientStream {
    fn new(
        inner: ShadowCryptoStream,
        target: Address,
        protocol: SsrProtocol,
        protocol_param: String,
        key: Vec<u8>,
    ) -> Self {
        let iv = inner.sent_nonce().to_vec();
        Self {
            inner,
            crypto_context: Context::new(ServerType::Local),
            codec: SsrProtocolCodec::new(protocol, key, iv, protocol_param),
            target: Some(target),
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }
}

impl AsyncRead for SsrClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let mut temp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp);
            let this = &mut *self;
            ready!(Pin::new(&mut this.inner).poll_read_decrypted(
                cx,
                &this.crypto_context,
                &mut read_buf
            ))?;
            if read_buf.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            let this = &mut *self;
            this.codec
                .decode(read_buf.filled(), &mut this.read_buffer)?;
            if drain_buffer(&mut this.read_buffer, buf) {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for SsrClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all_shadow_crypto(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }

        let target_len = self
            .target
            .as_ref()
            .map(Address::serialized_len)
            .unwrap_or_default();
        let mut payload = BytesMut::with_capacity(target_len + buf.len());
        if let Some(target) = self.target.take() {
            target.write_to_buf(&mut payload);
        }
        payload.extend_from_slice(buf);
        let encoded = self.codec.encode(&payload)?;
        self.pending_write = Some(PendingWrite::new(Bytes::from(encoded), buf.len()));

        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all_shadow_crypto(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) => Poll::Ready(Ok(original_len)),
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

enum SsrProtocolCodec {
    VerifySimple(VerifySimpleCodec),
    VerifySha1(VerifySha1Codec),
    AuthSimple(EarlyAuthCodec),
    AuthSha1(EarlyAuthCodec),
    AuthSha1V2(EarlyAuthCodec),
    AuthSha1V4(AuthSha1V4Codec),
    AuthAes128(AuthAes128Codec),
    AuthChain(AuthChainCodec),
}

impl SsrProtocolCodec {
    fn new(protocol: SsrProtocol, key: Vec<u8>, iv: Vec<u8>, protocol_param: String) -> Self {
        match protocol {
            SsrProtocol::Origin => unreachable!("origin does not use native SSR codec"),
            SsrProtocol::VerifySimple => Self::VerifySimple(VerifySimpleCodec::new()),
            SsrProtocol::VerifySha1 => Self::VerifySha1(VerifySha1Codec::new(key, iv)),
            SsrProtocol::AuthSimple => {
                Self::AuthSimple(EarlyAuthCodec::new(key, iv, EarlyAuthKind::Simple))
            }
            SsrProtocol::AuthSha1 => {
                Self::AuthSha1(EarlyAuthCodec::new(key, iv, EarlyAuthKind::Sha1))
            }
            SsrProtocol::AuthSha1V2 => {
                Self::AuthSha1V2(EarlyAuthCodec::new(key, iv, EarlyAuthKind::Sha1V2))
            }
            SsrProtocol::AuthSha1V4 => Self::AuthSha1V4(AuthSha1V4Codec::new(key, iv)),
            SsrProtocol::AuthAes128Md5 => Self::AuthAes128(AuthAes128Codec::new(
                key,
                iv,
                protocol_param,
                SsrHmacKind::Md5,
                "auth_aes128_md5",
            )),
            SsrProtocol::AuthAes128Sha1 => Self::AuthAes128(AuthAes128Codec::new(
                key,
                iv,
                protocol_param,
                SsrHmacKind::Sha1,
                "auth_aes128_sha1",
            )),
            SsrProtocol::AuthChainA => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_a", AuthChainVariant::A),
            )),
            SsrProtocol::AuthChainB => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_b", AuthChainVariant::B),
            )),
            SsrProtocol::AuthChainC => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_c", AuthChainVariant::C),
            )),
            SsrProtocol::AuthChainD => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_d", AuthChainVariant::D),
            )),
            SsrProtocol::AuthChainE => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_e", AuthChainVariant::E),
            )),
            SsrProtocol::AuthChainF => Self::AuthChain(AuthChainCodec::new(
                key,
                iv,
                protocol_param,
                AuthChainProfile::new("auth_chain_f", AuthChainVariant::F),
            )),
        }
    }

    fn encode(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::VerifySimple(codec) => Ok(codec.encode(payload)),
            Self::VerifySha1(codec) => Ok(codec.encode(payload)),
            Self::AuthSimple(codec) | Self::AuthSha1(codec) | Self::AuthSha1V2(codec) => {
                Ok(codec.encode(payload))
            }
            Self::AuthSha1V4(codec) => Ok(codec.encode(payload)),
            Self::AuthAes128(codec) => Ok(codec.encode(payload)),
            Self::AuthChain(codec) => codec.encode(payload),
        }
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        match self {
            Self::VerifySimple(codec) => codec.decode(payload, output),
            Self::VerifySha1(codec) => codec.decode(payload, output),
            Self::AuthSimple(codec) | Self::AuthSha1(codec) | Self::AuthSha1V2(codec) => {
                codec.decode(payload, output)
            }
            Self::AuthSha1V4(codec) => codec.decode(payload, output),
            Self::AuthAes128(codec) => codec.decode(payload, output),
            Self::AuthChain(codec) => codec.decode(payload, output),
        }
    }

    fn encode_packet(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::VerifySimple(codec) => Ok(codec.encode_packet(payload)),
            Self::VerifySha1(codec) => Ok(codec.encode_packet(payload)),
            Self::AuthSimple(codec) | Self::AuthSha1(codec) | Self::AuthSha1V2(codec) => {
                Ok(codec.encode_packet(payload))
            }
            Self::AuthSha1V4(codec) => Ok(codec.encode_packet(payload)),
            Self::AuthAes128(codec) => Ok(codec.encode_packet(payload)),
            Self::AuthChain(codec) => codec.encode_packet(payload),
        }
    }

    fn decode_packet(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::VerifySimple(codec) => Ok(codec.decode_packet(payload)),
            Self::VerifySha1(codec) => Ok(codec.decode_packet(payload)),
            Self::AuthSimple(codec) | Self::AuthSha1(codec) | Self::AuthSha1V2(codec) => {
                Ok(codec.decode_packet(payload))
            }
            Self::AuthSha1V4(codec) => Ok(codec.decode_packet(payload)),
            Self::AuthAes128(codec) => codec.decode_packet(payload),
            Self::AuthChain(codec) => codec.decode_packet(payload),
        }
    }
}

struct VerifySimpleCodec {
    recv_buffer: BytesMut,
    raw_recv: bool,
}

impl VerifySimpleCodec {
    fn new() -> Self {
        Self {
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        const UNIT_LEN: usize = 4096;
        let mut output = Vec::with_capacity(payload.len() + payload.len() / UNIT_LEN * 8 + 8);
        for chunk in payload.chunks(UNIT_LEN) {
            self.pack_data(&mut output, chunk);
        }
        output
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 2 {
            let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if !(6..=8192).contains(&length) {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR verify_simple response length is invalid",
                ));
            }
            if length > self.recv_buffer.len() {
                break;
            }
            let frame = self.recv_buffer.split_to(length);
            let expected = u32::from_le_bytes([
                frame[length - 4],
                frame[length - 3],
                frame[length - 2],
                frame[length - 1],
            ]);
            if adler32(&frame[..length - 4]) != expected {
                self.raw_recv = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR verify_simple response checksum mismatch",
                ));
            }
            output.extend_from_slice(&frame[2..length - 4]);
        }
        Ok(())
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn decode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn pack_data(&self, output: &mut Vec<u8>, payload: &[u8]) {
        let start = output.len();
        let length = payload.len() + 6;
        output.extend_from_slice(&(length as u16).to_be_bytes());
        output.extend_from_slice(payload);
        let checksum = adler32(&output[start..]);
        output.extend_from_slice(&checksum.to_le_bytes());
    }
}

include!("ssr/protocol/verify_sha1.rs");

#[derive(Clone, Copy)]
enum EarlyAuthKind {
    Simple,
    Sha1,
    Sha1V2,
}

struct EarlyAuthCodec {
    key: Vec<u8>,
    iv: Vec<u8>,
    kind: EarlyAuthKind,
    client_id: Vec<u8>,
    connection_id: u32,
    sent_header: bool,
    recv_buffer: BytesMut,
    raw_recv: bool,
}

impl EarlyAuthCodec {
    fn new(key: Vec<u8>, iv: Vec<u8>, kind: EarlyAuthKind) -> Self {
        let client_id_len = if matches!(kind, EarlyAuthKind::Sha1V2) {
            8
        } else {
            4
        };
        let mut client_id = vec![0_u8; client_id_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_id);
        Self {
            key,
            iv,
            kind,
            client_id,
            connection_id: rand::random::<u32>() & 0x00ff_ffff,
            sent_header: false,
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        let unit_len = match self.kind {
            EarlyAuthKind::Simple => 4096,
            EarlyAuthKind::Sha1 | EarlyAuthKind::Sha1V2 => 8100,
        };
        let mut output = Vec::with_capacity(payload.len() + 96);
        let mut remaining = payload;
        if !self.sent_header {
            let head = get_ssr_head_size(remaining, 30).min(remaining.len());
            let data_len = match self.kind {
                EarlyAuthKind::Simple => head,
                EarlyAuthKind::Sha1 => {
                    (head + (rand::random::<u8>() as usize % 32)).min(remaining.len())
                }
                EarlyAuthKind::Sha1V2 => {
                    (head + (rand::random::<u16>() as usize % 512)).min(remaining.len())
                }
            };
            self.pack_auth_data(&mut output, &remaining[..data_len]);
            remaining = &remaining[data_len..];
            self.sent_header = true;
        }
        for chunk in remaining.chunks(unit_len) {
            self.pack_data(&mut output, chunk);
        }
        output
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 4 {
            let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth response length is invalid",
                ));
            }
            if length > self.recv_buffer.len() {
                break;
            }
            let frame = self.recv_buffer.split_to(length);
            let expected = u32::from_le_bytes([
                frame[length - 4],
                frame[length - 3],
                frame[length - 2],
                frame[length - 1],
            ]);
            if adler32(&frame[..length - 4]) != expected {
                self.raw_recv = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth response checksum mismatch",
                ));
            }
            let mut pos = frame[4] as usize;
            if pos < 255 {
                pos += 5;
            } else {
                pos = u16::from_be_bytes([frame[5], frame[6]]) as usize + 7;
            }
            if pos > length - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth response padding is invalid",
                ));
            }
            output.extend_from_slice(&frame[pos..length - 4]);
        }
        Ok(())
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn decode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn pack_auth_data(&mut self, output: &mut Vec<u8>, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let random_len = match self.kind {
            EarlyAuthKind::Simple => 0,
            EarlyAuthKind::Sha1 => rand::random::<u8>() as usize % 32,
            EarlyAuthKind::Sha1V2 => rand::random::<u16>() as usize % 512,
        };
        let auth_len = self.auth_data_len();
        let packed_len = 2 + 4 + 1 + random_len + auth_len + payload.len() + 10;
        let salt = self.salt();
        let mut crc_data = Vec::with_capacity(2 + salt.len() + self.key.len());
        crc_data.extend_from_slice(&(packed_len as u16).to_be_bytes());
        crc_data.extend_from_slice(salt.as_bytes());
        crc_data.extend_from_slice(&self.key);
        let start = output.len();
        output.extend_from_slice(&(packed_len as u16).to_be_bytes());
        output.extend_from_slice(&crc32fast::hash(&crc_data).to_le_bytes());
        self.push_random(output, random_len);
        self.push_auth_data(output);
        output.extend_from_slice(payload);
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let tag = match self.kind {
            EarlyAuthKind::Simple => hmac_sha1(&mac_key, &output[start + 6..]),
            EarlyAuthKind::Sha1 | EarlyAuthKind::Sha1V2 => hmac_sha1(&mac_key, &output[start..]),
        };
        output.extend_from_slice(&tag[..10]);
    }

    fn pack_data(&self, output: &mut Vec<u8>, payload: &[u8]) {
        let random_len = match self.kind {
            EarlyAuthKind::Simple => 0,
            EarlyAuthKind::Sha1 => rand::random::<u8>() as usize % 32,
            EarlyAuthKind::Sha1V2 => rand::random::<u16>() as usize % 512,
        };
        let packed_len = 2 + 2 + 1 + random_len + payload.len() + 4;
        let start = output.len();
        output.extend_from_slice(&(packed_len as u16).to_be_bytes());
        let crc = crc32fast::hash(&output[start..start + 2]) as u16;
        output.extend_from_slice(&crc.to_le_bytes());
        self.push_random(output, random_len);
        output.extend_from_slice(payload);
        let checksum = adler32(&output[start + 4..]);
        output.extend_from_slice(&checksum.to_le_bytes());
    }

    fn push_random(&self, output: &mut Vec<u8>, size: usize) {
        if size < 255 {
            output.push(size as u8);
        } else {
            output.push(255);
            output.extend_from_slice(&(size as u16).to_be_bytes());
        }
        push_random_bytes(output, size);
    }

    fn push_auth_data(&mut self, output: &mut Vec<u8>) {
        if !matches!(self.kind, EarlyAuthKind::Sha1V2) {
            output.extend_from_slice(&unix_timestamp_u32().to_le_bytes());
        }
        output.extend_from_slice(&self.client_id);
        output.extend_from_slice(&self.connection_id.to_le_bytes());
        self.connection_id = self.connection_id.wrapping_add(1);
    }

    fn auth_data_len(&self) -> usize {
        match self.kind {
            EarlyAuthKind::Simple | EarlyAuthKind::Sha1 => 12,
            EarlyAuthKind::Sha1V2 => 12,
        }
    }

    fn salt(&self) -> &'static str {
        match self.kind {
            EarlyAuthKind::Simple => "auth_simple",
            EarlyAuthKind::Sha1 => "auth_sha1",
            EarlyAuthKind::Sha1V2 => "auth_sha1_v2",
        }
    }
}

struct AuthSha1V4Codec {
    key: Vec<u8>,
    iv: Vec<u8>,
    client_id: [u8; 4],
    connection_id: u32,
    sent_header: bool,
    recv_buffer: BytesMut,
    raw_recv: bool,
}

impl AuthSha1V4Codec {
    fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        let mut client_id = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_id);
        Self {
            key,
            iv,
            client_id,
            connection_id: rand::random::<u32>() & 0x00ff_ffff,
            sent_header: false,
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(payload.len() + 64);
        let mut remaining = payload;
        if !self.sent_header {
            let data_len = get_auth_sha1_v4_data_len(remaining);
            self.pack_auth_data(&mut output, &remaining[..data_len]);
            remaining = &remaining[data_len..];
            self.sent_header = true;
        }
        while remaining.len() > 8100 {
            self.pack_data(&mut output, &remaining[..8100]);
            remaining = &remaining[8100..];
        }
        if !remaining.is_empty() {
            self.pack_data(&mut output, remaining);
        }
        output
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 4 {
            let checksum = crc32fast::hash(&self.recv_buffer[..2]) as u16;
            let expected = u16::from_le_bytes([self.recv_buffer[2], self.recv_buffer[3]]);
            if checksum != expected {
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_sha1_v4 response CRC mismatch",
                ));
            }

            let length = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_sha1_v4 response length is invalid",
                ));
            }
            if length > self.recv_buffer.len() {
                break;
            }
            let frame = &self.recv_buffer[..length];
            let actual_adler = adler32(&frame[..length - 4]);
            let expected_adler = u32::from_le_bytes([
                frame[length - 4],
                frame[length - 3],
                frame[length - 2],
                frame[length - 1],
            ]);
            if actual_adler != expected_adler {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_sha1_v4 response checksum mismatch",
                ));
            }

            let mut pos = frame[4] as usize;
            if pos < 255 {
                pos += 5;
            } else {
                pos = u16::from_be_bytes([frame[5], frame[6]]) as usize + 7;
            }
            if pos > length - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_sha1_v4 response padding is invalid",
                ));
            }
            output.extend_from_slice(&frame[pos..length - 4]);
            let _ = self.recv_buffer.split_to(length);
        }
        Ok(())
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn decode_packet(&self, payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn pack_auth_data(&mut self, output: &mut Vec<u8>, data: &[u8]) {
        let random_len = self.random_data_len(12 + data.len());
        let mut packed_len = 2 + 4 + 3 + random_len + 12 + data.len() + 10;
        if random_len < 128 {
            packed_len -= 2;
        }

        let mut crc_data = Vec::with_capacity(2 + "auth_sha1_v4".len() + self.key.len());
        crc_data.extend_from_slice(&(packed_len as u16).to_be_bytes());
        crc_data.extend_from_slice(b"auth_sha1_v4");
        crc_data.extend_from_slice(&self.key);

        let mut hmac_key = Vec::with_capacity(self.iv.len() + self.key.len());
        hmac_key.extend_from_slice(&self.iv);
        hmac_key.extend_from_slice(&self.key);

        let start = output.len();
        output.extend_from_slice(&crc_data[..2]);
        output.extend_from_slice(&crc32fast::hash(&crc_data).to_le_bytes());
        pack_auth_sha1_v4_random(output, random_len);
        self.put_auth_data(output);
        output.extend_from_slice(data);

        let mut mac =
            <Hmac<Sha1> as Mac>::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
        mac.update(&output[start + 10..]);
        let tag = mac.finalize().into_bytes();
        output.extend_from_slice(&tag[..10]);
    }

    fn pack_data(&mut self, output: &mut Vec<u8>, data: &[u8]) {
        let random_len = self.random_data_len(data.len());
        let mut packed_len = 2 + 2 + 3 + random_len + data.len() + 4;
        if random_len < 128 {
            packed_len -= 2;
        }
        let start = output.len();
        output.extend_from_slice(&(packed_len as u16).to_be_bytes());
        let crc = crc32fast::hash(&output[start..start + 2]) as u16;
        output.extend_from_slice(&crc.to_le_bytes());
        pack_auth_sha1_v4_random(output, random_len);
        output.extend_from_slice(data);
        let checksum = adler32(&output[start + 4..]);
        output.extend_from_slice(&checksum.to_le_bytes());
    }

    fn put_auth_data(&mut self, output: &mut Vec<u8>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs() as u32)
            .unwrap_or_default();
        output.extend_from_slice(&timestamp.to_le_bytes());
        output.extend_from_slice(&self.client_id);
        output.extend_from_slice(&self.connection_id.to_le_bytes());
        self.connection_id = self.connection_id.wrapping_add(1);
    }

    fn random_data_len(&self, size: usize) -> usize {
        if size > 1200 {
            0
        } else if size > 400 {
            rand::random::<u8>() as usize
        } else {
            (rand::random::<u16>() as usize) % 512
        }
    }
}

#[derive(Clone, Copy)]
enum SsrHmacKind {
    Md5,
    Sha1,
}

impl SsrHmacKind {
    fn digest(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => hmac_md5(key, data).to_vec(),
            Self::Sha1 => {
                let mut hmac =
                    <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
                hmac.update(data);
                hmac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn digest_fixed(self, key: &[u8], data: &[u8]) -> [u8; 20] {
        match self {
            Self::Md5 => {
                let digest = hmac_md5(key, data);
                let mut out = [0_u8; 20];
                out[..16].copy_from_slice(&digest);
                out
            }
            Self::Sha1 => hmac_sha1(key, data),
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => md5::compute(data).0.to_vec(),
            Self::Sha1 => {
                use sha1::Digest;
                Sha1::digest(data).to_vec()
            }
        }
    }
}

struct SsrUserData {
    user_key: Vec<u8>,
    user_id: [u8; 4],
}

impl SsrUserData {
    fn auth_aes(key: &[u8], param: &str, hmac_kind: SsrHmacKind) -> Self {
        let mut user_id = [0_u8; 4];
        let mut user_key = Vec::new();
        if let Some((id, password)) = param.split_once(':') {
            if let Ok(id) = id.parse::<u32>() {
                user_id.copy_from_slice(&id.to_le_bytes());
                user_key = hmac_kind.hash(password.as_bytes());
            }
        }
        if user_key.is_empty() {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut user_id);
            user_key = key.to_vec();
        }
        Self { user_key, user_id }
    }

    fn auth_chain(key: &[u8], param: &str) -> Self {
        let mut user_id = [0_u8; 4];
        let mut user_key = Vec::new();
        if let Some((id, password)) = param.split_once(':') {
            if let Ok(id) = id.parse::<u32>() {
                user_id.copy_from_slice(&id.to_le_bytes());
                user_key = password.as_bytes().to_vec();
            }
        }
        if user_key.is_empty() {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut user_id);
            user_key = key.to_vec();
        }
        Self { user_key, user_id }
    }
}

struct AuthAes128Codec {
    key: Vec<u8>,
    iv: Vec<u8>,
    salt: &'static str,
    hmac_kind: SsrHmacKind,
    user: SsrUserData,
    auth: SsrAuthData,
    sent_header: bool,
    pack_id: u32,
    recv_id: u32,
    recv_buffer: BytesMut,
    raw_recv: bool,
}

impl AuthAes128Codec {
    fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        protocol_param: String,
        hmac_kind: SsrHmacKind,
        salt: &'static str,
    ) -> Self {
        let user = SsrUserData::auth_aes(&key, &protocol_param, hmac_kind);
        Self {
            key,
            iv,
            salt,
            hmac_kind,
            user,
            auth: SsrAuthData::new(),
            sent_header: false,
            pack_id: 1,
            recv_id: 1,
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        let full_len = payload.len();
        let mut output = Vec::with_capacity(payload.len() + 96);
        let mut remaining = payload;
        if !self.sent_header {
            let data_len = get_auth_sha1_v4_data_len(remaining);
            self.pack_auth_data(&mut output, &remaining[..data_len]);
            remaining = &remaining[data_len..];
            self.sent_header = true;
        }
        while remaining.len() > 8100 {
            self.pack_data(&mut output, &remaining[..8100], full_len);
            remaining = &remaining[8100..];
        }
        if !remaining.is_empty() {
            self.pack_data(&mut output, remaining, full_len);
        }
        output
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 4 {
            let header_mac = with_appended_u32_le(&self.user.user_key, self.recv_id, |mac_key| {
                self.hmac_kind.digest_fixed(mac_key, &self.recv_buffer[..2])
            });
            if header_mac[..2] != self.recv_buffer[2..4] {
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_aes128 response MAC mismatch",
                ));
            }
            let length = u16::from_le_bytes([self.recv_buffer[0], self.recv_buffer[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_aes128 response length is invalid",
                ));
            }
            if length > self.recv_buffer.len() {
                break;
            }
            let frame = &self.recv_buffer[..length];
            let mac = with_appended_u32_le(&self.user.user_key, self.recv_id, |mac_key| {
                self.hmac_kind.digest_fixed(mac_key, &frame[..length - 4])
            });
            if mac[..4] != frame[length - 4..length] {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_aes128 response checksum mismatch",
                ));
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let mut pos = frame[4] as usize;
            if pos < 255 {
                pos += 5;
            } else {
                pos = u16::from_le_bytes([frame[5], frame[6]]) as usize + 7;
            }
            if pos > length - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_aes128 response padding is invalid",
                ));
            }
            output.extend_from_slice(&frame[pos..length - 4]);
            let _ = self.recv_buffer.split_to(length);
        }
        Ok(())
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(payload.len() + 8);
        output.extend_from_slice(payload);
        output.extend_from_slice(&self.user.user_id);
        let mac = self.hmac_kind.digest(&self.user.user_key, &output);
        output.extend_from_slice(&mac[..4]);
        output
    }

    fn decode_packet(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR auth_aes128 UDP packet is too short",
            ));
        }
        let data_len = payload.len() - 4;
        let expected = self.hmac_kind.digest(&self.key, &payload[..data_len]);
        if expected[..4] != payload[data_len..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR auth_aes128 UDP checksum mismatch",
            ));
        }
        Ok(payload[..data_len].to_vec())
    }

    fn pack_auth_data(&mut self, output: &mut Vec<u8>, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let random_len = if data.len() > 400 {
            rand::random::<u16>() as usize % 512
        } else {
            rand::random::<u16>() as usize % 1024
        };
        let packed_len = 7 + 4 + 16 + 4 + random_len + data.len() + 4;
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        output.push(rand::random());
        let mac = self.hmac_kind.digest(&mac_key, output);
        output.extend_from_slice(&mac[..6]);
        output.extend_from_slice(&self.user.user_id);
        output.extend_from_slice(&self.auth.encrypted_block(
            &self.user.user_key,
            packed_len as u16,
            random_len as u16,
            self.salt,
        ));
        let mac = self.hmac_kind.digest(&mac_key, &output[7..]);
        output.extend_from_slice(&mac[..4]);
        push_random_bytes(output, random_len);
        output.extend_from_slice(data);
        let mac = self.hmac_kind.digest(&self.user.user_key, output);
        output.extend_from_slice(&mac[..4]);
    }

    fn pack_data(&mut self, output: &mut Vec<u8>, data: &[u8], full_len: usize) {
        let random_len = self.rand_data_len(data.len(), full_len);
        let mut packed_len = 2 + 2 + 3 + random_len + data.len() + 4;
        if random_len < 128 {
            packed_len -= 2;
        }
        let pack_id = self.pack_id;
        self.pack_id = self.pack_id.wrapping_add(1);
        let start = output.len();
        output.extend_from_slice(&(packed_len as u16).to_le_bytes());
        let mac = with_appended_u32_le(&self.user.user_key, pack_id, |mac_key| {
            self.hmac_kind
                .digest_fixed(mac_key, &output[start..start + 2])
        });
        output.extend_from_slice(&mac[..2]);
        pack_auth_sha1_v4_random(output, random_len);
        output.extend_from_slice(data);
        let mac = with_appended_u32_le(&self.user.user_key, pack_id, |mac_key| {
            self.hmac_kind.digest_fixed(mac_key, &output[start + 4..])
        });
        output.extend_from_slice(&mac[..4]);
    }

    fn rand_data_len(&self, data_len: usize, full_len: usize) -> usize {
        if full_len >= 32 * 1024 {
            return 0;
        }
        let rev = 1460_i32 - data_len as i32 - 9;
        if rev == 0 {
            0
        } else if rev < 0 {
            if rev > -1460 {
                rand::random::<u16>() as usize % (rev + 1460) as usize
            } else {
                rand::random::<u8>() as usize % 32
            }
        } else if data_len > 900 {
            rand::random::<u16>() as usize % rev as usize
        } else {
            rand::random::<u16>() as usize % rev as usize
        }
    }
}

struct SsrAuthData {
    client_id: [u8; 4],
    connection_id: u32,
    timestamp: u32,
}

impl SsrAuthData {
    fn new() -> Self {
        let mut client_id = [0_u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_id);
        Self {
            client_id,
            connection_id: rand::random::<u32>() & 0x00ff_ffff,
            timestamp: unix_timestamp_u32(),
        }
    }

    fn encrypted_block(
        &mut self,
        user_key: &[u8],
        packed: u16,
        random: u16,
        salt: &str,
    ) -> [u8; 16] {
        self.connection_id = self.connection_id.wrapping_add(1);
        let mut plain = [0_u8; 16];
        plain[..4].copy_from_slice(&self.timestamp.to_le_bytes());
        plain[4..8].copy_from_slice(&self.client_id);
        plain[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        plain[12..14].copy_from_slice(&packed.to_le_bytes());
        plain[14..16].copy_from_slice(&random.to_le_bytes());
        let key_material = format!("{}{}", BASE64_STANDARD.encode(user_key), salt);
        let key = shadowsocks_evp_bytes_to_key(key_material.as_bytes(), 16);
        let cipher = Aes128::new_from_slice(&key).expect("AES-128 key size is fixed");
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        let mut out = [0_u8; 16];
        out.copy_from_slice(&block);
        out
    }
}

include!("ssr/protocol/auth_chain.rs");

fn get_ssr_head_size(data: &[u8], fallback: usize) -> usize {
    match data.first().map(|value| value & 7) {
        Some(1) => 7,
        Some(4) => 19,
        Some(3) if data.len() >= 2 => 4 + data[1] as usize,
        _ => fallback,
    }
}

fn get_auth_sha1_v4_data_len(data: &[u8]) -> usize {
    let head = get_ssr_head_size(data, 30);
    data.len().min(head + (rand::random::<u8>() as usize % 32))
}

fn pack_auth_sha1_v4_random(output: &mut Vec<u8>, size: usize) {
    if size < 128 {
        output.push((size + 1) as u8);
        push_random_bytes(output, size);
    } else {
        output.push(255);
        output.extend_from_slice(&((size + 3) as u16).to_be_bytes());
        push_random_bytes(output, size);
    }
}

fn push_random_bytes(output: &mut Vec<u8>, size: usize) {
    let start = output.len();
    output.resize(start + size, 0);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut output[start..]);
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        key_block[..16].copy_from_slice(&md5::compute(key).0);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = md5::Context::new();
    inner.consume(ipad);
    inner.consume(data);
    let inner = inner.finalize();
    let mut outer = md5::Context::new();
    outer.consume(opad);
    outer.consume(inner.0);
    outer.finalize().0
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(data);
    let digest = hmac.finalize().into_bytes();
    let mut out = [0_u8; 20];
    out.copy_from_slice(&digest);
    out
}

fn with_appended_bytes<R>(prefix: &[u8], suffix: &[u8], f: impl FnOnce(&[u8]) -> R) -> R {
    if prefix.len() + suffix.len() <= 128 {
        let mut stack = [0_u8; 128];
        stack[..prefix.len()].copy_from_slice(prefix);
        stack[prefix.len()..prefix.len() + suffix.len()].copy_from_slice(suffix);
        f(&stack[..prefix.len() + suffix.len()])
    } else {
        let mut key = Vec::with_capacity(prefix.len() + suffix.len());
        key.extend_from_slice(prefix);
        key.extend_from_slice(suffix);
        f(&key)
    }
}

fn with_appended_u32_le<R>(prefix: &[u8], value: u32, f: impl FnOnce(&[u8]) -> R) -> R {
    with_appended_bytes(prefix, &value.to_le_bytes(), f)
}

fn with_appended_u32_be<R>(prefix: &[u8], value: u32, f: impl FnOnce(&[u8]) -> R) -> R {
    with_appended_bytes(prefix, &value.to_be_bytes(), f)
}

fn ssr_chain_udp_rc4_key(user_key: &[u8], md5_data: &[u8; 16]) -> Vec<u8> {
    let key_material = format!(
        "{}{}",
        BASE64_STANDARD.encode(user_key),
        BASE64_STANDARD.encode(md5_data)
    );
    shadowsocks_evp_bytes_to_key(key_material.as_bytes(), 16)
}

fn shadowsocks_evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    legacy_evp_bytes_to_key(password, key_len)
}

fn unix_timestamp_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
