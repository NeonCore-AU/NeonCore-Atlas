struct SimpleObfsHttpStream<S> {
    inner: S,
    host: String,
    port: u16,
    first_request: bool,
    first_response: bool,
    read_buffer: BytesMut,
    pending_write: Option<PendingWrite>,
}

impl<S> SimpleObfsHttpStream<S> {
    fn new(inner: S, host: String, port: u16) -> Self {
        Self {
            inner,
            host,
            port,
            first_request: true,
            first_response: true,
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SimpleObfsHttpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        if !self.first_response {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        loop {
            let mut temp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "simple-obfs HTTP response ended before headers",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.read_buffer.extend_from_slice(read_buf.filled());
                    if let Some(header_end) = find_header_end(&self.read_buffer) {
                        let body = self.read_buffer.split_off(header_end + 4);
                        self.read_buffer = body;
                        self.first_response = false;
                        let _ = drain_buffer(&mut self.read_buffer, buf);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SimpleObfsHttpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) => {
                    if original_len > 0 {
                        return Poll::Ready(Ok(original_len));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        if self.first_request {
            self.first_request = false;
            let packet = http_obfs_request(&self.host, self.port, buf);
            self.pending_write = Some(PendingWrite::new(Bytes::from(packet), buf.len()));
        }
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SsrHttpObfsStream<S> {
    inner: SimpleObfsHttpStream<S>,
    host: String,
    port: u16,
    post: bool,
    headers: String,
    first_request: bool,
    pending_write: Option<PendingWrite>,
}

impl<S> SsrHttpObfsStream<S> {
    fn new(inner: S, host: String, port: u16, post: bool, headers: String) -> Self {
        Self {
            inner: SimpleObfsHttpStream::new(inner, host.clone(), port),
            host,
            port,
            post,
            headers,
            first_request: true,
            pending_write: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SsrHttpObfsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsrHttpObfsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner.inner) {
                Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        if self.first_request {
            self.first_request = false;
            let packet =
                ssr_http_obfs_request(&self.host, self.port, self.post, &self.headers, buf);
            self.pending_write = Some(PendingWrite::new(Bytes::from(packet), buf.len()));
            if let Some(mut pending) = self.pending_write.take() {
                match pending.poll_write_all(cx, &mut self.inner.inner) {
                    Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        self.pending_write = Some(pending);
                        return Poll::Pending;
                    }
                }
            }
        }
        Pin::new(&mut self.inner.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner.inner).poll_shutdown(cx)
    }
}

struct SimpleObfsTlsStream<S> {
    inner: S,
    host: String,
    first_request: bool,
    first_response: bool,
    read_state: Option<TlsReadState>,
    read_buffer: BytesMut,
    pending_write: Option<PendingWrite>,
}

impl<S> SimpleObfsTlsStream<S> {
    fn new(inner: S, host: String) -> Self {
        Self {
            inner,
            host,
            first_request: true,
            first_response: true,
            read_state: None,
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SimpleObfsTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_state.is_none() {
                self.read_state = Some(TlsReadState::new(0));
            }
            let mut state = self.read_state.take().expect("TLS read state should exist");
            match state.poll_read_record(cx, &mut self.inner) {
                Poll::Pending => {
                    self.read_state = Some(state);
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(record)) => {
                    self.read_state = None;
                    if self.first_response && record.content_type != 0x17 {
                        continue;
                    }
                    self.first_response = false;
                    self.read_buffer.extend_from_slice(&record.payload);
                    let _ = drain_buffer(&mut self.read_buffer, buf);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SimpleObfsTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        if self.first_request {
            self.first_request = false;
            let packet = tls_obfs_client_hello(buf, &self.host);
            self.pending_write = Some(PendingWrite::new(Bytes::from(packet), buf.len()));
        } else {
            self.pending_write = Some(PendingWrite::new(
                Bytes::from(tls_obfs_record(buf)),
                buf.len(),
            ));
        }
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
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

include!("ssr/obfs/tls_ticket.rs");

struct RandomHeadStream<S> {
    inner: S,
    sent_header: bool,
    received_response: bool,
    flushed_payload: bool,
    pending_write: Option<PendingWrite>,
    buffered_payload: BytesMut,
}

impl<S> RandomHeadStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            sent_header: false,
            received_response: false,
            flushed_payload: false,
            pending_write: None,
            buffered_payload: BytesMut::new(),
        }
    }

    fn random_head_packet() -> Bytes {
        let random_len = (rand::random::<u8>() as usize % 96) + 4;
        let mut packet = vec![0_u8; random_len + 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet[..random_len]);
        let checksum = 0xffff_ffff_u32.wrapping_sub(crc32fast::hash(&packet[..random_len]));
        packet[random_len..].copy_from_slice(&checksum.to_le_bytes());
        Bytes::from(packet)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RandomHeadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
        if self.received_response {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let mut discard = [0_u8; 8192];
        let mut read_buf = ReadBuf::new(&mut discard);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) if read_buf.filled().is_empty() => Poll::Ready(Ok(())),
            Poll::Ready(Ok(())) => {
                self.received_response = true;
                self.flushed_payload = true;
                if !self.buffered_payload.is_empty() {
                    let pending =
                        PendingWrite::new(Bytes::from(self.buffered_payload.split().freeze()), 0);
                    self.pending_write = Some(pending);
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
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RandomHeadStream<S> {
    fn poll_write(
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

        if self.received_response && !self.flushed_payload {
            self.flushed_payload = true;
            if !self.buffered_payload.is_empty() {
                let pending =
                    PendingWrite::new(Bytes::from(self.buffered_payload.split().freeze()), 0);
                self.pending_write = Some(pending);
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
            }
        }

        if self.received_response {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        self.buffered_payload.extend_from_slice(buf);
        if !self.sent_header {
            self.sent_header = true;
            self.pending_write = Some(PendingWrite::new(Self::random_head_packet(), buf.len()));
            if let Some(mut pending) = self.pending_write.take() {
                match pending.poll_write_all(cx, &mut self.inner) {
                    Poll::Ready(Ok(original_len)) => return Poll::Ready(Ok(original_len)),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        self.pending_write = Some(pending);
                        return Poll::Pending;
                    }
                }
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct PendingWrite {
    data: Bytes,
    offset: usize,
    original_len: usize,
}

impl PendingWrite {
    fn new(data: Bytes, original_len: usize) -> Self {
        Self {
            data,
            offset: 0,
            original_len,
        }
    }

    fn poll_write_all<S: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
    ) -> Poll<io::Result<usize>> {
        while self.offset < self.data.len() {
            match Pin::new(&mut *stream).poll_write(cx, &self.data[self.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "simple-obfs transport write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.offset += n,
            }
        }
        Poll::Ready(Ok(self.original_len))
    }

    fn poll_write_all_shadow_crypto(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut ShadowCryptoStream,
    ) -> Poll<io::Result<usize>> {
        while self.offset < self.data.len() {
            match Pin::new(&mut *stream).poll_write_encrypted(cx, &self.data[self.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "encrypted write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.offset += n,
            }
        }
        Poll::Ready(Ok(self.original_len))
    }
}

struct TlsReadState {
    header: [u8; 5],
    header_read: usize,
    discard_payload_prefix: usize,
    payload_remaining: Option<usize>,
}

struct TlsRecord {
    content_type: u8,
    payload: Vec<u8>,
}

impl TlsReadState {
    fn new(discard_payload_prefix: usize) -> Self {
        Self {
            header: [0, 0, 0, 0, 0],
            header_read: 0,
            discard_payload_prefix,
            payload_remaining: None,
        }
    }

    fn poll_read_record<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
    ) -> Poll<io::Result<TlsRecord>> {
        let mut output = Vec::new();
        while self.header_read < self.header.len() {
            let mut read_buf = ReadBuf::new(&mut self.header[self.header_read..]);
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "simple-obfs TLS frame ended before header",
                    )));
                }
                Poll::Ready(Ok(())) => self.header_read += read_buf.filled().len(),
            }
        }
        if !matches!(self.header[0], 0x14 | 0x16 | 0x17) || self.header[1] != 0x03 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "simple-obfs TLS frame header is invalid",
            )));
        }
        let remaining = self
            .payload_remaining
            .get_or_insert_with(|| u16::from_be_bytes([self.header[3], self.header[4]]) as usize);
        while *remaining > 0 {
            let mut scratch = [0u8; 8192];
            let take = (*remaining).min(scratch.len());
            let mut read_buf = ReadBuf::new(&mut scratch[..take]);
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "simple-obfs TLS frame ended before payload",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    *remaining -= read_buf.filled().len();
                    let filled = read_buf.filled();
                    let discard = self.discard_payload_prefix.min(filled.len());
                    self.discard_payload_prefix -= discard;
                    output.extend_from_slice(&filled[discard..]);
                }
            }
        }
        Poll::Ready(Ok(TlsRecord {
            content_type: self.header[0],
            payload: output,
        }))
    }
}

fn drain_buffer(buffer: &mut BytesMut, target: &mut ReadBuf<'_>) -> bool {
    if buffer.is_empty() || target.remaining() == 0 {
        return false;
    }
    let take = buffer.len().min(target.remaining());
    target.put_slice(&buffer[..take]);
    let _ = buffer.split_to(take);
    true
}

fn drain_bytes_buffer(buffer: &mut BytesMut, target: &mut ReadBuf<'_>) -> bool {
    drain_buffer(buffer, target)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_ssr_http_obfs_param(param: &str, fallback_host: &str) -> (String, String) {
    let trimmed = param.trim();
    let (host, headers) = trimmed.split_once('#').unwrap_or((trimmed, ""));
    let host = host
        .split(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or(fallback_host)
        .to_string();
    let headers = headers
        .replace("\\n", "\r\n")
        .replace('\n', "\r\n")
        .trim()
        .to_string();
    (host, headers)
}

fn http_obfs_request(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    use base64::Engine;

    let mut key = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let websocket_key = base64::engine::general_purpose::URL_SAFE.encode(key);
    let user_agent_minor = rand::random::<u8>() % 54;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: curl/7.{user_agent_minor}.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {websocket_key}\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    let mut out = request.into_bytes();
    out.extend_from_slice(payload);
    out
}

fn ssr_http_obfs_request(
    host: &str,
    port: u16,
    post: bool,
    headers: &str,
    payload: &[u8],
) -> Vec<u8> {
    let head_len = payload.len().min(30);
    let head_data_len = if payload.len().saturating_sub(head_len) > 64 {
        head_len + (rand::random::<u8>() as usize % 65)
    } else {
        payload.len()
    };
    let head_data_len = head_data_len.min(payload.len());
    let (head_data, rest) = payload.split_at(head_data_len);
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut out = Vec::with_capacity(256 + payload.len() + headers.len());
    if post {
        out.extend_from_slice(b"POST /");
    } else {
        out.extend_from_slice(b"GET /");
    }
    for byte in head_data {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(b'%');
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\n");
    if headers.is_empty() {
        out.extend_from_slice(b"User-Agent: Mozilla/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n");
    } else {
        out.extend_from_slice(headers.as_bytes());
        out.extend_from_slice(b"\r\n\r\n");
    }
    out.extend_from_slice(rest);
    out
}

fn tls_obfs_record(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn tls_obfs_client_hello(payload: &[u8], server: &str) -> Vec<u8> {
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);

    let mut out = Vec::with_capacity(256 + payload.len() + server.len());
    out.push(22);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&((212 + payload.len() + server.len()) as u16).to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&((208 + payload.len() + server.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as u32)
        .unwrap_or_default();
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&random);
    out.push(32);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&((79 + payload.len() + server.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x23]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    out.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    out.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);
    out.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    out
}

fn push_random_bytes_mut(output: &mut BytesMut, size: usize) {
    let start = output.len();
    output.resize(start + size, 0);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut output[start..]);
}
