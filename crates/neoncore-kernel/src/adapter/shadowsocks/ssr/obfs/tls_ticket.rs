struct SsrTlsTicketStream<S> {
    inner: S,
    host: String,
    key: Vec<u8>,
    client_id: [u8; 32],
    handshake_status: u8,
    read_raw: BytesMut,
    read_buffer: BytesMut,
    send_buffer: BytesMut,
    pending_write: Option<PendingWrite>,
}

impl<S> SsrTlsTicketStream<S> {
    fn new(inner: S, host: String, key: Vec<u8>) -> Self {
        let mut client_id = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_id);
        Self {
            inner,
            host,
            key,
            client_id,
            handshake_status: 0,
            read_raw: BytesMut::new(),
            read_buffer: BytesMut::new(),
            send_buffer: BytesMut::new(),
            pending_write: None,
        }
    }

    fn queue_finish(&mut self) {
        let packet = ssr_tls_ticket_finish(&self.key, &self.client_id, self.send_buffer.split());
        self.handshake_status = 8;
        self.pending_write = Some(PendingWrite::new(packet, 0));
    }
}

impl<S> Unpin for SsrTlsTicketStream<S> {}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsrTlsTicketStream<S> {
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
        if drain_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.handshake_status == 8 {
                let drained = {
                    let this = &mut *self;
                    ssr_tls_ticket_drain_records(&mut this.read_raw, &mut this.read_buffer)
                };
                match drained {
                    Ok(true) if drain_buffer(&mut self.read_buffer, buf) => {
                        return Poll::Ready(Ok(()));
                    }
                    Ok(_) => {}
                    Err(err) => return Poll::Ready(Err(err)),
                }
            } else if ssr_tls_ticket_has_server_handshake(&self.read_raw) {
                ssr_tls_ticket_verify_server_handshake(&self.read_raw, &self.key, &self.client_id)?;
                self.read_raw.clear();
                self.queue_finish();
                if let Some(mut pending) = self.pending_write.take() {
                    match pending.poll_write_all(cx, &mut self.inner) {
                        Poll::Ready(Ok(_)) => return Poll::Pending,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            self.pending_write = Some(pending);
                            return Poll::Pending;
                        }
                    }
                }
            }

            let mut temp = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => self.read_raw.extend_from_slice(read_buf.filled()),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsrTlsTicketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(original_len)) if original_len > 0 => {
                    return Poll::Ready(Ok(original_len));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        if self.handshake_status == 8 {
            self.pending_write = Some(PendingWrite::new(
                ssr_tls_ticket_records(buf, true),
                buf.len(),
            ));
        } else {
            if !buf.is_empty() {
                if self.send_buffer.len().saturating_add(buf.len())
                    > SSR_TLS_TICKET_MAX_PENDING_BYTES
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR TLS ticket pending payload is too large before handshake",
                    )));
                }
                self.send_buffer
                    .extend_from_slice(&ssr_tls_ticket_records(buf, true));
            }
            if self.handshake_status == 0 {
                self.handshake_status = 1;
                let packet = ssr_tls_ticket_client_hello(&self.host, &self.key, &self.client_id);
                self.pending_write = Some(PendingWrite::new(packet, buf.len()));
            } else {
                return Poll::Ready(Ok(buf.len()));
            }
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
        while let Some(mut pending) = self.pending_write.take() {
            match pending.poll_write_all(cx, &mut self.inner) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut *self).poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn ssr_tls_ticket_records(payload: &[u8], random_chunks: bool) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + payload.len() / 2048 * 5 + 5);
    let mut remaining = payload;
    while remaining.len() > 2048 {
        let mut size = if random_chunks {
            (rand::random::<u16>() as usize % 4096) + 100
        } else {
            2048
        };
        size = size.min(remaining.len());
        ssr_tls_ticket_pack_record(&mut out, &remaining[..size]);
        remaining = &remaining[size..];
    }
    if !remaining.is_empty() {
        ssr_tls_ticket_pack_record(&mut out, remaining);
    }
    out.freeze()
}

fn ssr_tls_ticket_pack_record(out: &mut BytesMut, payload: &[u8]) {
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.put_u16(payload.len() as u16);
    out.extend_from_slice(payload);
}

fn ssr_tls_ticket_client_hello(host: &str, key: &[u8], client_id: &[u8; 32]) -> Bytes {
    let host = ssr_tls_ticket_host(host);
    let mut data = BytesMut::new();
    data.extend_from_slice(&[0x03, 0x03]);
    ssr_tls_ticket_pack_auth_data(&mut data, key, client_id);
    data.put_u8(0x20);
    data.extend_from_slice(client_id);
    data.extend_from_slice(&[
        0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0,
        0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a,
        0x01, 0x00,
    ]);

    let mut ext = BytesMut::new();
    ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    ssr_tls_ticket_pack_sni(&mut ext, &host);
    ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    ssr_tls_ticket_pack_ticket(&mut ext);
    ext.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04,
        0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b,
        0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
    ]);
    data.put_u16(ext.len() as u16);
    data.extend_from_slice(&ext);

    let mut ret = BytesMut::with_capacity(data.len() + 9);
    ret.extend_from_slice(&[0x16, 0x03, 0x01]);
    ret.put_u16((data.len() + 4) as u16);
    ret.extend_from_slice(&[0x01, 0x00]);
    ret.put_u16(data.len() as u16);
    ret.extend_from_slice(&data);
    ret.freeze()
}

fn ssr_tls_ticket_pack_auth_data(out: &mut BytesMut, key: &[u8], client_id: &[u8; 32]) {
    let start = out.len();
    out.extend_from_slice(&unix_timestamp_u32().to_be_bytes());
    push_random_bytes_mut(out, 18);
    let tag = ssr_tls_ticket_hmac(key, client_id, &out[start..]);
    out.extend_from_slice(&tag[..10]);
}

fn ssr_tls_ticket_pack_sni(out: &mut BytesMut, host: &str) {
    let len = host.len() as u16;
    out.extend_from_slice(&[0x00, 0x00]);
    out.put_u16(len + 5);
    out.put_u16(len + 3);
    out.put_u8(0);
    out.put_u16(len);
    out.extend_from_slice(host.as_bytes());
}

fn ssr_tls_ticket_pack_ticket(out: &mut BytesMut) {
    let length = 16 * ((rand::random::<u8>() as usize % 17) + 8);
    out.extend_from_slice(&[0x00, 0x23]);
    out.put_u16(length as u16);
    push_random_bytes_mut(out, length);
}

fn ssr_tls_ticket_finish(key: &[u8], client_id: &[u8; 32], buffered: BytesMut) -> Bytes {
    let mut out = BytesMut::with_capacity(43 + buffered.len());
    out.extend_from_slice(&[
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20,
    ]);
    push_random_bytes_mut(&mut out, 22);
    let tag = ssr_tls_ticket_hmac(key, client_id, &out);
    out.extend_from_slice(&tag[..10]);
    out.extend_from_slice(&buffered);
    out.freeze()
}

fn ssr_tls_ticket_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed
        .as_bytes()
        .last()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return String::new();
    }
    let hosts = trimmed
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        String::new()
    } else {
        hosts[rand::random::<usize>() % hosts.len()].to_string()
    }
}

fn ssr_tls_ticket_hmac(key: &[u8], client_id: &[u8; 32], data: &[u8]) -> [u8; 20] {
    with_appended_bytes(key, client_id, |mac_key| hmac_sha1(mac_key, data))
}

fn ssr_tls_ticket_has_server_handshake(buffer: &[u8]) -> bool {
    buffer.len() >= 11 + 32 + 1 + 32
}

fn ssr_tls_ticket_verify_server_handshake(
    buffer: &[u8],
    key: &[u8],
    client_id: &[u8; 32],
) -> io::Result<()> {
    if buffer.len() < 43 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowsocksR TLS ticket response is too short",
        ));
    }
    let first = ssr_tls_ticket_hmac(key, client_id, &buffer[11..33]);
    let final_tag = ssr_tls_ticket_hmac(key, client_id, &buffer[..buffer.len() - 10]);
    if first[..10] != buffer[33..43] || final_tag[..10] != buffer[buffer.len() - 10..] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowsocksR TLS ticket response HMAC mismatch",
        ));
    }
    Ok(())
}

fn ssr_tls_ticket_drain_records(raw: &mut BytesMut, output: &mut BytesMut) -> io::Result<bool> {
    let mut drained = false;
    loop {
        if raw.len() < 5 {
            return Ok(drained);
        }
        if raw[..3] != [0x17, 0x03, 0x03] {
            raw.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR TLS ticket record header is invalid",
            ));
        }
        let size = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + size {
            return Ok(drained);
        }
        let frame = raw.split_to(5 + size);
        output.extend_from_slice(&frame[5..]);
        drained = true;
    }
}
