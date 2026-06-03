enum ShadowCryptoStream {
    BuiltIn(CryptoStream<ShadowsocksTransport>),
    Legacy(NeonLegacyCryptoStream<ShadowsocksTransport>),
}

impl Unpin for ShadowCryptoStream {}

impl ShadowCryptoStream {
    fn sent_nonce(&self) -> &[u8] {
        match self {
            Self::BuiltIn(stream) => stream.sent_nonce(),
            Self::Legacy(stream) => stream.sent_nonce(),
        }
    }

    fn poll_read_decrypted(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        context: &Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            Self::BuiltIn(stream) => Pin::new(stream)
                .poll_read_decrypted(cx, context, buf)
                .map_err(io::Error::from),
            Self::Legacy(stream) => Pin::new(stream).poll_read_decrypted(cx, buf),
        }
    }

    fn poll_write_encrypted(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this {
            Self::BuiltIn(stream) => Pin::new(stream)
                .poll_write_encrypted(cx, buf)
                .map_err(io::Error::from),
            Self::Legacy(stream) => Pin::new(stream).poll_write_encrypted(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            Self::BuiltIn(stream) => Pin::new(stream).poll_flush(cx).map_err(io::Error::from),
            Self::Legacy(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            Self::BuiltIn(stream) => Pin::new(stream).poll_shutdown(cx).map_err(io::Error::from),
            Self::Legacy(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

struct ShadowsocksClientStream {
    inner: ShadowCryptoStream,
    target: Option<Address>,
    pending_write: Option<PendingWrite>,
}

impl ShadowsocksClientStream {
    fn new(inner: ShadowCryptoStream, target: Address) -> Self {
        Self {
            inner,
            target: Some(target),
            pending_write: None,
        }
    }
}

impl AsyncRead for ShadowsocksClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let context = Context::new(ServerType::Local);
        Pin::new(&mut self.inner).poll_read_decrypted(cx, &context, buf)
    }
}

impl AsyncWrite for ShadowsocksClientStream {
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

        let mut payload = BytesMut::with_capacity(buf.len() + 64);
        if let Some(target) = self.target.take() {
            target.write_to_buf(&mut payload);
        }
        payload.extend_from_slice(buf);
        self.pending_write = Some(PendingWrite::new(payload.freeze(), buf.len()));
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
