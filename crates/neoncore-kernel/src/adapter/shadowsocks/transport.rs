enum ShadowsocksTransport {
    Plain(ShadowTcpStream),
    Http(SimpleObfsHttpStream<ShadowTcpStream>),
    SsrHttp(SsrHttpObfsStream<ShadowTcpStream>),
    Tls(SimpleObfsTlsStream<ShadowTcpStream>),
    SsrTls(SsrTlsTicketStream<ShadowTcpStream>),
    RandomHead(RandomHeadStream<ShadowTcpStream>),
    WsPlain(WebSocketTransport<ShadowTcpStream>),
    WsTls(WebSocketTransport<TlsStream<ShadowTcpStream>>),
    ShadowTls(ShadowTlsStream<ShadowTcpStream>),
    Kcptun(smux_rust::Stream),
    H2(H2Transport),
    XHttp(BoxedProxyStream),
    ExternalSip003(ExternalSip003Stream),
}

impl AsyncRead for ShadowsocksTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::SsrHttp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::SsrTls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::RandomHead(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::WsPlain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::WsTls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::ShadowTls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Kcptun(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::H2(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::XHttp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::ExternalSip003(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ShadowsocksTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::SsrHttp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::SsrTls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::RandomHead(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::WsPlain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::WsTls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::ShadowTls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Kcptun(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::H2(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::XHttp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::ExternalSip003(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Http(stream) => Pin::new(stream).poll_flush(cx),
            Self::SsrHttp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::SsrTls(stream) => Pin::new(stream).poll_flush(cx),
            Self::RandomHead(stream) => Pin::new(stream).poll_flush(cx),
            Self::WsPlain(stream) => Pin::new(stream).poll_flush(cx),
            Self::WsTls(stream) => Pin::new(stream).poll_flush(cx),
            Self::ShadowTls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Kcptun(stream) => Pin::new(stream).poll_flush(cx),
            Self::H2(stream) => Pin::new(stream).poll_flush(cx),
            Self::XHttp(stream) => Pin::new(stream).poll_flush(cx),
            Self::ExternalSip003(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::SsrHttp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::SsrTls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::RandomHead(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::WsPlain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::WsTls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::ShadowTls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Kcptun(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::H2(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::XHttp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::ExternalSip003(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

struct KcptunPoolSlot {
    session: Arc<smux_rust::Session>,
    expires_at: Option<StdInstant>,
    scavenge_after: Option<StdInstant>,
}

impl KcptunPoolSlot {
    fn new(session: Arc<smux_rust::Session>, config: &KcptunConfig) -> Self {
        let created_at = StdInstant::now();
        let expires_at =
            (config.auto_expire > 0).then(|| created_at + Duration::from_secs(config.auto_expire));
        let scavenge_after =
            expires_at.map(|expires| expires + Duration::from_secs(config.scavenge_ttl.max(1)));
        Self {
            session,
            expires_at,
            scavenge_after,
        }
    }

    fn reusable(&self, now: StdInstant) -> bool {
        !self.session.is_closed() && self.expires_at.is_none_or(|expires| now < expires)
    }

    fn should_scavenge(&self, now: StdInstant) -> bool {
        self.session.is_closed()
            || self
                .scavenge_after
                .is_some_and(|scavenge_after| now >= scavenge_after)
    }
}

struct KcptunSessionPool {
    sessions: Vec<Option<KcptunPoolSlot>>,
    rr: usize,
    last_used: StdInstant,
}

impl KcptunSessionPool {
    fn new(size: usize) -> Self {
        Self {
            sessions: (0..size).map(|_| None).collect(),
            rr: 0,
            last_used: StdInstant::now(),
        }
    }

    fn scavenge(&mut self, now: StdInstant) {
        self.last_used = now;
        for slot in &mut self.sessions {
            if slot.as_ref().is_some_and(|slot| slot.should_scavenge(now)) {
                *slot = None;
            }
        }
    }

    fn session_at(&mut self, idx: usize, now: StdInstant) -> Option<Arc<smux_rust::Session>> {
        self.sessions
            .get(idx)
            .and_then(|slot| slot.as_ref())
            .filter(|slot| slot.reusable(now))
            .map(|slot| slot.session.clone())
    }
}

async fn open_kcptun_stream(
    address: SocketAddr,
    config: &KcptunConfig,
) -> anyhow::Result<smux_rust::Stream> {
    let pools = KCPTUN_SESSION_POOLS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let key = config.pool_key(address);
    let (idx, session) = {
        let mut pools = pools.lock().await;
        let now = StdInstant::now();
        pools.retain(|_, pool| {
            pool.scavenge(now);
            pool.sessions.iter().any(Option::is_some)
                || now.duration_since(pool.last_used)
                    < Duration::from_secs(config.scavenge_ttl.max(1))
        });
        let pool = pools
            .entry(key.clone())
            .or_insert_with(|| KcptunSessionPool::new(config.conn));
        if pool.sessions.len() != config.conn {
            *pool = KcptunSessionPool::new(config.conn);
        }
        pool.scavenge(now);
        let idx = pool.rr % pool.sessions.len();
        pool.rr = pool.rr.wrapping_add(1);
        let session = pool.session_at(idx, now);
        (idx, session)
    };

    let session = match session {
        Some(session) => session,
        None => {
            let create_lock = kcptun_create_lock(&key, idx).await;
            let _guard = create_lock.lock().await;
            if let Some(session) = kcptun_session_from_pool(&key, idx, config).await {
                session
            } else {
                let session = create_kcptun_session(address, config).await?;
                let mut pools = pools.lock().await;
                let pool = pools
                    .entry(key.clone())
                    .or_insert_with(|| KcptunSessionPool::new(config.conn));
                if pool.sessions.len() != config.conn {
                    *pool = KcptunSessionPool::new(config.conn);
                }
                pool.sessions[idx] = Some(KcptunPoolSlot::new(session.clone(), config));
                session
            }
        }
    };

    if let Ok(stream) = session.open_stream().await {
        return Ok(stream);
    }

    let create_lock = kcptun_create_lock(&key, idx).await;
    let _guard = create_lock.lock().await;
    let session = create_kcptun_session(address, config).await?;
    {
        let mut pools = pools.lock().await;
        let pool = pools
            .entry(key)
            .or_insert_with(|| KcptunSessionPool::new(config.conn));
        if pool.sessions.len() == config.conn {
            pool.sessions[idx] = Some(KcptunPoolSlot::new(session.clone(), config));
        }
    }
    session.open_stream().await.map_err(Into::into)
}

async fn kcptun_create_lock(key: &str, idx: usize) -> Arc<tokio::sync::Mutex<()>> {
    let locks = KCPTUN_SESSION_CREATES.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let mut locks = locks.lock().await;
    locks
        .entry(format!("{key}:{idx}"))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

async fn kcptun_session_from_pool(
    key: &str,
    idx: usize,
    config: &KcptunConfig,
) -> Option<Arc<smux_rust::Session>> {
    let pools = KCPTUN_SESSION_POOLS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let mut pools = pools.lock().await;
    let now = StdInstant::now();
    let pool = pools.get_mut(key)?;
    if pool.sessions.len() != config.conn {
        return None;
    }
    pool.scavenge(now);
    pool.session_at(idx, now)
}

async fn create_kcptun_session(
    address: SocketAddr,
    config: &KcptunConfig,
) -> anyhow::Result<Arc<smux_rust::Session>> {
    let key = derive_key(&config.key);
    let kcp_config = KcpConfig {
        mtu: config.mtu,
        nodelay: KcpNoDelayConfig {
            nodelay: config.no_delay != 0,
            interval: config.interval,
            resend: config.resend,
            nc: config.no_congestion,
        },
        wnd_size: (config.snd_wnd, config.rcv_wnd),
        stream: true,
        flush_write: false,
        flush_acks_input: config.ack_nodelay,
        fec_data_shards: config.data_shard,
        fec_parity_shards: config.parity_shard,
        crypt: create_block_crypt(&config.crypt, &key)?,
        ..Default::default()
    };
    let socket = create_kcptun_udp_socket(address, config)?;
    let kcp = KcpStream::connect_with_socket(&kcp_config, socket, address).await?;
    let smux_config = smux_rust::Config {
        version: config.smux_ver,
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(config.keep_alive),
        keep_alive_timeout: Duration::from_secs(config.keep_alive.saturating_mul(3).max(1)),
        max_frame_size: config.frame_size,
        max_receive_buffer: config.smux_buf,
        max_stream_buffer: config.stream_buf,
    };
    smux_config
        .verify()
        .map_err(|err| anyhow::anyhow!("invalid kcptun smux config: {err}"))?;
    if config.no_comp {
        if config.rate_limit > 0 {
            smux_rust::client(
                Box::new(RateLimitedStream::new(kcp, config.rate_limit)),
                Some(smux_config),
            )
            .await
            .map_err(Into::into)
        } else {
            smux_rust::client(Box::new(kcp), Some(smux_config))
                .await
                .map_err(Into::into)
        }
    } else {
        let stream = CompStream::new(kcp);
        if config.rate_limit > 0 {
            smux_rust::client(
                Box::new(RateLimitedStream::new(stream, config.rate_limit)),
                Some(smux_config),
            )
            .await
            .map_err(Into::into)
        } else {
            smux_rust::client(Box::new(stream), Some(smux_config))
                .await
                .map_err(Into::into)
        }
    }
}

fn create_kcptun_udp_socket(
    address: SocketAddr,
    config: &KcptunConfig,
) -> anyhow::Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    if config.sock_buf > 0 {
        let size = usize::try_from(config.sock_buf).unwrap_or(usize::MAX);
        socket.set_recv_buffer_size(size)?;
        socket.set_send_buffer_size(size)?;
    }
    if config.dscp > 0 && address.is_ipv4() {
        socket.set_tos_v4((config.dscp.min(63)) << 2)?;
    }
    if config.dscp > 0 && address.is_ipv6() {
        socket.set_tclass_v6((config.dscp.min(63)) << 2)?;
    }
    let bind_addr = if address.is_ipv4() {
        "0.0.0.0:0".parse::<SocketAddr>()?
    } else {
        "[::]:0".parse::<SocketAddr>()?
    };
    socket.bind(&bind_addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(Into::into)
}

struct RateLimitedStream<S> {
    inner: S,
    bytes_per_sec: f64,
    tokens: f64,
    last_refill: StdInstant,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S> RateLimitedStream<S> {
    fn new(inner: S, rate_limit: u32) -> Self {
        let bytes_per_sec = (rate_limit as f64) * 1024.0 * 1024.0;
        Self {
            inner,
            bytes_per_sec,
            tokens: bytes_per_sec,
            last_refill: StdInstant::now(),
            wait: None,
        }
    }

    fn refill(&mut self) {
        let now = StdInstant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.bytes_per_sec).min(self.bytes_per_sec);
    }
}

impl<S> Unpin for RateLimitedStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for RateLimitedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RateLimitedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.wait = None;
                break;
            }
            if self.wait.is_none() {
                let wait = Duration::from_secs_f64((1.0 - self.tokens) / self.bytes_per_sec);
                self.wait = Some(Box::pin(tokio::time::sleep(wait)));
            }
            if let Some(wait) = &mut self.wait {
                ready!(wait.as_mut().poll(cx));
            }
            self.wait = None;
        }
        let allowed = buf.len().min(self.tokens as usize).min(64 * 1024).max(1);
        let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]))?;
        self.tokens = (self.tokens - written as f64).max(0.0);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn connect_websocket_plugin(
    stream: ShadowTcpStream,
    host: &str,
    path: &str,
    tls: bool,
) -> anyhow::Result<ShadowsocksTransport> {
    let path = if path.is_empty() { "/" } else { path };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let scheme = if tls { "wss" } else { "ws" };
    let uri = format!("{scheme}://{host}{path}");
    let mut request = uri.into_client_request()?;
    request
        .headers_mut()
        .insert("Host", HeaderValue::from_str(host)?);
    if tls {
        let domain = host.split(':').next().unwrap_or(host);
        let connector = native_tls::TlsConnector::builder().build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let tls_stream = connector.connect(domain, stream).await?;
        let (ws, _) = client_async(request, tls_stream).await?;
        Ok(ShadowsocksTransport::WsTls(WebSocketTransport::new(ws)))
    } else {
        let (ws, _) = client_async(request, stream).await?;
        Ok(ShadowsocksTransport::WsPlain(WebSocketTransport::new(ws)))
    }
}

async fn connect_h2_plugin(
    stream: ShadowTcpStream,
    host: &str,
    path: &str,
    tls: bool,
) -> anyhow::Result<ShadowsocksTransport> {
    let path = if path.is_empty() { "/" } else { path };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if tls {
        let domain = host.split(':').next().unwrap_or(host);
        let mut builder = native_tls::TlsConnector::builder();
        builder.request_alpns(&["h2"]);
        let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
        let tls_stream = connector.connect(domain, stream).await?;
        let transport = h2_transport_from_stream(tls_stream, host, &path).await?;
        Ok(ShadowsocksTransport::H2(transport))
    } else {
        let transport = h2_transport_from_stream(stream, host, &path).await?;
        Ok(ShadowsocksTransport::H2(transport))
    }
}

async fn connect_xhttp_plugin(
    address: SocketAddr,
    stream: ShadowTcpStream,
    config: &ShadowsocksConfig,
    xhttp: &XHttpPluginConfig,
) -> anyhow::Result<ShadowsocksTransport> {
    if xhttp.version == XHttpVersion::H3 {
        return Ok(ShadowsocksTransport::XHttp(
            connect_h3_xhttp_plugin(address, config, xhttp).await?,
        ));
    }
    let version = resolve_xhttp_version(xhttp);
    let mode = resolve_xhttp_mode(xhttp);
    if version == XHttpVersion::H1 && mode == XHttpMode::PacketUp {
        return Ok(ShadowsocksTransport::XHttp(
            connect_http1_xhttp_packet_up_plugin(address, stream, config, xhttp).await?,
        ));
    }
    if version == XHttpVersion::H1 && mode == XHttpMode::StreamUp {
        return Ok(ShadowsocksTransport::XHttp(
            connect_http1_xhttp_stream_up_plugin(address, stream, config, xhttp).await?,
        ));
    }
    if version == XHttpVersion::H1 {
        let secured = xhttp_box_stream(
            stream,
            &xhttp.host,
            xhttp.tls,
            xhttp.skip_cert_verify,
            &["http/1.1"],
        )
        .await?;
        return Ok(ShadowsocksTransport::XHttp(
            connect_http1_xhttp_stream_plugin(secured, xhttp).await?,
        ));
    }
    let secured = xhttp_box_stream(
        stream,
        &xhttp.host,
        xhttp.tls,
        xhttp.skip_cert_verify,
        &["h2", "http/1.1"],
    )
    .await?;
    match (version, mode) {
        (XHttpVersion::H2, XHttpMode::PacketUp) => Ok(ShadowsocksTransport::XHttp(
            connect_h2_xhttp_packet_up_plugin(secured, xhttp).await?,
        )),
        (XHttpVersion::H2, XHttpMode::StreamUp) => Ok(ShadowsocksTransport::XHttp(
            connect_h2_xhttp_stream_up_plugin(secured, xhttp).await?,
        )),
        (XHttpVersion::H2, _) => Ok(ShadowsocksTransport::XHttp(
            connect_h2_xhttp_stream_plugin(secured, xhttp).await?,
        )),
        _ => Ok(ShadowsocksTransport::XHttp(
            connect_http1_xhttp_stream_plugin(secured, xhttp).await?,
        )),
    }
}

async fn xhttp_box_stream(
    stream: ShadowTcpStream,
    host: &str,
    tls: bool,
    skip_cert_verify: bool,
    alpns: &[&str],
) -> anyhow::Result<BoxedProxyStream> {
    if !tls {
        return Ok(boxed_stream(stream));
    }
    let domain = host.split(':').next().unwrap_or(host);
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(skip_cert_verify);
    if !alpns.is_empty() {
        builder.request_alpns(alpns);
    }
    let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
    Ok(boxed_stream(connector.connect(domain, stream).await?))
}

fn resolve_xhttp_mode(config: &XHttpPluginConfig) -> XHttpMode {
    match config.mode {
        XHttpMode::Auto if config.tls => XHttpMode::PacketUp,
        XHttpMode::Auto => XHttpMode::StreamUp,
        value => value,
    }
}

fn resolve_xhttp_version(config: &XHttpPluginConfig) -> XHttpVersion {
    match config.version {
        XHttpVersion::Auto if config.tls => XHttpVersion::H2,
        XHttpVersion::Auto => XHttpVersion::H1,
        value => value,
    }
}

async fn connect_http1_xhttp_stream_plugin(
    mut stream: BoxedProxyStream,
    config: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let path = xhttp_base_path(&config.path);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n",
        config.host
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    spawn_http1_xhttp_chunked_bridge(bridge, stream);
    Ok(local)
}

fn spawn_http1_xhttp_chunked_bridge(bridge: DuplexStream, stream: BoxedProxyStream) {
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let (mut upload, mut download) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; FLOW_COPY_BUFFER_SIZE];
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.write_all(b"0\r\n\r\n").await;
                    break;
                }
                Ok(n) => {
                    let header = format!("{n:x}\r\n");
                    if remote_write.write_all(header.as_bytes()).await.is_err()
                        || remote_write.write_all(&buf[..n]).await.is_err()
                        || remote_write.write_all(b"\r\n").await.is_err()
                        || remote_write.flush().await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = remote_write.shutdown().await;
    });
    tokio::spawn(async move {
        if read_http_response_headers_generic(&mut remote_read)
            .await
            .is_err()
        {
            let _ = download.shutdown().await;
            return;
        }
        let _ = tokio::io::copy(&mut remote_read, &mut download).await;
        let _ = download.shutdown().await;
    });
}

async fn connect_http1_xhttp_stream_up_plugin(
    address: SocketAddr,
    download_stream: ShadowTcpStream,
    config: &ShadowsocksConfig,
    xhttp: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let session = xhttp_session_id();
    let download_stream = xhttp_box_stream(
        download_stream,
        &xhttp.host,
        xhttp.tls,
        xhttp.skip_cert_verify,
        &["http/1.1"],
    )
    .await?;
    let upload_stream = ShadowTcpStream::connect_with_opts(&address, &config.connect_opts()).await?;
    let upload_stream = xhttp_box_stream(
        upload_stream,
        &xhttp.host,
        xhttp.tls,
        xhttp.skip_cert_verify,
        &["http/1.1"],
    )
    .await?;
    spawn_http1_xhttp_split_stream_bridge(
        bridge,
        download_stream,
        upload_stream,
        xhttp.host.clone(),
        xhttp_base_path(&xhttp.path),
        session,
    );
    Ok(local)
}

async fn connect_http1_xhttp_packet_up_plugin(
    address: SocketAddr,
    download_stream: ShadowTcpStream,
    config: &ShadowsocksConfig,
    xhttp: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let session = xhttp_session_id();
    let download_stream = xhttp_box_stream(
        download_stream,
        &xhttp.host,
        xhttp.tls,
        xhttp.skip_cert_verify,
        &["http/1.1"],
    )
    .await?;
    spawn_http1_xhttp_packet_bridge(
        bridge,
        download_stream,
        address,
        config.connect_opts(),
        xhttp.clone(),
        session,
    );
    Ok(local)
}

fn spawn_http1_xhttp_split_stream_bridge(
    bridge: DuplexStream,
    mut download_stream: BoxedProxyStream,
    mut upload_stream: BoxedProxyStream,
    host: String,
    base_path: String,
    session: String,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let download_path = xhttp_path_with_query(&base_path, &session, None);
    let upload_path = xhttp_path_with_query(&base_path, &session, Some(0));
    let download_host = host.clone();
    tokio::spawn(async move {
        let request = format!(
            "GET {download_path} HTTP/1.1\r\nHost: {download_host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
        );
        if download_stream.write_all(request.as_bytes()).await.is_ok()
            && download_stream.flush().await.is_ok()
            && read_http_response_headers_generic(&mut download_stream)
                .await
                .is_ok()
        {
            let _ = tokio::io::copy(&mut download_stream, &mut download).await;
        }
        let _ = download.shutdown().await;
    });
    tokio::spawn(async move {
        let request = format!(
            "POST {upload_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
        );
        if upload_stream.write_all(request.as_bytes()).await.is_err()
            || upload_stream.flush().await.is_err()
        {
            return;
        }
        let mut buf = vec![0_u8; FLOW_COPY_BUFFER_SIZE];
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => {
                    let _ = upload_stream.write_all(b"0\r\n\r\n").await;
                    break;
                }
                Ok(n) => {
                    let header = format!("{n:x}\r\n");
                    if upload_stream.write_all(header.as_bytes()).await.is_err()
                        || upload_stream.write_all(&buf[..n]).await.is_err()
                        || upload_stream.write_all(b"\r\n").await.is_err()
                        || upload_stream.flush().await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = upload_stream.shutdown().await;
    });
}

fn spawn_http1_xhttp_packet_bridge(
    bridge: DuplexStream,
    mut download_stream: BoxedProxyStream,
    address: SocketAddr,
    connect_opts: ConnectOpts,
    config: XHttpPluginConfig,
    session: String,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let download_path = xhttp_path_with_query(&config.path, &session, None);
    let host = config.host.clone();
    tokio::spawn(async move {
        let request = format!(
            "GET {download_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
        );
        if download_stream.write_all(request.as_bytes()).await.is_ok()
            && download_stream.flush().await.is_ok()
            && read_http_response_headers_generic(&mut download_stream)
                .await
                .is_ok()
        {
            let _ = tokio::io::copy(&mut download_stream, &mut download).await;
        }
        let _ = download.shutdown().await;
    });
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let failed = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(XHTTP_PACKET_POST_WORKERS);
        for _ in 0..XHTTP_PACKET_POST_WORKERS {
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<(u64, Bytes)>(XHTTP_PACKET_POST_QUEUE);
            let worker_address = address;
            let worker_connect_opts = connect_opts.clone();
            let worker_config = config.clone();
            let worker_session = session.clone();
            let worker_failed = failed.clone();
            tokio::spawn(async move {
                let mut worker = Http1XHttpPostWorker::new(
                    worker_address,
                    worker_connect_opts,
                    worker_config,
                    worker_session,
                );
                while let Some((seq, payload)) = rx.recv().await {
                    if let Err(err) = worker.send(seq, payload).await {
                        worker_failed.store(true, Ordering::Relaxed);
                        tracing::warn!(
                            error = %err,
                            seq,
                            "Shadowsocks XHTTP H1 packet upload failed"
                        );
                        break;
                    }
                }
            });
            workers.push(tx);
        }
        loop {
            if failed.load(Ordering::Relaxed) {
                break;
            }
            let payload = match read_xhttp_post_batch(
                &mut upload,
                config.max_each_post_bytes,
                config.min_posts_interval_ms,
            )
            .await
            {
                Ok(Some(payload)) => payload,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(error = %err, "Shadowsocks XHTTP H1 upload read failed");
                    break;
                }
            };
            let post_seq = seq;
            seq = seq.saturating_add(1);
            let lane = (post_seq as usize) % workers.len();
            if workers[lane].send((post_seq, payload)).await.is_err() {
                failed.store(true, Ordering::Relaxed);
                break;
            }
            pace_xhttp_posts(config.min_posts_interval_ms).await;
        }
    });
}

struct Http1XHttpPostWorker {
    address: SocketAddr,
    config: XHttpPluginConfig,
    session: String,
    connect_opts: ConnectOpts,
    stream: Option<BoxedProxyStream>,
}

impl Http1XHttpPostWorker {
    fn new(
        address: SocketAddr,
        connect_opts: ConnectOpts,
        config: XHttpPluginConfig,
        session: String,
    ) -> Self {
        Self {
            address,
            config,
            session,
            connect_opts,
            stream: None,
        }
    }

    async fn send(&mut self, seq: u64, payload: Bytes) -> anyhow::Result<()> {
        if self.stream.is_none() {
            self.stream = Some(
                open_http1_xhttp_post_stream(
                    self.address,
                    self.connect_opts.clone(),
                    self.config.clone(),
                )
                .await?,
            );
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("XHTTP H1 POST worker stream is not open"))?;
        match send_http1_xhttp_post_on_stream(stream, &self.config, &self.session, seq, &payload)
            .await
        {
            Ok(reusable) => {
                if !reusable {
                    self.stream = None;
                }
                Ok(())
            }
            Err(err) => {
                self.stream = None;
                Err(err)
            }
        }
    }
}

async fn open_http1_xhttp_post_stream(
    address: SocketAddr,
    connect_opts: ConnectOpts,
    config: XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let stream = ShadowTcpStream::connect_with_opts(&address, &connect_opts).await?;
    xhttp_box_stream(
        stream,
        &config.host,
        config.tls,
        config.skip_cert_verify,
        &["http/1.1"],
    )
    .await
}

async fn send_http1_xhttp_post_on_stream(
    stream: &mut BoxedProxyStream,
    config: &XHttpPluginConfig,
    session: &str,
    seq: u64,
    payload: &Bytes,
) -> anyhow::Result<bool> {
    let path = xhttp_path_with_query(&config.path, session, Some(seq));
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
        config.host,
        payload.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    let headers = read_http_response_headers_generic(stream).await?;
    drain_http1_response_body(stream, &headers).await
}

async fn connect_h2_xhttp_stream_plugin(
    stream: BoxedProxyStream,
    config: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let (mut client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method("POST")
        .uri(xhttp_base_path(&config.path))
        .header("authority", config.host.clone())
        .header("content-type", "application/octet-stream")
        .body(())?;
    let (response, send) = client.send_request(request, false)?;
    spawn_h2_xhttp_stream_bridge(bridge, response, send);
    Ok(local)
}

fn spawn_h2_xhttp_stream_bridge(
    bridge: DuplexStream,
    response: h2::client::ResponseFuture,
    mut send: h2::SendStream<Bytes>,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let (upload_failure_tx, mut upload_failure_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let mut payload = BytesMut::with_capacity(FLOW_COPY_BUFFER_SIZE);
            match upload.read_buf(&mut payload).await {
                Ok(0) => {
                    let _ = send.send_data(Bytes::new(), true);
                    break;
                }
                Ok(_) => {
                    if send_h2_data_frames(&mut send, payload.freeze(), false)
                        .await
                        .is_err()
                    {
                        let _ = upload_failure_tx.send(true);
                        break;
                    }
                }
                Err(_) => {
                    let _ = upload_failure_tx.send(true);
                    break;
                }
            }
        }
    });
    tokio::spawn(async move {
        let response = tokio::select! {
            changed = upload_failure_rx.changed() => {
                if changed.is_ok() && *upload_failure_rx.borrow() {
                    let _ = download.shutdown().await;
                    return;
                }
                let _ = download.shutdown().await;
                return;
            }
            response = response => response
        };
        let Ok(response) = response else {
            let _ = download.shutdown().await;
            return;
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "Shadowsocks XHTTP H2 stream response rejected"
            );
            let _ = download.shutdown().await;
            return;
        }
        let mut body = response.into_body();
        loop {
            tokio::select! {
                changed = upload_failure_rx.changed() => {
                    if changed.is_ok() && *upload_failure_rx.borrow() {
                        break;
                    }
                }
                chunk = body.data() => {
                    match chunk {
                        Some(Ok(data)) => {
                            if download.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }
        let _ = download.shutdown().await;
    });
}

async fn connect_h2_xhttp_stream_up_plugin(
    stream: BoxedProxyStream,
    config: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let (mut client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let session = xhttp_session_id();
    let download_request = http::Request::builder()
        .method("GET")
        .uri(xhttp_path_with_query(&config.path, &session, None))
        .header("authority", config.host.clone())
        .body(())?;
    let download_response = client.send_request(download_request, true)?.0;
    let upload_request = http::Request::builder()
        .method("POST")
        .uri(xhttp_path_with_query(&config.path, &session, Some(0)))
        .header("authority", config.host.clone())
        .header("content-type", "application/octet-stream")
        .body(())?;
    let (upload_response, upload_send) = client.send_request(upload_request, false)?;
    spawn_h2_xhttp_stream_up_bridge(bridge, download_response, upload_response, upload_send);
    Ok(local)
}

fn spawn_h2_xhttp_stream_up_bridge(
    bridge: DuplexStream,
    download_response: h2::client::ResponseFuture,
    upload_response: h2::client::ResponseFuture,
    mut upload_send: h2::SendStream<Bytes>,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let (upload_failure_tx, mut upload_failure_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let mut payload = BytesMut::with_capacity(FLOW_COPY_BUFFER_SIZE);
            match upload.read_buf(&mut payload).await {
                Ok(0) => {
                    let _ = upload_send.send_data(Bytes::new(), true);
                    break;
                }
                Ok(_) => {
                    if send_h2_data_frames(&mut upload_send, payload.freeze(), false)
                        .await
                        .is_err()
                    {
                        let _ = upload_failure_tx.send(true);
                        break;
                    }
                }
                Err(_) => {
                    let _ = upload_failure_tx.send(true);
                    break;
                }
            }
        }
        match upload_response.await {
            Ok(response) => {
                if !response.status().is_success() {
                    tracing::warn!(
                        status = %response.status(),
                        "Shadowsocks XHTTP H2 upload response rejected"
                    );
                    let _ = upload_failure_tx.send(true);
                    return;
                }
                let mut body = response.into_body();
                while let Some(chunk) = body.data().await {
                    if let Err(err) = chunk {
                        tracing::warn!(error = %err, "Shadowsocks XHTTP H2 upload response failed");
                        let _ = upload_failure_tx.send(true);
                        break;
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "Shadowsocks XHTTP H2 upload response failed");
                let _ = upload_failure_tx.send(true);
            }
        }
    });
    tokio::spawn(async move {
        let response = tokio::select! {
            changed = upload_failure_rx.changed() => {
                if changed.is_ok() && *upload_failure_rx.borrow() {
                    let _ = download.shutdown().await;
                    return;
                }
                let _ = download.shutdown().await;
                return;
            }
            response = download_response => response
        };
        let Ok(response) = response else {
            let _ = download.shutdown().await;
            return;
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "Shadowsocks XHTTP H2 download response rejected"
            );
            let _ = download.shutdown().await;
            return;
        }
        let mut body = response.into_body();
        loop {
            tokio::select! {
                changed = upload_failure_rx.changed() => {
                    if changed.is_ok() && *upload_failure_rx.borrow() {
                        break;
                    }
                }
                chunk = body.data() => {
                    match chunk {
                        Some(Ok(data)) => {
                            if download.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }
        let _ = download.shutdown().await;
    });
}

async fn h2_reserved_capacity(
    send: &mut h2::SendStream<Bytes>,
    requested: usize,
) -> io::Result<usize> {
    send.reserve_capacity(requested);
    loop {
        match futures_util::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(0)) => continue,
            Some(Ok(capacity)) => return Ok(capacity.min(requested)),
            Some(Err(err)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, err)),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 send stream is closed",
                ))
            }
        }
    }
}

async fn send_h2_data_frames(
    send: &mut h2::SendStream<Bytes>,
    mut payload: Bytes,
    end_of_stream: bool,
) -> io::Result<()> {
    if payload.is_empty() {
        send.send_data(Bytes::new(), end_of_stream)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        return Ok(());
    }
    while !payload.is_empty() {
        let requested = payload.len().min(H2_MAX_DATA_FRAME);
        let capacity = h2_reserved_capacity(send, requested).await?;
        let frame = payload.split_to(capacity.min(payload.len()));
        let end = end_of_stream && payload.is_empty();
        send.send_data(frame, end)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
    }
    Ok(())
}

async fn connect_h2_xhttp_packet_up_plugin(
    stream: BoxedProxyStream,
    config: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let (mut client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let session = xhttp_session_id();
    let download_request = http::Request::builder()
        .method("GET")
        .uri(xhttp_path_with_query(&config.path, &session, None))
        .header("authority", config.host.clone())
        .body(())?;
    let response = client.send_request(download_request, true)?;
    spawn_h2_xhttp_packet_bridge(
        bridge,
        response.0,
        client,
        config.host.clone(),
        xhttp_base_path(&config.path),
        session,
        config.max_each_post_bytes,
        config.min_posts_interval_ms,
    );
    Ok(local)
}

fn spawn_h2_xhttp_packet_bridge(
    bridge: DuplexStream,
    response: h2::client::ResponseFuture,
    client: h2::client::SendRequest<Bytes>,
    authority: String,
    base_path: String,
    session: String,
    max_post_bytes: usize,
    min_posts_interval_ms: u64,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let (upload_failure_tx, mut upload_failure_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let post_slots = Arc::new(tokio::sync::Semaphore::new(XHTTP_PACKET_POST_WORKERS));
        let failed = Arc::new(AtomicBool::new(false));
        loop {
            if failed.load(Ordering::Relaxed) {
                break;
            }
            let payload =
                match read_xhttp_post_batch(&mut upload, max_post_bytes, min_posts_interval_ms)
                    .await
                {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!(error = %err, "Shadowsocks XHTTP H2 upload read failed");
                        break;
                    }
                };
            let Ok(permit) = post_slots.clone().acquire_owned().await else {
                break;
            };
            let mut client = client.clone();
            let path = xhttp_path_with_query(&base_path, &session, Some(seq));
            seq = seq.saturating_add(1);
            let authority = authority.clone();
            let failed = failed.clone();
            let upload_failure_tx = upload_failure_tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = async move {
                    let request = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authority", authority)
                    .header("content-type", "application/octet-stream")
                    .body(())?;
                    let (response, mut send) = client.send_request(request, false)?;
                    send_h2_data_frames(&mut send, payload, true).await?;
                    let response = response.await?;
                    if !response.status().is_success() {
                        anyhow::bail!("Shadowsocks XHTTP H2 POST returned {}", response.status());
                    }
                    let mut body = response.into_body();
                    while let Some(chunk) = body.data().await {
                        let _ = chunk?;
                    }
                    anyhow::Ok(())
                }
                .await;
                if let Err(err) = result {
                    failed.store(true, Ordering::Relaxed);
                    let _ = upload_failure_tx.send(true);
                    tracing::warn!(error = %err, "Shadowsocks XHTTP H2 packet upload failed");
                }
            });
            pace_xhttp_posts(min_posts_interval_ms).await;
        }
    });
    tokio::spawn(async move {
        let response = tokio::select! {
            changed = upload_failure_rx.changed() => {
                if changed.is_ok() && *upload_failure_rx.borrow() {
                    let _ = download.shutdown().await;
                    return;
                }
                let _ = download.shutdown().await;
                return;
            }
            response = response => response
        };
        let Ok(response) = response else {
            let _ = download.shutdown().await;
            return;
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "Shadowsocks XHTTP H2 packet download response rejected"
            );
            let _ = download.shutdown().await;
            return;
        }
        let mut body = response.into_body();
        loop {
            tokio::select! {
                changed = upload_failure_rx.changed() => {
                    if changed.is_ok() && *upload_failure_rx.borrow() {
                        break;
                    }
                }
                chunk = body.data() => {
                    match chunk {
                        Some(Ok(data)) => {
                            if download.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }
        let _ = download.shutdown().await;
    });
}

async fn read_xhttp_post_batch<R>(
    upload: &mut R,
    max_post_bytes: usize,
    _min_posts_interval_ms: u64,
) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let post_limit = max_post_bytes.clamp(1, XHTTP_MAX_POST_BYTES);
    let mut payload = BytesMut::with_capacity(post_limit);
    let first = upload.read_buf(&mut payload).await?;
    if first == 0 {
        return Ok(None);
    }
    let timer = sleep(XHTTP_BATCH_WINDOW);
    tokio::pin!(timer);
    while payload.len() < post_limit {
        tokio::select! {
            read = upload.read_buf(&mut payload) => {
                let n = read?;
                if n == 0 {
                    break;
                }
            }
            _ = &mut timer => break,
        }
    }
    Ok(Some(payload.freeze()))
}

async fn pace_xhttp_posts(min_posts_interval_ms: u64) {
    if min_posts_interval_ms > 0 {
        sleep(Duration::from_millis(min_posts_interval_ms.min(1000))).await;
    }
}

async fn connect_h3_xhttp_plugin(
    address: SocketAddr,
    _config: &ShadowsocksConfig,
    xhttp: &XHttpPluginConfig,
) -> anyhow::Result<BoxedProxyStream> {
    if !xhttp.tls {
        anyhow::bail!("Shadowsocks XHTTP H3 requires TLS");
    }
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let server_name = xhttp
        .host
        .split(':')
        .next()
        .unwrap_or(&xhttp.host)
        .to_string();
    let bind = match address.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(h3_xhttp_quinn_config(xhttp.skip_cert_verify)?);
    let connection = endpoint.connect(address, &server_name)?.await?;
    let (mut driver, client) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    spawn_h3_xhttp_packet_bridge(bridge, client, xhttp.clone());
    Ok(local)
}

fn h3_xhttp_quinn_config(skip_cert_verify: bool) -> anyhow::Result<quinn::ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut tls = if skip_cert_verify {
        rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ShadowTlsInsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )))
}

fn spawn_h3_xhttp_packet_bridge(
    bridge: DuplexStream,
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    config: XHttpPluginConfig,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let (upload_failure_tx, mut upload_failure_rx) = tokio::sync::watch::channel(false);
    let session = xhttp_session_id();
    let download_uri = format!(
        "https://{}{}",
        config.host,
        xhttp_path_with_query(&config.path, &session, None)
    );
    let mut download_client = client.clone();
    tokio::spawn(async move {
        let request = match http::Request::builder()
            .method("GET")
            .uri(download_uri)
            .body(())
        {
            Ok(value) => value,
            Err(_) => {
                let _ = download.shutdown().await;
                return;
            }
        };
        let Ok(mut stream) = download_client.send_request(request).await else {
            let _ = download.shutdown().await;
            return;
        };
        let response = match stream.recv_response().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                tracing::warn!(
                    status = %response.status(),
                    "Shadowsocks XHTTP H3 download rejected"
                );
                let _ = download.shutdown().await;
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "Shadowsocks XHTTP H3 download failed");
                let _ = download.shutdown().await;
                return;
            }
        };
        drop(response);
        loop {
            tokio::select! {
                changed = upload_failure_rx.changed() => {
                    if changed.is_ok() && *upload_failure_rx.borrow() {
                        break;
                    }
                }
                data = stream.recv_data() => {
                    match data {
                        Ok(Some(mut data)) => {
                            let bytes = data.copy_to_bytes(data.remaining());
                            if download.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
        let _ = download.shutdown().await;
    });
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let post_slots = Arc::new(tokio::sync::Semaphore::new(XHTTP_PACKET_POST_WORKERS));
        let failed = Arc::new(AtomicBool::new(false));
        loop {
            if failed.load(Ordering::Relaxed) {
                break;
            }
            let payload = match read_xhttp_post_batch(
                &mut upload,
                config.max_each_post_bytes,
                config.min_posts_interval_ms,
            )
            .await
            {
                Ok(Some(payload)) => payload,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(error = %err, "Shadowsocks XHTTP H3 upload read failed");
                    break;
                }
            };
            let Ok(permit) = post_slots.clone().acquire_owned().await else {
                break;
            };
            let mut upload_client = client.clone();
            let uri = format!(
                "https://{}{}",
                config.host,
                xhttp_path_with_query(&config.path, &session, Some(seq))
            );
            seq = seq.saturating_add(1);
            let failed = failed.clone();
            let upload_failure_tx = upload_failure_tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = async move {
                    let request = http::Request::builder().method("POST").uri(uri).body(())?;
                    let mut stream = upload_client.send_request(request).await?;
                    stream.send_data(payload).await?;
                    stream.finish().await?;
                    let response = stream.recv_response().await?;
                    if !response.status().is_success() {
                        anyhow::bail!("Shadowsocks XHTTP H3 POST returned {}", response.status());
                    }
                    while let Some(mut data) = stream.recv_data().await? {
                        let _ = data.copy_to_bytes(data.remaining());
                    }
                    anyhow::Ok(())
                }
                .await;
                if let Err(err) = result {
                    failed.store(true, Ordering::Relaxed);
                    let _ = upload_failure_tx.send(true);
                    tracing::warn!(error = %err, "Shadowsocks XHTTP H3 packet upload failed");
                }
            });
            pace_xhttp_posts(config.min_posts_interval_ms).await;
        }
    });
}

fn xhttp_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn xhttp_base_path(path: &str) -> String {
    let mut path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn xhttp_path_with_query(base_path: &str, session: &str, seq: Option<u64>) -> String {
    let base_path = xhttp_base_path(base_path);
    let join = if base_path.contains('?') { '&' } else { '?' };
    match seq {
        Some(seq) => format!("{base_path}{join}session={session}&seq={seq}"),
        None => format!("{base_path}{join}session={session}"),
    }
}

async fn read_http_response_headers_generic<R>(stream: &mut R) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while response.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&response);
            if !text.starts_with("HTTP/1.1 2") && !text.starts_with("HTTP/1.0 2") {
                anyhow::bail!(
                    "Shadowsocks XHTTP rejected: {}",
                    text.lines().next().unwrap_or("")
                );
            }
            return Ok(text.into_owned());
        }
    }
    anyhow::bail!("Shadowsocks XHTTP response is too large")
}

async fn drain_http1_response_body<R>(stream: &mut R, headers: &str) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
{
    if http_response_has_no_body(headers) {
        return Ok(!http_header_contains(headers, "connection", "close"));
    }
    if http_header_contains(headers, "transfer-encoding", "chunked") {
        drain_http1_chunked_body(stream).await?;
        return Ok(!http_header_contains(headers, "connection", "close"));
    }
    if let Some(length) = http_content_length(headers)? {
        drain_exact_http_body(stream, length).await?;
        return Ok(!http_header_contains(headers, "connection", "close"));
    }
    if http_header_contains(headers, "connection", "close") {
        drain_http_body_until_eof(stream).await?;
        return Ok(false);
    }
    Ok(true)
}

fn http_response_has_no_body(headers: &str) -> bool {
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_default();
    matches!(status, 100..=199 | 204 | 304)
}

fn http_content_length(headers: &str) -> anyhow::Result<Option<usize>> {
    let mut length = None;
    for value in http_header_values(headers, "content-length") {
        length = Some(value.trim().parse::<usize>().map_err(|err| {
            anyhow::anyhow!("invalid Shadowsocks XHTTP content-length value {value:?}: {err}")
        })?);
    }
    Ok(length)
}

fn http_header_contains(headers: &str, name: &str, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    http_header_values(headers, name).into_iter().any(|value| {
        value
            .split(',')
            .map(|part| part.trim().to_ascii_lowercase())
            .any(|part| part == needle)
    })
}

fn http_header_values<'a>(headers: &'a str, name: &str) -> Vec<&'a str> {
    headers
        .lines()
        .skip(1)
        .filter_map(|line| line.trim_end_matches('\r').split_once(':'))
        .filter_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.trim()))
        .collect()
}

async fn drain_exact_http_body<R>(stream: &mut R, mut remaining: usize) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    if remaining > XHTTP_H1_MAX_RESPONSE_DRAIN_BYTES {
        anyhow::bail!("Shadowsocks XHTTP response body is too large to drain");
    }
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..take]).await?;
        remaining -= take;
    }
    Ok(())
}

async fn drain_http1_chunked_body<R>(stream: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut drained = 0_usize;
    loop {
        let line = read_http1_line(stream, 4096).await?;
        let size_text = line
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches('\r');
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            anyhow::anyhow!("invalid Shadowsocks XHTTP chunk size {size_text:?}: {err}")
        })?;
        if size == 0 {
            loop {
                let trailer = read_http1_line(stream, 8192).await?;
                if trailer == "\r\n" || trailer == "\n" {
                    return Ok(());
                }
            }
        }
        drained = drained.saturating_add(size);
        if drained > XHTTP_H1_MAX_RESPONSE_DRAIN_BYTES {
            anyhow::bail!("Shadowsocks XHTTP chunked response body is too large to drain");
        }
        drain_exact_http_body(stream, size).await?;
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            anyhow::bail!("invalid Shadowsocks XHTTP chunk delimiter");
        }
    }
}

async fn drain_http_body_until_eof<R>(stream: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut drained = 0_usize;
    let mut buffer = [0_u8; 8192];
    loop {
        let n = timeout(Duration::from_secs(5), stream.read(&mut buffer)).await??;
        if n == 0 {
            return Ok(());
        }
        drained = drained.saturating_add(n);
        if drained > XHTTP_H1_MAX_RESPONSE_DRAIN_BYTES {
            anyhow::bail!("Shadowsocks XHTTP close-delimited response body is too large to drain");
        }
    }
}

async fn read_http1_line<R>(stream: &mut R, max_len: usize) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(64);
    let mut byte = [0_u8; 1];
    while line.len() < max_len {
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
    }
    anyhow::bail!("Shadowsocks XHTTP line is too large")
}

struct ExternalSip003Stream {
    inner: TokioTcpStream,
    _process: Arc<ExternalSip003Process>,
}

impl Unpin for ExternalSip003Stream {}

impl AsyncRead for ExternalSip003Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ExternalSip003Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ExternalSip003Process {
    local_addr: SocketAddr,
    child: StdMutex<Child>,
    last_used: StdMutex<StdInstant>,
    diagnostics: Arc<Sip003Diagnostics>,
}

impl ExternalSip003Process {
    fn is_running(&self) -> bool {
        self.child
            .lock()
            .map(|mut child| {
                child
                    .try_wait()
                    .map(|status| status.is_none())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = StdInstant::now();
        }
    }

    fn idle_expired(&self, now: StdInstant) -> bool {
        self.last_used
            .lock()
            .map(|last_used| now.duration_since(*last_used) >= SIP003_IDLE_TIMEOUT)
            .unwrap_or(true)
    }
}

struct Sip003Diagnostics {
    lines: StdMutex<VecDeque<String>>,
}

impl Sip003Diagnostics {
    fn new() -> Self {
        Self {
            lines: StdMutex::new(VecDeque::with_capacity(32)),
        }
    }

    fn push(&self, source: &str, message: impl Into<String>) {
        let mut message = message.into();
        while message.ends_with('\n') || message.ends_with('\r') {
            message.pop();
        }
        if message.is_empty() {
            return;
        }
        if let Ok(mut lines) = self.lines.lock() {
            if lines.len() >= 32 {
                lines.pop_front();
            }
            lines.push_back(format!("{source}: {message}"));
        }
    }

    fn snapshot(&self) -> String {
        self.lines
            .lock()
            .map(|lines| lines.iter().cloned().collect::<Vec<_>>().join(" | "))
            .unwrap_or_default()
    }
}

impl Drop for ExternalSip003Process {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.start_kill();
        }
    }
}

async fn open_sip003_plugin_stream(
    config: &ShadowsocksConfig,
    program: &str,
    options: &str,
) -> anyhow::Result<ExternalSip003Stream> {
    let key = sip003_pool_key(config, program, options);
    let pool = SIP003_PLUGIN_PROCESSES.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let mut last_error = None;
    for _ in 0..2 {
        let mut process = {
            let mut pool = pool.lock().await;
            let now = StdInstant::now();
            pool.retain(|_, process| {
                process.is_running()
                    && !(Arc::strong_count(process) == 1 && process.idle_expired(now))
            });
            pool.get(&key).cloned()
        };
        if process.is_none() {
            let create_lock = sip003_create_lock(&key).await;
            let _guard = create_lock.lock().await;
            process = {
                let pool = pool.lock().await;
                pool.get(&key).cloned()
            };
            if process.is_none() {
                let created = Arc::new(start_sip003_process(config, program, options).await?);
                let mut pool = pool.lock().await;
                process = Some(
                    pool.entry(key.clone())
                        .or_insert_with(|| created.clone())
                        .clone(),
                );
            }
        }
        let process = process.expect("SIP003 process exists after creation");
        match TokioTcpStream::connect(process.local_addr).await {
            Ok(inner) => {
                process.touch();
                return Ok(ExternalSip003Stream {
                    inner,
                    _process: process,
                });
            }
            Err(err) => {
                let details = process.diagnostics.snapshot();
                last_error = Some(if details.is_empty() {
                    err
                } else {
                    io::Error::new(err.kind(), format!("{err}; plugin output: {details}"))
                });
                pool.lock().await.remove(&key);
            }
        }
    }
    Err(anyhow::anyhow!(
        "Shadowsocks SIP003 plugin {program} did not accept a local connection: {}",
        last_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn start_sip003_process(
    config: &ShadowsocksConfig,
    program: &str,
    options: &str,
) -> anyhow::Result<ExternalSip003Process> {
    let mut last_error = None;
    for _ in 0..16 {
        let local_addr = reserve_sip003_local_addr().await?;

        let mut command = Command::new(program);
        command
            .env("SS_REMOTE_HOST", &config.server)
            .env("SS_REMOTE_PORT", config.server_port.to_string())
            .env("SS_LOCAL_HOST", "127.0.0.1")
            .env("SS_LOCAL_PORT", local_addr.port().to_string())
            .env("SS_PLUGIN_OPTIONS", options)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|err| {
            release_sip003_port(local_addr.port());
            anyhow::anyhow!("failed to start Shadowsocks SIP003 plugin {program}: {err}")
        })?;
        let diagnostics = Arc::new(Sip003Diagnostics::new());
        if let Some(stdout) = child.stdout.take() {
            spawn_sip003_output_capture("stdout", stdout, diagnostics.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_sip003_output_capture("stderr", stderr, diagnostics.clone());
        }
        let process = ExternalSip003Process {
            local_addr,
            child: StdMutex::new(child),
            last_used: StdMutex::new(StdInstant::now()),
            diagnostics,
        };
        for _ in 0..50 {
            if !process.is_running() {
                let details = process.diagnostics.snapshot();
                last_error = Some(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    if details.is_empty() {
                        "plugin process exited before opening its listener".to_string()
                    } else {
                        format!(
                            "plugin process exited before opening its listener; plugin output: {details}"
                        )
                    },
                ));
                break;
            }
            match TokioTcpStream::connect(local_addr).await {
                Ok(stream) => {
                    drop(stream);
                    release_sip003_port(local_addr.port());
                    return Ok(process);
                }
                Err(err) => {
                    last_error = Some(err);
                    sleep(Duration::from_millis(20)).await;
                }
            }
        }
        release_sip003_port(local_addr.port());
    }
    Err(anyhow::anyhow!(
        "Shadowsocks SIP003 plugin {program} did not open its local listener: {}",
        last_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn reserve_sip003_local_addr() -> anyhow::Result<SocketAddr> {
    for _ in 0..32 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        drop(listener);
        let ports = SIP003_RESERVED_PORTS.get_or_init(|| StdMutex::new(HashSet::new()));
        let mut ports = ports
            .lock()
            .map_err(|_| anyhow::anyhow!("SIP003 port reservation lock poisoned"))?;
        if ports.insert(local_addr.port()) {
            return Ok(local_addr);
        }
    }
    anyhow::bail!("could not reserve a local port for a Shadowsocks SIP003 plugin")
}

fn release_sip003_port(port: u16) {
    if let Some(ports) = SIP003_RESERVED_PORTS.get() {
        if let Ok(mut ports) = ports.lock() {
            ports.remove(&port);
        }
    }
}

fn spawn_sip003_output_capture<R>(source: &'static str, reader: R, diagnostics: Arc<Sip003Diagnostics>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::with_capacity(256);
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let message = String::from_utf8_lossy(&line).into_owned();
                    diagnostics.push(source, message);
                }
                Err(err) => {
                    diagnostics.push(source, format!("output capture failed: {err}"));
                    break;
                }
            }
        }
    });
}

async fn sip003_create_lock(key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = SIP003_PLUGIN_CREATES.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let mut locks = locks.lock().await;
    locks.retain(|_, lock| Arc::strong_count(lock) > 1);
    locks
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn sip003_pool_key(config: &ShadowsocksConfig, program: &str, options: &str) -> String {
    let material = format!(
        "{}\0{}\0{}\0{}",
        config.server, config.server_port, program, options
    );
    let digest = Sha256::digest(material.as_bytes());
    format!("{digest:x}")
}

async fn h2_transport_from_stream<S>(
    stream: S,
    host: &str,
    path: &str,
) -> anyhow::Result<H2Transport>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method("PUT")
        .uri(path)
        .header("host", host)
        .header("accept-encoding", "identity")
        .body(())?;
    let (response, send_stream) = sender.send_request(request, false)?;
    let response = response.await?;
    if !response.status().is_success() {
        anyhow::bail!("Shadowsocks h2 transport returned {}", response.status());
    }
    Ok(H2Transport::new(response.into_body(), send_stream))
}

struct H2Transport {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    read_buffer: BytesMut,
    requested_write_capacity: usize,
    closed: bool,
}

impl H2Transport {
    fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            read_buffer: BytesMut::new(),
            requested_write_capacity: 0,
            closed: false,
        }
    }
}

impl Unpin for H2Transport {}

impl AsyncRead for H2Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_bytes_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, err)));
                }
                Poll::Ready(Some(Ok(data))) => {
                    if buf.remaining() >= data.len() {
                        buf.put_slice(&data);
                    } else {
                        let take = buf.remaining();
                        buf.put_slice(&data[..take]);
                        self.read_buffer.extend_from_slice(&data[take..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2 transport is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let requested = buf.len().min(H2_MAX_DATA_FRAME);
        if self.requested_write_capacity == 0 {
            self.send.reserve_capacity(requested);
            self.requested_write_capacity = requested;
        }
        let capacity = match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(capacity)) => capacity,
            Some(Err(err)) => {
                self.requested_write_capacity = 0;
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)));
            }
            None => {
                self.requested_write_capacity = 0;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 transport send stream is closed",
                )));
            }
        };
        self.requested_write_capacity = 0;
        if capacity == 0 {
            self.send.reserve_capacity(requested);
            self.requested_write_capacity = requested;
            return Poll::Pending;
        }
        let n = requested.min(capacity);
        self.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            self.send
                .send_data(Bytes::new(), true)
                .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        }
        Poll::Ready(Ok(()))
    }
}

struct WebSocketTransport<S> {
    inner: WebSocketStream<S>,
    read_buffer: BytesMut,
    pending_flush: bool,
}

impl<S> WebSocketTransport<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buffer: BytesMut::new(),
            pending_flush: false,
        }
    }
}

impl<S> Unpin for WebSocketTransport<S> {}

impl<S> AsyncRead for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_bytes_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, err)));
                }
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    if buf.remaining() >= data.len() {
                        buf.put_slice(&data);
                    } else {
                        let take = buf.remaining();
                        buf.put_slice(&data[..take]);
                        self.read_buffer.extend_from_slice(&data[take..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(_))) => continue,
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_flush {
            ready!(Pin::new(&mut *self).poll_flush(cx))?;
        }
        ready!(Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err)))?;
        let bytes = Bytes::copy_from_slice(buf);
        Pin::new(&mut self.inner)
            .start_send(Message::Binary(bytes))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        self.pending_flush = true;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err)))?;
        self.pending_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err)))?;
        self.pending_flush = false;
        Poll::Ready(Ok(()))
    }
}

struct ShadowTlsStream<S> {
    inner: S,
    mode: ShadowTlsMode,
    read_raw: BytesMut,
    read_buffer: BytesMut,
    pending_write: Option<PendingShadowTlsWrite>,
}

enum ShadowTlsMode {
    Plain,
    V2 {
        auth_tag: Option<[u8; 8]>,
    },
    V3 {
        hmac_add: Hmac<Sha1>,
        hmac_verify: Hmac<Sha1>,
        hmac_ignore: Option<Hmac<Sha1>>,
    },
}

struct PendingShadowTlsWrite {
    data: bytes::Bytes,
    offset: usize,
    original_len: usize,
}

impl ShadowTlsStream<ShadowTcpStream> {
    async fn connect(stream: ShadowTcpStream, config: &ShadowTlsConfig) -> anyhow::Result<Self> {
        match config.version {
            1 => Self::connect_v1(stream, config).await,
            2 => Self::connect_v2(stream, config).await,
            3 => Self::connect_v3(stream, config).await,
            version => anyhow::bail!("unsupported ShadowTLS version: {version}"),
        }
    }

    async fn connect_v1(stream: ShadowTcpStream, config: &ShadowTlsConfig) -> anyhow::Result<Self> {
        let tls_config = shadow_tls_rustls_config(config, &[&rustls::version::TLS12])?;
        let server_name = ServerName::try_from(config.host.clone())
            .map_err(|_| anyhow::anyhow!("ShadowTLS host is invalid"))?;
        let tls = RustlsConnector::from(Arc::new(tls_config))
            .connect(server_name, stream)
            .await?;
        let (inner, _) = tls.into_inner();
        Ok(Self::new_plain(inner))
    }

    async fn connect_v2(stream: ShadowTcpStream, config: &ShadowTlsConfig) -> anyhow::Result<Self> {
        let tls_config = shadow_tls_rustls_config(config, rustls::DEFAULT_VERSIONS)?;
        let server_name = ServerName::try_from(config.host.clone())
            .map_err(|_| anyhow::anyhow!("ShadowTLS host is invalid"))?;
        let hashed = HashedReadStream::new(stream, config.password.as_bytes())?;
        let tls = RustlsConnector::from(Arc::new(tls_config))
            .connect(server_name, hashed)
            .await?;
        let (hashed, _) = tls.into_inner();
        let digest = hashed.digest();
        let mut auth_tag = [0_u8; 8];
        auth_tag.copy_from_slice(&digest[..8]);
        Ok(Self::new_v2(hashed.into_inner(), auth_tag))
    }

    async fn connect_v3(stream: ShadowTcpStream, config: &ShadowTlsConfig) -> anyhow::Result<Self> {
        let tls_config = shadow_tls_rustls_config(config, rustls::DEFAULT_VERSIONS)?;
        let server_name = ServerName::try_from(config.host.clone())
            .map_err(|_| anyhow::anyhow!("ShadowTLS host is invalid"))?;
        let handshake = ShadowTlsV3HandshakeStream::new(stream, &config.password)?;
        let tls = RustlsConnector::from(Arc::new(tls_config))
            .connect(server_name, handshake)
            .await?;
        let (handshake, _) = tls.into_inner();
        let state = handshake.into_verified_state()?;
        Ok(Self::new_v3(
            state.inner,
            state.hmac_add,
            state.hmac_verify,
            state.hmac_ignore,
        ))
    }
}

impl<S> ShadowTlsStream<S> {
    fn new_plain(inner: S) -> Self {
        Self {
            inner,
            mode: ShadowTlsMode::Plain,
            read_raw: BytesMut::new(),
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }

    fn new_v2(inner: S, auth_tag: [u8; 8]) -> Self {
        Self {
            inner,
            mode: ShadowTlsMode::V2 {
                auth_tag: Some(auth_tag),
            },
            read_raw: BytesMut::new(),
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }

    fn new_v3(
        inner: S,
        hmac_add: Hmac<Sha1>,
        hmac_verify: Hmac<Sha1>,
        hmac_ignore: Option<Hmac<Sha1>>,
    ) -> Self {
        Self {
            inner,
            mode: ShadowTlsMode::V3 {
                hmac_add,
                hmac_verify,
                hmac_ignore,
            },
            read_raw: BytesMut::new(),
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }
}

fn shadow_tls_rustls_config(
    config: &ShadowTlsConfig,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = if config.skip_cert_verify {
        rustls::ClientConfig::builder_with_protocol_versions(versions)
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ShadowTlsInsecureVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_protocol_versions(versions)
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls_config.alpn_protocols = config
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(tls_config)
}

impl<S> Unpin for ShadowTlsStream<S> {}

impl<S> AsyncRead for ShadowTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if matches!(self.mode, ShadowTlsMode::Plain) {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if drain_bytes_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            let drained = {
                let this = &mut *self;
                shadow_tls_drain_records(&mut this.read_raw, &mut this.read_buffer, &mut this.mode)
            };
            match drained {
                Ok(true) if drain_bytes_buffer(&mut self.read_buffer, buf) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                Err(err) => return Poll::Ready(Err(err)),
            }

            let mut temp = [0_u8; 4096];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    if self.read_raw.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS record ended early",
                    )));
                }
                Poll::Ready(Ok(())) => self.read_raw.extend_from_slice(read_buf.filled()),
            }
        }
    }
}

impl<S> AsyncWrite for ShadowTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.mode, ShadowTlsMode::Plain) {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        if self.pending_write.is_none() {
            let data = shadow_tls_encode_records(buf, &mut self.mode).freeze();
            self.pending_write = Some(PendingShadowTlsWrite {
                data,
                offset: 0,
                original_len: buf.len(),
            });
        }

        loop {
            let Some(mut pending) = self.pending_write.take() else {
                return Poll::Ready(Ok(0));
            };
            while pending.offset < pending.data.len() {
                let n = ready!(
                    Pin::new(&mut self.inner).poll_write(cx, &pending.data[pending.offset..])
                )?;
                if n == 0 {
                    self.pending_write = Some(pending);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS stream closed while writing",
                    )));
                }
                pending.offset += n;
            }
            let original_len = pending.original_len;
            return Poll::Ready(Ok(original_len));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while let Some(mut pending) = self.pending_write.take() {
            while pending.offset < pending.data.len() {
                let n = ready!(
                    Pin::new(&mut self.inner).poll_write(cx, &pending.data[pending.offset..])
                )?;
                if n == 0 {
                    self.pending_write = Some(pending);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS stream closed while flushing",
                    )));
                }
                pending.offset += n;
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut *self).poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ShadowTlsV3HandshakeStream<S> {
    inner: S,
    password: String,
    wrote_client_hello: bool,
    read_raw: BytesMut,
    read_buffer: BytesMut,
    server_random: Option<[u8; 32]>,
    read_hmac: Option<Hmac<Sha1>>,
    read_hmac_key: Option<[u8; 32]>,
    is_tls13: bool,
    authorized: bool,
    pending_write: Option<PendingShadowTlsWrite>,
}

struct ShadowTlsV3State<S> {
    inner: S,
    hmac_add: Hmac<Sha1>,
    hmac_verify: Hmac<Sha1>,
    hmac_ignore: Option<Hmac<Sha1>>,
}

impl<S> ShadowTlsV3HandshakeStream<S> {
    fn new(inner: S, password: &str) -> anyhow::Result<Self> {
        Ok(Self {
            inner,
            password: password.to_string(),
            wrote_client_hello: false,
            read_raw: BytesMut::new(),
            read_buffer: BytesMut::new(),
            server_random: None,
            read_hmac: None,
            read_hmac_key: None,
            is_tls13: false,
            authorized: false,
            pending_write: None,
        })
    }

    fn into_verified_state(self) -> anyhow::Result<ShadowTlsV3State<S>> {
        if !self.authorized {
            anyhow::bail!("ShadowTLS v3 handshake was not authorised");
        }
        let server_random = self
            .server_random
            .ok_or_else(|| anyhow::anyhow!("ShadowTLS v3 server random is missing"))?;
        let mut hmac_add = <Hmac<Sha1> as Mac>::new_from_slice(self.password.as_bytes())?;
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = <Hmac<Sha1> as Mac>::new_from_slice(self.password.as_bytes())?;
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        Ok(ShadowTlsV3State {
            inner: self.inner,
            hmac_add,
            hmac_verify,
            hmac_ignore: self.read_hmac,
        })
    }
}

impl<S> Unpin for ShadowTlsV3HandshakeStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsV3HandshakeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if drain_bytes_buffer(&mut self.read_buffer, buf) {
            return Poll::Ready(Ok(()));
        }
        loop {
            let drained = shadow_tls_v3_drain_handshake_records(&mut self)?;
            if drained && drain_bytes_buffer(&mut self.read_buffer, buf) {
                return Poll::Ready(Ok(()));
            }
            let mut temp = [0_u8; 4096];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    if self.read_raw.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS v3 handshake record ended early",
                    )));
                }
                Poll::Ready(Ok(())) => self.read_raw.extend_from_slice(read_buf.filled()),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsV3HandshakeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.wrote_client_hello && self.pending_write.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        if self.pending_write.is_none() {
            self.wrote_client_hello = true;
            let mut patched = BytesMut::from(buf);
            shadow_tls_v3_patch_client_hello(&mut patched, self.password.as_bytes())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.pending_write = Some(PendingShadowTlsWrite {
                data: patched.freeze(),
                offset: 0,
                original_len: buf.len(),
            });
        }
        while let Some(mut pending) = self.pending_write.take() {
            while pending.offset < pending.data.len() {
                let n = ready!(
                    Pin::new(&mut self.inner).poll_write(cx, &pending.data[pending.offset..])
                )?;
                if n == 0 {
                    self.pending_write = Some(pending);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS v3 ClientHello write returned zero",
                    )));
                }
                pending.offset += n;
            }
            return Poll::Ready(Ok(pending.original_len));
        }
        Poll::Ready(Ok(0))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn shadow_tls_v3_patch_client_hello(record: &mut BytesMut, password: &[u8]) -> anyhow::Result<()> {
    if record.len() < 5 || record[0] != 0x16 {
        return Ok(());
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len || record[5] != 0x01 {
        return Ok(());
    }
    let payload_start = 5;
    let session_len_offset = payload_start + 38;
    if record.len() <= session_len_offset {
        anyhow::bail!("ShadowTLS v3 ClientHello is too short");
    }
    let session_len = record[session_len_offset] as usize;
    if session_len != 32 {
        anyhow::bail!("ShadowTLS v3 requires a 32-byte TLS session id");
    }
    let session_start = session_len_offset + 1;
    let session_end = session_start + session_len;
    if record.len() < session_end {
        anyhow::bail!("ShadowTLS v3 ClientHello session id is truncated");
    }
    rand::thread_rng().fill_bytes(&mut record[session_start..session_start + 28]);
    record[session_start + 28..session_end].fill(0);
    let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(password)?;
    hmac.update(&record[payload_start..session_start]);
    hmac.update(&record[session_start..session_end]);
    hmac.update(&record[session_end..payload_start + record_len]);
    let digest = hmac.finalize().into_bytes();
    record[session_start + 28..session_end].copy_from_slice(&digest[..4]);
    Ok(())
}

fn shadow_tls_v3_drain_handshake_records<S>(
    stream: &mut ShadowTlsV3HandshakeStream<S>,
) -> io::Result<bool> {
    let mut drained = false;
    loop {
        if stream.read_raw.len() < 5 {
            return Ok(drained);
        }
        let len = u16::from_be_bytes([stream.read_raw[3], stream.read_raw[4]]) as usize;
        if stream.read_raw.len() < 5 + len {
            return Ok(drained);
        }
        let mut frame = stream.read_raw.split_to(5 + len);
        match frame[0] {
            0x16 => {
                shadow_tls_v3_capture_server_hello(stream, &frame);
                stream.read_buffer.extend_from_slice(&frame);
            }
            0x17 => {
                if shadow_tls_v3_unwrap_handshake_application_data(stream, &mut frame)? {
                    stream.read_buffer.extend_from_slice(&frame);
                } else {
                    stream.read_buffer.extend_from_slice(&frame);
                }
            }
            _ => stream.read_buffer.extend_from_slice(&frame),
        }
        drained = true;
    }
}

fn shadow_tls_v3_capture_server_hello<S>(stream: &mut ShadowTlsV3HandshakeStream<S>, frame: &[u8]) {
    if frame.len() < 5 + 1 + 3 + 2 + 32 || frame[5] != 0x02 {
        return;
    }
    let mut server_random = [0_u8; 32];
    server_random.copy_from_slice(&frame[5 + 1 + 3 + 2..5 + 1 + 3 + 2 + 32]);
    stream.server_random = Some(server_random);
    let mut hmac = match <Hmac<Sha1> as Mac>::new_from_slice(stream.password.as_bytes()) {
        Ok(hmac) => hmac,
        Err(_) => return,
    };
    hmac.update(&server_random);
    let mut key_hasher = Sha256::new();
    key_hasher.update(stream.password.as_bytes());
    key_hasher.update(server_random);
    let key = key_hasher.finalize();
    let mut read_hmac_key = [0_u8; 32];
    read_hmac_key.copy_from_slice(&key);
    stream.read_hmac = Some(hmac);
    stream.read_hmac_key = Some(read_hmac_key);
    stream.is_tls13 = shadow_tls_v3_server_hello_is_tls13(&frame[5..]);
    if !stream.is_tls13 {
        stream.authorized = true;
    }
}

fn shadow_tls_v3_server_hello_is_tls13(payload: &[u8]) -> bool {
    if payload.len() < 1 + 3 + 2 + 32 + 1 {
        return false;
    }
    let mut offset = 1 + 3 + 2 + 32;
    let session_len = payload[offset] as usize;
    offset += 1 + session_len;
    if payload.len() < offset + 2 {
        return false;
    }
    let cipher_suite = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    if (0x1301..=0x1305).contains(&cipher_suite) {
        return true;
    }
    offset += 2;
    if payload.len() <= offset {
        return false;
    }
    let compression_len = payload[offset] as usize;
    offset += 1 + compression_len;
    if payload.len() < offset + 2 {
        return false;
    }
    let extensions_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2;
    let end = (offset + extensions_len).min(payload.len());
    while offset + 4 <= end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > end {
            return false;
        }
        if ext_type == 0x002b && ext_len >= 2 && payload[offset..offset + ext_len].contains(&0x04) {
            return true;
        }
        offset += ext_len;
    }
    false
}

fn shadow_tls_v3_unwrap_handshake_application_data<S>(
    stream: &mut ShadowTlsV3HandshakeStream<S>,
    frame: &mut BytesMut,
) -> io::Result<bool> {
    if frame.len() < 9 {
        return Ok(false);
    }
    let Some(hmac) = stream.read_hmac.as_mut() else {
        return Ok(false);
    };
    if !shadow_tls_v3_verify_application_data(frame, hmac, false) {
        stream.authorized = false;
        return Ok(false);
    }
    let Some(key) = stream.read_hmac_key else {
        return Ok(false);
    };
    for (index, byte) in frame[9..].iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
    let new_len = frame.len() - 9;
    frame.copy_within(0..5, 4);
    frame.advance(4);
    frame[3..5].copy_from_slice(&(new_len as u16).to_be_bytes());
    stream.authorized = true;
    Ok(true)
}

struct HashedReadStream<S> {
    inner: S,
    hmac: Hmac<Sha1>,
}

impl<S> HashedReadStream<S> {
    fn new(inner: S, password: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            inner,
            hmac: <Hmac<Sha1> as Mac>::new_from_slice(password)?,
        })
    }

    fn digest(&self) -> [u8; 20] {
        let bytes = self.hmac.clone().finalize().into_bytes();
        let mut digest = [0_u8; 20];
        digest.copy_from_slice(&bytes);
        digest
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> Unpin for HashedReadStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for HashedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = ready!(Pin::new(&mut self.inner).poll_read(cx, buf));
        if result.is_ok() {
            let filled = buf.filled();
            if filled.len() > before {
                self.hmac.update(&filled[before..]);
            }
        }
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HashedReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct ShadowTlsInsecureVerifier;

impl ServerCertVerifier for ShadowTlsInsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn shadow_tls_encode_records(payload: &[u8], mode: &mut ShadowTlsMode) -> BytesMut {
    const MAX_RECORD_PAYLOAD: usize = 16 * 1024;
    let mut output = BytesMut::with_capacity(payload.len() + 16);
    let mut offset = 0;
    let mut auth_tag = match mode {
        ShadowTlsMode::V2 { auth_tag } => auth_tag.take(),
        _ => None,
    };
    if payload.is_empty() {
        shadow_tls_push_record(&mut output, auth_tag.as_ref(), &[]);
        return output;
    }
    while offset < payload.len() {
        let reserve = auth_tag.as_ref().map(|tag| tag.len()).unwrap_or(0);
        let take = (MAX_RECORD_PAYLOAD - reserve).min(payload.len() - offset);
        match mode {
            ShadowTlsMode::V3 { hmac_add, .. } => {
                shadow_tls_push_v3_record(&mut output, hmac_add, &payload[offset..offset + take]);
            }
            _ => shadow_tls_push_record(
                &mut output,
                auth_tag.as_ref(),
                &payload[offset..offset + take],
            ),
        }
        auth_tag = None;
        offset += take;
    }
    output
}

fn shadow_tls_push_record(output: &mut BytesMut, auth_tag: Option<&[u8; 8]>, payload: &[u8]) {
    let len = auth_tag.map(|tag| tag.len()).unwrap_or(0) + payload.len();
    output.extend_from_slice(&[0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]);
    if let Some(auth_tag) = auth_tag {
        output.extend_from_slice(auth_tag);
    }
    output.extend_from_slice(payload);
}

fn shadow_tls_push_v3_record(output: &mut BytesMut, hmac_add: &mut Hmac<Sha1>, payload: &[u8]) {
    let len = 4 + payload.len();
    output.extend_from_slice(&[0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]);
    hmac_add.update(payload);
    let tag = hmac_first4(hmac_add);
    hmac_add.update(&tag);
    output.extend_from_slice(&tag);
    output.extend_from_slice(payload);
}

fn shadow_tls_drain_records(
    raw: &mut BytesMut,
    output: &mut BytesMut,
    mode: &mut ShadowTlsMode,
) -> io::Result<bool> {
    let mut drained = false;
    loop {
        if raw.len() < 5 {
            return Ok(drained);
        }
        if raw[0] != 0x17 || raw[1] != 0x03 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS received a non-application-data record",
            ));
        }
        let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + len {
            return Ok(drained);
        }
        let frame = raw.split_to(5 + len);
        match mode {
            ShadowTlsMode::V3 {
                hmac_verify,
                hmac_ignore,
                ..
            } => {
                if let Some(ignore) = hmac_ignore {
                    if shadow_tls_v3_verify_application_data(&frame, ignore, false) {
                        drained = true;
                        continue;
                    }
                    *hmac_ignore = None;
                }
                if !shadow_tls_v3_verify_application_data(&frame, hmac_verify, true) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ShadowTLS v3 application data verification failed",
                    ));
                }
                output.extend_from_slice(&frame[9..]);
            }
            _ => output.extend_from_slice(&frame[5..]),
        }
        drained = true;
    }
}

fn shadow_tls_v3_verify_application_data(
    frame: &[u8],
    hmac: &mut Hmac<Sha1>,
    update: bool,
) -> bool {
    if frame.len() < 9 || frame[0] != 0x17 || frame[1] != 0x03 || frame[2] != 0x03 {
        return false;
    }
    hmac.update(&frame[9..]);
    let expected = hmac_first4(hmac);
    if update {
        hmac.update(&expected);
    }
    frame[5..9] == expected[..]
}

fn hmac_first4(hmac: &Hmac<Sha1>) -> [u8; 4] {
    let digest = hmac.clone().finalize().into_bytes();
    [digest[0], digest[1], digest[2], digest[3]]
}
