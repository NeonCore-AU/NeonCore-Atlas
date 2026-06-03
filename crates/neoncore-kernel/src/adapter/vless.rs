use crate::{
    adapter::{
        boxed_stream,
        reality::{RealityCertificateVerifier, RealitySessionId, REALITY_X25519_GROUP},
        BoxedProxyStream, NetworkCapability, OutboundAdapter, OutboundContext,
    },
    buffer_pool::PooledBuffer,
    dns::DnsResolver,
    flow::{
        FlowPipe, FLOW_COPY_BUFFER_SIZE, LARGE_FLOW_PIPE_CAPACITY, SMALL_FLOW_COPY_BUFFER_SIZE,
    },
    packet_session::{packet_target_key, PacketSessionDemux},
    session::{KernelNode, TargetAddress},
    tcp_tuning::tune_tcp_stream,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::{Buf, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    io::{Read as StdRead, Write as StdWrite},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
        Arc, Mutex as StdMutex, OnceLock, Weak,
    },
    task::{Context, Poll},
};
use tokio::io::DuplexStream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::Mutex,
    time::{sleep, timeout, Duration, Instant},
};
use tokio_rustls::{
    rustls::{
        self, client::Resumption, pki_types::ServerName, CipherSuite, NamedGroup, SignatureScheme,
    },
    TlsConnector,
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
};
use tracing::debug;

pub struct VlessAdapter;

static VLESS_MUX_WORKERS: OnceLock<Mutex<HashMap<String, Weak<VlessMuxWorker>>>> = OnceLock::new();
static XHTTP_H2_XMUX_MANAGERS: OnceLock<Mutex<HashMap<String, Arc<Mutex<XHttpH2XmuxManager>>>>> =
    OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessConfig {
    pub server: String,
    pub server_port: u16,
    pub uuid: [u8; 16],
    pub sni: Option<String>,
    pub flow: Option<String>,
    pub security: VlessSecurity,
    pub transport: VlessTransport,
    pub insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessSecurity {
    None,
    Reality {
        public_key: String,
        short_id: String,
        fingerprint: Option<String>,
    },
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTransport {
    pub kind: VlessTransportKind,
    pub host: Option<String>,
    pub path: String,
    pub service_name: String,
    pub authority: Option<String>,
    pub mode: XHttpMode,
    pub http_version: XHttpVersion,
    pub sc_max_each_post_bytes: usize,
    pub sc_min_posts_interval_ms: u64,
    pub xmux: XHttpXmuxConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessTransportKind {
    Tcp,
    WebSocket,
    Grpc,
    H2,
    HttpUpgrade,
    XHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpVersion {
    Auto,
    H1,
    H2,
    H3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpXmuxConfig {
    pub max_concurrency: i32,
    pub max_connections: i32,
    pub c_max_reuse_times: i32,
    pub h_max_request_times: i32,
    pub h_max_reusable_secs: u64,
}

impl Default for XHttpXmuxConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 0,
            max_connections: 0,
            c_max_reuse_times: 0,
            h_max_request_times: 0,
            h_max_reusable_secs: 0,
        }
    }
}

#[async_trait::async_trait]
impl OutboundAdapter for VlessAdapter {
    fn protocol_names(&self) -> &'static [&'static str] {
        &["vless"]
    }

    fn networks(&self) -> &'static [NetworkCapability] {
        &[NetworkCapability::Tcp, NetworkCapability::Udp]
    }

    fn validate(&self, node: &KernelNode) -> anyhow::Result<()> {
        let config = VlessConfig::from_node(node)?;
        if let VlessSecurity::Reality {
            public_key,
            short_id,
            ..
        } = &config.security
        {
            RealitySessionId::new(public_key, short_id)?;
        }
        Ok(())
    }

    async fn connect(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = VlessConfig::from_node(node)?;
        let request = build_tcp_request(&node.user_id, config.flow.as_deref(), target)?;
        let stream = open_vless_transport_stream(&config, context).await?;
        Ok(bridge_vless_stream(stream, request, vision_uuid(&config)))
    }

    async fn send_udp(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let config = VlessConfig::from_node(node)?;
        let worker = mux_worker_for(node, config, context).await?;
        worker.send_packet(target, payload).await
    }
}

async fn mux_worker_for(
    node: &KernelNode,
    config: VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<Arc<VlessMuxWorker>> {
    let key = format!(
        "{}:{}|{}|{:?}|{:?}|{}",
        config.server,
        config.server_port,
        config.sni.as_deref().unwrap_or(""),
        config.security,
        config.transport,
        config.flow.as_deref().unwrap_or("")
    );
    let workers = VLESS_MUX_WORKERS.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let mut workers = workers.lock().await;
        if let Some(worker) = workers.get(&key).and_then(Weak::upgrade) {
            if worker.is_closed() {
                workers.remove(&key);
            } else {
                return Ok(worker);
            }
        }
        workers.retain(|_, worker| worker.strong_count() > 0);
    }

    let stream = open_vless_mux_stream(node, &config, context).await?;
    let worker = Arc::new(VlessMuxWorker::new(stream, vision_uuid(&config)));
    workers.lock().await.insert(key, Arc::downgrade(&worker));
    Ok(worker)
}

async fn open_vless_mux_stream(
    node: &KernelNode,
    config: &VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    let mux_target = TargetAddress {
        host: "v1.mux.cool".to_string(),
        port: 666,
    };
    let request = build_request(
        &node.user_id,
        config.flow.as_deref(),
        VlessCommand::Mux,
        &mux_target,
    )?;
    let mut stream = open_vless_transport_stream(config, context).await?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(stream)
}

async fn open_vless_transport_stream(
    config: &VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    if config.transport.kind == VlessTransportKind::XHttp
        && config.transport.http_version == XHttpVersion::H3
    {
        return connect_h3_xhttp_transport(config, context).await;
    }
    if config.transport.kind == VlessTransportKind::XHttp
        && config.security != VlessSecurity::None
        && resolved_xhttp_mode(config) == XHttpMode::PacketUp
    {
        return connect_h2_xhttp_packet_up_pooled(config, context).await;
    }
    let tcp = connect_tcp(&config.server, config.server_port, context.resolver).await?;
    let secured = apply_vless_security(config, tcp).await?;
    match config.transport.kind {
        VlessTransportKind::Tcp => Ok(secured),
        VlessTransportKind::WebSocket => connect_ws_transport(config, secured).await,
        VlessTransportKind::HttpUpgrade => connect_http_upgrade_transport(config, secured).await,
        VlessTransportKind::H2 => {
            connect_h2_transport(config, secured, h2_path(config), H2PayloadMode::Raw).await
        }
        VlessTransportKind::Grpc => connect_grpc_transport(config, secured).await,
        VlessTransportKind::XHttp => connect_xhttp_transport(config, secured).await,
    }
}

async fn apply_vless_security(
    config: &VlessConfig,
    stream: TcpStream,
) -> anyhow::Result<BoxedProxyStream> {
    match &config.security {
        VlessSecurity::None => Ok(boxed_stream(stream)),
        VlessSecurity::Tls => {
            let sni = config.sni.as_deref().unwrap_or(&config.server);
            let mut builder = native_tls::TlsConnector::builder();
            builder.danger_accept_invalid_certs(config.insecure);
            match config.transport.kind {
                VlessTransportKind::H2 | VlessTransportKind::Grpc | VlessTransportKind::XHttp => {
                    builder.request_alpns(&["h2", "http/1.1"]);
                }
                VlessTransportKind::WebSocket | VlessTransportKind::HttpUpgrade => {
                    builder.request_alpns(&["http/1.1"]);
                }
                VlessTransportKind::Tcp => {}
            }
            let connector = builder.build()?;
            let connector = tokio_native_tls::TlsConnector::from(connector);
            Ok(boxed_stream(connector.connect(sni, stream).await?))
        }
        VlessSecurity::Reality {
            public_key,
            short_id,
            fingerprint,
        } => {
            let sni = config.sni.as_deref().unwrap_or(&config.server);
            Ok(boxed_stream(
                connect_reality_tls(stream, sni, public_key, short_id, fingerprint).await?,
            ))
        }
    }
}

async fn connect_ws_transport(
    config: &VlessConfig,
    stream: BoxedProxyStream,
) -> anyhow::Result<BoxedProxyStream> {
    let scheme = if config.security == VlessSecurity::None {
        "ws"
    } else {
        "wss"
    };
    let uri = format!(
        "{scheme}://{}{}",
        transport_authority(config, false),
        normalized_path(&config.transport.path)
    );
    let mut request = uri.into_client_request()?;
    if let Some(host) = transport_host(config) {
        request
            .headers_mut()
            .insert("Host", HeaderValue::from_str(&host)?);
    }
    if let Some(ed) = early_data_header(config) {
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_str(&BASE64_STANDARD.encode(ed))?,
        );
    }
    let (ws, _) = client_async(request, stream).await?;
    Ok(websocket_stream_pipe(ws))
}

async fn connect_http_upgrade_transport(
    config: &VlessConfig,
    mut stream: BoxedProxyStream,
) -> anyhow::Result<BoxedProxyStream> {
    let path = normalized_path(&config.transport.path);
    let host = transport_host(config).unwrap_or_else(|| transport_authority(config, false));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_http_upgrade_response(&mut stream).await?;
    Ok(stream)
}

async fn connect_grpc_transport(
    config: &VlessConfig,
    stream: BoxedProxyStream,
) -> anyhow::Result<BoxedProxyStream> {
    let path = grpc_path(&config.transport.service_name);
    connect_h2_transport(config, stream, path, H2PayloadMode::GrpcHunk).await
}

async fn connect_xhttp_transport(
    config: &VlessConfig,
    stream: BoxedProxyStream,
) -> anyhow::Result<BoxedProxyStream> {
    if config.security == VlessSecurity::None {
        return connect_http1_stream_transport(config, stream, xhttp_path(config)).await;
    }
    match resolved_xhttp_mode(config) {
        XHttpMode::PacketUp => connect_h2_xhttp_packet_up(config, stream).await,
        XHttpMode::StreamOne | XHttpMode::StreamUp | XHttpMode::Auto => {
            connect_h2_transport(config, stream, xhttp_path(config), H2PayloadMode::Raw).await
        }
    }
}

fn resolved_xhttp_mode(config: &VlessConfig) -> XHttpMode {
    match config.transport.mode {
        XHttpMode::Auto if matches!(config.security, VlessSecurity::Reality { .. }) => {
            XHttpMode::StreamOne
        }
        XHttpMode::Auto => XHttpMode::PacketUp,
        value => value,
    }
}

async fn connect_h2_xhttp_packet_up_pooled(
    config: &VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    let manager = xhttp_h2_xmux_manager(config).await;
    let client = {
        let mut manager = manager.lock().await;
        manager.get_client(config, context).await?
    };
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    client.open_usage.fetch_add(1, Ordering::Relaxed);
    let session = xhttp_session_id();
    let mut sender = client.sender.clone();
    let download_request = ::http::Request::builder()
        .method("GET")
        .uri(xhttp_path_with_query(config, &session, None))
        .header("authority", client.authority.clone())
        .body(())?;
    let response = sender.send_request(download_request, true)?;
    client.left_requests.fetch_sub(1, Ordering::Relaxed);
    spawn_h2_xhttp_packet_bridge(
        bridge,
        response.0,
        client.sender.clone(),
        client.authority.clone(),
        xhttp_path(config),
        session,
        config.transport.sc_max_each_post_bytes,
        config.transport.sc_min_posts_interval_ms,
        Some(client),
    );
    Ok(local)
}

async fn connect_h2_xhttp_packet_up(
    config: &VlessConfig,
    stream: BoxedProxyStream,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let authority = transport_host(config).unwrap_or_else(|| transport_authority(config, false));
    let (mut client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let session = xhttp_session_id();
    let download_request = ::http::Request::builder()
        .method("GET")
        .uri(xhttp_path_with_query(config, &session, None))
        .header("authority", authority.clone())
        .body(())?;
    let response = client.send_request(download_request, true)?;
    spawn_h2_xhttp_packet_bridge(
        bridge,
        response.0,
        client,
        authority,
        xhttp_path(config),
        session,
        config.transport.sc_max_each_post_bytes,
        config.transport.sc_min_posts_interval_ms,
        None,
    );
    Ok(local)
}

async fn xhttp_h2_xmux_manager(config: &VlessConfig) -> Arc<Mutex<XHttpH2XmuxManager>> {
    let key = xhttp_h2_xmux_key(config);
    let managers = XHTTP_H2_XMUX_MANAGERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut managers = managers.lock().await;
    managers
        .entry(key)
        .or_insert_with(|| {
            Arc::new(Mutex::new(XHttpH2XmuxManager::new(
                config.transport.xmux.clone(),
            )))
        })
        .clone()
}

fn xhttp_h2_xmux_key(config: &VlessConfig) -> String {
    format!(
        "{}:{}|{}|{:?}|{}|{}|{:?}",
        config.server,
        config.server_port,
        config.sni.as_deref().unwrap_or(""),
        config.security,
        transport_host(config).unwrap_or_default(),
        xhttp_path(config),
        config.transport.xmux
    )
}

struct XHttpH2XmuxManager {
    config: XHttpXmuxConfig,
    clients: Vec<Arc<XHttpH2XmuxClient>>,
}

impl XHttpH2XmuxManager {
    fn new(config: XHttpXmuxConfig) -> Self {
        Self {
            config,
            clients: Vec::new(),
        }
    }

    async fn get_client(
        &mut self,
        config: &VlessConfig,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Arc<XHttpH2XmuxClient>> {
        self.retain_usable();
        if self.clients.is_empty() || self.should_open_more_connections() {
            return self.new_client(config, context).await;
        }
        if let Some(client) = self.reusable_client() {
            return Ok(client);
        }
        self.new_client(config, context).await
    }

    fn retain_usable(&mut self) {
        self.clients.retain(|client| client.is_usable());
    }

    fn should_open_more_connections(&self) -> bool {
        self.config.max_connections > 0 && self.clients.len() < self.config.max_connections as usize
    }

    fn reusable_client(&mut self) -> Option<Arc<XHttpH2XmuxClient>> {
        let candidates: Vec<_> = self
            .clients
            .iter()
            .filter(|client| {
                self.config.max_concurrency <= 0
                    || client.open_usage.load(Ordering::Relaxed) < self.config.max_concurrency
            })
            .cloned()
            .collect();
        let client = candidates
            .into_iter()
            .min_by_key(|client| client.open_usage.load(Ordering::Relaxed))?;
        client.consume_connection_reuse();
        Some(client)
    }

    async fn new_client(
        &mut self,
        config: &VlessConfig,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Arc<XHttpH2XmuxClient>> {
        let stream = open_h2_xhttp_stream(config, context).await?;
        let authority =
            transport_host(config).unwrap_or_else(|| transport_authority(config, false));
        let (sender, connection) = h2::client::handshake(stream).await?;
        let closed = Arc::new(AtomicBool::new(false));
        let closed_for_task = closed.clone();
        tokio::spawn(async move {
            let _ = connection.await;
            closed_for_task.store(true, Ordering::Relaxed);
        });
        let left_usage = if self.config.c_max_reuse_times > 0 {
            self.config.c_max_reuse_times.saturating_sub(1)
        } else {
            -1
        };
        let left_requests = if self.config.h_max_request_times > 0 {
            self.config.h_max_request_times
        } else {
            i32::MAX
        };
        let reusable_until = (self.config.h_max_reusable_secs > 0)
            .then(|| Instant::now() + Duration::from_secs(self.config.h_max_reusable_secs));
        let client = Arc::new(XHttpH2XmuxClient {
            sender,
            authority,
            open_usage: AtomicI32::new(0),
            left_usage: AtomicI32::new(left_usage),
            left_requests: AtomicI32::new(left_requests),
            reusable_until,
            closed,
        });
        self.clients.push(client.clone());
        Ok(client)
    }
}

struct XHttpH2XmuxClient {
    sender: h2::client::SendRequest<Bytes>,
    authority: String,
    open_usage: AtomicI32,
    left_usage: AtomicI32,
    left_requests: AtomicI32,
    reusable_until: Option<Instant>,
    closed: Arc<AtomicBool>,
}

impl XHttpH2XmuxClient {
    fn is_usable(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
            && self.left_usage.load(Ordering::Relaxed) != 0
            && self.left_requests.load(Ordering::Relaxed) > 0
            && self
                .reusable_until
                .map(|deadline| Instant::now() <= deadline)
                .unwrap_or(true)
    }

    fn consume_connection_reuse(&self) {
        let mut current = self.left_usage.load(Ordering::Relaxed);
        while current > 0 {
            match self.left_usage.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

async fn open_h2_xhttp_stream(
    config: &VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    let tcp = connect_tcp(&config.server, config.server_port, context.resolver).await?;
    apply_vless_security(config, tcp).await
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
    xmux_client: Option<Arc<XHttpH2XmuxClient>>,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let upload_xmux_client = xmux_client.clone();
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let mut buf = vec![0_u8; max_post_bytes.max(16 * 1024)];
        let mut last_write = Instant::now();
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if min_posts_interval_ms > 0 {
                        let interval = Duration::from_millis(min_posts_interval_ms);
                        let elapsed = last_write.elapsed();
                        if elapsed < interval {
                            sleep(interval - elapsed).await;
                        }
                    }
                    last_write = Instant::now();
                    if let Some(xmux_client) = &upload_xmux_client {
                        xmux_client.left_requests.fetch_sub(1, Ordering::Relaxed);
                    }
                    let mut client = client.clone();
                    let path = format!("{base_path}?session={session}&seq={seq}");
                    seq = seq.saturating_add(1);
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    let authority = authority.clone();
                    tokio::spawn(async move {
                        let request = match ::http::Request::builder()
                            .method("POST")
                            .uri(path)
                            .header("authority", authority)
                            .header("content-type", "application/octet-stream")
                            .body(())
                        {
                            Ok(value) => value,
                            Err(_) => return,
                        };
                        let Ok((response, mut send)) = client.send_request(request, false) else {
                            return;
                        };
                        let _ = send.send_data(payload, true);
                        if let Ok(response) = response.await {
                            let mut body = response.into_body();
                            while body.data().await.transpose().ok().flatten().is_some() {}
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let Ok(response) = response.await else {
            let _ = download.shutdown().await;
            return;
        };
        let mut body = response.into_body();
        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(data) => {
                    if download.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = download.shutdown().await;
        if let Some(xmux_client) = xmux_client {
            xmux_client.open_usage.fetch_sub(1, Ordering::Relaxed);
        }
    });
}

async fn run_h3_xhttp_bridge(
    bridge: DuplexStream,
    remote: SocketAddr,
    server_name: String,
    authority: String,
    base_path: String,
    insecure: bool,
) -> anyhow::Result<()> {
    let bind = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(h3_quinn_client_config(insecure)?);
    let connection = endpoint.connect(remote, &server_name)?.await?;
    let (mut driver, client) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    spawn_h3_xhttp_packet_bridge(bridge, client, authority, base_path);
    Ok(())
}

fn h3_quinn_client_config(insecure: bool) -> anyhow::Result<quinn::ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut tls = if insecure {
        let verifier = RealityCertificateVerifier::new(provider.clone());
        rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
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
    authority: String,
    base_path: String,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    let session = xhttp_session_id();
    let download_uri = format!(
        "https://{authority}{}",
        xhttp_path_with_query_raw(&base_path, &session, None)
    );
    let mut download_client = client.clone();
    tokio::spawn(async move {
        let request = match ::http::Request::builder()
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
        if stream.recv_response().await.is_err() {
            let _ = download.shutdown().await;
            return;
        }
        loop {
            match stream.recv_data().await {
                Ok(Some(mut data)) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    if download.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = download.shutdown().await;
    });
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let mut buf = vec![0_u8; 256 * 1024];
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut upload_client = client.clone();
                    let uri = format!(
                        "https://{authority}{}",
                        xhttp_path_with_query_raw(&base_path, &session, Some(seq))
                    );
                    seq = seq.saturating_add(1);
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    tokio::spawn(async move {
                        let request =
                            match ::http::Request::builder().method("POST").uri(uri).body(()) {
                                Ok(value) => value,
                                Err(_) => return,
                            };
                        let Ok(mut stream) = upload_client.send_request(request).await else {
                            return;
                        };
                        if stream.send_data(payload).await.is_ok() {
                            let _ = stream.finish().await;
                            let _ = stream.recv_response().await;
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });
}

async fn connect_h3_xhttp_transport(
    config: &VlessConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    if config.security == VlessSecurity::None {
        anyhow::bail!("VLESS XHTTP H3 requires TLS");
    }
    let server = TargetAddress {
        host: config.server.clone(),
        port: config.server_port,
    };
    let addresses = context.resolver.resolve_proxy_server(&server).await?;
    let remote = addresses
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no resolved address for VLESS XHTTP H3 server"))?;
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let server_name = config.sni.as_deref().unwrap_or(&config.server).to_string();
    let authority = transport_host(config).unwrap_or_else(|| transport_authority(config, false));
    let path = xhttp_path(config);
    let insecure = config.insecure;
    tokio::spawn(async move {
        let _ = run_h3_xhttp_bridge(bridge, remote, server_name, authority, path, insecure).await;
    });
    Ok(local)
}

async fn connect_http1_stream_transport(
    config: &VlessConfig,
    mut stream: BoxedProxyStream,
    path: String,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let host = transport_host(config).unwrap_or_else(|| transport_authority(config, true));
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    spawn_http1_chunked_bridge(bridge, stream);
    Ok(local)
}

fn spawn_http1_chunked_bridge(bridge: DuplexStream, stream: BoxedProxyStream) {
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
        if read_http_response_headers(&mut remote_read).await.is_err() {
            let _ = download.shutdown().await;
            return;
        }
        let _ = tokio::io::copy(&mut remote_read, &mut download).await;
        let _ = download.shutdown().await;
    });
}

#[derive(Clone, Copy)]
enum H2PayloadMode {
    Raw,
    GrpcHunk,
}

async fn connect_h2_transport(
    config: &VlessConfig,
    stream: BoxedProxyStream,
    path: String,
    mode: H2PayloadMode,
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let authority = transport_host(config).unwrap_or_else(|| transport_authority(config, false));
    let (mut client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = ::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("authority", authority)
        .header(
            "content-type",
            match mode {
                H2PayloadMode::Raw => "application/octet-stream",
                H2PayloadMode::GrpcHunk => "application/grpc",
            },
        )
        .body(())?;
    let (response, send) = client.send_request(request, false)?;
    spawn_h2_body_bridge(bridge, response, send, mode);
    Ok(local)
}

fn websocket_stream_pipe<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> BoxedProxyStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    spawn_websocket_bridge(bridge, ws);
    local
}

fn spawn_websocket_bridge<S>(bridge: DuplexStream, ws: tokio_tungstenite::WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut writer, mut reader) = ws.split();
    let (mut upload, mut download) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; FLOW_COPY_BUFFER_SIZE];
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => {
                    let _ = writer.close().await;
                    break;
                }
                Ok(n) => {
                    if writer
                        .send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = reader.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    if download.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = download.shutdown().await;
    });
}

fn spawn_h2_body_bridge(
    bridge: DuplexStream,
    response: h2::client::ResponseFuture,
    mut send: h2::SendStream<Bytes>,
    mode: H2PayloadMode,
) {
    let (mut upload, mut download) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; FLOW_COPY_BUFFER_SIZE];
        loop {
            match upload.read(&mut buf).await {
                Ok(0) => {
                    let _ = send.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    let data = match mode {
                        H2PayloadMode::Raw => Bytes::copy_from_slice(&buf[..n]),
                        H2PayloadMode::GrpcHunk => encode_grpc_hunk(&buf[..n]),
                    };
                    if send.send_data(data, false).is_err() {
                        break;
                    }
                    let _ = send.reserve_capacity(n);
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let Ok(response) = response.await else {
            let _ = download.shutdown().await;
            return;
        };
        let mut body = response.into_body();
        let mut grpc_decoder = GrpcHunkDecoder::default();
        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(data) => match mode {
                    H2PayloadMode::Raw => {
                        if download.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    H2PayloadMode::GrpcHunk => {
                        let hunks = grpc_decoder.push(&data);
                        for hunk in hunks {
                            if download.write_all(&hunk).await.is_err() {
                                let _ = download.shutdown().await;
                                return;
                            }
                        }
                    }
                },
                Err(_) => break,
            }
        }
        let _ = download.shutdown().await;
    });
}

fn encode_grpc_hunk(payload: &[u8]) -> Bytes {
    let mut message = Vec::with_capacity(payload.len() + 8);
    message.push(0x0a);
    write_protobuf_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);
    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

#[derive(Default)]
struct GrpcHunkDecoder {
    pending: Vec<u8>,
}

impl GrpcHunkDecoder {
    fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.pending.len() < 5 {
                break;
            }
            let compressed = self.pending[0];
            let len = u32::from_be_bytes([
                self.pending[1],
                self.pending[2],
                self.pending[3],
                self.pending[4],
            ]) as usize;
            if compressed != 0 || self.pending.len() < 5 + len {
                break;
            }
            let message = self.pending[5..5 + len].to_vec();
            self.pending.drain(..5 + len);
            if let Some(payload) = decode_grpc_hunk_message(&message) {
                out.push(payload);
            }
        }
        out
    }
}

fn decode_grpc_hunk_message(message: &[u8]) -> Option<Vec<u8>> {
    if message.first().copied()? != 0x0a {
        return None;
    }
    let (len, offset) = read_protobuf_varint(&message[1..])?;
    let start = 1 + offset;
    let end = start.checked_add(len as usize)?;
    (message.len() >= end).then(|| message[start..end].to_vec())
}

fn read_protobuf_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in data.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        if index >= 9 {
            return None;
        }
    }
    None
}

async fn read_http_upgrade_response(stream: &mut BoxedProxyStream) -> anyhow::Result<()> {
    let text = read_http_response_headers(stream).await?;
    if !text.starts_with("HTTP/1.1 101") && !text.starts_with("HTTP/1.0 101") {
        anyhow::bail!(
            "VLESS HTTPUpgrade rejected: {}",
            text.lines().next().unwrap_or("")
        );
    }
    Ok(())
}

async fn read_http_response_headers<R>(stream: &mut R) -> anyhow::Result<String>
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
            return Ok(text.into_owned());
        }
    }
    anyhow::bail!("VLESS HTTP response is too large")
}

async fn connect_reality_tls(
    stream: TcpStream,
    sni: &str,
    public_key: &str,
    short_id: &str,
    fingerprint: &Option<String>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<RecordLimitedTcp>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![&REALITY_X25519_GROUP];
    let verifier = RealityCertificateVerifier::new(provider.clone());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.reality_session_id_generator =
        Some(Arc::new(RealitySessionId::new(public_key, short_id)?));
    apply_tls_fingerprint_profile(&mut config, fingerprint.as_deref())?;

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("VLESS REALITY SNI is invalid"))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, RecordLimitedTcp::new(stream))
        .await
        .map_err(Into::into)
}

fn apply_tls_fingerprint_profile(
    config: &mut rustls::ClientConfig,
    fingerprint: Option<&str>,
) -> anyhow::Result<()> {
    let Some(fingerprint) = fingerprint.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    match fingerprint {
        "chrome" | "edge" => {
            config.client_hello_fingerprint_profile =
                Some(rustls::client::ClientHelloFingerprintProfile::Chrome);
            apply_browser_ja_profile(config, BrowserJaProfile::Chrome);
            Ok(())
        }
        "firefox" => {
            config.client_hello_fingerprint_profile =
                Some(rustls::client::ClientHelloFingerprintProfile::Firefox);
            apply_browser_ja_profile(config, BrowserJaProfile::Firefox);
            Ok(())
        }
        "safari" | "ios" => {
            config.client_hello_fingerprint_profile =
                Some(rustls::client::ClientHelloFingerprintProfile::Safari);
            apply_browser_ja_profile(config, BrowserJaProfile::Safari);
            Ok(())
        }
        "android" | "random" | "randomized" => {
            config.client_hello_fingerprint_profile =
                Some(rustls::client::ClientHelloFingerprintProfile::Randomized);
            apply_browser_ja_profile(config, BrowserJaProfile::Chrome);
            Ok(())
        }
        "none" => Ok(()),
        value => anyhow::bail!("unsupported VLESS REALITY fingerprint: {value}"),
    }
}

#[derive(Clone, Copy)]
enum BrowserJaProfile {
    Chrome,
    Firefox,
    Safari,
}

fn apply_browser_ja_profile(config: &mut rustls::ClientConfig, profile: BrowserJaProfile) {
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.client_hello_grease = Some(0x0a0a);
    config.client_hello_cipher_suites = Some(match profile {
        BrowserJaProfile::Chrome | BrowserJaProfile::Safari => vec![
            CipherSuite::Unknown(0x0a0a),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        BrowserJaProfile::Firefox => vec![
            CipherSuite::Unknown(0x0a0a),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ],
    });
    config.client_hello_supported_groups = Some(match profile {
        BrowserJaProfile::Chrome | BrowserJaProfile::Safari => vec![
            NamedGroup::Unknown(0x0a0a),
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ],
        BrowserJaProfile::Firefox => vec![
            NamedGroup::Unknown(0x0a0a),
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
            NamedGroup::secp521r1,
        ],
    });
    config.client_hello_signature_schemes = Some(match profile {
        BrowserJaProfile::Chrome | BrowserJaProfile::Safari => vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        BrowserJaProfile::Firefox => vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
    });
}

impl VlessConfig {
    pub fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&node.user_id)?;
        let security = match node.parameter("security").unwrap_or("none") {
            "none" => VlessSecurity::None,
            "tls" => VlessSecurity::Tls,
            "reality" => {
                let Some(sni) = node.parameter("sni") else {
                    anyhow::bail!("VLESS Reality requires parameter: sni");
                };
                let Some(public_key) = node.parameter("pbk") else {
                    anyhow::bail!("VLESS Reality requires parameter: pbk");
                };
                let Some(short_id) = node.parameter("sid") else {
                    anyhow::bail!("VLESS Reality requires parameter: sid");
                };
                let _ = sni;
                VlessSecurity::Reality {
                    public_key: public_key.to_string(),
                    short_id: short_id.to_string(),
                    fingerprint: node.parameter("fp").map(str::to_string),
                }
            }
            value => anyhow::bail!("unsupported VLESS security mode: {value}"),
        };
        Ok(Self {
            server: node.server.clone(),
            server_port: node.server_port,
            uuid,
            sni: node.parameter("sni").map(str::to_string),
            flow: node.parameter("flow").map(str::to_string),
            security,
            transport: VlessTransport::from_node(node)?,
            insecure: node
                .parameter("insecure")
                .map(|value| matches!(value, "1" | "true" | "yes"))
                .unwrap_or(false),
        })
    }
}

impl VlessTransport {
    fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        let kind = match node
            .parameter("type")
            .or_else(|| node.parameter("network"))
            .unwrap_or("tcp")
            .to_ascii_lowercase()
            .as_str()
        {
            "tcp" | "raw" => VlessTransportKind::Tcp,
            "ws" | "websocket" => VlessTransportKind::WebSocket,
            "grpc" | "gun" | "multi" => VlessTransportKind::Grpc,
            "h2" | "http" => VlessTransportKind::H2,
            "httpupgrade" | "http-upgrade" | "http_upgrade" => VlessTransportKind::HttpUpgrade,
            "xhttp" | "splithttp" | "split-http" | "split_http" => VlessTransportKind::XHttp,
            value => anyhow::bail!("unsupported VLESS transport: {value}"),
        };
        let path = node
            .parameter("path")
            .or_else(|| node.parameter("ws-path"))
            .or_else(|| node.parameter("h2-path"))
            .or_else(|| node.parameter("xhttp-path"))
            .unwrap_or("/")
            .to_string();
        let service_name = node
            .parameter("serviceName")
            .or_else(|| node.parameter("service_name"))
            .or_else(|| node.parameter("grpc-service-name"))
            .unwrap_or("Tun")
            .to_string();
        let mode = match node.parameter("mode").unwrap_or("auto") {
            "auto" | "" => XHttpMode::Auto,
            "stream-one" | "stream_one" => XHttpMode::StreamOne,
            "stream-up" | "stream_up" => XHttpMode::StreamUp,
            "packet-up" | "packet_up" => XHttpMode::PacketUp,
            value => anyhow::bail!("unsupported VLESS XHTTP mode: {value}"),
        };
        let http_version = match node
            .parameter("httpVersion")
            .or_else(|| node.parameter("http_version"))
            .or_else(|| node.parameter("alpn"))
            .unwrap_or("auto")
            .to_ascii_lowercase()
            .as_str()
        {
            "auto" | "" => XHttpVersion::Auto,
            "1" | "1.1" | "h1" | "http/1.1" => XHttpVersion::H1,
            "2" | "h2" | "http/2" => XHttpVersion::H2,
            "3" | "h3" | "http/3" => XHttpVersion::H3,
            value => anyhow::bail!("unsupported VLESS XHTTP HTTP version: {value}"),
        };
        Ok(Self {
            kind,
            host: node
                .parameter("host")
                .or_else(|| node.parameter("ws-host"))
                .or_else(|| node.parameter("authority"))
                .map(str::to_string),
            path,
            service_name,
            authority: node.parameter("authority").map(str::to_string),
            mode,
            http_version,
            sc_max_each_post_bytes: parse_usize_param(
                node,
                &[
                    "scMaxEachPostBytes",
                    "sc_max_each_post_bytes",
                    "xhttp-post-bytes",
                ],
                256 * 1024,
            )?,
            sc_min_posts_interval_ms: parse_u64_param(
                node,
                &["scMinPostsIntervalMs", "sc_min_posts_interval_ms"],
                0,
            )?,
            xmux: XHttpXmuxConfig {
                max_concurrency: parse_i32_param(node, &["xmuxMaxConcurrency"], 0)?,
                max_connections: parse_i32_param(node, &["xmuxMaxConnections"], 0)?,
                c_max_reuse_times: parse_i32_param(node, &["xmuxCMaxReuseTimes"], 0)?,
                h_max_request_times: parse_i32_param(node, &["xmuxHMaxRequestTimes"], 0)?,
                h_max_reusable_secs: parse_u64_param(node, &["xmuxHMaxReusableSecs"], 0)?,
            },
        })
    }
}

fn parse_usize_param(node: &KernelNode, keys: &[&str], default: usize) -> anyhow::Result<usize> {
    let Some(value) = keys.iter().find_map(|key| node.parameter(key)) else {
        return Ok(default);
    };
    value
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid numeric VLESS parameter {value}: {err}"))
}

fn parse_u64_param(node: &KernelNode, keys: &[&str], default: u64) -> anyhow::Result<u64> {
    let Some(value) = keys.iter().find_map(|key| node.parameter(key)) else {
        return Ok(default);
    };
    value
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid numeric VLESS parameter {value}: {err}"))
}

fn parse_i32_param(node: &KernelNode, keys: &[&str], default: i32) -> anyhow::Result<i32> {
    let Some(value) = keys.iter().find_map(|key| node.parameter(key)) else {
        return Ok(default);
    };
    value
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid numeric VLESS parameter {value}: {err}"))
}

fn transport_host(config: &VlessConfig) -> Option<String> {
    config
        .transport
        .host
        .clone()
        .or_else(|| config.transport.authority.clone())
        .or_else(|| config.sni.clone())
}

fn transport_authority(config: &VlessConfig, always_port: bool) -> String {
    let host = transport_host(config).unwrap_or_else(|| config.server.clone());
    let default_port = match config.security {
        VlessSecurity::None => 80,
        _ => 443,
    };
    if always_port || config.server_port != default_port {
        format!("{host}:{}", config.server_port)
    } else {
        host
    }
}

fn normalized_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn h2_path(config: &VlessConfig) -> String {
    normalized_path(&config.transport.path)
}

fn xhttp_path(config: &VlessConfig) -> String {
    let mut path = normalized_path(&config.transport.path);
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn xhttp_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn xhttp_path_with_query(config: &VlessConfig, session: &str, seq: Option<u64>) -> String {
    xhttp_path_with_query_raw(&xhttp_path(config), session, seq)
}

fn xhttp_path_with_query_raw(base_path: &str, session: &str, seq: Option<u64>) -> String {
    let join = if base_path.contains('?') { '&' } else { '?' };
    match seq {
        Some(seq) => format!("{base_path}{join}session={session}&seq={seq}"),
        None => format!("{base_path}{join}session={session}"),
    }
}

fn grpc_path(service_name: &str) -> String {
    if service_name.starts_with('/') {
        let mut parts = service_name.rsplitn(2, '/');
        let method = parts.next().unwrap_or("Tun");
        let service = parts.next().unwrap_or("").trim_start_matches('/');
        if service.is_empty() {
            format!("/{method}")
        } else {
            format!("/{service}/{method}")
        }
    } else {
        format!("/{service_name}/Tun")
    }
}

fn early_data_header(config: &VlessConfig) -> Option<&[u8]> {
    let _ = config;
    None
}

async fn connect_tcp(host: &str, port: u16, resolver: &DnsResolver) -> anyhow::Result<TcpStream> {
    let server = TargetAddress {
        host: host.to_string(),
        port,
    };
    let addresses = resolver.resolve_proxy_server(&server).await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(value) => {
                tune_tcp_stream(&value);
                return Ok(value);
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no resolved address for VLESS server")))
}

pub fn build_tcp_request(
    uuid: &str,
    flow: Option<&str>,
    target: &TargetAddress,
) -> anyhow::Result<Vec<u8>> {
    build_request(uuid, flow, VlessCommand::Tcp, target)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VlessCommand {
    Tcp,
    #[allow(dead_code)]
    Udp,
    Mux,
}

impl VlessCommand {
    fn code(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Mux => 3,
        }
    }
}

fn build_request(
    uuid: &str,
    flow: Option<&str>,
    command: VlessCommand,
    target: &TargetAddress,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0);
    out.extend_from_slice(&parse_uuid(uuid)?);
    let addon = build_addon(flow)?;
    if addon.len() > u8::MAX as usize {
        anyhow::bail!("VLESS addon is too large");
    }
    out.push(addon.len() as u8);
    out.extend_from_slice(&addon);
    out.push(command.code());
    if command != VlessCommand::Mux {
        out.extend_from_slice(&target.port.to_be_bytes());
        encode_address(&target.host, &mut out)?;
    }
    Ok(out)
}

fn build_addon(flow: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let Some(flow) = flow.filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(flow.len() + 3);
    out.push(0x0a);
    write_protobuf_varint(flow.len() as u64, &mut out);
    out.extend_from_slice(flow.as_bytes());
    Ok(out)
}

fn write_protobuf_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn vision_uuid(config: &VlessConfig) -> Option<[u8; 16]> {
    is_vision_flow(config.flow.as_deref()).then_some(config.uuid)
}

fn is_vision_flow(flow: Option<&str>) -> bool {
    matches!(
        flow,
        Some("xtls-rprx-vision") | Some("xtls-rprx-vision-udp443")
    )
}

#[allow(dead_code)]
async fn send_udp_packet<S>(
    mut stream: S,
    request: Vec<u8>,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("VLESS UDP payload is too large");
    }
    let mut packet = Vec::with_capacity(request.len() + 2 + payload.len());
    packet.extend_from_slice(&request);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    read_vless_response_header(&mut stream).await?;
    read_udp_packet(&mut stream).await
}

async fn read_vless_response_header<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] != 0 {
        anyhow::bail!("unsupported VLESS response version: {}", header[0]);
    }
    if header[1] > 0 {
        let mut addon = vec![0_u8; header[1] as usize];
        reader.read_exact(&mut addon).await?;
    }
    Ok(())
}

#[allow(dead_code)]
async fn read_udp_packet<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    timeout(Duration::from_secs(20), reader.read_exact(&mut len)).await??;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

struct VlessMuxWorker {
    writer: Mutex<VlessMuxWriter>,
    pending: PacketSessionDemux,
    read_task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    next_request_id: AtomicU64,
    closed: Arc<AtomicBool>,
}

struct VlessMuxWriter {
    writer: tokio::io::WriteHalf<BoxedProxyStream>,
    vision_uuid: Option<[u8; 16]>,
    vision_uuid_pending: bool,
    first_packet: bool,
}

struct VlessMuxReader {
    reader: tokio::io::ReadHalf<BoxedProxyStream>,
    response_header_read: bool,
    vision_downlink: Option<VisionUnpaddingState>,
    read_buffer: BytesMut,
}

#[derive(Debug)]
struct XudpPacket {
    target: Option<TargetAddress>,
    payload: Vec<u8>,
}

impl VlessMuxWorker {
    fn new(stream: BoxedProxyStream, vision_uuid: Option<[u8; 16]>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let pending = PacketSessionDemux::new();
        let closed = Arc::new(AtomicBool::new(false));
        let read_task = spawn_vless_mux_reader(
            VlessMuxReader {
                reader,
                response_header_read: false,
                vision_downlink: vision_uuid.map(VisionUnpaddingState::new),
                read_buffer: BytesMut::with_capacity(SMALL_FLOW_COPY_BUFFER_SIZE),
            },
            pending.clone(),
            Arc::clone(&closed),
        );
        Self {
            writer: Mutex::new(VlessMuxWriter {
                writer,
                vision_uuid,
                vision_uuid_pending: vision_uuid.is_some(),
                first_packet: true,
            }),
            pending,
            read_task: StdMutex::new(Some(read_task)),
            next_request_id: AtomicU64::new(0),
            closed,
        }
    }

    async fn send_packet(&self, target: &TargetAddress, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_closed() {
            anyhow::bail!("VLESS mux worker is closed");
        }
        let target_key = packet_target_key(&target.host, target.port);
        let wait = self.pending.register(
            target_key.clone(),
            self.next_request_id.fetch_add(1, Ordering::Relaxed),
        );
        {
            let mut writer = self.writer.lock().await;
            let frame = encode_xudp_packet(target, payload, writer.first_packet)?;
            writer.first_packet = false;
            if let Err(err) = writer.write_frame(&frame).await {
                self.pending.remove(&wait);
                self.close();
                return Err(err);
            }
        }
        let request_id = wait.request_id;
        let receiver = wait.receiver;
        match timeout(Duration::from_secs(20), receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.pending.remove_by_id(&target_key, request_id);
                self.close();
                anyhow::bail!("VLESS XUDP worker closed before a response arrived")
            }
            Err(_) => {
                self.pending.remove_by_id(&target_key, request_id);
                anyhow::bail!("VLESS XUDP packet response timed out")
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Ok(mut task) = self.read_task.lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
        self.pending
            .fail_all(anyhow::anyhow!("VLESS XUDP worker closed"));
    }
}

impl VlessMuxWriter {
    async fn write_frame(&mut self, frame: &[u8]) -> anyhow::Result<()> {
        if let Some(uuid) = self.vision_uuid {
            let uuid = self.vision_uuid_pending.then_some(uuid);
            self.vision_uuid_pending = false;
            let padded = xtls_padding(Some(frame), 0, uuid, true);
            self.writer.write_all(&padded).await?;
        } else {
            self.writer.write_all(frame).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }
}

impl VlessMuxReader {
    async fn read_packet(&mut self) -> anyhow::Result<XudpPacket> {
        loop {
            if let Some(packet) = take_xudp_packet(&mut self.read_buffer)? {
                return Ok(packet);
            }
            let mut encrypted = PooledBuffer::with_capacity(SMALL_FLOW_COPY_BUFFER_SIZE);
            encrypted.resize(SMALL_FLOW_COPY_BUFFER_SIZE, 0);
            let n = timeout(
                Duration::from_secs(20),
                self.reader.read(&mut encrypted[..]),
            )
            .await??;
            if n == 0 {
                anyhow::bail!("VLESS mux stream closed");
            }
            if let Some(downlink) = self.vision_downlink.as_mut() {
                let result = downlink.push(&encrypted[..n]);
                for chunk in result.chunks {
                    self.read_buffer.extend_from_slice(chunk.as_ref());
                }
            } else {
                self.read_buffer.extend_from_slice(&encrypted[..n]);
            }
        }
    }
}

fn spawn_vless_mux_reader(
    mut reader: VlessMuxReader,
    pending: PacketSessionDemux,
    closed: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let result = async {
                if !reader.response_header_read {
                    read_vless_response_header(&mut reader.reader).await?;
                    reader.response_header_read = true;
                }
                reader.read_packet().await
            }
            .await;
            match result {
                Ok(packet) => {
                    let delivered = if let Some(target) = packet.target.as_ref() {
                        let key = packet_target_key(&target.host, target.port);
                        pending.deliver(&key, Ok(packet.payload))
                    } else {
                        pending.deliver_next(Ok(packet.payload))
                    };
                    if !delivered {
                        tracing::warn!("discarded VLESS XUDP packet without a matching waiter");
                    }
                }
                Err(err) => {
                    closed.store(true, Ordering::Relaxed);
                    pending.fail_all(err);
                    break;
                }
            }
        }
    })
}

fn encode_xudp_packet(
    target: &TargetAddress,
    payload: &[u8],
    first_packet: bool,
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("XUDP payload is too large");
    }
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.push(if first_packet { 1 } else { 2 });
    out.push(1);
    out.push(2);
    encode_port_then_address(target, &mut out)?;
    if first_packet {
        out.extend_from_slice(&[0_u8; 8]);
    }
    let meta_len = out.len() - 2;
    if meta_len > u16::MAX as usize {
        anyhow::bail!("XUDP metadata is too large");
    }
    out[0..2].copy_from_slice(&(meta_len as u16).to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn take_xudp_packet(buffer: &mut BytesMut) -> anyhow::Result<Option<XudpPacket>> {
    loop {
        if buffer.len() < 2 {
            return Ok(None);
        }
        let meta_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
        if meta_len < 4 {
            anyhow::bail!("invalid XUDP metadata length: {meta_len}");
        }
        if buffer.len() < 2 + meta_len + 2 {
            return Ok(None);
        }
        let meta = &buffer[2..2 + meta_len];
        let status = meta[2];
        let option = meta[3];
        let target = if meta.len() > 4 && meta[4] == 2 {
            let (target, _) = decode_port_then_address(&meta[5..])?;
            Some(target)
        } else {
            None
        };
        let payload_len_offset = 2 + meta_len;
        let payload_len =
            u16::from_be_bytes([buffer[payload_len_offset], buffer[payload_len_offset + 1]])
                as usize;
        let frame_len = 2 + meta_len + 2 + payload_len;
        if buffer.len() < frame_len {
            return Ok(None);
        }
        let frame = buffer.split_to(frame_len);
        let payload = frame[payload_len_offset + 2..].to_vec();
        if status == 4 {
            continue;
        }
        if option & 1 == 0 || payload.is_empty() {
            continue;
        }
        return Ok(Some(XudpPacket { target, payload }));
    }
}

fn encode_port_then_address(target: &TargetAddress, out: &mut Vec<u8>) -> anyhow::Result<()> {
    out.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&target.host, out)
}

fn decode_port_then_address(input: &[u8]) -> anyhow::Result<(TargetAddress, usize)> {
    if input.len() < 3 {
        anyhow::bail!("XUDP target address is truncated");
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    let (host, address_len) = decode_address(&input[2..])?;
    Ok((TargetAddress { host, port }, address_len + 2))
}

fn decode_address(input: &[u8]) -> anyhow::Result<(String, usize)> {
    let Some(atyp) = input.first().copied() else {
        anyhow::bail!("VLESS address is empty");
    };
    match atyp {
        1 => {
            if input.len() < 5 {
                anyhow::bail!("VLESS IPv4 address is truncated");
            }
            Ok((
                Ipv4Addr::new(input[1], input[2], input[3], input[4]).to_string(),
                5,
            ))
        }
        2 => {
            if input.len() < 2 {
                anyhow::bail!("VLESS domain address is truncated");
            }
            let len = input[1] as usize;
            if input.len() < 2 + len {
                anyhow::bail!("VLESS domain address is truncated");
            }
            Ok((String::from_utf8(input[2..2 + len].to_vec())?, 2 + len))
        }
        3 => {
            if input.len() < 17 {
                anyhow::bail!("VLESS IPv6 address is truncated");
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[1..17]);
            Ok((Ipv6Addr::from(octets).to_string(), 17))
        }
        other => anyhow::bail!("invalid VLESS address type {other}"),
    }
}

fn encode_address(host: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        out.push(1);
        out.extend_from_slice(&ip.octets());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        out.push(3);
        out.extend_from_slice(&ip.octets());
        return Ok(());
    }
    if host.len() > u8::MAX as usize {
        anyhow::bail!("domain name is too long for VLESS address encoding");
    }
    out.push(2);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    Ok(())
}

fn parse_uuid(value: &str) -> anyhow::Result<[u8; 16]> {
    let compact: String = value.chars().filter(|char| *char != '-').collect();
    if compact.len() != 32 || !compact.chars().all(|char| char.is_ascii_hexdigit()) {
        anyhow::bail!("VLESS requires a valid UUID");
    }
    let mut bytes = [0_u8; 16];
    for index in 0..16 {
        bytes[index] = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

fn bridge_vless_stream<S>(
    stream: S,
    request: Vec<u8>,
    vision_uuid: Option<[u8; 16]>,
) -> BoxedProxyStream
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let (mut local_read, mut local_write) = tokio::io::split(bridge);

    tokio::spawn(async move {
        let mut vision_state = vision_uuid.map(VisionUnpaddingState::new);
        let mut first = [0u8; 2];
        match remote_read.read_exact(&mut first).await {
            Ok(_) if first[0] == 0 => {
                if first[1] > 0 {
                    let mut addon = vec![0u8; first[1] as usize];
                    if remote_read.read_exact(&mut addon).await.is_err() {
                        let _ = local_write.shutdown().await;
                        return;
                    }
                }
            }
            Ok(_) => {
                if write_downlink(&mut local_write, &mut vision_state, &first)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = local_write.shutdown().await;
                return;
            }
        }
        let mut buffer = [0u8; FLOW_COPY_BUFFER_SIZE];
        loop {
            match remote_read.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if write_downlink(&mut local_write, &mut vision_state, &buffer[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    tokio::spawn(async move {
        let first_payload = read_first_payload(&mut local_read).await;
        if let Some(uuid) = vision_uuid {
            let first_padding = xtls_padding(first_payload.as_deref(), 0, Some(uuid), true);
            if remote_write.write_all(&request).await.is_err()
                || remote_write.write_all(&first_padding).await.is_err()
            {
                let _ = remote_write.shutdown().await;
                return;
            }
            let mut uplink = VisionUplinkState::new();
            let mut buffer = [0u8; FLOW_COPY_BUFFER_SIZE];
            loop {
                match local_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) if uplink.padding() => {
                        let decision = uplink.command_for(&buffer[..n], false);
                        let padded = xtls_padding(Some(&buffer[..n]), decision.command, None, true);
                        if remote_write.write_all(&padded).await.is_err() {
                            break;
                        }
                    }
                    Ok(n) => {
                        if remote_write.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        } else {
            if remote_write.write_all(&request).await.is_err() {
                let _ = remote_write.shutdown().await;
                return;
            }
            if let Some(first_payload) = first_payload {
                if remote_write.write_all(&first_payload).await.is_err() {
                    let _ = remote_write.shutdown().await;
                    return;
                }
            }
            let _ = tokio::io::copy(&mut local_read, &mut remote_write).await;
        }
        let _ = remote_write.shutdown().await;
    });

    local
}

#[allow(dead_code)]
fn bridge_vision_stream(
    stream: tokio_rustls::client::TlsStream<RecordLimitedTcp>,
    request: Vec<u8>,
    uuid: [u8; 16],
) -> anyhow::Result<BoxedProxyStream> {
    let (local, bridge) = FlowPipe::new(LARGE_FLOW_PIPE_CAPACITY).into_parts();
    tokio::spawn(async move {
        let mut remote = VisionRemote::Tls(Some(stream));
        let (mut local_read, mut local_write) = tokio::io::split(bridge);
        let mut response_header = VlessResponseHeaderStripper::default();
        let mut downlink = VisionUnpaddingState::new(uuid);
        let mut downlink_raw = false;
        let mut downlink_direct_confirmed = false;
        let mut uplink = VisionUplinkState::new();
        let mut remote_buffer = [0u8; FLOW_COPY_BUFFER_SIZE];
        let mut local_buffer = [0u8; FLOW_COPY_BUFFER_SIZE];

        let first_payload = read_first_payload(&mut local_read).await;
        let first_padding = xtls_padding(first_payload.as_deref(), 0, Some(uuid), true);
        if remote.write_all(&request).await.is_err()
            || remote.write_all(&first_padding).await.is_err()
            || remote.flush().await.is_err()
        {
            let _ = local_write.shutdown().await;
            return;
        }

        loop {
            tokio::select! {
                read = remote.read(&mut remote_buffer) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) if downlink_raw => {
                            if local_write.write_all(&remote_buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                        Ok(n) => {
                            let Some(payload) = response_header.push(&remote_buffer[..n]) else {
                                continue;
                            };
                            if payload.is_empty() {
                                continue;
                            }
                            let result = downlink.push(&payload);
                            for chunk in result.chunks {
                                if local_write.write_all(chunk.as_ref()).await.is_err() {
                                    return;
                                }
                            }
                            if result.direct {
                                debug!("vision downlink switching to raw read");
                                if remote.switch_downlink_to_raw().is_err() {
                                    break;
                                }
                                downlink_raw = true;
                                downlink_direct_confirmed = true;
                            }
                        }
                        Err(_) => break,
                    }
                }
                read = local_read.read(&mut local_buffer) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) if uplink.padding() => {
                            let decision =
                                uplink.command_for(&local_buffer[..n], downlink_direct_confirmed);
                            debug!(command = decision.command, len = n, "vision uplink padding block");
                            let padded = xtls_padding(Some(&local_buffer[..n]), decision.command, None, true);
                            if remote.write_all(&padded).await.is_err() {
                                break;
                            }
                            if decision.direct {
                                debug!("vision uplink switching to raw write");
                                if remote.switch_uplink_to_raw().await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(n) => {
                            if remote.write_all(&local_buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        let _ = local_write.shutdown().await;
        let _ = remote.shutdown().await;
    });
    Ok(local)
}

async fn read_first_payload<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; SMALL_FLOW_COPY_BUFFER_SIZE];
    match timeout(Duration::from_millis(500), reader.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
        Ok(Ok(n)) => {
            buffer.truncate(n);
            Some(buffer)
        }
    }
}

async fn write_downlink<W>(
    writer: &mut W,
    state: &mut Option<VisionUnpaddingState>,
    data: &[u8],
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(state) = state else {
        return writer.write_all(data).await;
    };
    let result = state.push(data);
    for chunk in result.chunks {
        writer.write_all(chunk.as_ref()).await?;
    }
    Ok(())
}

fn xtls_padding(
    content: Option<&[u8]>,
    command: u8,
    uuid: Option<[u8; 16]>,
    long: bool,
) -> Vec<u8> {
    let content = content.unwrap_or(&[]);
    let padding_len = if long && content.len() < 900 {
        900usize.saturating_sub(content.len())
    } else {
        0
    };
    let mut out =
        Vec::with_capacity(uuid.map(|_| 16).unwrap_or(0) + 5 + content.len() + padding_len);
    if let Some(uuid) = uuid {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

struct VisionUnpaddingState {
    uuid: [u8; 16],
    pending: Vec<u8>,
    mode: VisionUnpaddingMode,
}

impl VisionUnpaddingState {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            pending: Vec::new(),
            mode: VisionUnpaddingMode::Unknown,
        }
    }

    fn push<'a>(&mut self, data: &'a [u8]) -> VisionPushResult<'a> {
        if matches!(self.mode, VisionUnpaddingMode::Raw) {
            return VisionPushResult {
                chunks: vec![VisionChunk::Borrowed(data)],
                direct: false,
            };
        }
        if self.pending.is_empty() {
            return self.push_without_pending(data);
        }
        self.pending.extend_from_slice(data);
        let mut output = Vec::new();
        let mut direct = false;
        loop {
            match self.mode {
                VisionUnpaddingMode::Unknown => {
                    if self.pending.len() < 16 {
                        break;
                    }
                    if self.pending[..16] == self.uuid {
                        self.pending.drain(..16);
                        self.mode = VisionUnpaddingMode::Padding;
                    } else {
                        self.mode = VisionUnpaddingMode::Raw;
                        output.push(VisionChunk::Owned(std::mem::take(&mut self.pending)));
                        break;
                    }
                }
                VisionUnpaddingMode::Padding => {
                    if self.pending.len() < 5 {
                        break;
                    }
                    let command = self.pending[0];
                    if command > 2 {
                        self.mode = VisionUnpaddingMode::Raw;
                        output.push(VisionChunk::Owned(std::mem::take(&mut self.pending)));
                        break;
                    }
                    let content_len =
                        u16::from_be_bytes([self.pending[1], self.pending[2]]) as usize;
                    let padding_len =
                        u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
                    let block_len = 5 + content_len + padding_len;
                    if self.pending.len() < block_len {
                        break;
                    }
                    if content_len > 0 {
                        output.push(VisionChunk::Owned(
                            self.pending[5..5 + content_len].to_vec(),
                        ));
                    }
                    debug!(
                        command,
                        content_len, padding_len, "vision downlink padding block"
                    );
                    self.pending.drain(..block_len);
                    if command != 0 {
                        direct = command == 2;
                        self.mode = VisionUnpaddingMode::Raw;
                        if !self.pending.is_empty() {
                            output.push(VisionChunk::Owned(std::mem::take(&mut self.pending)));
                        }
                        break;
                    }
                }
                VisionUnpaddingMode::Raw => {
                    if !self.pending.is_empty() {
                        output.push(VisionChunk::Owned(std::mem::take(&mut self.pending)));
                    }
                    break;
                }
            }
        }
        VisionPushResult {
            chunks: output,
            direct,
        }
    }

    fn push_without_pending<'a>(&mut self, data: &'a [u8]) -> VisionPushResult<'a> {
        let mut input = data;
        let mut output = Vec::new();
        let mut direct = false;

        if matches!(self.mode, VisionUnpaddingMode::Unknown) {
            if input.len() < 16 {
                self.pending.extend_from_slice(input);
                return VisionPushResult {
                    chunks: output,
                    direct,
                };
            }
            if input[..16] == self.uuid {
                input = &input[16..];
                self.mode = VisionUnpaddingMode::Padding;
            } else {
                self.mode = VisionUnpaddingMode::Raw;
                output.push(VisionChunk::Borrowed(data));
                return VisionPushResult {
                    chunks: output,
                    direct,
                };
            }
        }

        let mut offset = 0;
        while offset < input.len() {
            if input.len() - offset < 5 {
                self.pending.extend_from_slice(&input[offset..]);
                break;
            }
            let command = input[offset];
            if command > 2 {
                self.mode = VisionUnpaddingMode::Raw;
                output.push(VisionChunk::Borrowed(&input[offset..]));
                break;
            }
            let content_len = u16::from_be_bytes([input[offset + 1], input[offset + 2]]) as usize;
            let padding_len = u16::from_be_bytes([input[offset + 3], input[offset + 4]]) as usize;
            let block_len = 5 + content_len + padding_len;
            if input.len() - offset < block_len {
                self.pending.extend_from_slice(&input[offset..]);
                break;
            }
            if content_len > 0 {
                output.push(VisionChunk::Borrowed(
                    &input[offset + 5..offset + 5 + content_len],
                ));
            }
            debug!(
                command,
                content_len, padding_len, "vision downlink padding block"
            );
            offset += block_len;
            if command != 0 {
                direct = command == 2;
                self.mode = VisionUnpaddingMode::Raw;
                if offset < input.len() {
                    output.push(VisionChunk::Borrowed(&input[offset..]));
                }
                break;
            }
        }

        VisionPushResult {
            chunks: output,
            direct,
        }
    }
}

enum VisionUnpaddingMode {
    Unknown,
    Padding,
    Raw,
}

enum VisionChunk<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for VisionChunk<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}

struct VisionPushResult<'a> {
    chunks: Vec<VisionChunk<'a>>,
    direct: bool,
}

#[derive(Default)]
#[allow(dead_code)]
struct VlessResponseHeaderStripper {
    pending: Vec<u8>,
    done: bool,
}

impl VlessResponseHeaderStripper {
    fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.done {
            return Some(data.to_vec());
        }
        self.pending.extend_from_slice(data);
        if self.pending.len() < 2 {
            return None;
        }
        if self.pending[0] != 0 {
            self.done = true;
            return Some(std::mem::take(&mut self.pending));
        }
        let header_len = 2 + self.pending[1] as usize;
        if self.pending.len() < header_len {
            return None;
        }
        self.done = true;
        let payload = self.pending.split_off(header_len);
        self.pending.clear();
        Some(payload)
    }
}

#[allow(dead_code)]
enum VisionRemote {
    Tls(Option<tokio_rustls::client::TlsStream<RecordLimitedTcp>>),
    Manual {
        tcp: TcpStream,
        tls: rustls::ClientConnection,
        downlink_raw: bool,
        uplink_raw: bool,
    },
}

impl VisionRemote {
    async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(Some(stream)) => stream.read(buffer).await,
            Self::Tls(None) => Ok(0),
            Self::Manual {
                tcp,
                tls,
                downlink_raw,
                ..
            } => {
                if *downlink_raw {
                    tcp.read(buffer).await
                } else {
                    read_rustls_from_tcp(tls, tcp, buffer).await
                }
            }
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tls(Some(stream)) => stream.write_all(data).await,
            Self::Tls(None) => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS stream has switched to raw mode",
            )),
            Self::Manual {
                tcp,
                tls,
                uplink_raw,
                ..
            } => {
                if *uplink_raw {
                    tcp.write_all(data).await
                } else {
                    tls.writer().write_all(data)?;
                    flush_rustls_to_tcp(tls, tcp).await
                }
            }
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(Some(stream)) => stream.flush().await,
            Self::Tls(None) => Ok(()),
            Self::Manual { tcp, tls, .. } => {
                if !tls.wants_write() {
                    return tcp.flush().await;
                }
                flush_rustls_to_tcp(tls, tcp).await?;
                tcp.flush().await
            }
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(Some(stream)) => stream.shutdown().await,
            Self::Tls(None) => Ok(()),
            Self::Manual { tcp, tls, .. } => {
                tls.send_close_notify();
                let _ = flush_rustls_to_tcp(tls, tcp).await;
                tcp.shutdown().await
            }
        }
    }

    fn switch_downlink_to_raw(&mut self) -> std::io::Result<()> {
        self.ensure_manual()?;
        if let Self::Manual { downlink_raw, .. } = self {
            *downlink_raw = true;
        }
        Ok(())
    }

    async fn switch_uplink_to_raw(&mut self) -> std::io::Result<()> {
        self.flush().await?;
        self.ensure_manual()?;
        if let Self::Manual { uplink_raw, .. } = self {
            *uplink_raw = true;
        }
        Ok(())
    }

    fn ensure_manual(&mut self) -> std::io::Result<()> {
        let Self::Tls(stream) = self else {
            return Ok(());
        };
        let Some(stream) = stream.take() else {
            return Ok(());
        };
        let (tcp, tls) = stream.into_inner();
        *self = Self::Manual {
            tcp: tcp.into_inner(),
            tls,
            downlink_raw: false,
            uplink_raw: false,
        };
        Ok(())
    }
}

#[allow(dead_code)]
async fn read_rustls_from_tcp(
    tls: &mut rustls::ClientConnection,
    tcp: &mut TcpStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        match tls.reader().read(buffer) {
            Ok(n) if n > 0 => return Ok(n),
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
        let mut encrypted = [0_u8; SMALL_FLOW_COPY_BUFFER_SIZE];
        let n = tcp.read(&mut encrypted).await?;
        if n == 0 {
            return Ok(0);
        }
        let mut input = std::io::Cursor::new(&encrypted[..n]);
        tls.read_tls(&mut input)?;
        tls.process_new_packets()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    }
}

#[allow(dead_code)]
async fn flush_rustls_to_tcp(
    tls: &mut rustls::ClientConnection,
    tcp: &mut TcpStream,
) -> std::io::Result<()> {
    while tls.wants_write() {
        let mut encrypted = [0_u8; SMALL_FLOW_COPY_BUFFER_SIZE];
        let mut output = std::io::Cursor::new(&mut encrypted[..]);
        let written = tls.write_tls(&mut output)?;
        if written == 0 {
            break;
        }
        tcp.write_all(&encrypted[..written]).await?;
    }
    Ok(())
}

struct RecordLimitedTcp {
    tcp: TcpStream,
    header: [u8; 5],
    header_len: usize,
    remaining_body: Option<usize>,
    pending_yield: bool,
}

impl RecordLimitedTcp {
    fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            header: [0; 5],
            header_len: 0,
            remaining_body: None,
            pending_yield: false,
        }
    }

    #[allow(dead_code)]
    fn into_inner(self) -> TcpStream {
        self.tcp
    }
}

impl AsyncRead for RecordLimitedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pending_yield {
            self.pending_yield = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let limit = if let Some(remaining) = self.remaining_body {
            remaining.min(buf.remaining())
        } else {
            (5 - self.header_len).min(buf.remaining())
        };
        let mut temp = [0_u8; 16 * 1024];
        let temp_len = limit.min(temp.len());
        let mut limited = ReadBuf::new(&mut temp[..temp_len]);
        match Pin::new(&mut self.tcp).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let read = limited.filled().len();
        if read == 0 {
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(limited.filled());

        if let Some(remaining) = self.remaining_body {
            let next = remaining.saturating_sub(read);
            if next == 0 {
                self.remaining_body = None;
                self.header_len = 0;
                self.header = [0; 5];
                self.pending_yield = true;
            } else {
                self.remaining_body = Some(next);
            }
        } else {
            let just_read = limited.filled();
            let header_start = self.header_len;
            let header_end = header_start + read;
            self.header[header_start..header_end].copy_from_slice(just_read);
            self.header_len += read;
            if self.header_len == 5 {
                let body_len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if body_len == 0 {
                    self.header_len = 0;
                    self.header = [0; 5];
                    self.pending_yield = true;
                } else {
                    self.remaining_body = Some(body_len);
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordLimitedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

struct VisionUplinkState {
    traffic: VisionTrafficState,
}

const VISION_UPLINK_DIRECT_MIN_BYTES: usize = 8 * 1024;
const VISION_PACKET_FILTER_LIMIT: i32 = 8;

impl VisionUplinkState {
    fn new() -> Self {
        Self {
            traffic: VisionTrafficState::new(),
        }
    }

    fn padding(&self) -> bool {
        self.traffic.uplink.padding
    }

    fn command_for(&mut self, data: &[u8], peer_direct_confirmed: bool) -> VisionUplinkDecision {
        self.traffic.filter_tls(data);
        if self.traffic.is_tls_handshake(data) {
            return VisionUplinkDecision::padding(0);
        }
        if self.traffic.is_tls
            && !self.traffic.uplink.direct_sent
            && data.starts_with(&[0x17, 0x03, 0x03])
            && (peer_direct_confirmed || data.len() >= VISION_UPLINK_DIRECT_MIN_BYTES)
            && is_complete_tls_application_data(data)
        {
            self.traffic.uplink.padding = false;
            self.traffic.uplink.direct_sent = true;
            self.traffic.uplink.direct_copy = true;
            return VisionUplinkDecision {
                command: 2,
                direct: true,
            };
        }
        if !self.traffic.is_tls {
            self.traffic.uplink.padding = false;
            return VisionUplinkDecision::padding(1);
        }
        VisionUplinkDecision::padding(0)
    }
}

struct VisionTrafficState {
    packet_filter_remaining: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    is_tls13: bool,
    remaining_server_hello: i32,
    uplink: VisionLinkState,
    #[allow(dead_code)]
    downlink: VisionLinkState,
}

struct VisionLinkState {
    padding: bool,
    direct_copy: bool,
    direct_sent: bool,
}

impl VisionTrafficState {
    fn new() -> Self {
        Self {
            packet_filter_remaining: VISION_PACKET_FILTER_LIMIT,
            is_tls: false,
            is_tls12_or_above: false,
            is_tls13: false,
            remaining_server_hello: -1,
            uplink: VisionLinkState::new(),
            downlink: VisionLinkState::new(),
        }
    }

    fn is_tls_handshake(&self, data: &[u8]) -> bool {
        data.starts_with(&[0x16, 0x03])
    }

    fn filter_tls(&mut self, data: &[u8]) {
        if self.packet_filter_remaining <= 0 {
            return;
        }
        self.packet_filter_remaining -= 1;
        if data.len() < 6 {
            return;
        }
        if data.starts_with(&[0x16, 0x03]) {
            self.is_tls = true;
            return;
        }
        if data.starts_with(&[0x16, 0x03, 0x03]) && data[5] == 0x02 {
            self.is_tls = true;
            self.is_tls12_or_above = true;
            self.remaining_server_hello =
                (i32::from(data[3]) << 8 | i32::from(data[4])).saturating_add(5);
            if data
                .windows(6)
                .any(|window| window == [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
            {
                self.is_tls13 = true;
                self.packet_filter_remaining = 0;
            }
        }
    }
}

impl VisionLinkState {
    fn new() -> Self {
        Self {
            padding: true,
            direct_copy: false,
            direct_sent: false,
        }
    }
}

struct VisionUplinkDecision {
    command: u8,
    direct: bool,
}

impl VisionUplinkDecision {
    fn padding(command: u8) -> Self {
        Self {
            command,
            direct: false,
        }
    }
}

fn is_complete_tls_application_data(data: &[u8]) -> bool {
    let mut offset = 0;
    while offset < data.len() {
        if data.len() - offset < 5 {
            return false;
        }
        if data[offset] != 0x17 || data[offset + 1] != 0x03 || data[offset + 2] != 0x03 {
            return false;
        }
        let record_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        offset += 5;
        if data.len() - offset < record_len {
            return false;
        }
        offset += record_len;
    }
    offset == data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::KernelDnsConfig;
    use serde_json::json;
    use tokio::net::TcpListener;

    #[test]
    fn config_accepts_reality_parameters() {
        let node = KernelNode {
            id: None,
            protocol: "vless".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            parameters: json!({
                "security": "reality",
                "sni": "www.example.com",
                "pbk": "public-key",
                "sid": "short-id",
                "fp": "chrome"
            }),
        };

        let config = VlessConfig::from_node(&node).unwrap();
        assert_eq!(config.uuid[0], 0x00);
        assert_eq!(config.uuid[15], 0xff);
        assert_eq!(config.sni, Some("www.example.com".to_string()));
    }

    #[test]
    fn config_accepts_tls_tcp_parameters() {
        let node = KernelNode {
            id: None,
            protocol: "vless".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            parameters: json!({
                "security": "tls",
                "type": "tcp",
                "sni": "www.example.com"
            }),
        };

        VlessAdapter.validate(&node).unwrap();
    }

    #[test]
    fn config_accepts_vless_websocket_transport() {
        let node = KernelNode {
            id: None,
            protocol: "vless".to_string(),
            server: "server.example.com".to_string(),
            server_port: 443,
            user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            parameters: json!({
                "security": "tls",
                "type": "ws",
                "host": "cdn.example.com",
                "path": "/ray"
            }),
        };

        let config = VlessConfig::from_node(&node).unwrap();
        assert_eq!(config.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(config.transport.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(config.transport.path, "/ray");
    }

    #[test]
    fn config_accepts_vless_h2_grpc_httpupgrade_and_xhttp_transports() {
        for (transport, expected) in [
            ("h2", VlessTransportKind::H2),
            ("grpc", VlessTransportKind::Grpc),
            ("httpupgrade", VlessTransportKind::HttpUpgrade),
            ("xhttp", VlessTransportKind::XHttp),
            ("splithttp", VlessTransportKind::XHttp),
        ] {
            let node = KernelNode {
                id: None,
                protocol: "vless".to_string(),
                server: "server.example.com".to_string(),
                server_port: 443,
                user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
                parameters: json!({
                    "security": "tls",
                    "type": transport,
                    "serviceName": "svc",
                    "path": "/x",
                    "mode": "stream-one"
                }),
            };

            let config = VlessConfig::from_node(&node).unwrap();
            assert_eq!(config.transport.kind, expected);
        }
    }

    #[test]
    fn grpc_path_matches_service_name_shape() {
        assert_eq!(grpc_path("svc"), "/svc/Tun");
        assert_eq!(grpc_path("/custom/TunMulti"), "/custom/TunMulti");
    }

    #[test]
    fn grpc_hunk_frame_round_trips_payload() {
        let frame = encode_grpc_hunk(b"hello");
        let mut decoder = GrpcHunkDecoder::default();

        assert_eq!(decoder.push(&frame[..3]).len(), 0);
        assert_eq!(decoder.push(&frame[3..]), vec![b"hello".to_vec()]);
    }

    #[test]
    fn xhttp_h3_and_packet_tuning_parameters_parse() {
        let node = KernelNode {
            id: None,
            protocol: "vless".to_string(),
            server: "server.example.com".to_string(),
            server_port: 443,
            user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            parameters: json!({
                "security": "tls",
                "type": "xhttp",
                "alpn": "h3",
                "mode": "packet-up",
                "scMaxEachPostBytes": "131072",
                "scMinPostsIntervalMs": "3",
                "xmuxMaxConcurrency": "8"
            }),
        };

        let config = VlessConfig::from_node(&node).unwrap();
        assert_eq!(config.transport.kind, VlessTransportKind::XHttp);
        assert_eq!(config.transport.http_version, XHttpVersion::H3);
        assert_eq!(config.transport.sc_max_each_post_bytes, 131072);
        assert_eq!(config.transport.sc_min_posts_interval_ms, 3);
        assert_eq!(config.transport.xmux.max_concurrency, 8);
    }

    #[test]
    fn xhttp_query_builder_preserves_existing_query() {
        assert_eq!(
            xhttp_path_with_query_raw("/x?ed=1", "abc", Some(7)),
            "/x?ed=1&session=abc&seq=7"
        );
    }

    #[test]
    fn chrome_fingerprint_sets_ja_profile_fields() {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![&REALITY_X25519_GROUP];
        let verifier = RealityCertificateVerifier::new(provider.clone());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        apply_tls_fingerprint_profile(&mut config, Some("chrome")).unwrap();

        assert_eq!(config.client_hello_grease, Some(0x0a0a));
        assert_eq!(
            config.client_hello_cipher_suites.as_ref().unwrap()[..2],
            [
                CipherSuite::Unknown(0x0a0a),
                CipherSuite::TLS13_AES_128_GCM_SHA256
            ]
        );
        assert_eq!(
            config.client_hello_supported_groups.as_ref().unwrap()[..2],
            [NamedGroup::Unknown(0x0a0a), NamedGroup::X25519]
        );
        assert_eq!(
            config.client_hello_signature_schemes.as_ref().unwrap()[0],
            SignatureScheme::ECDSA_NISTP256_SHA256
        );
    }

    #[test]
    fn tcp_request_encodes_domain_target() {
        let target = TargetAddress {
            host: "example.com".to_string(),
            port: 443,
        };

        let request =
            build_tcp_request("00112233-4455-6677-8899-aabbccddeeff", None, &target).unwrap();

        assert_eq!(request[0], 0);
        assert_eq!(
            &request[1..17],
            &[0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]
        );
        assert_eq!(request[17], 0);
        assert_eq!(request[18], 1);
        assert_eq!(&request[19..21], &443_u16.to_be_bytes());
        assert_eq!(request[21], 2);
        assert_eq!(request[22], "example.com".len() as u8);
        assert_eq!(&request[23..], b"example.com");
    }

    #[test]
    fn addon_uses_protobuf_flow_encoding() {
        let addon = build_addon(Some("xtls-rprx-vision")).unwrap();

        assert_eq!(addon[0], 0x0a);
        assert_eq!(addon[1] as usize, "xtls-rprx-vision".len());
        assert_eq!(&addon[2..], b"xtls-rprx-vision");
    }

    #[test]
    fn udp_request_uses_vless_udp_command() {
        let target = TargetAddress {
            host: "8.8.8.8".to_string(),
            port: 53,
        };
        let request = build_request(
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
            VlessCommand::Udp,
            &target,
        )
        .unwrap();

        assert_eq!(request[18], 2);
        assert_eq!(&request[19..21], &53_u16.to_be_bytes());
        assert_eq!(request[21], 1);
        assert_eq!(&request[22..], &[8, 8, 8, 8]);
    }

    #[test]
    fn xudp_new_packet_encodes_mux_metadata() {
        let target = TargetAddress {
            host: "8.8.8.8".to_string(),
            port: 53,
        };
        let packet = encode_xudp_packet(&target, b"query", true).unwrap();

        let meta_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
        assert_eq!(meta_len, 20);
        assert_eq!(&packet[2..4], &[0, 0]);
        assert_eq!(packet[4], 1);
        assert_eq!(packet[5], 1);
        assert_eq!(packet[6], 2);
        assert_eq!(&packet[7..9], &53_u16.to_be_bytes());
        assert_eq!(packet[9], 1);
        assert_eq!(&packet[10..14], &[8, 8, 8, 8]);
        assert_eq!(&packet[14..22], &[0_u8; 8]);
        assert_eq!(&packet[22..24], &5_u16.to_be_bytes());
        assert_eq!(&packet[24..], b"query");
    }

    #[test]
    fn xudp_reader_extracts_payload() {
        let target = TargetAddress {
            host: "8.8.8.8".to_string(),
            port: 53,
        };
        let frame = encode_xudp_packet(&target, b"reply", true).unwrap();
        let mut buffer = BytesMut::from(frame.as_slice());

        let packet = take_xudp_packet(&mut buffer).unwrap().unwrap();

        assert_eq!(&packet.payload, b"reply");
        assert_eq!(packet.target.as_ref().unwrap(), &target);
        assert!(buffer.is_empty());
    }

    #[test]
    fn xudp_followup_packet_preserves_target_metadata() {
        let target = TargetAddress {
            host: "dns.google".to_string(),
            port: 53,
        };
        let packet = encode_xudp_packet(&target, b"reply", false).unwrap();
        let meta_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
        let mut buffer = BytesMut::from(packet.as_slice());

        assert!(meta_len > 4);
        let decoded = take_xudp_packet(&mut buffer).unwrap().unwrap();

        assert_eq!(decoded.target.as_ref().unwrap(), &target);
        assert_eq!(&decoded.payload, b"reply");
    }

    #[test]
    fn xudp_reader_keeps_targetless_packet_for_fifo_fallback() {
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&4_u16.to_be_bytes());
        buffer.extend_from_slice(&[0, 0, 2, 1]);
        buffer.extend_from_slice(&5_u16.to_be_bytes());
        buffer.extend_from_slice(b"reply");

        let packet = take_xudp_packet(&mut buffer).unwrap().unwrap();

        assert!(packet.target.is_none());
        assert_eq!(&packet.payload, b"reply");
    }

    #[tokio::test]
    async fn mux_worker_relays_xudp_packet() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target = TargetAddress {
            host: "8.8.8.8".to_string(),
            port: 53,
        };
        let server_task = tokio::spawn(async move {
            let mut len = [0_u8; 2];
            server.read_exact(&mut len).await.unwrap();
            let meta_len = u16::from_be_bytes(len) as usize;
            let mut meta = vec![0_u8; meta_len];
            server.read_exact(&mut meta).await.unwrap();
            assert_eq!(meta[2], 1);
            assert_eq!(meta[3], 1);

            server.read_exact(&mut len).await.unwrap();
            let payload_len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; payload_len];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"query");

            server.write_all(&[0, 0]).await.unwrap();
            let response = encode_xudp_packet(
                &TargetAddress {
                    host: "8.8.8.8".to_string(),
                    port: 53,
                },
                b"reply",
                false,
            )
            .unwrap();
            server.write_all(&response).await.unwrap();
        });
        let worker = VlessMuxWorker::new(boxed_stream(client), None);

        let response = worker.send_packet(&target, b"query").await.unwrap();

        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_adapter_connects_and_strips_response_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 32];
            let len = stream.read(&mut request).await.unwrap();
            assert_eq!(request[0], 0);
            assert_eq!(request[18], 1);
            assert!(len > 21);
            stream.write_all(&[0, 0]).await.unwrap();
            stream.write_all(b"payload").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let node = KernelNode {
            id: None,
            protocol: "vless".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: port,
            user_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            parameters: json!({
                "security": "none",
                "type": "tcp"
            }),
        };
        let target = TargetAddress {
            host: "example.com".to_string(),
            port: 443,
        };
        let resolver = DnsResolver::new(KernelDnsConfig::default());
        let context = OutboundContext {
            resolver: &resolver,
        };

        let mut stream = VlessAdapter
            .connect(&node, &target, &context)
            .await
            .unwrap();
        let mut payload = [0_u8; 7];
        stream.read_exact(&mut payload).await.unwrap();

        assert_eq!(&payload, b"payload");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_packet_writer_uses_vless_length_packets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 26];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0);
            assert_eq!(request[18], 2);
            assert_eq!(&request[19..21], &53_u16.to_be_bytes());
            assert_eq!(request[21], 1);
            assert_eq!(&request[22..26], &[8, 8, 8, 8]);

            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"query");

            stream.write_all(&[0, 0]).await.unwrap();
            stream.write_all(&5_u16.to_be_bytes()).await.unwrap();
            stream.write_all(b"reply").await.unwrap();
        });

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let target = TargetAddress {
            host: "8.8.8.8".to_string(),
            port: 53,
        };
        let request = build_request(
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
            VlessCommand::Udp,
            &target,
        )
        .unwrap();
        let response = send_udp_packet(stream, request, b"query").await.unwrap();

        assert_eq!(&response, b"reply");
        server.await.unwrap();
    }

    #[test]
    fn vision_uplink_keeps_padding_for_small_complete_tls_application_data() {
        let mut state = VisionUplinkState::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(state.command_for(&client_hello, false).command, 0);

        let application_data = [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let decision = state.command_for(&application_data, false);

        assert_eq!(decision.command, 0);
        assert!(!decision.direct);
        assert!(state.padding());
    }

    #[test]
    fn vision_uplink_switches_to_direct_on_large_complete_tls_application_data() {
        let mut state = VisionUplinkState::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(state.command_for(&client_hello, false).command, 0);

        let payload_len = VISION_UPLINK_DIRECT_MIN_BYTES - 5;
        let mut application_data = Vec::with_capacity(VISION_UPLINK_DIRECT_MIN_BYTES);
        application_data.extend_from_slice(&[
            0x17,
            0x03,
            0x03,
            (payload_len >> 8) as u8,
            payload_len as u8,
        ]);
        application_data.resize(VISION_UPLINK_DIRECT_MIN_BYTES, 0xaa);

        let decision = state.command_for(&application_data, false);

        assert_eq!(decision.command, 2);
        assert!(decision.direct);
        assert!(!state.padding());
    }

    #[test]
    fn vision_uplink_switches_small_complete_tls_after_peer_direct() {
        let mut state = VisionUplinkState::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(state.command_for(&client_hello, false).command, 0);

        let application_data = [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let decision = state.command_for(&application_data, true);

        assert_eq!(decision.command, 2);
        assert!(decision.direct);
        assert!(!state.padding());
    }

    #[test]
    fn vision_downlink_switches_to_direct_on_command_two() {
        let uuid = [7_u8; 16];
        let mut state = VisionUnpaddingState::new(uuid);
        let mut block = Vec::new();
        block.extend_from_slice(&uuid);
        block.extend_from_slice(&[2, 0, 3, 0, 0, b'a', b'b', b'c']);

        let result = state.push(&block);

        assert!(result.direct);
        let chunks = vision_chunks_to_vec(result.chunks);
        assert_eq!(chunks, vec![b"abc".to_vec()]);
    }

    fn vision_chunks_to_vec(chunks: Vec<VisionChunk<'_>>) -> Vec<Vec<u8>> {
        chunks
            .into_iter()
            .map(|chunk| chunk.as_ref().to_vec())
            .collect()
    }

    #[test]
    fn vision_uplink_keeps_padding_for_partial_tls_application_data() {
        let mut state = VisionUplinkState::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(state.command_for(&client_hello, false).command, 0);

        let partial_application_data = [0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb];
        let decision = state.command_for(&partial_application_data, false);

        assert_eq!(decision.command, 0);
        assert!(!decision.direct);
        assert!(state.padding());
    }
}
