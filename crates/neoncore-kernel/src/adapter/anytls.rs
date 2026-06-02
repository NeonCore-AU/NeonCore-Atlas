use crate::{
    adapter::{BoxedProxyStream, NetworkCapability, OutboundAdapter, OutboundContext},
    session::{KernelNode, TargetAddress},
    tcp_tuning::tune_tcp_stream,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex as StdMutex, OnceLock, Weak,
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex},
    time::{timeout, Duration},
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    },
    TlsConnector,
};

pub struct AnyTlsAdapter;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PUSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const HEADER_LEN: usize = 7;
const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
const DEFAULT_IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MIN_IDLE_SESSIONS: usize = 0;
const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

static CLIENTS: OnceLock<Mutex<HashMap<String, Weak<AnyTlsClient>>>> = OnceLock::new();

#[async_trait::async_trait]
impl OutboundAdapter for AnyTlsAdapter {
    fn protocol_names(&self) -> &'static [&'static str] {
        &["anytls"]
    }

    fn networks(&self) -> &'static [NetworkCapability] {
        &[NetworkCapability::Tcp, NetworkCapability::Udp]
    }

    fn validate(&self, node: &KernelNode) -> anyhow::Result<()> {
        AnyTlsConfig::from_node(node)?;
        Ok(())
    }

    async fn connect(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = AnyTlsConfig::from_node(node)?;
        let client = client_for(config, context).await?;
        Ok(Box::pin(client.open_stream(target.clone()).await?))
    }

    async fn send_udp(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let config = AnyTlsConfig::from_node(node)?;
        let client = client_for(config, context).await?;
        client.send_uot(target.clone(), payload).await
    }
}

#[derive(Debug, Clone)]
struct AnyTlsConfig {
    server: String,
    server_port: u16,
    password: String,
    sni: String,
    insecure: bool,
    idle_session_timeout: Duration,
    min_idle_sessions: usize,
}

impl AnyTlsConfig {
    fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        if node.server.is_empty() || node.server_port == 0 {
            anyhow::bail!("AnyTLS endpoint is invalid");
        }
        if node.user_id.is_empty() {
            anyhow::bail!("AnyTLS requires a password");
        }
        Ok(Self {
            server: node.server.clone(),
            server_port: node.server_port,
            password: node.user_id.clone(),
            sni: node.parameter("sni").unwrap_or(&node.server).to_string(),
            insecure: node
                .parameter("insecure")
                .or_else(|| node.parameter("skip-cert-verify"))
                .map(|value| matches!(value, "1" | "true" | "yes"))
                .unwrap_or(false),
            idle_session_timeout: node
                .parameter("idle_session_timeout")
                .or_else(|| node.parameter("idle-session-timeout"))
                .and_then(parse_duration)
                .unwrap_or(DEFAULT_IDLE_SESSION_TIMEOUT),
            min_idle_sessions: node
                .parameter("min_idle_session")
                .or_else(|| node.parameter("min-idle-session"))
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_MIN_IDLE_SESSIONS),
        })
    }

    fn cache_key(&self) -> String {
        format!(
            "{}:{}|{}|{}|{}",
            self.server, self.server_port, self.sni, self.password, self.insecure
        )
    }
}

fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Some(seconds) = value.strip_suffix('s') {
        return seconds.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds.parse::<u64>().ok().map(Duration::from_millis);
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

async fn client_for(
    mut config: AnyTlsConfig,
    context: &OutboundContext<'_>,
) -> anyhow::Result<Arc<AnyTlsClient>> {
    let key = config.cache_key();
    let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let mut clients = clients.lock().await;
        if let Some(client) = clients.get(&key).and_then(Weak::upgrade) {
            return Ok(client);
        }
        clients.retain(|_, client| client.strong_count() > 0);
    }

    let resolved = context
        .resolver
        .resolve_proxy_server(&TargetAddress {
            host: config.server.clone(),
            port: config.server_port,
        })
        .await?;
    let address = resolved
        .first()
        .ok_or_else(|| anyhow::anyhow!("no usable resolved address for AnyTLS server"))?;
    config.server = address.ip().to_string();

    let client = Arc::new(AnyTlsClient {
        config,
        idle: Mutex::new(VecDeque::new()),
        udp: Mutex::new(HashMap::new()),
    });
    clients.lock().await.insert(key, Arc::downgrade(&client));
    Ok(client)
}

struct AnyTlsClient {
    config: AnyTlsConfig,
    idle: Mutex<VecDeque<IdleSession>>,
    udp: Mutex<HashMap<String, Arc<AnyTlsUdpConn>>>,
}

struct IdleSession {
    session: Arc<AnyTlsSession>,
    since: Instant,
}

impl AnyTlsClient {
    async fn open_stream(self: Arc<Self>, target: TargetAddress) -> anyhow::Result<AnyTlsStream> {
        self.cleanup_idle().await;
        let session = match self.take_idle().await {
            Some(session) => session,
            None => self.create_session().await?,
        };
        let stream = session.open_stream(target).await?;
        Ok(AnyTlsStream {
            client: Arc::downgrade(&self),
            session,
            stream_id: stream.stream_id,
            incoming: stream.incoming,
            current: None,
            closed: false,
            synack: Some(stream.synack),
        })
    }

    async fn send_uot(
        self: Arc<Self>,
        target: TargetAddress,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.cleanup_udp().await;
        let key = udp_conn_key(&target);
        let conn = Arc::clone(&self)
            .udp_conn(key.clone(), target.clone())
            .await?;
        match conn.send(payload).await {
            Ok(response) => Ok(response),
            Err(first_error) => {
                conn.close();
                self.remove_udp_conn(&key, &conn).await;
                let conn = Arc::clone(&self).udp_conn(key, target).await?;
                conn.send(payload).await.map_err(|second_error| {
                    anyhow::anyhow!(
                        "AnyTLS UoT packet conn failed after reconnect: {second_error}; previous error: {first_error}"
                    )
                })
            }
        }
    }

    async fn udp_conn(
        self: Arc<Self>,
        key: String,
        target: TargetAddress,
    ) -> anyhow::Result<Arc<AnyTlsUdpConn>> {
        {
            let udp = self.udp.lock().await;
            if let Some(conn) = udp.get(&key) {
                if !conn.is_closed() {
                    return Ok(Arc::clone(conn));
                }
            }
        }

        let conn = Arc::new(AnyTlsUdpConn::open(Arc::clone(&self), target).await?);
        let mut udp = self.udp.lock().await;
        match udp.get(&key) {
            Some(existing) if !existing.is_closed() => Ok(Arc::clone(existing)),
            _ => {
                udp.insert(key, Arc::clone(&conn));
                Ok(conn)
            }
        }
    }

    async fn remove_udp_conn(&self, key: &str, conn: &Arc<AnyTlsUdpConn>) {
        let mut udp = self.udp.lock().await;
        if udp
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, conn))
        {
            udp.remove(key);
        }
    }

    async fn cleanup_udp(&self) {
        let mut udp = self.udp.lock().await;
        let timeout = self.config.idle_session_timeout;
        udp.retain(|_, conn| !conn.is_closed() && !conn.is_idle_expired(timeout));
    }

    async fn take_idle(&self) -> Option<Arc<AnyTlsSession>> {
        let mut idle = self.idle.lock().await;
        while let Some(entry) = idle.pop_back() {
            if !entry.session.is_closed() {
                return Some(entry.session);
            }
        }
        None
    }

    async fn release(&self, session: Arc<AnyTlsSession>) {
        if session.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().await;
        idle.push_back(IdleSession {
            session,
            since: Instant::now(),
        });
    }

    async fn cleanup_idle(&self) {
        let mut idle = self.idle.lock().await;
        let timeout = self.config.idle_session_timeout;
        let min_idle = self.config.min_idle_sessions;
        let mut kept = VecDeque::with_capacity(idle.len());
        while let Some(entry) = idle.pop_front() {
            let expired = entry.since.elapsed() >= timeout;
            if entry.session.is_closed() || (expired && kept.len() >= min_idle) {
                entry.session.close();
            } else {
                kept.push_back(entry);
            }
        }
        *idle = kept;
    }

    async fn create_session(&self) -> anyhow::Result<Arc<AnyTlsSession>> {
        let server = format!("{}:{}", self.config.server, self.config.server_port);
        let tcp = TcpStream::connect(&server).await?;
        tune_tcp_stream(&tcp);
        let tls_config = build_tls_config(self.config.insecure)?;
        let server_name = build_server_name(&self.config.sni)?;
        let tls = TlsConnector::from(Arc::new(tls_config))
            .connect(server_name, tcp)
            .await?;
        let (reader, writer) = tokio::io::split(tls);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let session = Arc::new(AnyTlsSession {
            write_tx,
            streams: Mutex::new(HashMap::new()),
            synacks: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            padding: Mutex::new(PaddingFactory::default()),
            packet_counter: AtomicU32::new(1),
            closed: AtomicBool::new(false),
        });

        send_authentication(&session.write_tx, &self.config.password)?;
        send_settings(&session)?;

        tokio::spawn(write_loop(writer, write_rx, Arc::downgrade(&session)));
        tokio::spawn(read_loop(reader, Arc::downgrade(&session)));
        Ok(session)
    }
}

struct AnyTlsUdpConn {
    target: TargetAddress,
    stream: Mutex<AnyTlsStream>,
    last_used: StdMutex<Instant>,
    closed: AtomicBool,
}

impl AnyTlsUdpConn {
    async fn open(client: Arc<AnyTlsClient>, target: TargetAddress) -> anyhow::Result<Self> {
        let mut stream = client
            .open_stream(TargetAddress {
                host: UOT_MAGIC_ADDRESS.to_string(),
                port: 0,
            })
            .await?;
        let mut request = Vec::new();
        request.push(0);
        request.extend_from_slice(&encode_socks_address(&target)?);
        stream.write_all(&request).await?;
        stream.flush().await?;

        Ok(Self {
            target,
            stream: Mutex::new(stream),
            last_used: StdMutex::new(Instant::now()),
            closed: AtomicBool::new(false),
        })
    }

    async fn send(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS UoT packet conn is closed");
        }
        let packet = encode_uot_packet(self.target.clone(), payload)?;
        let mut stream = self.stream.lock().await;
        stream.write_all(&packet).await?;
        stream.flush().await?;
        let response = timeout(
            Duration::from_secs(20),
            read_uot_packet(&mut *stream, false),
        )
        .await
        .map_err(|_| anyhow::anyhow!("AnyTLS UoT packet timed out"))??;
        self.touch();
        Ok(response.1)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn is_idle_expired(&self, timeout: Duration) -> bool {
        self.last_used
            .lock()
            .map(|last_used| last_used.elapsed() >= timeout)
            .unwrap_or(true)
    }

    fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = Instant::now();
        }
    }
}

fn udp_conn_key(target: &TargetAddress) -> String {
    format!("{}:{}", target.host, target.port)
}

struct AnyTlsSession {
    write_tx: mpsc::UnboundedSender<SessionWrite>,
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>,
    synacks: Mutex<HashMap<u32, oneshot::Sender<anyhow::Result<()>>>>,
    next_stream_id: AtomicU32,
    padding: Mutex<PaddingFactory>,
    packet_counter: AtomicU32,
    closed: AtomicBool,
}

impl AnyTlsSession {
    async fn open_stream(self: &Arc<Self>, target: TargetAddress) -> anyhow::Result<OpenStream> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS session is closed");
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (synack_tx, synack_rx) = oneshot::channel();
        self.streams.lock().await.insert(stream_id, incoming_tx);
        self.synacks.lock().await.insert(stream_id, synack_tx);

        let mut initial = Vec::new();
        append_frame(&mut initial, CMD_SYN, stream_id, &[])?;
        let destination = encode_socks_address(&target)?;
        append_frame(&mut initial, CMD_PUSH, stream_id, &destination)?;
        self.write_tx
            .send(SessionWrite::Frames(Bytes::from(initial)))
            .map_err(|_| anyhow::anyhow!("AnyTLS writer is closed"))?;

        Ok(OpenStream {
            stream_id,
            incoming: incoming_rx,
            synack: synack_rx,
        })
    }

    fn write_data(&self, stream_id: u32, data: Bytes) -> std::io::Result<usize> {
        let len = data.len();
        self.write_tx
            .send(SessionWrite::Frame {
                cmd: CMD_PUSH,
                stream_id,
                data,
            })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AnyTLS closed"))?;
        Ok(len)
    }

    fn finish_stream(&self, stream_id: u32) {
        let _ = self.write_tx.send(SessionWrite::Frame {
            cmd: CMD_FIN,
            stream_id,
            data: Bytes::new(),
        });
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.write_tx.send(SessionWrite::Close);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

struct OpenStream {
    stream_id: u32,
    incoming: mpsc::UnboundedReceiver<Bytes>,
    synack: oneshot::Receiver<anyhow::Result<()>>,
}

enum SessionWrite {
    Raw(Bytes),
    Frames(Bytes),
    Frame {
        cmd: u8,
        stream_id: u32,
        data: Bytes,
    },
    Close,
}

struct AnyTlsStream {
    client: Weak<AnyTlsClient>,
    session: Arc<AnyTlsSession>,
    stream_id: u32,
    incoming: mpsc::UnboundedReceiver<Bytes>,
    current: Option<Bytes>,
    closed: bool,
    synack: Option<oneshot::Receiver<anyhow::Result<()>>>,
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if !self.closed {
            self.session.finish_stream(self.stream_id);
        }
        let session = Arc::clone(&self.session);
        let stream_id = self.stream_id;
        tokio::spawn(async move {
            session.streams.lock().await.remove(&stream_id);
            session.synacks.lock().await.remove(&stream_id);
        });
        if let Some(client) = self.client.upgrade() {
            let session = Arc::clone(&self.session);
            tokio::spawn(async move {
                client.release(session).await;
            });
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(synack) = self.synack.as_mut() {
            match Pin::new(synack).poll(cx) {
                Poll::Ready(Ok(Ok(()))) | Poll::Ready(Err(_)) => {
                    self.synack = None;
                }
                Poll::Ready(Ok(Err(err))) => {
                    self.synack = None;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        err.to_string(),
                    )));
                }
                Poll::Pending => {}
            }
        }

        loop {
            if let Some(current) = self.current.as_mut() {
                let n = current.len().min(buf.remaining());
                if n > 0 {
                    buf.put_slice(&current[..n]);
                    current.advance(n);
                    if current.is_empty() {
                        self.current = None;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
            match Pin::new(&mut self.incoming).poll_recv(cx) {
                Poll::Ready(Some(data)) => self.current = Some(data),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closed || self.session.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS stream is closed",
            )));
        }
        Poll::Ready(
            self.session
                .write_data(self.stream_id, Bytes::copy_from_slice(data)),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.closed {
            self.session.finish_stream(self.stream_id);
            let session = Arc::clone(&self.session);
            let stream_id = self.stream_id;
            tokio::spawn(async move {
                session.streams.lock().await.remove(&stream_id);
                session.synacks.lock().await.remove(&stream_id);
            });
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

async fn write_loop(
    mut writer: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut write_rx: mpsc::UnboundedReceiver<SessionWrite>,
    session: Weak<AnyTlsSession>,
) {
    while let Some(item) = write_rx.recv().await {
        let Some(session) = session.upgrade() else {
            break;
        };
        let result = match item {
            SessionWrite::Raw(bytes) => writer.write_all(&bytes).await.map_err(anyhow::Error::from),
            SessionWrite::Frames(frames) => {
                write_with_padding(&mut writer, &session, BytesMut::from(&frames[..])).await
            }
            SessionWrite::Frame {
                cmd,
                stream_id,
                data,
            } => {
                let mut frame = Vec::with_capacity(HEADER_LEN + data.len());
                let result = append_frame(&mut frame, cmd, stream_id, &data);
                match result {
                    Ok(()) => {
                        write_with_padding(&mut writer, &session, BytesMut::from(&frame[..])).await
                    }
                    Err(err) => Err(err),
                }
            }
            SessionWrite::Close => break,
        };
        if result.is_err() {
            session.close();
            break;
        }
    }
    let _ = writer.shutdown().await;
}

async fn read_loop(
    mut reader: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    session: Weak<AnyTlsSession>,
) {
    let mut buffer = BytesMut::with_capacity(8192);
    loop {
        match reader.read_buf(&mut buffer).await {
            Ok(0) => {
                if let Some(session) = session.upgrade() {
                    close_session(&session).await;
                }
                break;
            }
            Ok(_) => {
                while let Some(frame) = decode_frame(&mut buffer) {
                    let Some(session) = session.upgrade() else {
                        return;
                    };
                    handle_frame(&session, frame).await;
                }
            }
            Err(_) => {
                if let Some(session) = session.upgrade() {
                    close_session(&session).await;
                }
                break;
            }
        }
    }
}

async fn handle_frame(session: &Arc<AnyTlsSession>, frame: Frame) {
    match frame.cmd {
        CMD_PUSH => {
            if let Some(tx) = session.streams.lock().await.get(&frame.stream_id) {
                let _ = tx.send(frame.data);
            }
        }
        CMD_FIN => {
            session.streams.lock().await.remove(&frame.stream_id);
        }
        CMD_SYNACK => {
            if let Some(tx) = session.synacks.lock().await.remove(&frame.stream_id) {
                let result = if frame.data.is_empty() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "AnyTLS server error: {}",
                        String::from_utf8_lossy(&frame.data)
                    ))
                };
                let _ = tx.send(result);
            }
        }
        CMD_ALERT => {
            close_session(session).await;
        }
        CMD_UPDATE_PADDING_SCHEME => {
            if let Ok(next) = PaddingFactory::new(&frame.data) {
                *session.padding.lock().await = next;
            }
        }
        CMD_HEART_REQUEST => {
            let _ = session.write_tx.send(SessionWrite::Frame {
                cmd: CMD_HEART_RESPONSE,
                stream_id: frame.stream_id,
                data: Bytes::new(),
            });
        }
        CMD_WASTE | CMD_SERVER_SETTINGS | CMD_HEART_RESPONSE => {}
        _ => {}
    }
}

async fn close_session(session: &Arc<AnyTlsSession>) {
    if session.closed.swap(true, Ordering::Relaxed) {
        return;
    }
    for (_, tx) in session.synacks.lock().await.drain() {
        let _ = tx.send(Err(anyhow::anyhow!("AnyTLS session closed")));
    }
    session.streams.lock().await.clear();
}

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
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

fn build_tls_config(insecure: bool) -> anyhow::Result<ClientConfig> {
    let roots = RootCertStore::empty();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier));
    }
    Ok(config)
}

fn build_server_name(value: &str) -> anyhow::Result<ServerName<'static>> {
    let normalized = value.trim().trim_matches('[').trim_matches(']');
    if normalized.is_empty() {
        anyhow::bail!("AnyTLS SNI is empty");
    }
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(normalized.to_string())
            .map_err(|_| anyhow::anyhow!("AnyTLS SNI is invalid"))
    }
}

fn send_authentication(
    write_tx: &mpsc::UnboundedSender<SessionWrite>,
    password: &str,
) -> anyhow::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let password_hash = hasher.finalize();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&password_hash);
    out.extend_from_slice(&30_u16.to_be_bytes());
    out.resize(out.len() + 30, 0);
    write_tx
        .send(SessionWrite::Raw(Bytes::from(out)))
        .map_err(|_| anyhow::anyhow!("AnyTLS writer is closed"))
}

fn send_settings(session: &Arc<AnyTlsSession>) -> anyhow::Result<()> {
    let padding = PaddingFactory::default();
    let settings = format!("v=2\nclient=neoncore/0.1.0\npadding-md5={}", padding.md5);
    let mut frame = Vec::new();
    append_frame(&mut frame, CMD_SETTINGS, 0, settings.as_bytes())?;
    session
        .write_tx
        .send(SessionWrite::Frames(Bytes::from(frame)))
        .map_err(|_| anyhow::anyhow!("AnyTLS writer is closed"))
}

struct Frame {
    cmd: u8,
    stream_id: u32,
    data: Bytes,
}

fn decode_frame(buffer: &mut BytesMut) -> Option<Frame> {
    if buffer.len() < HEADER_LEN {
        return None;
    }
    let cmd = buffer[0];
    let stream_id = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
    let data_len = u16::from_be_bytes([buffer[5], buffer[6]]) as usize;
    if buffer.len() < HEADER_LEN + data_len {
        return None;
    }
    buffer.advance(HEADER_LEN);
    let data = buffer.split_to(data_len).freeze();
    Some(Frame {
        cmd,
        stream_id,
        data,
    })
}

async fn write_with_padding<W>(
    writer: &mut W,
    session: &AnyTlsSession,
    mut buffer: BytesMut,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let packet = session.packet_counter.fetch_add(1, Ordering::SeqCst);
    let padding = session.padding.lock().await.clone();
    if packet < padding.stop {
        for size in padding.sizes(packet) {
            let remaining = buffer.len();
            if size == PaddingSize::Check {
                if remaining == 0 {
                    break;
                }
                continue;
            }
            let PaddingSize::Payload(size) = size else {
                continue;
            };
            if remaining > size {
                writer.write_all(&buffer[..size]).await?;
                buffer.advance(size);
            } else if remaining > 0 {
                let padding_len = size.saturating_sub(remaining + HEADER_LEN);
                if padding_len > 0 {
                    buffer.put_u8(CMD_WASTE);
                    buffer.put_u32(0);
                    buffer.put_u16(padding_len as u16);
                    buffer.resize(buffer.len() + padding_len, 0);
                }
                writer.write_all(&buffer).await?;
                buffer.clear();
            } else {
                let mut waste = Vec::with_capacity(HEADER_LEN + size);
                append_frame(&mut waste, CMD_WASTE, 0, &vec![0_u8; size])?;
                writer.write_all(&waste).await?;
            }
        }
    }
    if !buffer.is_empty() {
        writer.write_all(&buffer).await?;
    }
    writer.flush().await?;
    Ok(())
}

fn append_frame(out: &mut Vec<u8>, cmd: u8, stream_id: u32, data: &[u8]) -> anyhow::Result<()> {
    if data.len() > u16::MAX as usize {
        anyhow::bail!("AnyTLS frame is too large");
    }
    out.put_u8(cmd);
    out.put_u32(stream_id);
    out.put_u16(data.len() as u16);
    out.extend_from_slice(data);
    Ok(())
}

fn encode_socks_address(target: &TargetAddress) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(ipv4) = target.host.parse::<Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target.host.parse::<Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&ipv6.octets());
    } else {
        let domain = target.host.as_bytes();
        if domain.len() > u8::MAX as usize {
            anyhow::bail!("AnyTLS target domain is too long");
        }
        out.push(0x03);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

fn encode_uot_packet(target: TargetAddress, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("UoT payload is too large");
    }
    let mut out = encode_uot_address(&target)?;
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn encode_uot_address(target: &TargetAddress) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(ipv4) = target.host.parse::<Ipv4Addr>() {
        out.push(0x00);
        out.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target.host.parse::<Ipv6Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ipv6.octets());
    } else {
        let domain = target.host.as_bytes();
        if domain.len() > u8::MAX as usize {
            anyhow::bail!("UoT target domain is too long");
        }
        out.push(0x02);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

async fn read_uot_packet<R>(
    reader: &mut R,
    is_connect: bool,
) -> anyhow::Result<(Option<TargetAddress>, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let destination = if is_connect {
        None
    } else {
        Some(read_uot_address(reader).await?)
    };
    let mut len = [0_u8; 2];
    reader.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok((destination, payload))
}

async fn read_uot_address<R>(reader: &mut R) -> anyhow::Result<TargetAddress>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp).await?;
    let host = match atyp[0] {
        0x00 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x01 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        0x02 => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len).await?;
            let mut name = vec![0_u8; len[0] as usize];
            reader.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        _ => anyhow::bail!("unsupported UoT address type"),
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port).await?;
    Ok(TargetAddress {
        host,
        port: u16::from_be_bytes(port),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PaddingSize {
    Payload(usize),
    Check,
}

#[derive(Debug, Clone)]
struct PaddingFactory {
    md5: String,
    stop: u32,
    entries: Vec<Vec<PaddingSize>>,
}

impl Default for PaddingFactory {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
            .expect("default AnyTLS padding scheme should be valid")
    }
}

impl PaddingFactory {
    fn new(raw: &[u8]) -> anyhow::Result<Self> {
        let mut stop = None;
        let mut entries = vec![Vec::new(); 32];
        for line in String::from_utf8_lossy(raw).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key == "stop" {
                stop = Some(value.parse::<u32>()?);
                continue;
            }
            let Ok(index) = key.parse::<usize>() else {
                continue;
            };
            if index >= entries.len() {
                entries.resize(index + 1, Vec::new());
            }
            entries[index] = parse_padding_sizes(value);
        }
        let digest = md5::compute(raw);
        Ok(Self {
            md5: format!("{digest:x}"),
            stop: stop.ok_or_else(|| anyhow::anyhow!("AnyTLS padding stop is missing"))?,
            entries,
        })
    }

    fn sizes(&self, packet: u32) -> Vec<PaddingSize> {
        let Some(entry) = self.entries.get(packet as usize) else {
            return Vec::new();
        };
        entry
            .iter()
            .map(|size| match size {
                PaddingSize::Check => PaddingSize::Check,
                PaddingSize::Payload(size) => PaddingSize::Payload(*size),
            })
            .collect()
    }
}

fn parse_padding_sizes(value: &str) -> Vec<PaddingSize> {
    let mut sizes = Vec::new();
    for part in value.split(',').map(str::trim) {
        if part == "c" {
            sizes.push(PaddingSize::Check);
            continue;
        }
        let Some((min, max)) = part.split_once('-') else {
            continue;
        };
        let Ok(min) = min.parse::<usize>() else {
            continue;
        };
        let Ok(max) = max.parse::<usize>() else {
            continue;
        };
        if min == 0 || max == 0 {
            continue;
        }
        let low = min.min(max);
        let high = min.max(max);
        let size = if low == high {
            low
        } else {
            rand::thread_rng().gen_range(low..high)
        };
        sizes.push(PaddingSize::Payload(size));
    }
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_required_credentials() {
        let node = KernelNode {
            id: None,
            protocol: "anytls".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "secret".to_string(),
            parameters: json!({
                "sni": "edge.example.com"
            }),
        };

        AnyTlsAdapter.validate(&node).unwrap();
    }

    #[test]
    fn encodes_domain_destination() {
        let target = TargetAddress {
            host: "www.google.com".to_string(),
            port: 443,
        };
        let encoded = encode_socks_address(&target).unwrap();
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1] as usize, "www.google.com".len());
        assert_eq!(&encoded[2..16], b"www.google.com");
        assert_eq!(&encoded[16..], &443_u16.to_be_bytes());
    }

    #[test]
    fn default_padding_starts_after_authentication_packet() {
        let padding = PaddingFactory::default();
        let sizes = padding.sizes(1);
        assert_eq!(sizes.len(), 1);
        match sizes[0] {
            PaddingSize::Payload(size) => assert!((100..400).contains(&size)),
            PaddingSize::Check => panic!("unexpected check marker"),
        }
    }

    #[test]
    fn config_accepts_pool_tuning() {
        let node = KernelNode {
            id: None,
            protocol: "anytls".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "secret".to_string(),
            parameters: json!({
                "sni": "edge.example.com",
                "idle_session_timeout": "20s",
                "min_idle_session": "2"
            }),
        };
        let config = AnyTlsConfig::from_node(&node).unwrap();
        assert_eq!(config.idle_session_timeout, Duration::from_secs(20));
        assert_eq!(config.min_idle_sessions, 2);
    }
}
