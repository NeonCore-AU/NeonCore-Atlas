use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::{debug, error, info, warn};

mod adapter;
mod buffer_pool;
mod connection;
mod dns;
mod flow;
mod outbound;
mod packet_session;
mod routing;
mod session;
mod tcp_tuning;

use adapter::NetworkCapability;
use connection::{ConnectionContext, InboundKind};
use dns::DnsResolver;
use flow::FlowLink;
use outbound::OutboundHandler;
use routing::{RouteDecision, Router};
use session::{KernelNode, KernelSession, TargetAddress};

const SOCKS_UDP_MAX_IN_FLIGHT: usize = 512;

#[derive(Parser)]
#[command(name = "neoncore-kernel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        session: PathBuf,
    },
    Check {
        #[arg(long)]
        session: PathBuf,
    },
    ResolveServer {
        #[arg(long)]
        session: PathBuf,
    },
    Capabilities,
}

#[derive(Clone)]
struct KernelRuntime {
    session: Arc<KernelSession>,
    router: Router,
    resolver: DnsResolver,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Command::Run { session } => run(session).await,
        Command::Check { session } => {
            let session = read_session(session)?;
            validate_session(&session)?;
            println!("{}", serde_json::to_string_pretty(&session)?);
            Ok(())
        }
        Command::ResolveServer { session } => resolve_server(session).await,
        Command::Capabilities => {
            println!("{}", serde_json::to_string_pretty(&kernel_capabilities())?);
            Ok(())
        }
    }
}

fn kernel_capabilities() -> serde_json::Value {
    serde_json::json!({
        "capability_schema_version": 2,
        "manual_node_schema_version": 1,
        "packet_session": {
            "demux": {
                "target_aware": true,
                "targetless_fallback": "fifo",
                "late_packet_policy": "discard_without_waiter"
            },
            "shared_by": [
                "shadowsocks.direct_udp",
                "shadowsocks.uot",
                "anytls.uot",
                "vless.xudp"
            ]
        },
        "shadowsocks": {
            "udp_modes": ["direct", "uot"],
            "uot": {
                "enabled": true,
                "packet_session": "target_aware",
                "supported_versions": [1],
                "requires_explicit_mode_for_plugins": true,
                "targetless_fallback": "fifo"
            },
            "mux": {
                "tcp": false,
                "udp": "uot",
                "xudp": false
            },
            "plugins": {
                "none": {
                    "tcp": true,
                    "udp": "direct",
                    "uot": false,
                    "native": true,
                    "multiplex": false
                },
                "kcptun": {
                    "tcp": true,
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "native": true,
                    "multiplex": true,
                    "pool": { "enabled": true, "idle_timeout_secs": 180 }
                },
                "v2ray-plugin": {
                    "tcp": true,
                    "modes": ["websocket"],
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "native": true,
                    "multiplex": false
                },
                "gost": {
                    "tcp": true,
                    "modes": ["websocket"],
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "native": true,
                    "multiplex": false
                },
                "gost-plugin": {
                    "tcp": true,
                    "modes": ["websocket"],
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "native": true,
                    "multiplex": false
                },
                "shadow-tls": {
                    "tcp": true,
                    "versions": ["1", "2", "3"],
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "native": true,
                    "multiplex": false
                },
                "cloak": {
                    "tcp": true,
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "external_program": true,
                    "native": false,
                    "multiplex": false
                },
                "external-sip003": {
                    "tcp": true,
                    "udp": "uot",
                    "uot": true,
                    "requires_explicit_uot": true,
                    "external_program": true,
                    "native": false,
                    "multiplex": false
                }
            },
            "obfuscation": ["none", "http", "tls", "ssl", "h1", "h2", "wss", "websocket", "httpupgrade", "xhttp"],
            "xhttp": {
                "modes": ["auto", "stream-one", "stream-up", "packet-up"],
                "http_versions": ["auto", "1.1", "h2", "h3"],
                "packet_up": {
                    "batching": true,
                    "keep_alive_post": true,
                    "retry_non_replayable_batches": false
                }
            }
        },
        "shadowsocksr": {
            "udp_modes": ["direct", "uot"],
            "uot": {
                "enabled": true,
                "packet_session": "target_aware",
                "requires_explicit_mode_for_plugins": true
            },
            "mux": {
                "tcp": false,
                "udp": "uot",
                "xudp": false
            },
            "protocols": [
                "origin",
                "verify_simple",
                "verify_sha1",
                "auth_simple",
                "auth_sha1",
                "auth_sha1_v2",
                "auth_sha1_v4",
                "auth_aes128_md5",
                "auth_aes128_sha1",
                "auth_chain_a",
                "auth_chain_b",
                "auth_chain_c",
                "auth_chain_d",
                "auth_chain_e",
                "auth_chain_f"
            ],
            "obfs": ["plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"],
            "packet_session": "target_aware"
        },
        "vless": {
            "udp": ["xudp"],
            "mux": {
                "xudp": {
                    "packet_session": "target_aware",
                    "targetless_fallback": "fifo",
                    "response_target_metadata": true
                }
            }
        },
        "anytls": {
            "udp": ["uot"],
            "uot": {
                "packet_session": "target_aware",
                "targetless_fallback": "fifo"
            }
        }
    })
}

#[derive(Debug, Serialize)]
struct ResolvedServerOutput {
    server: String,
    server_port: u16,
    addresses: Vec<String>,
}

async fn resolve_server(path: PathBuf) -> anyhow::Result<()> {
    let session = read_session(path)?;
    validate_session(&session)?;
    let resolver = DnsResolver::new(session.dns.clone());
    let target = TargetAddress {
        host: session.selected_node.server.clone(),
        port: session.selected_node.server_port,
    };
    let addresses = resolver
        .resolve_proxy_server(&target)
        .await?
        .into_iter()
        .map(|address| address.ip().to_string())
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&ResolvedServerOutput {
            server: target.host,
            server_port: target.port,
            addresses,
        })?
    );
    Ok(())
}

async fn run(path: PathBuf) -> anyhow::Result<()> {
    let session = read_session(path)?;
    validate_session(&session)?;
    let runtime = KernelRuntime::new(session);
    let listener = TcpListener::bind((
        runtime.session.listen_host.as_str(),
        runtime.session.listen_port,
    ))
    .await?;
    info!(
        listen_host = %runtime.session.listen_host,
        listen_port = runtime.session.listen_port,
        "kernel listener started"
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tcp_tuning::tune_tcp_stream(&stream);
                let runtime = runtime.clone();
                debug!(%peer, "accepted inbound connection");
                tokio::spawn(async move {
                    if let Err(err) = handle_client(stream, runtime).await {
                        warn!(error = %err, "connection closed with error");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                info!("shutdown signal received");
                return Ok(());
            }
        }
    }
}

impl KernelRuntime {
    fn new(session: KernelSession) -> Self {
        let resolver = DnsResolver::new(session.dns.clone());
        let router = Router::new(&session);
        Self {
            session: Arc::new(session),
            router,
            resolver,
        }
    }

    async fn connect(
        &self,
        context: &mut ConnectionContext,
    ) -> anyhow::Result<adapter::BoxedProxyStream> {
        match self.router.decide(&context.target)? {
            RouteDecision::Direct => {
                let node = KernelNode {
                    id: Some("direct.runtime".to_string()),
                    protocol: "direct".to_string(),
                    server: "direct".to_string(),
                    server_port: 1,
                    user_id: String::new(),
                    parameters: serde_json::json!({}),
                };
                info!(
                    connection_id = context.id,
                    target = %context.target,
                    "routing selected direct outbound"
                );
                OutboundHandler::new(node, &self.resolver)
                    .connect(context)
                    .await
            }
            RouteDecision::Proxy(node) => {
                info!(
                    connection_id = context.id,
                    target = %context.target,
                    protocol = %node.protocol,
                    "routing selected proxy outbound"
                );
                OutboundHandler::new(node, &self.resolver)
                    .connect(context)
                    .await
            }
            RouteDecision::Reject => anyhow::bail!("route rejected target: {}", context.target),
        }
    }

    async fn send_udp(
        &self,
        context: &mut ConnectionContext,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self.router.decide(&context.target)? {
            RouteDecision::Direct => {
                let node = KernelNode {
                    id: Some("direct.runtime".to_string()),
                    protocol: "direct".to_string(),
                    server: "direct".to_string(),
                    server_port: 1,
                    user_id: String::new(),
                    parameters: serde_json::json!({}),
                };
                OutboundHandler::new(node, &self.resolver)
                    .send_udp(context, payload)
                    .await
            }
            RouteDecision::Proxy(node) => {
                OutboundHandler::new(node, &self.resolver)
                    .send_udp(context, payload)
                    .await
            }
            RouteDecision::Reject => anyhow::bail!("route rejected target: {}", context.target),
        }
    }
}

fn read_session(path: PathBuf) -> anyhow::Result<KernelSession> {
    let data = std::fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

fn validate_session(session: &KernelSession) -> anyhow::Result<()> {
    if session.listen_host != "127.0.0.1" {
        anyhow::bail!("kernel currently only listens on loopback");
    }
    if session.selected_node.server.is_empty() || session.selected_node.server_port == 0 {
        anyhow::bail!("selected node endpoint is invalid");
    }
    adapter::validate_node(&session.selected_node)?;
    for node in &session.nodes {
        adapter::validate_node(node)?;
    }
    Ok(())
}

async fn handle_client(mut client: TcpStream, runtime: KernelRuntime) -> anyhow::Result<()> {
    let mut first = [0_u8; 1];
    client.read_exact(&mut first).await?;
    match first[0] {
        0x05 => handle_socks5(client, first[0], runtime).await,
        b'C' | b'G' | b'P' | b'H' | b'D' | b'O' | b'T' => {
            handle_http(client, first[0], runtime).await
        }
        value => anyhow::bail!("unsupported inbound protocol first byte: {value}"),
    }
}

async fn handle_socks5(
    mut client: TcpStream,
    version: u8,
    runtime: KernelRuntime,
) -> anyhow::Result<()> {
    let mut methods_len = [0_u8; 1];
    client.read_exact(&mut methods_len).await?;
    let mut methods = vec![0_u8; methods_len[0] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[version, 0x00]).await?;

    let mut request_head = [0_u8; 4];
    client.read_exact(&mut request_head).await?;
    if request_head[1] == 0x03 {
        let _ = read_socks_target(&mut client, request_head[3]).await?;
        return handle_socks5_udp_associate(client, runtime).await;
    }
    if request_head[1] != 0x01 {
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("unsupported SOCKS command");
    }

    let target = read_socks_target(&mut client, request_head[3]).await?;
    let mut context = ConnectionContext::new(InboundKind::Socks5, target, NetworkCapability::Tcp);
    let remote = runtime.connect(&mut context).await?;
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    FlowLink::new(context, client, remote).relay().await
}

async fn handle_socks5_udp_associate(
    mut client: TcpStream,
    runtime: KernelRuntime,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind((runtime.session.listen_host.as_str(), 0)).await?);
    let local = socket.local_addr()?;
    let ip = match local.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => [127, 0, 0, 1],
    };
    let mut response = vec![0x05, 0x00, 0x00, 0x01];
    response.extend_from_slice(&ip);
    response.extend_from_slice(&local.port().to_be_bytes());
    client.write_all(&response).await?;

    let udp_semaphore = Arc::new(tokio::sync::Semaphore::new(SOCKS_UDP_MAX_IN_FLIGHT));
    let mut udp_buffer = vec![0_u8; 65_536];
    let mut control = [0_u8; 1];
    loop {
        tokio::select! {
            read = client.read(&mut control) => {
                if read? == 0 {
                    return Ok(());
                }
            }
            packet = socket.recv_from(&mut udp_buffer) => {
                let (n, peer) = packet?;
                let (target, payload) = parse_socks_udp_packet(&udp_buffer[..n])?;
                let payload = payload.to_vec();
                let runtime = runtime.clone();
                let socket = socket.clone();
                let permit = match udp_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(target = %target, "SOCKS UDP association is at capacity; dropping packet");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut context = ConnectionContext::new(
                        InboundKind::Socks5Udp,
                        target.clone(),
                        NetworkCapability::Udp,
                    );
                    match runtime.send_udp(&mut context, &payload).await {
                        Ok(reply) => match build_socks_udp_packet(&target, &reply) {
                            Ok(packet) => {
                                let _ = socket.send_to(&packet, peer).await;
                            }
                            Err(err) => {
                                warn!(error = %err, target = %target, "SOCKS UDP response build failed");
                            }
                        },
                        Err(err) => warn!(error = %err, target = %target, "SOCKS UDP relay failed"),
                    }
                });
            }
        }
    }
}

fn parse_socks_udp_packet(packet: &[u8]) -> anyhow::Result<(TargetAddress, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        anyhow::bail!("invalid SOCKS UDP header");
    }
    let mut index = 4;
    let host = match packet[3] {
        0x01 => {
            if packet.len() < index + 4 {
                anyhow::bail!("truncated SOCKS UDP IPv4 address");
            }
            let host = std::net::Ipv4Addr::new(
                packet[index],
                packet[index + 1],
                packet[index + 2],
                packet[index + 3],
            )
            .to_string();
            index += 4;
            host
        }
        0x03 => {
            if packet.len() < index + 1 {
                anyhow::bail!("truncated SOCKS UDP domain length");
            }
            let len = packet[index] as usize;
            index += 1;
            if packet.len() < index + len {
                anyhow::bail!("truncated SOCKS UDP domain");
            }
            let host = String::from_utf8(packet[index..index + len].to_vec())?;
            index += len;
            host
        }
        0x04 => {
            if packet.len() < index + 16 {
                anyhow::bail!("truncated SOCKS UDP IPv6 address");
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[index..index + 16]);
            index += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => anyhow::bail!("unsupported SOCKS UDP address type"),
    };
    if packet.len() < index + 2 {
        anyhow::bail!("truncated SOCKS UDP port");
    }
    let port = u16::from_be_bytes([packet[index], packet[index + 1]]);
    index += 2;
    Ok((TargetAddress { host, port }, &packet[index..]))
}

fn build_socks_udp_packet(target: &TargetAddress, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    if let Ok(ipv4) = target.host.parse::<std::net::Ipv4Addr>() {
        packet.push(0x01);
        packet.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target.host.parse::<std::net::Ipv6Addr>() {
        packet.push(0x04);
        packet.extend_from_slice(&ipv6.octets());
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            anyhow::bail!("SOCKS UDP response domain is too long");
        }
        packet.push(0x03);
        packet.push(host.len() as u8);
        packet.extend_from_slice(host);
    }
    packet.extend_from_slice(&target.port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_socks_target(client: &mut TcpStream, atyp: u8) -> anyhow::Result<TargetAddress> {
    let host = match atyp {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0_u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0_u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => anyhow::bail!("unsupported SOCKS address type"),
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    Ok(TargetAddress {
        host,
        port: u16::from_be_bytes(port),
    })
}

async fn handle_http(
    mut client: TcpStream,
    first: u8,
    runtime: KernelRuntime,
) -> anyhow::Result<()> {
    let mut head = vec![first];
    read_http_head(&mut client, &mut head).await?;
    let request = String::from_utf8(head)?;
    let mut lines = request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty HTTP request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = parse_host_port(uri, 443)?;
        let mut context =
            ConnectionContext::new(InboundKind::HttpConnect, target, NetworkCapability::Tcp);
        let remote = runtime.connect(&mut context).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return FlowLink::new(context, client, remote).relay().await;
    }

    let (target, origin_uri) = parse_http_forward_target(uri, &request)?;
    let mut context =
        ConnectionContext::new(InboundKind::HttpForward, target, NetworkCapability::Tcp);
    let remote = runtime.connect(&mut context).await?;
    let rewritten = rewrite_http_request(&request, method, uri, version, &origin_uri)?;
    let mut flow = FlowLink::new(context, client, remote);
    flow.write_outbound(rewritten.as_bytes()).await?;
    flow.relay().await
}

async fn read_http_head(client: &mut TcpStream, buffer: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut byte = [0_u8; 1];
    while buffer.len() < 65_536 {
        client.read_exact(&mut byte).await?;
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
    }
    anyhow::bail!("HTTP request header is too large")
}

fn parse_http_forward_target(uri: &str, request: &str) -> anyhow::Result<(TargetAddress, String)> {
    if let Some(rest) = uri.strip_prefix("http://") {
        let (authority, path) = split_authority_path(rest);
        return Ok((parse_host_port(authority, 80)?, path.to_string()));
    }
    let host = request
        .split("\r\n")
        .find_map(|line| {
            line.strip_prefix("Host:")
                .or_else(|| line.strip_prefix("host:"))
        })
        .map(str::trim)
        .ok_or_else(|| anyhow::anyhow!("HTTP request missing Host header"))?;
    Ok((parse_host_port(host, 80)?, uri.to_string()))
}

fn rewrite_http_request(
    request: &str,
    method: &str,
    original_uri: &str,
    version: &str,
    origin_uri: &str,
) -> anyhow::Result<String> {
    let first_line = format!("{method} {original_uri} {version}");
    let replacement = format!("{method} {origin_uri} {version}");
    Ok(request.replacen(&first_line, &replacement, 1))
}

fn split_authority_path(value: &str) -> (&str, &str) {
    match value.find('/') {
        Some(index) => (&value[..index], &value[index..]),
        None => (value, "/"),
    }
}

fn parse_host_port(value: &str, default_port: u16) -> anyhow::Result<TargetAddress> {
    if let Some(stripped) = value.strip_prefix('[') {
        let Some((host, rest)) = stripped.split_once(']') else {
            anyhow::bail!("invalid IPv6 authority");
        };
        let port = rest
            .strip_prefix(':')
            .map(str::parse)
            .transpose()?
            .unwrap_or(default_port);
        return Ok(TargetAddress {
            host: host.to_string(),
            port,
        });
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse()?),
        _ => (value, default_port),
    };
    Ok(TargetAddress {
        host: host.to_string(),
        port,
    })
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Err(err) = tracing_subscriber::fmt().with_env_filter(filter).try_init() {
        error!(error = %err, "failed to initialize logging");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;

    fn direct_session(port: u16) -> KernelSession {
        KernelSession {
            listen_host: "127.0.0.1".to_string(),
            listen_port: port,
            selected_node: KernelNode {
                id: Some("direct".to_string()),
                protocol: "direct".to_string(),
                server: "direct".to_string(),
                server_port: 1,
                user_id: String::new(),
                parameters: json!({}),
            },
            nodes: Vec::new(),
            routing: Default::default(),
            dns: Default::default(),
        }
    }

    async fn run_test_kernel(session: KernelSession) -> anyhow::Result<u16> {
        let runtime = KernelRuntime::new(session);
        let listener = TcpListener::bind((
            runtime.session.listen_host.as_str(),
            runtime.session.listen_port,
        ))
        .await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, runtime).await;
                });
            }
        });
        Ok(port)
    }

    #[tokio::test]
    async fn socks5_connect_relays_tcp_payload() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        let kernel_port = run_test_kernel(direct_session(0)).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", kernel_port))
            .await
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn http_connect_relays_tcp_payload() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        let kernel_port = run_test_kernel(direct_session(0)).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", kernel_port))
            .await
            .unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        read_http_head(&mut client, &mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200"));

        client.write_all(b"pong").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong");
    }

    #[tokio::test]
    async fn socks5_udp_associate_relays_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            let (n, peer) = echo.recv_from(&mut buffer).await.unwrap();
            echo.send_to(&buffer[..n], peer).await.unwrap();
        });

        let kernel_port = run_test_kernel(direct_session(0)).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", kernel_port))
            .await
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        let mut request = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0];
        request.extend_from_slice(&0_u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0x00);
        let relay_port = u16::from_be_bytes([response[8], response[9]]);

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0, 0x01, 127, 0, 0, 1];
        packet.extend_from_slice(&echo_port.to_be_bytes());
        packet.extend_from_slice(b"gram");
        udp.send_to(&packet, ("127.0.0.1", relay_port))
            .await
            .unwrap();

        let mut buffer = [0_u8; 1024];
        let (n, _) = udp.recv_from(&mut buffer).await.unwrap();
        let (target, payload) = parse_socks_udp_packet(&buffer[..n]).unwrap();
        assert_eq!(target.port, echo_port);
        assert_eq!(payload, b"gram");
    }
}
