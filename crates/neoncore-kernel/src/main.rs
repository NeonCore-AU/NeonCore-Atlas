use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

mod adapter;
mod dns;
mod routing;
mod session;

use dns::DnsResolver;
use routing::{RouteDecision, Router};
use session::{KernelNode, KernelSession, TargetAddress};

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
}

#[derive(Clone)]
struct KernelRuntime {
    session: Arc<KernelSession>,
    router: Router,
    resolver: DnsResolver,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
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
    }
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

    async fn connect(&self, target: &TargetAddress) -> anyhow::Result<adapter::BoxedProxyStream> {
        match self.router.decide(target)? {
            RouteDecision::Direct => {
                let node = KernelNode {
                    id: Some("direct.runtime".to_string()),
                    protocol: "direct".to_string(),
                    server: "direct".to_string(),
                    server_port: 1,
                    user_id: String::new(),
                    parameters: serde_json::json!({}),
                };
                info!(%target, "routing selected direct outbound");
                adapter::connect(&node, target, &self.resolver).await
            }
            RouteDecision::Proxy(node) => {
                info!(%target, protocol = %node.protocol, "routing selected proxy outbound");
                adapter::connect(&node, target, &self.resolver).await
            }
            RouteDecision::Reject => anyhow::bail!("route rejected target: {target}"),
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
    if request_head[1] != 0x01 {
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("unsupported SOCKS command");
    }

    let target = read_socks_target(&mut client, request_head[3]).await?;
    let remote = runtime.connect(&target).await?;
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    proxy_bidirectional(client, remote).await
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
        let remote = runtime.connect(&target).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return proxy_bidirectional(client, remote).await;
    }

    let (target, origin_uri) = parse_http_forward_target(uri, &request)?;
    let mut remote = runtime.connect(&target).await?;
    let rewritten = rewrite_http_request(&request, method, uri, version, &origin_uri)?;
    remote.write_all(rewritten.as_bytes()).await?;
    proxy_bidirectional(client, remote).await
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

async fn proxy_bidirectional(
    mut left: TcpStream,
    mut right: adapter::BoxedProxyStream,
) -> anyhow::Result<()> {
    let (from_left, from_right) = tokio::io::copy_bidirectional(&mut left, &mut right).await?;
    debug!(
        client_to_remote = from_left,
        remote_to_client = from_right,
        "connection relayed"
    );
    Ok(())
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
}
