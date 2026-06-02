use crate::{
    adapter::{
        boxed_stream,
        reality::{RealityCertificateVerifier, RealitySessionId, REALITY_X25519_GROUP},
        BoxedProxyStream, OutboundAdapter,
    },
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use std::{net::{Ipv4Addr, Ipv6Addr}, sync::Arc};
use tokio::{
    io::{duplex, AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{self, client::Resumption, pki_types::ServerName},
    TlsConnector,
};

pub struct VlessAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessConfig {
    pub server: String,
    pub server_port: u16,
    pub uuid: [u8; 16],
    pub sni: Option<String>,
    pub flow: Option<String>,
    pub security: VlessSecurity,
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

#[async_trait::async_trait]
impl OutboundAdapter for VlessAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        let config = VlessConfig::from_node(node)?;
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is available");
        }
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
        node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = VlessConfig::from_node(node)?;
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is implemented");
        }
        let request = build_tcp_request(&node.user_id, config.flow.as_deref(), target)?;
        let stream = connect_tcp(&config.server, config.server_port, resolver).await?;
        match &config.security {
            VlessSecurity::None => {
                let mut stream = stream;
                stream.write_all(&request).await?;
                Ok(bridge_vless_stream(stream, None))
            }
            VlessSecurity::Tls | VlessSecurity::Reality { .. } => {
                let sni = config.sni.as_deref().unwrap_or(&config.server);
                if let VlessSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } = &config.security
                {
                    let mut stream =
                        connect_reality_tls(stream, sni, public_key, short_id).await?;
                    stream.write_all(&request).await?;
                    return Ok(bridge_vless_stream(stream, Some(config.uuid)));
                }
                let connector = native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(config.insecure)
                    .build()?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let mut stream = connector.connect(sni, stream).await?;
                stream.write_all(&request).await?;
                Ok(bridge_vless_stream(stream, None))
            }
        }
    }
}

async fn connect_reality_tls(
    stream: TcpStream,
    sni: &str,
    public_key: &str,
    short_id: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
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

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("VLESS REALITY SNI is invalid"))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(Into::into)
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
            insecure: node
                .parameter("insecure")
                .map(|value| matches!(value, "1" | "true" | "yes"))
                .unwrap_or(false),
        })
    }
}

async fn connect_tcp(host: &str, port: u16, resolver: &DnsResolver) -> anyhow::Result<TcpStream> {
    let server = TargetAddress {
        host: host.to_string(),
        port,
    };
    let addresses = resolver.resolve(&server).await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(value) => return Ok(value),
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
    let mut out = Vec::new();
    out.push(0);
    out.extend_from_slice(&parse_uuid(uuid)?);
    let addon = build_addon(flow)?;
    if addon.len() > u8::MAX as usize {
        anyhow::bail!("VLESS addon is too large");
    }
    out.push(addon.len() as u8);
    out.extend_from_slice(&addon);
    out.push(1);
    out.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&target.host, &mut out)?;
    Ok(out)
}

fn build_addon(flow: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let Some(flow) = flow.filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    if flow.len() > u8::MAX as usize {
        anyhow::bail!("VLESS flow is too long");
    }
    let mut out = Vec::with_capacity(flow.len() + 2);
    out.push(0x0a);
    out.push(flow.len() as u8);
    out.extend_from_slice(flow.as_bytes());
    Ok(out)
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

fn bridge_vless_stream<S>(stream: S, vision_uuid: Option<[u8; 16]>) -> BoxedProxyStream
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (local, bridge) = duplex(128 * 1024);
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
        let mut buffer = [0u8; 16 * 1024];
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
        if let Some(uuid) = vision_uuid {
            if remote_write
                .write_all(&xtls_padding(None, 0, Some(uuid), true))
                .await
                .is_err()
            {
                let _ = remote_write.shutdown().await;
                return;
            }
            let mut uplink = VisionUplinkState::new();
            let mut buffer = [0u8; 16 * 1024];
            loop {
                match local_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) if uplink.padding => {
                        let command = uplink.command_for(&buffer[..n]);
                        let padded = xtls_padding(Some(&buffer[..n]), command, None, true);
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
            let _ = tokio::io::copy(&mut local_read, &mut remote_write).await;
        }
        let _ = remote_write.shutdown().await;
    });

    boxed_stream(local)
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
    let chunks = state.push(data);
    for chunk in chunks {
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

fn xtls_padding(content: Option<&[u8]>, command: u8, uuid: Option<[u8; 16]>, long: bool) -> Vec<u8> {
    let content = content.unwrap_or(&[]);
    let padding_len = if long && content.len() < 900 {
        900usize.saturating_sub(content.len())
    } else {
        0
    };
    let mut out = Vec::with_capacity(uuid.map(|_| 16).unwrap_or(0) + 5 + content.len() + padding_len);
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

    fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if matches!(self.mode, VisionUnpaddingMode::Raw) {
            return vec![data.to_vec()];
        }
        self.pending.extend_from_slice(data);
        let mut output = Vec::new();
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
                        output.push(std::mem::take(&mut self.pending));
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
                        output.push(std::mem::take(&mut self.pending));
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
                        output.push(self.pending[5..5 + content_len].to_vec());
                    }
                    self.pending.drain(..block_len);
                    if command != 0 {
                        self.mode = VisionUnpaddingMode::Raw;
                        if !self.pending.is_empty() {
                            output.push(std::mem::take(&mut self.pending));
                        }
                        break;
                    }
                }
                VisionUnpaddingMode::Raw => {
                    if !self.pending.is_empty() {
                        output.push(std::mem::take(&mut self.pending));
                    }
                    break;
                }
            }
        }
        output
    }
}

enum VisionUnpaddingMode {
    Unknown,
    Padding,
    Raw,
}

struct VisionUplinkState {
    padding: bool,
    saw_tls: bool,
}

impl VisionUplinkState {
    fn new() -> Self {
        Self {
            padding: true,
            saw_tls: false,
        }
    }

    fn command_for(&mut self, data: &[u8]) -> u8 {
        if data.starts_with(&[0x16, 0x03]) {
            self.saw_tls = true;
            return 0;
        }
        if self.saw_tls && data.starts_with(&[0x17, 0x03, 0x03]) {
            self.padding = false;
            return 1;
        }
        if !self.saw_tls {
            self.padding = false;
            return 1;
        }
        0
    }
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

        VlessAdapter::validate(&node).unwrap();
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

        let mut stream = VlessAdapter::connect(&node, &target, &resolver)
            .await
            .unwrap();
        let mut payload = [0_u8; 7];
        stream.read_exact(&mut payload).await.unwrap();

        assert_eq!(&payload, b"payload");
        server.await.unwrap();
    }
}
