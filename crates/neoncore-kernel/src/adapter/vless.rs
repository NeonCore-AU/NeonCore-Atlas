use crate::{
    adapter::{boxed_stream, BoxedProxyStream, OutboundAdapter},
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
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
        if matches!(config.security, VlessSecurity::Reality { .. }) {
            anyhow::bail!("VLESS REALITY transport requires the dedicated REALITY handshake");
        }
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is available");
        }
        Ok(())
    }

    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = VlessConfig::from_node(node)?;
        if matches!(config.security, VlessSecurity::Reality { .. }) {
            anyhow::bail!("VLESS REALITY transport requires the dedicated REALITY handshake");
        }
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is implemented");
        }
        let request = build_tcp_request(&node.user_id, target)?;
        let stream = connect_tcp(&config.server, config.server_port, resolver).await?;
        match &config.security {
            VlessSecurity::None => {
                let mut stream = stream;
                stream.write_all(&request).await?;
                read_response_header(&mut stream).await?;
                Ok(boxed_stream(stream))
            }
            VlessSecurity::Tls | VlessSecurity::Reality { .. } => {
                let sni = config.sni.as_deref().unwrap_or(&config.server);
                let connector = native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(config.insecure)
                    .build()?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let mut stream = connector.connect(sni, stream).await?;
                stream.write_all(&request).await?;
                read_response_header(&mut stream).await?;
                Ok(boxed_stream(stream))
            }
        }
    }
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

pub fn build_tcp_request(uuid: &str, target: &TargetAddress) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0);
    out.extend_from_slice(&parse_uuid(uuid)?);
    out.push(0);
    out.push(1);
    out.extend_from_slice(&target.port.to_be_bytes());
    encode_address(&target.host, &mut out)?;
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

async fn read_response_header<S>(stream: &mut S) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut fixed)).await??;
    let addon_len = fixed[1] as usize;
    if addon_len > 0 {
        let mut addon = vec![0_u8; addon_len];
        timeout(Duration::from_secs(5), stream.read_exact(&mut addon)).await??;
    }
    Ok(())
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

        let request = build_tcp_request("00112233-4455-6677-8899-aabbccddeeff", &target).unwrap();

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
