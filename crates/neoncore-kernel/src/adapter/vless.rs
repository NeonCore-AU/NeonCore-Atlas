use crate::{
    adapter::OutboundAdapter,
    session::{KernelNode, TargetAddress},
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::time::Duration;

pub struct VlessAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessConfig {
    pub server: String,
    pub server_port: u16,
    pub uuid: [u8; 16],
    pub sni: Option<String>,
    pub flow: Option<String>,
    pub security: VlessSecurity,
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

impl OutboundAdapter for VlessAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        let config = VlessConfig::from_node(node)?;
        if config.security != VlessSecurity::None {
            anyhow::bail!("VLESS encrypted transports are not available yet");
        }
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is available");
        }
        Ok(())
    }

    fn connect(node: &KernelNode, target: &TargetAddress) -> anyhow::Result<TcpStream> {
        let config = VlessConfig::from_node(node)?;
        if config.security != VlessSecurity::None {
            anyhow::bail!("VLESS encrypted transports are not implemented yet");
        }
        if node.parameter("type").unwrap_or("tcp") != "tcp" {
            anyhow::bail!("only VLESS TCP transport is implemented");
        }
        let request = build_tcp_request(&node.user_id, target)?;
        let mut stream = TcpStream::connect((config.server.as_str(), config.server_port))?;
        stream.write_all(&request)?;
        read_response_header(&mut stream)?;
        Ok(stream)
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
        })
    }
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

fn read_response_header(stream: &mut TcpStream) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut fixed = [0_u8; 2];
    stream.read_exact(&mut fixed)?;
    let addon_len = fixed[1] as usize;
    if addon_len > 0 {
        let mut addon = vec![0_u8; addon_len];
        stream.read_exact(&mut addon)?;
    }
    stream.set_read_timeout(None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_accepts_reality_parameters() {
        let node = KernelNode {
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
}
