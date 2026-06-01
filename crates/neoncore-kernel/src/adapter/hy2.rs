use crate::{
    adapter::OutboundAdapter,
    session::{KernelNode, TargetAddress},
};
use blake2::{
    digest::{consts::U32, FixedOutput},
    Blake2b, Digest,
};
use rand::RngCore;
use std::net::TcpStream;

pub struct Hy2Adapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2Config {
    pub server: String,
    pub server_port: u16,
    pub auth: String,
    pub sni: String,
    pub insecure: bool,
    pub obfs: Option<Hy2Obfs>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hy2Obfs {
    Salamander { password: String },
}

impl OutboundAdapter for Hy2Adapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        Hy2Config::from_node(node)?;
        anyhow::bail!("Hysteria2 transport is not available yet");
    }

    fn connect(node: &KernelNode, target: &TargetAddress) -> anyhow::Result<TcpStream> {
        Self::validate(node)?;
        let request = build_tcp_request(&target.to_string(), b"");
        anyhow::bail!(
            "Hysteria2 QUIC transport is not implemented yet; prepared TCP request frame with {} bytes",
            request.len()
        )
    }
}

impl Hy2Config {
    pub fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        if node.user_id.is_empty() {
            anyhow::bail!("Hysteria2 requires an authentication secret");
        }
        let Some(sni) = node.parameter("sni") else {
            anyhow::bail!("Hysteria2 requires an SNI value");
        };
        let obfs = match node.parameter("obfs") {
            Some("salamander") => {
                let password = node
                    .parameter("obfs-password")
                    .or_else(|| node.parameter("obfs_password"))
                    .ok_or_else(|| anyhow::anyhow!("Hysteria2 Salamander requires a password"))?;
                Some(Hy2Obfs::Salamander {
                    password: password.to_string(),
                })
            }
            Some(value) => anyhow::bail!("unsupported Hysteria2 obfuscation mode: {value}"),
            None => None,
        };
        Ok(Self {
            server: node.server.clone(),
            server_port: node.server_port,
            auth: node.user_id.clone(),
            sni: sni.to_string(),
            insecure: node
                .parameter("insecure")
                .map(|value| matches!(value, "1" | "true" | "yes"))
                .unwrap_or(false),
            obfs,
        })
    }
}

pub fn build_tcp_request(address: &str, padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_quic_varint(0x401, &mut out);
    write_quic_varint(address.len() as u64, &mut out);
    out.extend_from_slice(address.as_bytes());
    write_quic_varint(padding.len() as u64, &mut out);
    out.extend_from_slice(padding);
    out
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn salamander_obfuscate(packet: &[u8], key: &[u8]) -> [Vec<u8>; 1] {
    let mut salt = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut output = Vec::with_capacity(8 + packet.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&salamander_xor(packet, key, &salt));
    [output]
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn salamander_deobfuscate(datagram: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    if datagram.len() < 8 {
        anyhow::bail!("Salamander datagram is too short");
    }
    let salt: [u8; 8] = datagram[0..8].try_into()?;
    Ok(salamander_xor(&datagram[8..], key, &salt))
}

#[cfg_attr(not(test), allow(dead_code))]
fn salamander_xor(payload: &[u8], key: &[u8], salt: &[u8; 8]) -> Vec<u8> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(key);
    hasher.update(salt);
    let hash = hasher.finalize_fixed();
    payload
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ hash[index % hash.len()])
        .collect()
}

fn write_quic_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => {
            let encoded = (value as u16) | 0x4000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        16_384..=1_073_741_823 => {
            let encoded = (value as u32) | 0x8000_0000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => {
            let encoded = value | 0xC000_0000_0000_0000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn salamander_round_trips_payload() {
        let packet = b"quic packet bytes";
        let key = b"pre-shared-key";
        let [encoded] = salamander_obfuscate(packet, key);
        let decoded = salamander_deobfuscate(&encoded, key).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn tcp_request_uses_hysteria_message_id() {
        let frame = build_tcp_request("example.com:443", b"");
        assert_eq!(&frame[0..2], &[0x44, 0x01]);
        assert_eq!(frame[2], "example.com:443".len() as u8);
    }

    #[test]
    fn config_accepts_salamander_password() {
        let node = KernelNode {
            protocol: "hysteria2".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "secret".to_string(),
            parameters: json!({
                "sni": "edge.example.com",
                "obfs": "salamander",
                "obfs-password": "pepper"
            }),
        };

        let config = Hy2Config::from_node(&node).unwrap();
        assert_eq!(config.sni, "edge.example.com");
        assert_eq!(
            config.obfs,
            Some(Hy2Obfs::Salamander {
                password: "pepper".to_string()
            })
        );
    }

    #[test]
    fn config_rejects_salamander_without_password() {
        let node = KernelNode {
            protocol: "hy2".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 443,
            user_id: "secret".to_string(),
            parameters: json!({
                "sni": "edge.example.com",
                "obfs": "salamander"
            }),
        };

        assert!(Hy2Config::from_node(&node).is_err());
    }
}
