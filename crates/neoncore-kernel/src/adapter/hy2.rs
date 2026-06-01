use crate::{
    adapter::OutboundAdapter,
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use blake2::{
    digest::{consts::U32, FixedOutput},
    Blake2b, Digest,
};
use rand::RngCore;
use std::net::{SocketAddr, UdpSocket};
use tokio::net::TcpStream;

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

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2TcpResponse {
    pub ok: bool,
    pub message: String,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub payload: Vec<u8>,
}

#[async_trait::async_trait]
impl OutboundAdapter for Hy2Adapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        Hy2Config::from_node(node)?;
        anyhow::bail!("Hysteria2 transport is not available yet");
    }

    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        _resolver: &DnsResolver,
    ) -> anyhow::Result<TcpStream> {
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
pub fn parse_tcp_response(input: &[u8]) -> anyhow::Result<Hy2TcpResponse> {
    if input.is_empty() {
        anyhow::bail!("Hysteria2 TCP response is empty");
    }
    let ok = match input[0] {
        0 => true,
        1 => false,
        value => anyhow::bail!("invalid Hysteria2 TCP response status: {value}"),
    };
    let mut offset = 1;
    let message_len = read_quic_varint(input, &mut offset)? as usize;
    if input.len() < offset + message_len {
        anyhow::bail!("Hysteria2 TCP response message is truncated");
    }
    let message = String::from_utf8(input[offset..offset + message_len].to_vec())?;
    offset += message_len;
    let padding_len = read_quic_varint(input, &mut offset)? as usize;
    if input.len() < offset + padding_len {
        anyhow::bail!("Hysteria2 TCP response padding is truncated");
    }
    Ok(Hy2TcpResponse { ok, message })
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn build_udp_message(message: &Hy2UdpMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&message.session_id.to_be_bytes());
    out.extend_from_slice(&message.packet_id.to_be_bytes());
    out.push(message.fragment_id);
    out.push(message.fragment_count);
    write_quic_varint(message.address.len() as u64, &mut out);
    out.extend_from_slice(message.address.as_bytes());
    out.extend_from_slice(&message.payload);
    out
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_udp_message(input: &[u8]) -> anyhow::Result<Hy2UdpMessage> {
    if input.len() < 8 {
        anyhow::bail!("Hysteria2 UDP message is too short");
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into()?);
    let packet_id = u16::from_be_bytes(input[4..6].try_into()?);
    let fragment_id = input[6];
    let fragment_count = input[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        anyhow::bail!("Hysteria2 UDP fragment metadata is invalid");
    }
    let mut offset = 8;
    let address_len = read_quic_varint(input, &mut offset)? as usize;
    if input.len() < offset + address_len {
        anyhow::bail!("Hysteria2 UDP address is truncated");
    }
    let address = String::from_utf8(input[offset..offset + address_len].to_vec())?;
    offset += address_len;
    Ok(Hy2UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload: input[offset..].to_vec(),
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct SalamanderUdpSocket {
    socket: UdpSocket,
    password: Vec<u8>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SalamanderUdpSocket {
    pub fn bind(addr: SocketAddr, password: impl Into<Vec<u8>>) -> anyhow::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr)?,
            password: password.into(),
        })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn send_to(&self, packet: &[u8], target: SocketAddr) -> anyhow::Result<usize> {
        let [encoded] = salamander_obfuscate(packet, &self.password);
        Ok(self.socket.send_to(&encoded, target)?)
    }

    pub fn recv_from(&self, buffer: &mut [u8]) -> anyhow::Result<(usize, SocketAddr)> {
        let mut encoded = vec![0_u8; buffer.len() + 8];
        let (encoded_len, peer) = self.socket.recv_from(&mut encoded)?;
        let decoded = salamander_deobfuscate(&encoded[..encoded_len], &self.password)?;
        if decoded.len() > buffer.len() {
            anyhow::bail!("decoded datagram does not fit receive buffer");
        }
        buffer[..decoded.len()].copy_from_slice(&decoded);
        Ok((decoded.len(), peer))
    }
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

#[cfg_attr(not(test), allow(dead_code))]
fn read_quic_varint(input: &[u8], offset: &mut usize) -> anyhow::Result<u64> {
    if *offset >= input.len() {
        anyhow::bail!("QUIC varint is truncated");
    }
    let first = input[*offset];
    let tag = first >> 6;
    let len = match tag {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if input.len() < *offset + len {
        anyhow::bail!("QUIC varint is truncated");
    }
    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let raw = u16::from_be_bytes(input[*offset..*offset + 2].try_into()?);
            (raw & 0x3fff) as u64
        }
        4 => {
            let raw = u32::from_be_bytes(input[*offset..*offset + 4].try_into()?);
            (raw & 0x3fff_ffff) as u64
        }
        _ => {
            let raw = u64::from_be_bytes(input[*offset..*offset + 8].try_into()?);
            raw & 0x3fff_ffff_ffff_ffff
        }
    };
    *offset += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

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
    fn tcp_response_parses_status_message_and_padding() {
        let mut frame = vec![1];
        write_quic_varint(12, &mut frame);
        frame.extend_from_slice(b"dial failed!");
        write_quic_varint(3, &mut frame);
        frame.extend_from_slice(b"pad");

        let response = parse_tcp_response(&frame).unwrap();

        assert!(!response.ok);
        assert_eq!(response.message, "dial failed!");
    }

    #[test]
    fn udp_message_round_trips() {
        let message = Hy2UdpMessage {
            session_id: 0x1122_3344,
            packet_id: 7,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:443".to_string(),
            payload: b"hello".to_vec(),
        };

        let encoded = build_udp_message(&message);
        let decoded = parse_udp_message(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn config_accepts_salamander_password() {
        let node = KernelNode {
            id: None,
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
            id: None,
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

    #[test]
    fn salamander_udp_socket_round_trips_datagrams() {
        let left =
            SalamanderUdpSocket::bind("127.0.0.1:0".parse().unwrap(), b"shared".to_vec()).unwrap();
        let right =
            SalamanderUdpSocket::bind("127.0.0.1:0".parse().unwrap(), b"shared".to_vec()).unwrap();
        left.socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        right
            .socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        left.send_to(b"quic payload", right.local_addr().unwrap())
            .unwrap();

        let mut buffer = [0_u8; 64];
        let (len, peer) = right.recv_from(&mut buffer).unwrap();
        assert_eq!(peer, left.local_addr().unwrap());
        assert_eq!(&buffer[..len], b"quic payload");
    }
}
