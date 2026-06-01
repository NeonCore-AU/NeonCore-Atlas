use crate::{
    adapter::{boxed_stream, BoxedProxyStream, OutboundAdapter},
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use shadowsocks::{
    config::ServerType,
    context::Context,
    crypto::CipherKind,
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
    ServerConfig,
};
use std::{net::SocketAddr, str::FromStr};

pub struct ShadowsocksAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for ShadowsocksAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        ShadowsocksConfig::from_node(node)?;
        Ok(())
    }

    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        _resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = ShadowsocksConfig::from_node(node)?;
        let server = ServerConfig::new(
            (config.server, config.server_port),
            config.password,
            config.method,
        )?;
        let context = Context::new_shared(ServerType::Local);
        let stream = ProxyClientStream::connect(context, &server, target_address(target)).await?;
        Ok(boxed_stream(stream))
    }
}

struct ShadowsocksConfig {
    server: String,
    server_port: u16,
    password: String,
    method: CipherKind,
}

impl ShadowsocksConfig {
    fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        if node.server.is_empty() || node.server_port == 0 {
            anyhow::bail!("Shadowsocks endpoint is invalid");
        }
        if node.user_id.is_empty() {
            anyhow::bail!("Shadowsocks requires a password");
        }
        let method = node
            .parameter("method")
            .or_else(|| node.parameter("cipher"))
            .unwrap_or("2022-blake3-aes-256-gcm")
            .parse::<CipherKind>()
            .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher"))?;
        Ok(Self {
            server: node.server.clone(),
            server_port: node.server_port,
            password: node.user_id.clone(),
            method,
        })
    }
}

fn target_address(target: &TargetAddress) -> Address {
    let authority = target.to_string();
    match SocketAddr::from_str(&authority) {
        Ok(address) => Address::SocketAddress(address),
        Err(_) => Address::DomainNameAddress(target.host.clone(), target.port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_aead_2022_cipher() {
        let node = KernelNode {
            id: None,
            protocol: "shadowsocks".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "2022-blake3-aes-256-gcm"
            }),
        };

        ShadowsocksAdapter::validate(&node).unwrap();
    }

    #[test]
    fn accepts_classic_aead_cipher() {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm"
            }),
        };

        ShadowsocksAdapter::validate(&node).unwrap();
    }
}
