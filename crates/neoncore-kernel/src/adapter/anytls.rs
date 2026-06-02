use crate::{
    adapter::{boxed_stream, BoxedProxyStream, OutboundAdapter},
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use anytls_rs::{client::Client, padding::PaddingFactory, util::tls::create_client_config};
use bytes::Bytes;
use std::{net::IpAddr, sync::Arc};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

pub struct AnyTlsAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for AnyTlsAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        AnyTlsConfig::from_node(node)?;
        Ok(())
    }

    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        _resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = AnyTlsConfig::from_node(node)?;
        let client_config = create_client_config()?;
        let connector = Arc::new(TlsConnector::from(client_config));
        let client = Client::new(
            &config.password,
            format!("{}:{}", config.server, config.server_port),
            build_server_name(&config.sni)?,
            connector,
            PaddingFactory::default(),
        );
        let (stream, session) = client
            .create_proxy_stream((target.host.clone(), target.port))
            .await?;
        let stream_id = stream.id();
        let (local, bridge) = duplex(128 * 1024);
        let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge);

        let reader_stream = Arc::clone(&stream);
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let n = {
                    let mut reader = reader_stream.reader().lock().await;
                    match reader.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    }
                };
                if bridge_write.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
            let _ = bridge_write.shutdown().await;
        });

        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                match bridge_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if session
                            .write_data_frame(stream_id, Bytes::copy_from_slice(&buffer[..n]))
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

        Ok(boxed_stream(local))
    }
}

struct AnyTlsConfig {
    server: String,
    server_port: u16,
    password: String,
    sni: String,
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
        })
    }
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

        AnyTlsAdapter::validate(&node).unwrap();
    }
}
