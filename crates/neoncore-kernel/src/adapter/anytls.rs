use crate::{
    adapter::{boxed_stream, BoxedProxyStream, OutboundAdapter},
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub struct AnyTlsAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for AnyTlsAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()> {
        if node.server.is_empty() || node.server_port == 0 {
            anyhow::bail!("AnyTLS endpoint is invalid");
        }
        if node.user_id.is_empty() {
            anyhow::bail!("AnyTLS requires a password");
        }
        Ok(())
    }

    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream> {
        Self::validate(node)?;
        let tcp = connect_tcp(&node.server, node.server_port, resolver).await?;
        let sni = node.parameter("sni").unwrap_or(&node.server);
        let insecure = node
            .parameter("insecure")
            .map(|value| matches!(value, "1" | "true" | "yes"))
            .unwrap_or(false);
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(insecure)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let mut stream = connector.connect(sni, tcp).await?;
        let password = node.user_id.as_bytes();
        if password.len() > u16::MAX as usize {
            anyhow::bail!("AnyTLS password is too long");
        }
        let target = target.to_string();
        if target.len() > u16::MAX as usize {
            anyhow::bail!("AnyTLS target is too long");
        }
        stream
            .write_all(&(password.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(password).await?;
        stream
            .write_all(&(target.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(target.as_bytes()).await?;
        Ok(boxed_stream(stream))
    }
}

async fn connect_tcp(host: &str, port: u16, resolver: &DnsResolver) -> anyhow::Result<TcpStream> {
    let addresses = resolver
        .resolve(&TargetAddress {
            host: host.to_string(),
            port,
        })
        .await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(value) => return Ok(value),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no resolved address for AnyTLS server")))
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
