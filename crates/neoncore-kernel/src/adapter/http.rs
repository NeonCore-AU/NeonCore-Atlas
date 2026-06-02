use crate::{
    adapter::{
        boxed_stream, BoxedProxyStream, NetworkCapability, OutboundAdapter, OutboundContext,
    },
    session::{KernelNode, TargetAddress},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct HttpAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for HttpAdapter {
    fn protocol_names(&self) -> &'static [&'static str] {
        &["http", "https"]
    }

    fn networks(&self) -> &'static [NetworkCapability] {
        &[NetworkCapability::Tcp]
    }

    fn validate(&self, node: &KernelNode) -> anyhow::Result<()> {
        if node.server.is_empty() || node.server_port == 0 {
            anyhow::bail!("HTTP proxy endpoint is invalid");
        }
        Ok(())
    }

    async fn connect(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream> {
        self.validate(node)?;
        let proxy = TargetAddress {
            host: node.server.clone(),
            port: node.server_port,
        };
        let addresses = context.resolver.resolve_proxy_server(&proxy).await?;
        let mut stream = None;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(value) => {
                    let _ = value.set_nodelay(true);
                    stream = Some(value);
                    break;
                }
                Err(err) => last_error = Some(err),
            }
        }
        let mut stream = stream.ok_or_else(|| {
            last_error
                .map(anyhow::Error::from)
                .unwrap_or_else(|| anyhow::anyhow!("no resolved address for HTTP proxy"))
        })?;
        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
            target, target
        );
        stream.write_all(request.as_bytes()).await?;
        let response = read_http_head(&mut stream).await?;
        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            anyhow::bail!("HTTP proxy CONNECT failed");
        }
        Ok(boxed_stream(stream))
    }
}

async fn read_http_head(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut buffer = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while buffer.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8(buffer)?);
        }
    }
    anyhow::bail!("HTTP proxy response header is too large")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dns::DnsResolver, session::KernelDnsConfig};
    use serde_json::json;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_adapter_sends_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_http_head(&mut stream).await.unwrap();
            assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let node = KernelNode {
            id: None,
            protocol: "http".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: port,
            user_id: "".to_string(),
            parameters: json!({}),
        };
        let resolver = DnsResolver::new(KernelDnsConfig::default());
        let context = OutboundContext {
            resolver: &resolver,
        };

        let stream = HttpAdapter
            .connect(
                &node,
                &TargetAddress {
                    host: "example.com".to_string(),
                    port: 443,
                },
                &context,
            )
            .await
            .unwrap();

        drop(stream);
        server.await.unwrap();
    }
}
