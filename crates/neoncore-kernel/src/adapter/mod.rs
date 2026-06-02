use crate::{
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod anytls;

pub mod direct;
pub mod http;
pub mod hysteria2;
mod reality;
pub mod shadowsocks;
pub mod vless;

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedProxyStream = Pin<Box<dyn ProxyStream>>;

pub struct OutboundContext<'a> {
    pub resolver: &'a DnsResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCapability {
    Tcp,
    Udp,
}

pub fn boxed_stream<T>(stream: T) -> BoxedProxyStream
where
    T: ProxyStream + 'static,
{
    Box::pin(stream)
}

#[async_trait::async_trait]
pub trait OutboundAdapter: Send + Sync {
    fn protocol_names(&self) -> &'static [&'static str];

    fn networks(&self) -> &'static [NetworkCapability];

    fn validate(&self, node: &KernelNode) -> anyhow::Result<()>;

    async fn connect(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream>;

    async fn send_udp(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let _ = (node, target, payload, context);
        anyhow::bail!("UDP is not implemented for {}", self.protocol_names()[0])
    }
}

static DIRECT_ADAPTER: direct::DirectAdapter = direct::DirectAdapter;
static HTTP_ADAPTER: http::HttpAdapter = http::HttpAdapter;
static SHADOWSOCKS_ADAPTER: shadowsocks::ShadowsocksAdapter = shadowsocks::ShadowsocksAdapter;
static HY2_ADAPTER: hysteria2::Hy2Adapter = hysteria2::Hy2Adapter;
static VLESS_ADAPTER: vless::VlessAdapter = vless::VlessAdapter;
static ANYTLS_ADAPTER: anytls::AnyTlsAdapter = anytls::AnyTlsAdapter;

static OUTBOUND_ADAPTERS: &[&dyn OutboundAdapter] = &[
    &DIRECT_ADAPTER,
    &HTTP_ADAPTER,
    &SHADOWSOCKS_ADAPTER,
    &HY2_ADAPTER,
    &VLESS_ADAPTER,
    &ANYTLS_ADAPTER,
];

pub fn validate_node(node: &KernelNode) -> anyhow::Result<()> {
    adapter_for(&node.protocol)?.validate(node)
}

pub async fn connect_network(
    node: &KernelNode,
    target: &TargetAddress,
    network: NetworkCapability,
    resolver: &DnsResolver,
) -> anyhow::Result<BoxedProxyStream> {
    let context = OutboundContext { resolver };
    let adapter = adapter_for(&node.protocol)?;
    ensure_network(adapter, network)?;
    adapter.connect(node, target, &context).await
}

pub async fn send_udp_network(
    node: &KernelNode,
    target: &TargetAddress,
    payload: &[u8],
    resolver: &DnsResolver,
) -> anyhow::Result<Vec<u8>> {
    let context = OutboundContext { resolver };
    let adapter = adapter_for(&node.protocol)?;
    ensure_network(adapter, NetworkCapability::Udp)?;
    adapter.send_udp(node, target, payload, &context).await
}

fn adapter_for(protocol: &str) -> anyhow::Result<&'static dyn OutboundAdapter> {
    OUTBOUND_ADAPTERS
        .iter()
        .copied()
        .find(|adapter| {
            adapter
                .protocol_names()
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
        })
        .ok_or_else(|| anyhow::anyhow!("unsupported protocol: {protocol}"))
}

fn ensure_network(adapter: &dyn OutboundAdapter, network: NetworkCapability) -> anyhow::Result<()> {
    if adapter.networks().contains(&network) {
        return Ok(());
    }
    anyhow::bail!(
        "protocol {} does not support {:?}",
        adapter.protocol_names()[0],
        network
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(protocol: &str) -> KernelNode {
        KernelNode {
            id: None,
            protocol: protocol.to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8080,
            user_id: String::new(),
            parameters: json!({}),
        }
    }

    #[test]
    fn registry_accepts_protocol_aliases() {
        validate_node(&node("https")).unwrap();
        validate_node(&node("direct")).unwrap();
    }

    #[test]
    fn registry_rejects_unknown_protocols() {
        let err = validate_node(&node("unknown-protocol")).unwrap_err();
        assert!(err.to_string().contains("unsupported protocol"));
    }

    #[test]
    fn registry_exposes_network_capabilities() {
        let adapter = adapter_for("vless").unwrap();
        assert!(adapter.networks().contains(&NetworkCapability::Tcp));
    }
}
