use crate::{
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use tokio::net::TcpStream;

pub mod direct;
pub mod http;
pub mod hy2;
pub mod vless;

#[async_trait::async_trait]
pub trait OutboundAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()>;
    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<TcpStream>;
}

pub fn validate_node(node: &KernelNode) -> anyhow::Result<()> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::validate(node),
        "http" | "https" => http::HttpAdapter::validate(node),
        "hysteria2" | "hy2" => hy2::Hy2Adapter::validate(node),
        "vless" => vless::VlessAdapter::validate(node),
        "anytls" => anyhow::bail!("AnyTLS adapter is queued after Hysteria2 and VLESS"),
        protocol => anyhow::bail!("unsupported protocol: {protocol}"),
    }
}

pub async fn connect(
    node: &KernelNode,
    target: &TargetAddress,
    resolver: &DnsResolver,
) -> anyhow::Result<TcpStream> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::connect(node, target, resolver).await,
        "http" | "https" => http::HttpAdapter::connect(node, target, resolver).await,
        "hysteria2" | "hy2" => hy2::Hy2Adapter::connect(node, target, resolver).await,
        "vless" => vless::VlessAdapter::connect(node, target, resolver).await,
        protocol => anyhow::bail!("protocol {protocol} is not available for outbound traffic yet"),
    }
}
