use crate::{
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod anytls;

pub mod direct;
pub mod http;
pub mod hy2;
mod reality;
pub mod shadowsocks;
pub mod vless;

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedProxyStream = Pin<Box<dyn ProxyStream>>;

pub fn boxed_stream<T>(stream: T) -> BoxedProxyStream
where
    T: ProxyStream + 'static,
{
    Box::pin(stream)
}

#[async_trait::async_trait]
pub trait OutboundAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()>;
    async fn connect(
        node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<BoxedProxyStream>;
}

pub fn validate_node(node: &KernelNode) -> anyhow::Result<()> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::validate(node),
        "http" | "https" => http::HttpAdapter::validate(node),
        "ss" | "shadowsocks" => shadowsocks::ShadowsocksAdapter::validate(node),
        "hysteria2" | "hy2" => hy2::Hy2Adapter::validate(node),
        "vless" => vless::VlessAdapter::validate(node),
        "anytls" => anytls::AnyTlsAdapter::validate(node),
        protocol => anyhow::bail!("unsupported protocol: {protocol}"),
    }
}

pub async fn connect(
    node: &KernelNode,
    target: &TargetAddress,
    resolver: &DnsResolver,
) -> anyhow::Result<BoxedProxyStream> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::connect(node, target, resolver).await,
        "http" | "https" => http::HttpAdapter::connect(node, target, resolver).await,
        "ss" | "shadowsocks" => {
            shadowsocks::ShadowsocksAdapter::connect(node, target, resolver).await
        }
        "hysteria2" | "hy2" => hy2::Hy2Adapter::connect(node, target, resolver).await,
        "vless" => vless::VlessAdapter::connect(node, target, resolver).await,
        "anytls" => anytls::AnyTlsAdapter::connect(node, target, resolver).await,
        protocol => anyhow::bail!("protocol {protocol} is not available for outbound traffic yet"),
    }
}
