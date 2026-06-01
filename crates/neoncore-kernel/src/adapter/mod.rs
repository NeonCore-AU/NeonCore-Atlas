use crate::session::{KernelNode, TargetAddress};
use std::net::TcpStream;

pub mod direct;
pub mod hy2;
pub mod vless;

pub trait OutboundAdapter {
    fn validate(node: &KernelNode) -> anyhow::Result<()>;
    fn connect(node: &KernelNode, target: &TargetAddress) -> anyhow::Result<TcpStream>;
}

pub fn validate_node(node: &KernelNode) -> anyhow::Result<()> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::validate(node),
        "hysteria2" | "hy2" => hy2::Hy2Adapter::validate(node),
        "vless" => vless::VlessAdapter::validate(node),
        "anytls" => anyhow::bail!("AnyTLS adapter is queued after Hysteria2 and VLESS"),
        protocol => anyhow::bail!("unsupported protocol: {protocol}"),
    }
}

pub fn connect(node: &KernelNode, target: &TargetAddress) -> anyhow::Result<TcpStream> {
    match node.protocol.as_str() {
        "direct" => direct::DirectAdapter::connect(node, target),
        "hysteria2" | "hy2" => hy2::Hy2Adapter::connect(node, target),
        "vless" => vless::VlessAdapter::connect(node, target),
        protocol => anyhow::bail!("protocol {protocol} is not available for outbound traffic yet"),
    }
}
