use crate::{
    adapter::OutboundAdapter,
    session::{KernelNode, TargetAddress},
};
use std::net::TcpStream;

pub struct DirectAdapter;

impl OutboundAdapter for DirectAdapter {
    fn validate(_node: &KernelNode) -> anyhow::Result<()> {
        Ok(())
    }

    fn connect(_node: &KernelNode, target: &TargetAddress) -> anyhow::Result<TcpStream> {
        Ok(TcpStream::connect(target.to_string())?)
    }
}
