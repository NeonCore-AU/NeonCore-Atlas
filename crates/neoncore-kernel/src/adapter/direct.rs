use crate::{
    adapter::OutboundAdapter,
    dns::DnsResolver,
    session::{KernelNode, TargetAddress},
};
use tokio::net::TcpStream;

pub struct DirectAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for DirectAdapter {
    fn validate(_node: &KernelNode) -> anyhow::Result<()> {
        Ok(())
    }

    async fn connect(
        _node: &KernelNode,
        target: &TargetAddress,
        resolver: &DnsResolver,
    ) -> anyhow::Result<TcpStream> {
        let addresses = resolver.resolve(target).await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("no resolved address for {}", target)))
    }
}
