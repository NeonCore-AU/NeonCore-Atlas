use crate::{
    adapter::{
        boxed_stream, BoxedProxyStream, NetworkCapability, OutboundAdapter, OutboundContext,
    },
    session::{KernelNode, TargetAddress},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{timeout, Duration},
};

pub struct DirectAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for DirectAdapter {
    fn protocol_names(&self) -> &'static [&'static str] {
        &["direct"]
    }

    fn networks(&self) -> &'static [NetworkCapability] {
        &[NetworkCapability::Tcp, NetworkCapability::Udp]
    }

    fn validate(&self, _node: &KernelNode) -> anyhow::Result<()> {
        Ok(())
    }

    async fn connect(
        &self,
        _node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream> {
        let addresses = context.resolver.resolve(target).await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(boxed_stream(stream));
                }
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("no resolved address for {}", target)))
    }

    async fn send_udp(
        &self,
        _node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let addresses = context.resolver.resolve(target).await?;
        let address = addresses
            .first()
            .ok_or_else(|| anyhow::anyhow!("no resolved address for {}", target))?;
        let bind_addr = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.send_to(payload, address).await?;
        let mut response = vec![0_u8; 65_536];
        let (n, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut response)).await??;
        response.truncate(n);
        Ok(response)
    }
}
