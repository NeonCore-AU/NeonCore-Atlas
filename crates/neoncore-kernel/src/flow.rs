use crate::{
    adapter::{boxed_stream, BoxedProxyStream},
    connection::ConnectionContext,
};
use tokio::{
    io::{duplex, AsyncWriteExt, DuplexStream},
    net::TcpStream,
};
use tracing::debug;

#[allow(dead_code)]
pub const DEFAULT_FLOW_PIPE_CAPACITY: usize = 128 * 1024;
pub const LARGE_FLOW_PIPE_CAPACITY: usize = 4 * 1024 * 1024;
pub const SMALL_FLOW_COPY_BUFFER_SIZE: usize = 16 * 1024;
pub const FLOW_COPY_BUFFER_SIZE: usize = 128 * 1024;
pub const FLOW_LINK_BUFFER_SIZE: usize = 128 * 1024;

pub struct FlowPipe {
    local: DuplexStream,
    bridge: DuplexStream,
}

impl FlowPipe {
    pub fn new(capacity: usize) -> Self {
        let (local, bridge) = duplex(capacity);
        Self { local, bridge }
    }

    pub fn into_parts(self) -> (BoxedProxyStream, DuplexStream) {
        (boxed_stream(self.local), self.bridge)
    }
}

pub struct FlowLink {
    context: ConnectionContext,
    inbound: TcpStream,
    outbound: BoxedProxyStream,
}

impl FlowLink {
    pub fn new(context: ConnectionContext, inbound: TcpStream, outbound: BoxedProxyStream) -> Self {
        Self {
            context,
            inbound,
            outbound,
        }
    }

    pub async fn relay(mut self) -> anyhow::Result<()> {
        let (uplink_bytes, downlink_bytes) = tokio::io::copy_bidirectional_with_sizes(
            &mut self.inbound,
            &mut self.outbound,
            FLOW_LINK_BUFFER_SIZE,
            FLOW_LINK_BUFFER_SIZE,
        )
        .await?;
        let elapsed_ms = self.context.started_at.elapsed().as_millis();
        let outbound_protocol = self
            .context
            .selected_outbound
            .as_ref()
            .map(|selection| selection.protocol.as_str())
            .unwrap_or("unknown");
        let outbound_tag = self
            .context
            .selected_outbound
            .as_ref()
            .and_then(|selection| selection.tag.as_deref())
            .unwrap_or("default");
        debug!(
            connection_id = self.context.id,
            inbound = self.context.inbound.as_str(),
            target = %self.context.target,
            outbound_protocol,
            outbound_tag,
            uplink_bytes,
            downlink_bytes,
            elapsed_ms,
            "flow relayed"
        );
        Ok(())
    }

    pub async fn write_outbound(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.outbound.write_all(data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn flow_pipe_relays_local_and_bridge_halves() {
        let (mut local, mut bridge) = FlowPipe::new(1024).into_parts();

        bridge.write_all(b"pong").await.unwrap();
        let mut payload = [0_u8; 4];
        local.read_exact(&mut payload).await.unwrap();

        assert_eq!(&payload, b"pong");
    }
}
