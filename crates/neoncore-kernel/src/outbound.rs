use crate::{
    adapter::{self, BoxedProxyStream},
    connection::ConnectionContext,
    dns::DnsResolver,
    session::KernelNode,
};

pub struct OutboundHandler<'a> {
    node: KernelNode,
    resolver: &'a DnsResolver,
}

impl<'a> OutboundHandler<'a> {
    pub fn new(node: KernelNode, resolver: &'a DnsResolver) -> Self {
        Self { node, resolver }
    }

    pub async fn connect(
        &self,
        context: &mut ConnectionContext,
    ) -> anyhow::Result<BoxedProxyStream> {
        context.select_outbound(&self.node);
        adapter::connect_network(&self.node, &context.target, context.network, self.resolver).await
    }

    pub async fn send_udp(
        &self,
        context: &mut ConnectionContext,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        context.select_outbound(&self.node);
        adapter::send_udp_network(&self.node, &context.target, payload, self.resolver).await
    }
}
