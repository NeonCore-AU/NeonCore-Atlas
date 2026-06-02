use crate::{
    adapter::NetworkCapability,
    session::{KernelNode, TargetAddress},
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub id: u64,
    pub inbound: InboundKind,
    pub target: TargetAddress,
    pub network: NetworkCapability,
    pub selected_outbound: Option<OutboundSelection>,
    pub started_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    Socks5Udp,
    HttpConnect,
    HttpForward,
}

impl InboundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Socks5Udp => "socks5_udp",
            Self::HttpConnect => "http_connect",
            Self::HttpForward => "http_forward",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundSelection {
    pub tag: Option<String>,
    pub protocol: String,
}

impl ConnectionContext {
    pub fn new(inbound: InboundKind, target: TargetAddress, network: NetworkCapability) -> Self {
        Self {
            id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            inbound,
            target,
            network,
            selected_outbound: None,
            started_at: Instant::now(),
        }
    }

    pub fn select_outbound(&mut self, node: &KernelNode) {
        self.selected_outbound = Some(OutboundSelection {
            tag: node.id.clone(),
            protocol: node.protocol.clone(),
        });
    }
}
