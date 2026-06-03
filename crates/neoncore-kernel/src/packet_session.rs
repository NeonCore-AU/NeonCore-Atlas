use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

#[derive(Clone, Default)]
pub struct PacketSessionDemux {
    state: Arc<Mutex<PacketSessionState>>,
}

pub struct PacketSessionWait {
    pub key: String,
    pub request_id: u64,
    pub receiver: oneshot::Receiver<anyhow::Result<Vec<u8>>>,
}

struct PacketWaiter {
    request_id: u64,
    sender: oneshot::Sender<anyhow::Result<Vec<u8>>>,
}

#[derive(Default)]
struct PacketSessionState {
    pending: HashMap<String, VecDeque<PacketWaiter>>,
    fifo: VecDeque<(String, u64)>,
}

impl PacketSessionDemux {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.pending.values().map(VecDeque::len).sum())
            .unwrap_or(usize::MAX)
    }

    pub fn register(&self, key: impl Into<String>, request_id: u64) -> PacketSessionWait {
        let key = key.into();
        let (sender, receiver) = oneshot::channel();
        let mut state = self
            .state
            .lock()
            .expect("packet session demux lock poisoned");
        state
            .pending
            .entry(key.clone())
            .or_default()
            .push_back(PacketWaiter { request_id, sender });
        state.fifo.push_back((key.clone(), request_id));
        PacketSessionWait {
            key,
            request_id,
            receiver,
        }
    }

    pub fn remove(&self, wait: &PacketSessionWait) {
        self.remove_by_id(&wait.key, wait.request_id);
    }

    pub fn remove_by_id(&self, key: &str, request_id: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(queue) = state.pending.get_mut(key) {
            queue.retain(|waiter| waiter.request_id != request_id);
            if queue.is_empty() {
                state.pending.remove(key);
            }
        }
        state
            .fifo
            .retain(|(pending_key, pending_id)| pending_key != key || *pending_id != request_id);
    }

    pub fn deliver(&self, key: &str, result: anyhow::Result<Vec<u8>>) -> bool {
        let waiter = {
            let Ok(mut state) = self.state.lock() else {
                return false;
            };
            let Some(queue) = state.pending.get_mut(key) else {
                return false;
            };
            let waiter = queue.pop_front();
            if queue.is_empty() {
                state.pending.remove(key);
            }
            if let Some(waiter) = waiter.as_ref() {
                state.fifo.retain(|(pending_key, pending_id)| {
                    pending_key != key || *pending_id != waiter.request_id
                });
            }
            waiter
        };
        if let Some(waiter) = waiter {
            let _ = waiter.sender.send(result);
            true
        } else {
            false
        }
    }

    pub fn deliver_next(&self, result: anyhow::Result<Vec<u8>>) -> bool {
        let waiter = {
            let Ok(mut state) = self.state.lock() else {
                return false;
            };
            loop {
                let Some((key, request_id)) = state.fifo.pop_front() else {
                    return false;
                };
                let Some(queue) = state.pending.get_mut(&key) else {
                    continue;
                };
                let Some(position) = queue
                    .iter()
                    .position(|waiter| waiter.request_id == request_id)
                else {
                    continue;
                };
                let waiter = queue.remove(position);
                if queue.is_empty() {
                    state.pending.remove(&key);
                }
                break waiter;
            }
        };
        if let Some(waiter) = waiter {
            let _ = waiter.sender.send(result);
            true
        } else {
            false
        }
    }

    pub fn fail_all(&self, error: anyhow::Error) {
        let message = error.to_string();
        let waiters = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.fifo.clear();
            state
                .pending
                .drain()
                .flat_map(|(_, queue)| queue.into_iter().collect::<Vec<_>>())
                .collect::<Vec<_>>()
        };
        for waiter in waiters {
            let _ = waiter.sender.send(Err(anyhow::anyhow!(message.clone())));
        }
    }
}

pub fn packet_target_key(host: &str, port: u16) -> String {
    format!("{}:{port}", host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn demux_delivers_out_of_order_packets_by_target() {
        let demux = PacketSessionDemux::new();
        let first = demux.register("a.example:53", 1);
        let second = demux.register("b.example:53", 2);

        assert!(demux.deliver("b.example:53", Ok(b"second".to_vec())));
        assert!(demux.deliver("a.example:53", Ok(b"first".to_vec())));

        assert_eq!(second.receiver.await.unwrap().unwrap(), b"second");
        assert_eq!(first.receiver.await.unwrap().unwrap(), b"first");
        assert_eq!(demux.pending_count(), 0);
    }

    #[tokio::test]
    async fn demux_removes_timed_out_waiter_without_affecting_siblings() {
        let demux = PacketSessionDemux::new();
        let first = demux.register("a.example:53", 1);
        let second = demux.register("a.example:53", 2);

        demux.remove(&first);
        assert!(demux.deliver("a.example:53", Ok(b"second".to_vec())));
        assert!(first.receiver.await.is_err());
        assert_eq!(second.receiver.await.unwrap().unwrap(), b"second");
        assert_eq!(demux.pending_count(), 0);
    }

    #[tokio::test]
    async fn demux_can_deliver_targetless_packets_in_fifo_order() {
        let demux = PacketSessionDemux::new();
        let first = demux.register("a.example:53", 1);
        let second = demux.register("b.example:53", 2);

        assert!(demux.deliver_next(Ok(b"first".to_vec())));
        assert!(demux.deliver_next(Ok(b"second".to_vec())));

        assert_eq!(first.receiver.await.unwrap().unwrap(), b"first");
        assert_eq!(second.receiver.await.unwrap().unwrap(), b"second");
        assert_eq!(demux.pending_count(), 0);
    }
}
