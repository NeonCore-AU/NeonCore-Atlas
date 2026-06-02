use std::{
  collections::HashMap,
  sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
  },
  time::Duration,
};

use bytes::Bytes;
use quinn::Connection;
use tokio::sync::{mpsc, Mutex};

use crate::{
  protocol::{fragment_message, SessionDefraggers, UdpMessage, MAX_DATAGRAM_FRAME_SIZE},
  HysteriaError,
};

const UDP_REPLY_QUEUE: usize = 32;

pub(crate) struct UdpSessionManager {
  conn: Connection,
  next_id: AtomicU32,
  sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
}

impl UdpSessionManager {
  pub(crate) fn new(conn: Connection) -> Arc<Self> {
    let manager = Arc::new(Self {
      conn,
      next_id: AtomicU32::new(1),
      sessions: Mutex::new(HashMap::new()),
    });
    tokio::spawn(Self::receive_loop(Arc::clone(&manager)));
    manager
  }

  pub(crate) async fn exchange(
    &self,
    address: String,
    payload: Bytes,
    timeout: Duration,
  ) -> Result<Bytes, HysteriaError> {
    let session_id = self.next_session_id();
    let (tx, mut rx) = mpsc::channel(UDP_REPLY_QUEUE);
    self.sessions.lock().await.insert(session_id, tx);
    let result = async {
      self.send(session_id, address, payload).await?;
      let reply = tokio::time::timeout(timeout, rx.recv())
        .await
        .map_err(|_| HysteriaError::UdpTimeout)?
        .ok_or(HysteriaError::UdpSessionClosed)?;
      Ok(reply.payload)
    }
    .await;
    self.sessions.lock().await.remove(&session_id);
    result
  }

  async fn send(
    &self,
    session_id: u32,
    address: String,
    payload: Bytes,
  ) -> Result<(), HysteriaError> {
    let base = UdpMessage {
      session_id,
      packet_id: 0,
      fragment_id: 0,
      fragment_count: 1,
      address,
      payload,
    };
    let max_size = self
      .conn
      .max_datagram_size()
      .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
      .min(MAX_DATAGRAM_FRAME_SIZE);
    for message in fragment_message(base, max_size) {
      self.conn.send_datagram_wait(message.encode()).await?;
    }
    Ok(())
  }

  async fn receive_loop(manager: Arc<Self>) {
    let mut defraggers = SessionDefraggers::default();
    while let Ok(datagram) = manager.conn.read_datagram().await {
      let Ok(message) = UdpMessage::decode(&datagram) else {
        continue;
      };
      let Some(message) = defraggers.feed(message) else {
        continue;
      };
      let tx = {
        let sessions = manager.sessions.lock().await;
        sessions.get(&message.session_id).cloned()
      };
      if let Some(tx) = tx {
        let _ = tx.send(message).await;
      }
    }
    manager.sessions.lock().await.clear();
  }

  fn next_session_id(&self) -> u32 {
    loop {
      let id = self.next_id.fetch_add(1, Ordering::Relaxed);
      if id != 0 {
        return id;
      }
    }
  }
}
