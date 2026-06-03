impl ShadowsocksAdapter {
    async fn send_udp_over_uot(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
        config: &ShadowsocksConfig,
    ) -> anyhow::Result<Vec<u8>> {
        config.ensure_uot_supported()?;
        let key = uot_packet_conn_key(node, config);
        let pool = UOT_PACKET_CONNS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
        let conn_pool = {
            let mut pool = pool.lock().await;
            let now = StdInstant::now();
            let mut stale = Vec::new();
            for (key, conn_pool) in pool.iter() {
                if conn_pool.is_idle(now) {
                    stale.push(key.clone());
                }
            }
            for key in stale {
                pool.remove(&key);
            }
            pool.entry(key)
                .or_insert_with(|| Arc::new(UotPacketConnPool::new(UOT_INITIAL_POOL_LANES)))
                .clone()
        };
        conn_pool
            .send(self, node, target, payload, context)
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Shadowsocks UDP over {} needs server-side UoT support; preflight failed: {err}",
                    config.plugin.transport_name()
                )
            })
    }
}

struct UotPacketConnPool {
    lanes: StdMutex<Vec<Arc<UotPacketConn>>>,
    next: std::sync::atomic::AtomicUsize,
}

impl UotPacketConnPool {
    fn new(size: usize) -> Self {
        Self {
            lanes: StdMutex::new(
                (0..size.clamp(1, UOT_MAX_POOL_LANES))
                    .map(|_| Arc::new(UotPacketConn::new()))
                    .collect(),
            ),
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn is_idle(&self, now: StdInstant) -> bool {
        self.lanes
            .lock()
            .map(|lanes| {
                lanes.iter().all(|lane| {
                    lane.last_used()
                        .map(|last_used| now.duration_since(last_used) >= UOT_IDLE_TIMEOUT)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(true)
    }

    async fn send(
        &self,
        adapter: &ShadowsocksAdapter,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let lanes = self.lanes.lock().map(|lanes| lanes.clone()).unwrap_or_default();
        if lanes.is_empty() {
            anyhow::bail!("UoT packet connection pool is unavailable");
        }
        if let Some(lane) = lanes
            .iter()
            .find(|lane| lane.is_live() && lane.pending_count() == 0)
            .cloned()
        {
            return lane.send(adapter, node, target, payload, context).await;
        }
        let start = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % lanes.len();
        let lane = lanes
            .get(start)
            .cloned()
            .unwrap_or_else(|| self.grow_or_pick_lane(start));
        lane.send(adapter, node, target, payload, context).await
    }

    fn grow_or_pick_lane(&self, idx: usize) -> Arc<UotPacketConn> {
        let mut lanes = self.lanes.lock().expect("UoT lane pool lock poisoned");
        if lanes.len() < UOT_MAX_POOL_LANES {
            let lane = Arc::new(UotPacketConn::new());
            lanes.push(lane.clone());
            return lane;
        }
        lanes[idx % lanes.len()].clone()
    }
}

struct UotPacketConn {
    state: tokio::sync::Mutex<UotPacketConnState>,
    pending: PacketSessionDemux,
}

struct UotPacketConnState {
    writer: Option<tokio::io::WriteHalf<BoxedProxyStream>>,
    read_task: Option<tokio::task::JoinHandle<()>>,
    next_request_id: u64,
    last_used: StdInstant,
}

impl UotPacketConn {
    fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(UotPacketConnState {
                writer: None,
                read_task: None,
                next_request_id: 0,
                last_used: StdInstant::now(),
            }),
            pending: PacketSessionDemux::new(),
        }
    }

    fn last_used(&self) -> Option<StdInstant> {
        self.state.try_lock().ok().map(|state| state.last_used)
    }

    fn is_live(&self) -> bool {
        self.state
            .try_lock()
            .map(|state| {
                state.writer.is_some() && state.last_used.elapsed() < UOT_IDLE_TIMEOUT
            })
            .unwrap_or(false)
    }

    fn pending_count(&self) -> usize {
        self.pending.pending_count()
    }

    async fn send(
        &self,
        adapter: &ShadowsocksAdapter,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let expected_target = target_address(target);
        let target_key = udp_pending_key(&expected_target);
        let packet = encode_uot_packet(&expected_target, payload)?;

        let wait = {
            let mut state = self.state.lock().await;
            if state.writer.is_none() || state.last_used.elapsed() >= UOT_IDLE_TIMEOUT {
                self.reset_state(&mut state);
                let stream = open_uot_stream(adapter, node, context).await?;
                let (reader, writer) = tokio::io::split(stream);
                state.writer = Some(writer);
                state.read_task = Some(spawn_uot_reader(reader, self.pending.clone()));
            }
            state.last_used = StdInstant::now();
            let request_id = state.next_request_id;
            state.next_request_id = state.next_request_id.wrapping_add(1);
            let wait = self.pending.register(target_key.clone(), request_id);
            let writer = state
                .writer
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("UoT stream writer is not open"))?;
            let write_result = async {
                timeout(Duration::from_secs(10), writer.write_all(&packet)).await??;
                timeout(Duration::from_secs(10), writer.flush()).await??;
                anyhow::Ok(())
            }
            .await;
            if let Err(err) = write_result {
                self.pending.remove(&wait);
                self.reset_state(&mut state);
                return Err(err);
            }
            wait
        };

        let request_id = wait.request_id;
        let receiver = wait.receiver;
        match timeout(Duration::from_secs(15), receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.pending.remove_by_id(&target_key, request_id);
                self.close().await;
                anyhow::bail!("UoT packet connection closed before a response arrived")
            }
            Err(_) => {
                self.pending.remove_by_id(&target_key, request_id);
                anyhow::bail!("UoT packet response timed out")
            }
        }
    }

    async fn close(&self) {
        let mut state = self.state.lock().await;
        self.reset_state(&mut state);
    }

    fn reset_state(&self, state: &mut UotPacketConnState) {
        if let Some(task) = state.read_task.take() {
            task.abort();
        }
        state.writer = None;
        self.pending
            .fail_all(anyhow::anyhow!("UoT packet connection was reset"));
    }
}

async fn open_uot_stream(
    adapter: &ShadowsocksAdapter,
    node: &KernelNode,
    context: &OutboundContext<'_>,
) -> anyhow::Result<BoxedProxyStream> {
    let uot_target = TargetAddress {
        host: UOT_MAGIC_HOST.to_string(),
        port: UOT_MAGIC_PORT,
    };
    adapter.connect(node, &uot_target, context).await
}

fn uot_packet_conn_key(
    node: &KernelNode,
    config: &ShadowsocksConfig,
) -> String {
    let params = serde_json::to_string(&node.parameters).unwrap_or_default();
    let password_digest = Sha256::digest(config.password.as_bytes());
    let material = format!(
        "{}\0{}\0{}\0{}\0{}\0{:?}",
        node.protocol,
        config.server,
        config.server_port,
        format!("{password_digest:x}"),
        params,
        config.method
    );
    let digest = Sha256::digest(material.as_bytes());
    format!("{:x}", digest)
}

fn encode_uot_packet(address: &Address, payload: &[u8]) -> anyhow::Result<Bytes> {
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("UDP payload is too large for UoT framing");
    }
    let mut packet = BytesMut::with_capacity(64 + payload.len());
    address.write_to_buf(&mut packet);
    packet.put_u16(payload.len() as u16);
    packet.extend_from_slice(payload);
    Ok(packet.freeze())
}

fn spawn_uot_reader(
    mut reader: tokio::io::ReadHalf<BoxedProxyStream>,
    pending: PacketSessionDemux,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (address, payload) = match read_uot_packet(&mut reader).await {
                Ok(packet) => packet,
                Err(err) => {
                    pending.fail_all(err);
                    break;
                }
            };
            let key = udp_pending_key(&address);
            if !pending.deliver(&key, Ok(payload)) {
                tracing::warn!(
                    received = %address_display(&address),
                    "discarded UoT packet without a matching waiter"
                );
            }
        }
    })
}

async fn read_uot_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(Address, Vec<u8>)> {
    let atyp = read_u8(reader).await?;
    let address = match atyp {
        0x01 => {
            let mut ip = [0_u8; 4];
            reader.read_exact(&mut ip).await?;
            let port = read_u16(reader).await?;
            Address::SocketAddress(SocketAddr::from((ip, port)))
        }
        0x03 => {
            let len = read_u8(reader).await? as usize;
            let mut host = vec![0_u8; len];
            reader.read_exact(&mut host).await?;
            let port = read_u16(reader).await?;
            Address::DomainNameAddress(String::from_utf8(host)?, port)
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            reader.read_exact(&mut ip).await?;
            let port = read_u16(reader).await?;
            Address::SocketAddress(SocketAddr::from((ip, port)))
        }
        other => anyhow::bail!("invalid UoT address type {other}"),
    };
    let len = read_u16(reader).await? as usize;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok((address, payload))
}

#[cfg(test)]
async fn read_matching_uot_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: &Address,
) -> anyhow::Result<Vec<u8>> {
    let mut discarded_packets = 0_usize;
    let mut discarded_bytes = 0_usize;
    loop {
        let (address, payload) = read_uot_packet(reader).await?;
        if udp_address_matches(&address, expected) {
            return Ok(payload);
        }
        discarded_packets = discarded_packets.saturating_add(1);
        discarded_bytes = discarded_bytes.saturating_add(payload.len());
        if discarded_packets >= UOT_MAX_DISCARDED_PACKETS
            || discarded_bytes >= UOT_MAX_DISCARDED_BYTES
        {
            anyhow::bail!("UoT packet connection received too many packets for a different target");
        }
    }
}

async fn read_u8<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u8> {
    let mut value = [0_u8; 1];
    reader.read_exact(&mut value).await?;
    Ok(value[0])
}

async fn read_u16<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u16> {
    let mut value = [0_u8; 2];
    reader.read_exact(&mut value).await?;
    Ok(u16::from_be_bytes(value))
}
