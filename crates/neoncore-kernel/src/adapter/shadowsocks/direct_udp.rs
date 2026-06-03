impl ShadowsocksAdapter {
    async fn send_udp_direct(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        config: &ShadowsocksConfig,
        address: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        let key = direct_udp_packet_conn_key(node, config, address);
        let pools = DIRECT_UDP_PACKET_CONNS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
        let conn_pool = {
            let mut pools = pools.lock().await;
            let now = StdInstant::now();
            pools.retain(|_, pool| !pool.is_idle(now));
            pools
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(DirectUdpPacketConnPool::new(DIRECT_UDP_INITIAL_POOL_LANES))
                })
                .clone()
        };
        conn_pool.send(target, payload, config, address).await
    }
}

struct DirectUdpPacketConnPool {
    lanes: StdMutex<Vec<Arc<DirectUdpPacketConn>>>,
    next: std::sync::atomic::AtomicUsize,
}

impl DirectUdpPacketConnPool {
    fn new(size: usize) -> Self {
        Self {
            lanes: StdMutex::new(
                (0..size.clamp(1, DIRECT_UDP_MAX_POOL_LANES))
                    .map(|_| Arc::new(DirectUdpPacketConn::new()))
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
                        .map(|last_used| now.duration_since(last_used) >= DIRECT_UDP_IDLE_TIMEOUT)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(true)
    }

    async fn send(
        &self,
        target: &TargetAddress,
        payload: &[u8],
        config: &ShadowsocksConfig,
        address: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        let lanes = self.lanes.lock().map(|lanes| lanes.clone()).unwrap_or_default();
        if lanes.is_empty() {
            anyhow::bail!("direct UDP packet connection pool is unavailable");
        }
        if let Some(lane) = lanes
            .iter()
            .find(|lane| lane.is_live_for(address) && lane.pending_count() == 0)
            .cloned()
        {
            return lane.send(target, payload, config, address).await;
        }
        let start = self
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % lanes.len();
        let lane = lanes
            .get(start)
            .cloned()
            .unwrap_or_else(|| self.grow_or_pick_lane(start));
        lane.send(target, payload, config, address).await
    }

    fn grow_or_pick_lane(&self, idx: usize) -> Arc<DirectUdpPacketConn> {
        let mut lanes = self
            .lanes
            .lock()
            .expect("direct UDP lane pool lock poisoned");
        if lanes.len() < DIRECT_UDP_MAX_POOL_LANES {
            let lane = Arc::new(DirectUdpPacketConn::new());
            lanes.push(lane.clone());
            return lane;
        }
        lanes[idx % lanes.len()].clone()
    }
}

struct DirectUdpPacketConn {
    state: tokio::sync::Mutex<DirectUdpPacketConnState>,
    control: Arc<StdMutex<UdpSocketControlData>>,
    pending: PacketSessionDemux,
}

struct DirectUdpPacketConnState {
    socket: Option<Arc<UdpSocket>>,
    address: SocketAddr,
    decoder: Option<DirectUdpPacketDecoder>,
    read_task: Option<tokio::task::JoinHandle<()>>,
    next_request_id: u64,
    last_used: StdInstant,
}

impl DirectUdpPacketConn {
    fn new() -> Self {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random();
        control.packet_id = rand::random::<u32>() as u64;
        Self {
            state: tokio::sync::Mutex::new(DirectUdpPacketConnState {
                socket: None,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                decoder: None,
                read_task: None,
                next_request_id: 0,
                last_used: StdInstant::now(),
            }),
            control: Arc::new(StdMutex::new(control)),
            pending: PacketSessionDemux::new(),
        }
    }

    fn last_used(&self) -> Option<StdInstant> {
        self.state.try_lock().ok().map(|state| state.last_used)
    }

    fn is_live_for(&self, address: SocketAddr) -> bool {
        self.state
            .try_lock()
            .map(|state| {
                state.socket.is_some()
                    && state.address == address
                    && state.last_used.elapsed() < DIRECT_UDP_IDLE_TIMEOUT
            })
            .unwrap_or(false)
    }

    fn pending_count(&self) -> usize {
        self.pending.pending_count()
    }

    async fn send(
        &self,
        target: &TargetAddress,
        payload: &[u8],
        config: &ShadowsocksConfig,
        address: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        let target = target_address(target);
        let target_key = udp_pending_key(&target);
        let (socket, wait, packet) = {
            let mut state = self.state.lock().await;
            if state.socket.is_none()
                || state.address != address
                || state.last_used.elapsed() >= DIRECT_UDP_IDLE_TIMEOUT
            {
                self.reset_state(&mut state);
                let socket = Arc::new(open_direct_udp_socket(address).await?);
                state.address = address;
                state.decoder = Some(direct_udp_packet_decoder(config, address)?);
                state.socket = Some(socket.clone());
                reset_udp_control(&self.control);
                state.read_task = Some(spawn_direct_udp_reader(
                    socket,
                    state.decoder.clone().expect("direct UDP decoder is initialized"),
                    self.control.clone(),
                    self.pending.clone(),
                ));
            }
            state.last_used = StdInstant::now();
            let packet = self.encode_packet(&target, payload, config, address)?;
            let socket = state
                .socket
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("direct UDP socket is not open"))?;
            let request_id = state.next_request_id;
            state.next_request_id = state.next_request_id.wrapping_add(1);
            let wait = self.pending.register(target_key.clone(), request_id);
            (socket, wait, packet)
        };

        if let Err(err) = socket.send(&packet).await {
            self.pending.remove(&wait);
            self.close().await;
            return Err(err.into());
        }

        let request_id = wait.request_id;
        let receiver = wait.receiver;
        match timeout(Duration::from_secs(10), receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.pending.remove_by_id(&target_key, request_id);
                self.close().await;
                anyhow::bail!("direct UDP packet connection closed before a response arrived")
            }
            Err(_) => {
                self.pending.remove_by_id(&target_key, request_id);
                anyhow::bail!("direct UDP packet response timed out")
            }
        }
    }

    fn encode_packet(
        &self,
        target: &Address,
        payload: &[u8],
        config: &ShadowsocksConfig,
        address: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        match config.method {
            ShadowsocksMethod::BuiltIn(method) => {
                let server = ServerConfig::new(address, config.password.clone(), method)?;
                if config.ssr_protocol.is_native() || config.one_time_auth {
                    let protocol = if config.ssr_protocol.is_native() {
                        config.ssr_protocol.clone()
                    } else {
                        SsrProtocol::VerifySha1
                    };
                    let packet = encrypt_ssr_udp_builtin_packet(
                        method,
                        server.key(),
                        &target,
                        payload,
                        &protocol,
                        &config.ssr_protocol_param,
                    )?;
                    Ok(packet)
                } else {
                    let mut packet = BytesMut::new();
                    let mut control = self
                        .control
                        .lock()
                        .expect("direct UDP control lock poisoned");
                    control.packet_id = control.packet_id.wrapping_add(1);
                    let ss_context = Context::new(ServerType::Local);
                    encrypt_client_payload(
                        &ss_context,
                        method,
                        server.key(),
                        target,
                        &control,
                        server.identity_keys(),
                        payload,
                        &mut packet,
                    );
                    Ok(packet.to_vec())
                }
            }
            ShadowsocksMethod::NeonLegacy(method) => {
                let key = legacy_evp_bytes_to_key(config.password.as_bytes(), method.key_len());
                if config.ssr_protocol.is_native() || config.one_time_auth {
                    let protocol = if config.ssr_protocol.is_native() {
                        config.ssr_protocol.clone()
                    } else {
                        SsrProtocol::VerifySha1
                    };
                    let packet = encrypt_ssr_udp_legacy_packet(
                        method,
                        &key,
                        &target,
                        payload,
                        &protocol,
                        &config.ssr_protocol_param,
                    )?;
                    Ok(packet)
                } else {
                    encrypt_legacy_udp_packet(method, &key, target, payload)
                }
            }
        }
    }

    async fn close(&self) {
        let mut state = self.state.lock().await;
        self.reset_state(&mut state);
    }

    fn reset_state(&self, state: &mut DirectUdpPacketConnState) {
        if let Some(task) = state.read_task.take() {
            task.abort();
        }
        state.socket = None;
        state.decoder = None;
        self.pending
            .fail_all(anyhow::anyhow!("direct UDP packet connection was reset"));
    }
}

#[derive(Clone)]
enum DirectUdpPacketDecoder {
    BuiltInSsr {
        method: CipherKind,
        key: Vec<u8>,
        protocol: SsrProtocol,
        protocol_param: String,
    },
    BuiltInStandard {
        method: CipherKind,
        key: Vec<u8>,
    },
    LegacySsr {
        method: NeonLegacyCipherKind,
        key: Vec<u8>,
        protocol: SsrProtocol,
        protocol_param: String,
    },
    LegacyStandard {
        method: NeonLegacyCipherKind,
        key: Vec<u8>,
    },
}

struct DirectUdpDecodedPacket {
    target: Address,
    payload: Vec<u8>,
    returned_control: Option<UdpSocketControlData>,
}

fn direct_udp_packet_decoder(
    config: &ShadowsocksConfig,
    address: SocketAddr,
) -> anyhow::Result<DirectUdpPacketDecoder> {
    match config.method {
        ShadowsocksMethod::BuiltIn(method) => {
            let server = ServerConfig::new(address, config.password.clone(), method)?;
            if config.ssr_protocol.is_native() || config.one_time_auth {
                Ok(DirectUdpPacketDecoder::BuiltInSsr {
                    method,
                    key: server.key().to_vec(),
                    protocol: if config.ssr_protocol.is_native() {
                        config.ssr_protocol.clone()
                    } else {
                        SsrProtocol::VerifySha1
                    },
                    protocol_param: config.ssr_protocol_param.clone(),
                })
            } else {
                Ok(DirectUdpPacketDecoder::BuiltInStandard {
                    method,
                    key: server.key().to_vec(),
                })
            }
        }
        ShadowsocksMethod::NeonLegacy(method) => {
            let key = legacy_evp_bytes_to_key(config.password.as_bytes(), method.key_len());
            if config.ssr_protocol.is_native() || config.one_time_auth {
                Ok(DirectUdpPacketDecoder::LegacySsr {
                    method,
                    key,
                    protocol: if config.ssr_protocol.is_native() {
                        config.ssr_protocol.clone()
                    } else {
                        SsrProtocol::VerifySha1
                    },
                    protocol_param: config.ssr_protocol_param.clone(),
                })
            } else {
                Ok(DirectUdpPacketDecoder::LegacyStandard { method, key })
            }
        }
    }
}

fn decode_direct_udp_packet(
    decoder: &DirectUdpPacketDecoder,
    packet: &mut [u8],
) -> anyhow::Result<DirectUdpDecodedPacket> {
    match decoder {
        DirectUdpPacketDecoder::BuiltInSsr {
            method,
            key,
            protocol,
            protocol_param,
        } => {
            let (target, payload) =
                decrypt_ssr_udp_builtin_packet(*method, key, packet, protocol, protocol_param)?;
            Ok(DirectUdpDecodedPacket {
                target,
                payload,
                returned_control: None,
            })
        }
        DirectUdpPacketDecoder::BuiltInStandard { method, key } => {
            let ss_context = Context::new(ServerType::Local);
            let (len, target, returned_control) =
                decrypt_server_payload(&ss_context, *method, key, packet)?;
            let payload = packet[..len].to_vec();
            Ok(DirectUdpDecodedPacket {
                target,
                payload,
                returned_control,
            })
        }
        DirectUdpPacketDecoder::LegacySsr {
            method,
            key,
            protocol,
            protocol_param,
        } => {
            let (target, payload) =
                decrypt_ssr_udp_legacy_packet(*method, key, packet, protocol, protocol_param)?;
            Ok(DirectUdpDecodedPacket {
                target,
                payload,
                returned_control: None,
            })
        }
        DirectUdpPacketDecoder::LegacyStandard { method, key } => {
            let (target, payload) = decrypt_legacy_udp_packet(*method, key, packet)?;
            Ok(DirectUdpDecodedPacket {
                target,
                payload,
                returned_control: None,
            })
        }
    }
}

fn spawn_direct_udp_reader(
    socket: Arc<UdpSocket>,
    decoder: DirectUdpPacketDecoder,
    control: Arc<StdMutex<UdpSocketControlData>>,
    pending: PacketSessionDemux,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        loop {
            let n = match socket.recv(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    pending.fail_all(anyhow::anyhow!(err));
                    break;
                }
            };
            let mut packet = buffer[..n].to_vec();
            let decoded = match decode_direct_udp_packet(&decoder, &mut packet) {
                Ok(decoded) => decoded,
                Err(err) => {
                    tracing::warn!(error = %err, "discarded undecodable Shadowsocks UDP packet");
                    continue;
                }
            };
            let key = udp_pending_key(&decoded.target);
            let delivered = pending.deliver(&key, Ok(decoded.payload));
            if delivered {
                if let Some(returned_control) = decoded.returned_control {
                    if let Ok(mut control) = control.lock() {
                        control.server_session_id = returned_control.server_session_id;
                    }
                }
            } else {
                tracing::warn!(
                    received = %address_display(&decoded.target),
                    "discarded Shadowsocks UDP packet without a matching waiter"
                );
            }
        }
    })
}

async fn open_direct_udp_socket(address: SocketAddr) -> anyhow::Result<UdpSocket> {
    let bind_addr = if address.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(address).await?;
    Ok(socket)
}

fn direct_udp_packet_conn_key(
    node: &KernelNode,
    config: &ShadowsocksConfig,
    address: SocketAddr,
) -> String {
    let params = serde_json::to_string(&node.parameters).unwrap_or_default();
    let password_digest = Sha256::digest(config.password.as_bytes());
    let material = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{:?}",
        node.protocol,
        config.server,
        config.server_port,
        address,
        format!("{password_digest:x}"),
        params,
        config.method
    );
    let digest = Sha256::digest(material.as_bytes());
    format!("{digest:x}")
}

#[cfg(test)]
fn udp_address_matches(left: &Address, right: &Address) -> bool {
    match (left, right) {
        (Address::SocketAddress(left), Address::SocketAddress(right)) => left == right,
        (Address::DomainNameAddress(left_host, left_port), Address::DomainNameAddress(right_host, right_port)) => {
            left_port == right_port && left_host.eq_ignore_ascii_case(right_host)
        }
        (Address::SocketAddress(left), Address::DomainNameAddress(right_host, right_port))
        | (Address::DomainNameAddress(right_host, right_port), Address::SocketAddress(left)) => {
            left.port() == *right_port && left.ip().to_string().eq_ignore_ascii_case(right_host)
        }
    }
}

fn address_display(address: &Address) -> String {
    match address {
        Address::SocketAddress(address) => address.to_string(),
        Address::DomainNameAddress(host, port) => format!("{host}:{port}"),
    }
}

fn udp_pending_key(address: &Address) -> String {
    match address {
        Address::SocketAddress(address) => address.to_string(),
        Address::DomainNameAddress(host, port) => {
            format!("{}:{port}", host.to_ascii_lowercase())
        }
    }
}

fn reset_udp_control(control: &Arc<StdMutex<UdpSocketControlData>>) {
    if let Ok(mut control) = control.lock() {
        *control = UdpSocketControlData::default();
        control.client_session_id = rand::random();
        control.packet_id = rand::random::<u32>() as u64;
    }
}
