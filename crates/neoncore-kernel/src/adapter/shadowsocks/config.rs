#[derive(Clone, Debug, PartialEq, Eq)]
enum ShadowsocksPlugin {
    None,
    SimpleObfsHttp {
        host: String,
        port: u16,
    },
    SsrHttp {
        host: String,
        port: u16,
        post: bool,
        headers: String,
    },
    SimpleObfsTls {
        host: String,
    },
    SsrTls {
        host: String,
        key: Vec<u8>,
    },
    RandomHead,
    WebSocket {
        host: String,
        path: String,
        tls: bool,
    },
    XHttp(XHttpPluginConfig),
    ExternalSip003 {
        program: String,
        options: String,
    },
    ShadowTls(ShadowTlsConfig),
    Kcptun(KcptunConfig),
    H2 {
        host: String,
        path: String,
        tls: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowsocksUdpMode {
    Direct,
    UdpOverTcp,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XHttpMode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XHttpVersion {
    Auto,
    H1,
    H2,
    H3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct XHttpPluginConfig {
    host: String,
    path: String,
    tls: bool,
    mode: XHttpMode,
    version: XHttpVersion,
    max_each_post_bytes: usize,
    min_posts_interval_ms: u64,
    skip_cert_verify: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ShadowTlsConfig {
    host: String,
    password: String,
    version: u8,
    alpn: Vec<String>,
    skip_cert_verify: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KcptunConfig {
    key: String,
    crypt: String,
    mode: String,
    conn: usize,
    auto_expire: u64,
    scavenge_ttl: u64,
    mtu: usize,
    rate_limit: u32,
    snd_wnd: u16,
    rcv_wnd: u16,
    data_shard: usize,
    parity_shard: usize,
    dscp: u32,
    no_comp: bool,
    ack_nodelay: bool,
    no_delay: i32,
    interval: i32,
    resend: i32,
    no_congestion: bool,
    sock_buf: usize,
    smux_ver: u8,
    smux_buf: usize,
    frame_size: usize,
    stream_buf: usize,
    keep_alive: u64,
}

impl Default for KcptunConfig {
    fn default() -> Self {
        let mut config = Self {
            key: "it's a secrect".to_string(),
            crypt: "aes".to_string(),
            mode: "fast".to_string(),
            conn: 1,
            auto_expire: 0,
            scavenge_ttl: 600,
            mtu: 1350,
            rate_limit: 0,
            snd_wnd: 128,
            rcv_wnd: 512,
            data_shard: 10,
            parity_shard: 3,
            dscp: 0,
            no_comp: false,
            ack_nodelay: false,
            no_delay: 0,
            interval: 50,
            resend: 0,
            no_congestion: false,
            sock_buf: 4_194_304,
            smux_ver: 1,
            smux_buf: 4_194_304,
            frame_size: 8192,
            stream_buf: 2_097_152,
            keep_alive: 10,
        };
        config.apply_mode();
        config
    }
}

impl KcptunConfig {
    fn apply_mode(&mut self) {
        match self.mode.as_str() {
            "normal" => {
                self.no_delay = 0;
                self.interval = 40;
                self.resend = 2;
                self.no_congestion = true;
            }
            "fast" => {
                self.no_delay = 0;
                self.interval = 30;
                self.resend = 2;
                self.no_congestion = true;
            }
            "fast2" => {
                self.no_delay = 1;
                self.interval = 20;
                self.resend = 2;
                self.no_congestion = true;
            }
            "fast3" => {
                self.no_delay = 1;
                self.interval = 10;
                self.resend = 2;
                self.no_congestion = true;
            }
            _ => {}
        }
        if self.smux_ver == 0 {
            self.smux_ver = 1;
        } else if self.smux_ver > 2 {
            self.smux_ver = 2;
        }
        self.conn = self.conn.clamp(1, 16);
        self.frame_size = self.frame_size.clamp(1, 65_535);
        self.stream_buf = self.stream_buf.min(self.smux_buf);
    }

    fn pool_key(&self, address: SocketAddr) -> String {
        let key_digest = Sha256::digest(self.key.as_bytes());
        format!(
            "{address}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            format!("{key_digest:x}"),
            self.crypt,
            self.mode,
            self.conn,
            self.auto_expire,
            self.scavenge_ttl,
            self.mtu,
            self.rate_limit,
            self.snd_wnd,
            self.rcv_wnd,
            self.data_shard,
            self.parity_shard,
            self.dscp,
            self.no_comp,
            self.ack_nodelay,
            self.no_delay,
            self.interval,
            self.resend,
            self.no_congestion,
            self.smux_ver,
            self.smux_buf,
            self.frame_size,
            self.stream_buf
        )
    }
}

#[derive(Debug)]
struct ShadowsocksConfig {
    server: String,
    server_port: u16,
    password: String,
    method: ShadowsocksMethod,
    plugin: ShadowsocksPlugin,
    ssr_protocol: SsrProtocol,
    ssr_protocol_param: String,
    one_time_auth: bool,
    tcp_fast_open: bool,
    udp_relay: bool,
    udp_over_tcp: bool,
}

impl ShadowsocksConfig {
    fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        if node.server.is_empty() || node.server_port == 0 {
            anyhow::bail!("Shadowsocks endpoint is invalid");
        }
        if node.user_id.is_empty() {
            anyhow::bail!("Shadowsocks requires a password");
        }
        let method_value = node
            .parameter("method")
            .or_else(|| node.parameter("cipher"))
            .unwrap_or("2022-blake3-aes-256-gcm");
        let method = parse_shadowsocks_cipher(method_value)?;
        let ssr_protocol = SsrProtocol::from_node(node, method)?;
        let ssr_protocol_param = node
            .parameter("protocol_param")
            .or_else(|| node.parameter("protocol-param"))
            .unwrap_or("")
            .to_string();
        let plugin = ShadowsocksPlugin::from_node(node)?;
        let one_time_auth =
            bool_param(node, &["one-time-auth", "one_time_auth", "ota"]).unwrap_or(false);
        let tcp_fast_open = bool_param(
            node,
            &["tcp-fast-open", "tcp_fast_open", "fast-open", "fast_open"],
        )
        .unwrap_or(false);
        let udp_relay = bool_param(node, &["udp-relay", "udp_relay", "udp"]).unwrap_or(true);
        let udp_over_tcp =
            bool_param(node, &["udp-over-tcp", "udp_over_tcp", "uot"]).unwrap_or(false);
        Ok(Self {
            server: node.server.clone(),
            server_port: node.server_port,
            password: node.user_id.clone(),
            method,
            plugin,
            ssr_protocol,
            ssr_protocol_param,
            one_time_auth,
            tcp_fast_open,
            udp_relay,
            udp_over_tcp,
        })
    }

    async fn connect_transport(&self, address: SocketAddr) -> anyhow::Result<ShadowsocksTransport> {
        if let ShadowsocksPlugin::Kcptun(config) = &self.plugin {
            return Ok(ShadowsocksTransport::Kcptun(
                open_kcptun_stream(address, config).await?,
            ));
        }
        match &self.plugin {
            ShadowsocksPlugin::ExternalSip003 { program, options } => {
                return Ok(ShadowsocksTransport::ExternalSip003(
                    open_sip003_plugin_stream(self, program, options).await?,
                ));
            }
            ShadowsocksPlugin::XHttp(config) if config.version == XHttpVersion::H3 => {
                return Ok(ShadowsocksTransport::XHttp(
                    connect_h3_xhttp_plugin(address, self, config).await?,
                ));
            }
            _ => {}
        }
        let raw = ShadowTcpStream::connect_with_opts(&address, &self.connect_opts()).await?;
        match &self.plugin {
            ShadowsocksPlugin::None => Ok(ShadowsocksTransport::Plain(raw)),
            ShadowsocksPlugin::SimpleObfsHttp { host, port } => Ok(ShadowsocksTransport::Http(
                SimpleObfsHttpStream::new(raw, host.clone(), *port),
            )),
            ShadowsocksPlugin::SsrHttp {
                host,
                port,
                post,
                headers,
            } => Ok(ShadowsocksTransport::SsrHttp(SsrHttpObfsStream::new(
                raw,
                host.clone(),
                *port,
                *post,
                headers.clone(),
            ))),
            ShadowsocksPlugin::SimpleObfsTls { host } => Ok(ShadowsocksTransport::Tls(
                SimpleObfsTlsStream::new(raw, host.clone()),
            )),
            ShadowsocksPlugin::SsrTls { host, key } => Ok(ShadowsocksTransport::SsrTls(
                SsrTlsTicketStream::new(raw, host.clone(), key.clone()),
            )),
            ShadowsocksPlugin::RandomHead => {
                Ok(ShadowsocksTransport::RandomHead(RandomHeadStream::new(raw)))
            }
            ShadowsocksPlugin::WebSocket { host, path, tls } => {
                let stream = connect_websocket_plugin(raw, host, path, *tls).await?;
                Ok(stream)
            }
            ShadowsocksPlugin::XHttp(config) => {
                connect_xhttp_plugin(address, raw, self, config).await
            }
            ShadowsocksPlugin::ShadowTls(config) => Ok(ShadowsocksTransport::ShadowTls(
                ShadowTlsStream::connect(raw, config).await?,
            )),
            ShadowsocksPlugin::Kcptun(_) => unreachable!("kcptun returned before TCP connect"),
            ShadowsocksPlugin::ExternalSip003 { .. } => {
                unreachable!("external SIP003 plugin returned before TCP connect")
            }
            ShadowsocksPlugin::H2 { host, path, tls } => {
                connect_h2_plugin(raw, host, path, *tls).await
            }
        }
    }

    fn ensure_udp_supported(&self) -> anyhow::Result<()> {
        match self.udp_mode() {
            ShadowsocksUdpMode::Direct => Ok(()),
            ShadowsocksUdpMode::UdpOverTcp => {
                anyhow::bail!("Shadowsocks UDP over this transport uses UoT")
            }
            ShadowsocksUdpMode::Disabled => {
                if self.udp_relay && !matches!(self.plugin, ShadowsocksPlugin::None) {
                    anyhow::bail!(
                        "Shadowsocks UDP over {} requires udp-over-tcp=true; native plugin UDP fallback is not available",
                        self.plugin.transport_name()
                    );
                }
                anyhow::bail!("Shadowsocks UDP relay is disabled for this node")
            }
        }
    }

    fn ensure_uot_supported(&self) -> anyhow::Result<()> {
        match self.udp_mode() {
            ShadowsocksUdpMode::UdpOverTcp => Ok(()),
            ShadowsocksUdpMode::Direct => anyhow::bail!(
                "Shadowsocks direct UDP does not need UoT for this node"
            ),
            ShadowsocksUdpMode::Disabled => {
                anyhow::bail!("Shadowsocks UDP relay is disabled for this node")
            }
        }
    }

    fn ensure_tcp_supported(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn should_use_uot(&self) -> bool {
        matches!(self.udp_mode(), ShadowsocksUdpMode::UdpOverTcp)
    }

    fn connect_opts(&self) -> ConnectOpts {
        let mut opts = ConnectOpts::default();
        opts.tcp.fastopen = self.tcp_fast_open;
        opts
    }

    fn udp_mode(&self) -> ShadowsocksUdpMode {
        if !self.udp_relay {
            return ShadowsocksUdpMode::Disabled;
        }
        if self.udp_over_tcp {
            return ShadowsocksUdpMode::UdpOverTcp;
        }
        if !matches!(self.plugin, ShadowsocksPlugin::None) {
            return ShadowsocksUdpMode::Disabled;
        }
        ShadowsocksUdpMode::Direct
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowsocksMethod {
    BuiltIn(CipherKind),
    NeonLegacy(NeonLegacyCipherKind),
}

impl ShadowsocksMethod {
    fn category(self) -> CipherCategory {
        match self {
            Self::BuiltIn(method) => method.category(),
            Self::NeonLegacy(_) => CipherCategory::Stream,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NeonLegacyCipherKind {
    BlowfishCfb,
    Cast5Cfb,
    DesCfb,
    IdeaCfb,
    Rc2Cfb,
    SeedCfb,
    Salsa20,
    Rc4Md5_6,
}

impl NeonLegacyCipherKind {
    fn key_len(self) -> usize {
        match self {
            Self::DesCfb => 8,
            Self::BlowfishCfb
            | Self::Cast5Cfb
            | Self::IdeaCfb
            | Self::Rc2Cfb
            | Self::SeedCfb
            | Self::Rc4Md5_6 => 16,
            Self::Salsa20 => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::BlowfishCfb | Self::Cast5Cfb | Self::DesCfb | Self::Rc2Cfb | Self::Rc4Md5_6 => 8,
            Self::IdeaCfb => 8,
            Self::SeedCfb => 16,
            Self::Salsa20 => 8,
        }
    }
}

fn parse_shadowsocks_cipher(value: &str) -> anyhow::Result<ShadowsocksMethod> {
    let normalized = normalize_shadowsocks_cipher(value);
    let method = match normalized.as_str() {
        "bf-cfb" | "blowfish-cfb" => {
            ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::BlowfishCfb)
        }
        "cast5-cfb" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::Cast5Cfb),
        "des-cfb" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::DesCfb),
        "idea-cfb" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::IdeaCfb),
        "rc2-cfb" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::Rc2Cfb),
        "seed-cfb" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::SeedCfb),
        "salsa20" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::Salsa20),
        "rc4-md5-6" => ShadowsocksMethod::NeonLegacy(NeonLegacyCipherKind::Rc4Md5_6),
        _ => ShadowsocksMethod::BuiltIn(
            normalized
                .parse::<CipherKind>()
                .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher: {value}"))?,
        ),
    };
    Ok(method)
}

fn normalize_shadowsocks_cipher(value: &str) -> String {
    let lowered = value
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    match lowered.as_str() {
        "plain" => "none".to_string(),
        "aes-128-cfb128" => "aes-128-cfb".to_string(),
        "aes-192-cfb128" => "aes-192-cfb".to_string(),
        "aes-256-cfb128" => "aes-256-cfb".to_string(),
        "camellia-128-cfb128" => "camellia-128-cfb".to_string(),
        "camellia-192-cfb128" => "camellia-192-cfb".to_string(),
        "camellia-256-cfb128" => "camellia-256-cfb".to_string(),
        "chacha20" => "chacha20-ietf".to_string(),
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        "2022-blake3-chacha8-poly1305" => "2022-blake3-chacha8-poly1305".to_string(),
        value => value.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SsrProtocol {
    Origin,
    VerifySimple,
    VerifySha1,
    AuthSimple,
    AuthSha1,
    AuthSha1V2,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
    AuthChainC,
    AuthChainD,
    AuthChainE,
    AuthChainF,
}

impl SsrProtocol {
    fn from_node(node: &KernelNode, method: ShadowsocksMethod) -> anyhow::Result<Self> {
        if !node.protocol.eq_ignore_ascii_case("ssr")
            && !node.protocol.eq_ignore_ascii_case("shadowsocksr")
        {
            return Ok(Self::Origin);
        }
        let protocol = node
            .parameter("protocol")
            .unwrap_or("origin")
            .trim();
        let canonical_protocol = canonical_ssr_protocol_name(protocol)
            .ok_or_else(|| anyhow::anyhow!("unsupported ShadowsocksR protocol: {protocol}"))?;
        let protocol = match canonical_protocol {
            "origin" => Self::Origin,
            "verify_simple" => Self::VerifySimple,
            "verify_sha1" => Self::VerifySha1,
            "auth_simple" => Self::AuthSimple,
            "auth_sha1" => Self::AuthSha1,
            "auth_sha1_v2" => Self::AuthSha1V2,
            "auth_sha1_v4" => Self::AuthSha1V4,
            "auth_aes128_md5" => Self::AuthAes128Md5,
            "auth_aes128_sha1" => Self::AuthAes128Sha1,
            "auth_chain_a" => Self::AuthChainA,
            "auth_chain_b" => Self::AuthChainB,
            "auth_chain_c" => Self::AuthChainC,
            "auth_chain_d" => Self::AuthChainD,
            "auth_chain_e" => Self::AuthChainE,
            "auth_chain_f" => Self::AuthChainF,
            value => anyhow::bail!("unsupported ShadowsocksR protocol: {value}"),
        };
        if protocol.is_native()
            && method.category() != CipherCategory::Stream
            && method.category() != CipherCategory::None
        {
            anyhow::bail!("ShadowsocksR native protocols require a stream cipher");
        }
        Ok(protocol)
    }

    fn is_native(&self) -> bool {
        !matches!(self, Self::Origin)
    }
}

impl ShadowsocksPlugin {
    fn transport_name(&self) -> &'static str {
        match self {
            Self::None => "direct Shadowsocks UDP",
            Self::SimpleObfsHttp { .. } => "simple-obfs HTTP",
            Self::SsrHttp { .. } => "ShadowsocksR HTTP obfs",
            Self::SimpleObfsTls { .. } => "simple-obfs TLS",
            Self::SsrTls { .. } => "ShadowsocksR TLS obfs",
            Self::RandomHead => "ShadowsocksR random-head obfs",
            Self::WebSocket { .. } => "WebSocket plugin",
            Self::XHttp(_) => "XHTTP plugin",
            Self::ExternalSip003 { .. } => "SIP003 plugin",
            Self::ShadowTls(_) => "ShadowTLS plugin",
            Self::Kcptun(_) => "kcptun plugin",
            Self::H2 { .. } => "HTTP/2 plugin",
        }
    }

    fn from_node(node: &KernelNode) -> anyhow::Result<Self> {
        if node.protocol.eq_ignore_ascii_case("ssr")
            || node.protocol.eq_ignore_ascii_case("shadowsocksr")
        {
            return Self::from_ssr_node(node);
        }

        let plugin = node
            .parameter("plugin")
            .or_else(|| node.parameter("plugin_name"))
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let opts = node
            .parameter("plugin_opts")
            .or_else(|| node.parameter("plugin-opts"))
            .or_else(|| node.parameter("plugin_options"))
            .or_else(|| node.parameter("pluginOptions"))
            .unwrap_or("");
        let mut obfuscation = node
            .parameter("obfuscation")
            .or_else(|| node.parameter("obfs"))
            .or_else(|| node.parameter("mode"))
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if plugin.is_empty() {
            if !obfuscation.is_empty() && obfuscation != "none" {
                return Self::from_obfuscation(node, &obfuscation, opts);
            }
            return Ok(Self::None);
        }
        if obfuscation == "none" {
            obfuscation.clear();
        }
        if matches!(
            plugin.as_str(),
            "obfs-local" | "simple-obfs" | "simple_obfs"
        ) {
            return Self::from_simple_obfs_options(node, opts);
        }
        if matches!(plugin.as_str(), "v2ray-plugin" | "v2ray_plugin") {
            return Self::from_websocket_plugin_options(node, opts, "v2ray-plugin");
        }
        if matches!(plugin.as_str(), "gost" | "gost-plugin") {
            return Self::from_websocket_plugin_options(node, opts, "gost-plugin");
        }
        if matches!(plugin.as_str(), "shadow-tls" | "shadow_tls") {
            return Self::from_shadow_tls_options(node, opts);
        }
        if plugin == "kcptun" {
            return Self::from_kcptun_options(opts);
        }
        if matches!(
            plugin.as_str(),
            "cloak" | "ck-client" | "external-sip003" | "external_sip003" | "sip003"
        ) {
            return Self::from_external_sip003_options(node, opts, &plugin);
        }
        if !obfuscation.is_empty() {
            return Self::from_obfuscation(node, &obfuscation, opts);
        }
        anyhow::bail!("unsupported Shadowsocks plugin: {plugin}")
    }

    fn from_obfuscation(node: &KernelNode, obfuscation: &str, opts: &str) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let host = plugin_host(node, &values);
        let tls_enabled = plugin_bool(&values, "tls")
            || bool_param(node, &["obfuscation-tls", "obfuscation_tls", "tls"]).unwrap_or(false);
        match obfuscation {
            "http" | "h1" => Ok(Self::SimpleObfsHttp {
                host,
                port: node.server_port,
            }),
            "tls" | "ssl" => Ok(Self::SimpleObfsTls { host }),
            "websocket" | "ws" | "httpupgrade" | "http_upgrade" => Ok(Self::WebSocket {
                host,
                path: plugin_path(node, &values),
                tls: tls_enabled,
            }),
            "wss" => Ok(Self::WebSocket {
                host,
                path: plugin_path(node, &values),
                tls: true,
            }),
            "h2" => Ok(Self::H2 {
                host,
                path: plugin_path(node, &values),
                tls: tls_enabled
                    || !(plugin_bool(&values, "h2c")
                        || bool_param(node, &["h2c"]).unwrap_or(false)),
            }),
            "xhttp" => Ok(Self::XHttp(xhttp_plugin_config(
                node,
                &values,
                host,
                tls_enabled
                    || !(plugin_bool(&values, "h2c")
                        || bool_param(node, &["h2c"]).unwrap_or(false)),
            )?)),
            value => anyhow::bail!("unsupported Shadowsocks obfuscation: {value}"),
        }
    }

    fn from_ssr_node(node: &KernelNode) -> anyhow::Result<Self> {
        let obfs = node
            .parameter("obfs")
            .unwrap_or("plain")
            .trim();
        let canonical_obfs = canonical_ssr_obfs_name(obfs)
            .ok_or_else(|| anyhow::anyhow!("unsupported ShadowsocksR obfs: {obfs}"))?;
        match canonical_obfs {
            "plain" => Ok(Self::None),
            "http_simple" | "http_post" => {
                let param = node
                    .parameter("obfs_param")
                    .or_else(|| node.parameter("obfs-param"))
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&node.server);
                let (host, headers) = split_ssr_http_obfs_param(param, &node.server);
                Ok(Self::SsrHttp {
                    host,
                    port: node.server_port,
                    post: canonical_obfs == "http_post",
                    headers,
                })
            }
            "random_head" => Ok(Self::RandomHead),
            "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => {
                let host = node
                    .parameter("obfs_param")
                    .or_else(|| node.parameter("obfs-param"))
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&node.server)
                    .to_string();
                Ok(Self::SsrTls {
                    host,
                    key: ssr_obfs_key_from_node(node)?,
                })
            }
            value => anyhow::bail!("unsupported ShadowsocksR obfs: {value}"),
        }
    }

    fn from_simple_obfs_options(node: &KernelNode, opts: &str) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let mode = values
            .get("obfs")
            .or_else(|| values.get("mode"))
            .map(String::as_str)
            .or_else(|| node.parameter("obfs"))
            .unwrap_or("http")
            .to_ascii_lowercase();
        let host = plugin_host(node, &values);
        match mode.as_str() {
            "http" | "http_simple" | "http-post" | "http_post" => Ok(Self::SimpleObfsHttp {
                host,
                port: node.server_port,
            }),
            "tls" | "tls1.2_ticket_auth" | "tls1_2_ticket_auth" => Ok(Self::SimpleObfsTls { host }),
            value => anyhow::bail!("unsupported simple-obfs mode: {value}"),
        }
    }

    fn from_websocket_plugin_options(
        node: &KernelNode,
        opts: &str,
        name: &str,
    ) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let mode = values
            .get("mode")
            .map(String::as_str)
            .unwrap_or("websocket")
            .to_ascii_lowercase();
        if mode != "websocket" {
            anyhow::bail!("{name} mode is not implemented yet: {mode}");
        }
        Ok(Self::WebSocket {
            host: plugin_host(node, &values),
            path: plugin_path(node, &values),
            tls: plugin_bool(&values, "tls"),
        })
    }

    fn from_shadow_tls_options(node: &KernelNode, opts: &str) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let host = plugin_host(node, &values);
        let password = values
            .get("password")
            .or_else(|| values.get("passwd"))
            .or_else(|| values.get("psk"))
            .map(String::as_str)
            .or_else(|| node.parameter("shadow-tls-password"))
            .or_else(|| node.parameter("shadow_tls_password"))
            .filter(|value| !value.is_empty())
            .unwrap_or(&node.user_id)
            .to_string();
        let version = values
            .get("version")
            .or_else(|| values.get("v"))
            .map(String::as_str)
            .or_else(|| node.parameter("shadow-tls-version"))
            .or_else(|| node.parameter("shadow_tls_version"))
            .unwrap_or("2")
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("ShadowTLS version is invalid"))?;
        if !matches!(version, 1 | 2 | 3) {
            anyhow::bail!("unsupported ShadowTLS version: {version}");
        }
        let alpn = values
            .get("alpn")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let skip_cert_verify = plugin_bool(&values, "skip-cert-verify")
            || plugin_bool(&values, "skip_cert_verify")
            || plugin_bool(&values, "allowinsecure");
        Ok(Self::ShadowTls(ShadowTlsConfig {
            host,
            password,
            version,
            alpn,
            skip_cert_verify,
        }))
    }

    fn from_kcptun_options(opts: &str) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let mut config = KcptunConfig::default();
        config.key = plugin_string(&values, "key", &config.key);
        config.crypt = plugin_string(&values, "crypt", &config.crypt).to_ascii_lowercase();
        config.mode = plugin_string(&values, "mode", &config.mode).to_ascii_lowercase();
        config.conn = plugin_usize(&values, "conn", config.conn)?;
        config.auto_expire =
            plugin_u64_alias(&values, &["autoexpire", "auto-expire"], config.auto_expire)?;
        config.scavenge_ttl = plugin_u64_alias(
            &values,
            &["scavengettl", "scavenge-ttl"],
            config.scavenge_ttl,
        )?;
        config.mtu = plugin_usize(&values, "mtu", config.mtu)?;
        config.rate_limit =
            plugin_u32_alias(&values, &["ratelimit", "rate-limit"], config.rate_limit)?;
        config.snd_wnd = plugin_u16_alias(&values, &["sndwnd", "send-window"], config.snd_wnd)?;
        config.rcv_wnd = plugin_u16_alias(&values, &["rcvwnd", "receive-window"], config.rcv_wnd)?;
        config.data_shard =
            plugin_usize_alias(&values, &["datashard", "data-shard"], config.data_shard)?;
        config.parity_shard = plugin_usize_alias(
            &values,
            &["parityshard", "parity-shard"],
            config.parity_shard,
        )?;
        config.dscp = plugin_u32(&values, "dscp", config.dscp)?;
        config.no_comp = plugin_bool(&values, "nocomp") || plugin_bool(&values, "no-comp");
        config.ack_nodelay =
            plugin_bool(&values, "acknodelay") || plugin_bool(&values, "ack-nodelay");
        config.no_delay = plugin_i32_alias(&values, &["nodelay", "no-delay"], config.no_delay)?;
        config.interval = plugin_i32(&values, "interval", config.interval)?;
        config.resend = plugin_i32(&values, "resend", config.resend)?;
        config.no_congestion = plugin_bool(&values, "nc") || plugin_bool(&values, "no-congestion");
        config.sock_buf =
            plugin_usize_alias(&values, &["sockbuf", "socket-buffer"], config.sock_buf)?;
        config.smux_ver = plugin_u8_alias(&values, &["smuxver", "smux-version"], config.smux_ver)?;
        config.smux_buf =
            plugin_usize_alias(&values, &["smuxbuf", "smux-buffer"], config.smux_buf)?;
        config.frame_size =
            plugin_usize_alias(&values, &["framesize", "frame-size"], config.frame_size)?;
        config.stream_buf =
            plugin_usize_alias(&values, &["streambuf", "stream-buffer"], config.stream_buf)?;
        config.keep_alive =
            plugin_u64_alias(&values, &["keepalive", "keep-alive"], config.keep_alive)?;
        config.apply_mode();
        Ok(Self::Kcptun(config))
    }

    fn from_external_sip003_options(
        node: &KernelNode,
        opts: &str,
        plugin: &str,
    ) -> anyhow::Result<Self> {
        let values = parse_plugin_options(opts);
        let program = values
            .get("program")
            .or_else(|| values.get("path"))
            .or_else(|| values.get("plugin"))
            .map(String::as_str)
            .or_else(|| node.parameter("plugin_path"))
            .or_else(|| node.parameter("plugin-path"))
            .or_else(|| node.parameter("plugin_program"))
            .or_else(|| node.parameter("plugin-program"))
            .unwrap_or(match plugin {
                "cloak" => "ck-client",
                "external-sip003" | "external_sip003" | "sip003" => "",
                _ => plugin,
            })
            .trim()
            .to_string();
        if program.is_empty() {
            anyhow::bail!("Shadowsocks SIP003 plugin program is empty");
        }
        Ok(Self::ExternalSip003 {
            program,
            options: sanitize_sip003_options(opts),
        })
    }
}

fn sanitize_sip003_options(options: &str) -> String {
    split_plugin_options(options)
        .into_iter()
        .filter(|item| {
            split_plugin_option_pair(item)
                .map(|(key, _)| {
                    let key = unescape_plugin_option(&key).trim().to_ascii_lowercase();
                    !matches!(
                        key.as_str(),
                        "program"
                            | "path"
                            | "plugin"
                            | "plugin_program"
                            | "plugin-program"
                            | "plugin_path"
                            | "plugin-path"
                    )
                })
                .unwrap_or(true)
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn plugin_host(node: &KernelNode, values: &std::collections::HashMap<String, String>) -> String {
    values
        .get("obfs-host")
        .or_else(|| values.get("host"))
        .map(String::as_str)
        .or_else(|| node.parameter("obfs-host"))
        .or_else(|| node.parameter("obfs_host"))
        .or_else(|| node.parameter("host"))
        .filter(|value| !value.is_empty())
        .unwrap_or(&node.server)
        .to_string()
}

fn plugin_path(node: &KernelNode, values: &std::collections::HashMap<String, String>) -> String {
    values
        .get("path")
        .map(String::as_str)
        .or_else(|| node.parameter("path"))
        .filter(|value| !value.is_empty())
        .unwrap_or("/")
        .to_string()
}

fn xhttp_plugin_config(
    node: &KernelNode,
    values: &std::collections::HashMap<String, String>,
    host: String,
    tls: bool,
) -> anyhow::Result<XHttpPluginConfig> {
    Ok(XHttpPluginConfig {
        host,
        path: plugin_path(node, values),
        tls,
        mode: parse_xhttp_mode(
            values
                .get("mode")
                .map(String::as_str)
                .or_else(|| node.parameter("xhttp-mode"))
                .or_else(|| node.parameter("xhttp_mode"))
                .unwrap_or("auto"),
        )?,
        version: parse_xhttp_version(
            values
                .get("httpversion")
                .or_else(|| values.get("http-version"))
                .or_else(|| values.get("http_version"))
                .or_else(|| values.get("alpn"))
                .map(String::as_str)
                .or_else(|| node.parameter("httpVersion"))
                .or_else(|| node.parameter("http-version"))
                .or_else(|| node.parameter("http_version"))
                .or_else(|| node.parameter("alpn"))
                .unwrap_or("auto"),
        )?,
        max_each_post_bytes: plugin_usize_alias(
            values,
            &[
                "scmaxeachpostbytes",
                "sc-max-each-post-bytes",
                "sc_max_each_post_bytes",
                "xhttp-post-bytes",
            ],
            256 * 1024,
        )?,
        min_posts_interval_ms: plugin_u64_alias(
            values,
            &[
                "scminpostsintervalms",
                "sc-min-posts-interval-ms",
                "sc_min_posts_interval_ms",
                "xhttp-post-interval-ms",
            ],
            0,
        )?,
        skip_cert_verify: plugin_bool(values, "skip-cert-verify")
            || plugin_bool(values, "skip_cert_verify")
            || plugin_bool(values, "allowinsecure")
            || bool_param(
                node,
                &["skip-cert-verify", "skip_cert_verify", "allowInsecure"],
            )
            .unwrap_or(false),
    })
}

fn parse_xhttp_mode(value: &str) -> anyhow::Result<XHttpMode> {
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "" | "auto" => Ok(XHttpMode::Auto),
        "stream-one" => Ok(XHttpMode::StreamOne),
        "stream-up" => Ok(XHttpMode::StreamUp),
        "packet-up" => Ok(XHttpMode::PacketUp),
        value => anyhow::bail!("unsupported Shadowsocks XHTTP mode: {value}"),
    }
}

fn parse_xhttp_version(value: &str) -> anyhow::Result<XHttpVersion> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(XHttpVersion::Auto),
        "1" | "1.1" | "h1" | "http/1.1" => Ok(XHttpVersion::H1),
        "2" | "h2" | "http/2" => Ok(XHttpVersion::H2),
        "3" | "h3" | "http/3" => Ok(XHttpVersion::H3),
        value => anyhow::bail!("unsupported Shadowsocks XHTTP HTTP version: {value}"),
    }
}

fn ssr_obfs_key_from_node(node: &KernelNode) -> anyhow::Result<Vec<u8>> {
    let method_value = node
        .parameter("method")
        .or_else(|| node.parameter("cipher"))
        .unwrap_or("aes-256-cfb");
    match parse_shadowsocks_cipher(method_value)? {
        ShadowsocksMethod::BuiltIn(method) => {
            let dummy = SocketAddr::from(([127, 0, 0, 1], node.server_port));
            let server = ServerConfig::new(dummy, node.user_id.clone(), method)?;
            Ok(server.key().to_vec())
        }
        ShadowsocksMethod::NeonLegacy(method) => Ok(legacy_evp_bytes_to_key(
            node.user_id.as_bytes(),
            method.key_len(),
        )),
    }
}

fn plugin_bool(values: &std::collections::HashMap<String, String>, key: &str) -> bool {
    values
        .get(key)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "" | "0" | "false" | "no" | "off")
        })
        .unwrap_or(false)
}

fn bool_param(node: &KernelNode, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| node.parameter(key))
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "" | "0" | "false" | "no" | "off")
        })
}

fn plugin_string(
    values: &std::collections::HashMap<String, String>,
    key: &str,
    default: &str,
) -> String {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default.to_string())
}

fn plugin_usize(
    values: &std::collections::HashMap<String, String>,
    key: &str,
    default: usize,
) -> anyhow::Result<usize> {
    plugin_usize_alias(values, &[key], default)
}

fn plugin_usize_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: usize,
) -> anyhow::Result<usize> {
    parse_plugin_number(values, keys, default)
}

fn plugin_u64_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: u64,
) -> anyhow::Result<u64> {
    parse_plugin_number(values, keys, default)
}

fn plugin_u32(
    values: &std::collections::HashMap<String, String>,
    key: &str,
    default: u32,
) -> anyhow::Result<u32> {
    plugin_u32_alias(values, &[key], default)
}

fn plugin_u32_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: u32,
) -> anyhow::Result<u32> {
    parse_plugin_number(values, keys, default)
}

fn plugin_u16_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: u16,
) -> anyhow::Result<u16> {
    parse_plugin_number(values, keys, default)
}

fn plugin_u8_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: u8,
) -> anyhow::Result<u8> {
    parse_plugin_number(values, keys, default)
}

fn plugin_i32(
    values: &std::collections::HashMap<String, String>,
    key: &str,
    default: i32,
) -> anyhow::Result<i32> {
    plugin_i32_alias(values, &[key], default)
}

fn plugin_i32_alias(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: i32,
) -> anyhow::Result<i32> {
    parse_plugin_number(values, keys, default)
}

fn parse_plugin_number<T>(
    values: &std::collections::HashMap<String, String>,
    keys: &[&str],
    default: T,
) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let Some((key, value)) = keys
        .iter()
        .find_map(|key| values.get(*key).map(|value| (*key, value)))
        .filter(|(_, value)| !value.is_empty())
    else {
        return Ok(default);
    };
    value
        .parse::<T>()
        .map_err(|err| anyhow::anyhow!("invalid Shadowsocks plugin option {key}: {err}"))
}

fn target_address(target: &TargetAddress) -> Address {
    let authority = target.to_string();
    match SocketAddr::from_str(&authority) {
        Ok(address) => Address::SocketAddress(address),
        Err(_) => Address::DomainNameAddress(target.host.clone(), target.port),
    }
}
fn parse_plugin_options(options: &str) -> std::collections::HashMap<String, String> {
    let mut values = std::collections::HashMap::new();
    for item in split_plugin_options(options) {
        let Some((key, value)) = split_plugin_option_pair(&item) else {
            continue;
        };
        let key = unescape_plugin_option(&key).trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        values.insert(key, unescape_plugin_option(&value).trim().to_string());
    }
    values
}
fn split_plugin_options(options: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in options.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            ';' => {
                items.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    if escaped {
        current.push('\\');
    }
    items.push(current);
    items
}

fn split_plugin_option_pair(item: &str) -> Option<(String, String)> {
    let mut key = String::new();
    let mut value = String::new();
    let mut escaped = false;
    let mut seen_equal = false;
    for ch in item.chars() {
        if escaped {
            if seen_equal {
                value.push('\\');
                value.push(ch);
            } else {
                key.push('\\');
                key.push(ch);
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '=' if !seen_equal => seen_equal = true,
            _ if seen_equal => value.push(ch),
            _ => key.push(ch),
        }
    }
    if escaped {
        if seen_equal {
            value.push('\\');
        } else {
            key.push('\\');
        }
    }
    seen_equal.then_some((key, value))
}

fn unescape_plugin_option(value: &str) -> String {
    let mut output = String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            output.push(ch);
        }
    }
    if escaped {
        output.push('\\');
    }
    output
}
