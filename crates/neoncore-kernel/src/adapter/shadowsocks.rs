use crate::{
    adapter::{
        boxed_stream, BoxedProxyStream, NetworkCapability, OutboundAdapter, OutboundContext,
    },
    flow::{FlowPipe, FLOW_COPY_BUFFER_SIZE, LARGE_FLOW_PIPE_CAPACITY},
    packet_session::PacketSessionDemux,
    session::{KernelNode, TargetAddress},
};
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use blowfish::Blowfish;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use cast5::Cast5;
use cfb_mode::{
    cipher::{KeyIvInit as CfbKeyIvInit, StreamCipher as CfbStreamCipher},
    BufDecryptor, BufEncryptor,
};
use des::Des;
use futures_util::{ready, Sink, Stream};
use hmac::{Hmac, Mac};
use idea::Idea;
use kcptun_rust::{create_block_crypt, derive_key, CompStream};
use kisaseed::SEED;
use rand::RngCore;
use rc2::Rc2;
use rc4::{KeyInit as Rc4KeyInit, Rc4};
use rust_tokio_kcp::{KcpConfig, KcpNoDelayConfig, KcpStream};
use salsa20::Salsa20;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use shadowsocks::{
    config::ServerType,
    context::Context,
    crypto::{CipherCategory, CipherKind},
    net::{ConnectOpts, TcpStream as ShadowTcpStream},
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
        udprelay::{
            crypto_io::{decrypt_server_payload, encrypt_client_payload},
            options::UdpSocketControlData,
        },
    },
    ServerConfig,
};
use shadowsocks_crypto::v1::Cipher as SsV1Cipher;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    process::Stdio,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex, OnceLock,
    },
    task::{Context as TaskContext, Poll},
    time::{Instant as StdInstant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream, ReadBuf,
    },
    net::{TcpListener, TcpStream as TokioTcpStream, UdpSocket},
    process::{Child, Command},
    time::{sleep, timeout, Duration, Sleep},
};
use tokio_native_tls::TlsStream;
use tokio_rustls::{
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    },
    TlsConnector as RustlsConnector,
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    WebSocketStream,
};

static KCPTUN_SESSION_POOLS: OnceLock<tokio::sync::Mutex<HashMap<String, KcptunSessionPool>>> =
    OnceLock::new();
static KCPTUN_SESSION_CREATES: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();
static UOT_PACKET_CONNS: OnceLock<tokio::sync::Mutex<HashMap<String, Arc<UotPacketConnPool>>>> =
    OnceLock::new();
static DIRECT_UDP_PACKET_CONNS: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<DirectUdpPacketConnPool>>>,
> = OnceLock::new();
static SIP003_PLUGIN_PROCESSES: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<ExternalSip003Process>>>,
> = OnceLock::new();
static SIP003_PLUGIN_CREATES: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();
static SIP003_RESERVED_PORTS: OnceLock<StdMutex<HashSet<u16>>> = OnceLock::new();

const UOT_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_MAGIC_PORT: u16 = 443;
const H2_MAX_DATA_FRAME: usize = 16 * 1024;
const DIRECT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const DIRECT_UDP_INITIAL_POOL_LANES: usize = 8;
const DIRECT_UDP_MAX_POOL_LANES: usize = 64;
const UOT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const UOT_INITIAL_POOL_LANES: usize = 8;
const UOT_MAX_POOL_LANES: usize = 64;
#[cfg(test)]
const UOT_MAX_DISCARDED_PACKETS: usize = 8;
#[cfg(test)]
const UOT_MAX_DISCARDED_BYTES: usize = 256 * 1024;
const SIP003_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SSR_TLS_TICKET_MAX_PENDING_BYTES: usize = 1024 * 1024;
const XHTTP_PACKET_POST_WORKERS: usize = 8;
const XHTTP_PACKET_POST_QUEUE: usize = 32;
const XHTTP_MAX_POST_BYTES: usize = 4 * 1024 * 1024;
const XHTTP_H1_MAX_RESPONSE_DRAIN_BYTES: usize = 1024 * 1024;
const XHTTP_BATCH_WINDOW: Duration = Duration::from_millis(1);

type BlowfishCfbEnc = BufEncryptor<Blowfish>;
type BlowfishCfbDec = BufDecryptor<Blowfish>;
type Cast5CfbEnc = BufEncryptor<Cast5>;
type Cast5CfbDec = BufDecryptor<Cast5>;
type DesCfbEnc = BufEncryptor<Des>;
type DesCfbDec = BufDecryptor<Des>;
type IdeaCfbEnc = BufEncryptor<Idea>;
type IdeaCfbDec = BufDecryptor<Idea>;
type Rc2CfbEnc = BufEncryptor<Rc2>;
type Rc2CfbDec = BufDecryptor<Rc2>;

pub struct ShadowsocksAdapter;

#[async_trait::async_trait]
impl OutboundAdapter for ShadowsocksAdapter {
    fn protocol_names(&self) -> &'static [&'static str] {
        &["ss", "shadowsocks", "ssr", "shadowsocksr"]
    }

    fn networks(&self) -> &'static [NetworkCapability] {
        &[NetworkCapability::Tcp, NetworkCapability::Udp]
    }

    fn validate(&self, node: &KernelNode) -> anyhow::Result<()> {
        ShadowsocksConfig::from_node(node)?.ensure_tcp_supported()?;
        Ok(())
    }

    async fn connect(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<BoxedProxyStream> {
        let config = ShadowsocksConfig::from_node(node)?;
        config.ensure_tcp_supported()?;
        let resolved = context
            .resolver
            .resolve_proxy_server(&TargetAddress {
                host: config.server.clone(),
                port: config.server_port,
            })
            .await?;
        let address = *resolved
            .first()
            .ok_or_else(|| anyhow::anyhow!("no usable resolved address for Shadowsocks server"))?;
        let context = Context::new_shared(ServerType::Local);
        if let ShadowsocksMethod::NeonLegacy(method) = config.method {
            let transport = config.connect_transport(address).await?;
            let crypto = ShadowCryptoStream::Legacy(NeonLegacyCryptoStream::new(
                transport,
                method,
                &config.password,
            )?);
            if config.ssr_protocol.is_native() || config.one_time_auth {
                let protocol = if config.ssr_protocol.is_native() {
                    config.ssr_protocol.clone()
                } else {
                    SsrProtocol::VerifySha1
                };
                let stream = SsrClientStream::new(
                    crypto,
                    target_address(target),
                    protocol,
                    config.ssr_protocol_param.clone(),
                    legacy_evp_bytes_to_key(config.password.as_bytes(), method.key_len()),
                );
                return Ok(boxed_stream(stream));
            }
            let stream = ShadowsocksClientStream::new(crypto, target_address(target));
            return Ok(boxed_stream(stream));
        }

        let ShadowsocksMethod::BuiltIn(method) = config.method else {
            unreachable!("legacy methods returned above");
        };
        let server = ServerConfig::new(address, config.password.clone(), method)?;
        if config.ssr_protocol.is_native() || config.one_time_auth {
            let transport = config.connect_transport(address).await?;
            let crypto = CryptoStream::from_stream(
                &context,
                transport,
                StreamType::Client,
                method,
                server.key(),
            );
            let protocol = if config.ssr_protocol.is_native() {
                config.ssr_protocol.clone()
            } else {
                SsrProtocol::VerifySha1
            };
            let stream = SsrClientStream::new(
                ShadowCryptoStream::BuiltIn(crypto),
                target_address(target),
                protocol,
                config.ssr_protocol_param.clone(),
                server.key().to_vec(),
            );
            return Ok(boxed_stream(stream));
        }
        let transport = config.connect_transport(address).await?;
        let crypto = CryptoStream::from_stream(
            &context,
            transport,
            StreamType::Client,
            method,
            server.key(),
        );
        Ok(boxed_stream(ShadowsocksClientStream::new(
            ShadowCryptoStream::BuiltIn(crypto),
            target_address(target),
        )))
    }

    async fn send_udp(
        &self,
        node: &KernelNode,
        target: &TargetAddress,
        payload: &[u8],
        context: &OutboundContext<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let config = ShadowsocksConfig::from_node(node)?;
        if config.should_use_uot() {
            return self
                .send_udp_over_uot(node, target, payload, context, &config)
                .await;
        }
        config.ensure_udp_supported()?;
        let resolved = context
            .resolver
            .resolve_proxy_server(&TargetAddress {
                host: config.server.clone(),
                port: config.server_port,
            })
            .await?;
        let address = *resolved
            .first()
            .ok_or_else(|| anyhow::anyhow!("no usable resolved address for Shadowsocks server"))?;
        self.send_udp_direct(node, target, payload, &config, address)
            .await
    }
}

include!("shadowsocks/ssr_registry.rs");
include!("shadowsocks/config.rs");
include!("shadowsocks/direct_udp.rs");
include!("shadowsocks/uot.rs");
include!("shadowsocks/transport.rs");
include!("shadowsocks/client.rs");
include!("shadowsocks/ssr.rs");
include!("shadowsocks/legacy.rs");
include!("shadowsocks/obfs.rs");

#[cfg(test)]
mod tests;
