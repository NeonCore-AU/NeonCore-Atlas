use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub struct RealitySessionId {
    public_key: [u8; 32],
    short_id: Vec<u8>,
}

impl RealitySessionId {
    pub fn new(public_key: &str, short_id: &str) -> anyhow::Result<Self> {
        let public_key = URL_SAFE_NO_PAD
            .decode(public_key)
            .map_err(|err| anyhow::anyhow!("REALITY public key is invalid: {err}"))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("REALITY public key must be 32 bytes"))?;
        let short_id = decode_hex(short_id)?;
        if short_id.len() > 8 {
            anyhow::bail!("REALITY short id must be at most 8 bytes");
        }
        Ok(Self {
            public_key,
            short_id,
        })
    }
}

impl tokio_rustls::rustls::client::RealitySessionIdGenerator for RealitySessionId {
    fn generate_session_id(
        &self,
        key_share: &dyn ActiveKeyExchange,
        random: &[u8; 32],
        client_hello_with_zero_session_id: &[u8],
    ) -> Result<[u8; 32], Error> {
        let shared_secret = key_share
            .reality_shared_secret(&self.public_key)
            .ok_or_else(|| Error::General("REALITY requires an X25519 key share".into()))??;
        let mut auth_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared_secret.secret_bytes())
            .expand(b"REALITY", &mut auth_key)
            .map_err(|_| Error::General("REALITY auth key derivation failed".into()))?;

        let mut plaintext = [0u8; 16];
        plaintext[0] = 26;
        plaintext[1] = 6;
        plaintext[2] = 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::General("system time is before Unix epoch".into()))?
            .as_secs() as u32;
        plaintext[4..8].copy_from_slice(&now.to_be_bytes());
        plaintext[8..8 + self.short_id.len()].copy_from_slice(&self.short_id);

        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|_| Error::General("REALITY AEAD initialization failed".into()))?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&random[20..32]),
                Payload {
                    msg: &plaintext,
                    aad: client_hello_with_zero_session_id,
                },
            )
            .map_err(|_| Error::General("REALITY ClientHello authentication failed".into()))?;
        sealed
            .try_into()
            .map_err(|_| Error::General("REALITY session id length mismatch".into()))
    }
}

#[derive(Debug)]
pub struct RealityX25519Group;

impl SupportedKxGroup for RealityX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Ok(Box::new(RealityX25519Exchange {
            secret,
            public: *public.as_bytes(),
        }))
    }

    fn name(&self) -> tokio_rustls::rustls::NamedGroup {
        tokio_rustls::rustls::NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

pub static REALITY_X25519_GROUP: RealityX25519Group = RealityX25519Group;

struct RealityX25519Exchange {
    secret: StaticSecret,
    public: [u8; 32],
}

impl fmt::Debug for RealityX25519Exchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityX25519Exchange")
            .field("group", &"X25519")
            .finish_non_exhaustive()
    }
}

impl ActiveKeyExchange for RealityX25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != 32 {
            return Err(Error::General("invalid X25519 peer key share".into()));
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(peer_pub_key);
        let secret = self.secret.diffie_hellman(&PublicKey::from(peer));
        Ok(SharedSecret::from(secret.as_bytes().as_slice()))
    }

    fn reality_shared_secret(&self, peer_pub_key: &[u8]) -> Option<Result<SharedSecret, Error>> {
        if peer_pub_key.len() != 32 {
            return Some(Err(Error::General("invalid REALITY server public key".into())));
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(peer_pub_key);
        let secret = self.secret.diffie_hellman(&PublicKey::from(peer));
        Some(Ok(SharedSecret::from(secret.as_bytes().as_slice())))
    }

    fn group(&self) -> tokio_rustls::rustls::NamedGroup {
        tokio_rustls::rustls::NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }
}

#[derive(Debug)]
pub struct RealityCertificateVerifier {
    provider: CryptoProvider,
}

impl RealityCertificateVerifier {
    pub fn new(provider: CryptoProvider) -> Arc<Self> {
        Arc::new(Self { provider })
    }
}

impl ServerCertVerifier for RealityCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 {
        anyhow::bail!("REALITY short id hex has an odd length");
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let mut index = 0;
    while index < value.len() {
        output.push(u8::from_str_radix(&value[index..index + 2], 16)?);
        index += 2;
    }
    Ok(output)
}
