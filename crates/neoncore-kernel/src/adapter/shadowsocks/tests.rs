use super::*;
use crate::{dns::DnsResolver, session::KernelDnsConfig};
use serde_json::json;
use shadowsocks::relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_server_payload};
use tokio::net::UdpSocket;

#[test]
fn accepts_aead_2022_cipher() {
    let node = KernelNode {
        id: None,
        protocol: "shadowsocks".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "2022-blake3-aes-256-gcm"
        }),
    };

    ShadowsocksAdapter.validate(&node).unwrap();
}

#[test]
fn accepts_classic_aead_cipher() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm"
        }),
    };

    ShadowsocksAdapter.validate(&node).unwrap();
}

#[test]
fn accepts_extended_aead_ciphers() {
    for method in [
        "xchacha20-ietf-poly1305",
        "aes-256-ccm",
        "aes-128-ccm",
        "aes-256-gcm-siv",
        "aes-128-gcm-siv",
        "sm4-gcm",
        "sm4-ccm",
        "2022-blake3-chacha8-poly1305",
    ] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({ "method": method }),
        };

        ShadowsocksAdapter.validate(&node).unwrap();
    }
}

#[test]
fn accepts_legacy_stream_ciphers_and_aliases() {
    for method in [
        "none",
        "table",
        "rc4",
        "rc4-md5",
        "rc4-md5-6",
        "salsa20",
        "chacha20",
        "chacha20-ietf",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "aes 128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-cfb1",
        "aes-192-cfb1",
        "aes-256-cfb1",
        "aes-128-cfb8",
        "aes-192-cfb8",
        "aes-256-cfb8",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-ofb",
        "aes-192-ofb",
        "aes-256-ofb",
        "camellia-128-cfb",
        "camellia-192-cfb",
        "camellia-256-cfb",
        "camellia-128-cfb1",
        "camellia-192-cfb1",
        "camellia-256-cfb1",
        "camellia-128-cfb8",
        "camellia-192-cfb8",
        "camellia-256-cfb8",
        "camellia-128-ctr",
        "camellia-192-ctr",
        "camellia-256-ctr",
        "camellia-128-ofb",
        "camellia-192-ofb",
        "camellia-256-ofb",
    ] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({ "method": method }),
        };

        ShadowsocksAdapter.validate(&node).unwrap();
    }
}

#[test]
fn neon_legacy_ciphers_round_trip() {
    for method in [
        NeonLegacyCipherKind::BlowfishCfb,
        NeonLegacyCipherKind::Cast5Cfb,
        NeonLegacyCipherKind::DesCfb,
        NeonLegacyCipherKind::IdeaCfb,
        NeonLegacyCipherKind::Rc2Cfb,
        NeonLegacyCipherKind::SeedCfb,
        NeonLegacyCipherKind::Salsa20,
        NeonLegacyCipherKind::Rc4Md5_6,
    ] {
        let key = legacy_evp_bytes_to_key(b"test-password", method.key_len());
        let iv = vec![7_u8; method.iv_len()];
        let mut encrypted = b"neoncore legacy cipher round trip".to_vec();
        let plain = encrypted.clone();
        let mut enc = NeonLegacyCipher::new_with_direction(method, &key, &iv, true)
            .unwrap_or_else(|err| panic!("{method:?} encrypt init failed: {err}"));
        enc.apply(&mut encrypted);
        assert_ne!(encrypted, plain);
        let mut dec = NeonLegacyCipher::new_with_direction(method, &key, &iv, false)
            .unwrap_or_else(|err| panic!("{method:?} decrypt init failed: {err}"));
        dec.apply(&mut encrypted);
        assert_eq!(encrypted, plain);
    }
}

#[test]
fn accepts_simple_obfs_http_plugin() {
    let node = KernelNode {
        id: None,
        protocol: "shadowsocks".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin": "obfs-local",
            "plugin_opts": "obfs=http;obfs-host=cdn.example.com"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert_eq!(
        config.plugin,
        ShadowsocksPlugin::SimpleObfsHttp {
            host: "cdn.example.com".to_string(),
            port: 8388
        }
    );
}

#[test]
fn accepts_simple_obfs_tls_plugin() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 443,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-128-gcm",
            "plugin": "simple-obfs",
            "plugin_opts": "obfs=tls;obfs-host=cdn.example.com"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert_eq!(
        config.plugin,
        ShadowsocksPlugin::SimpleObfsTls {
            host: "cdn.example.com".to_string()
        }
    );
}

#[test]
fn ssr_http_obfs_uses_native_http_wrapper() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "origin",
            "obfs": "http_post",
            "obfs_param": "cdn.example.com#X-Test: one"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::SsrHttp {
            ref host,
            port: 8388,
            post: true,
            ref headers,
        } if host == "cdn.example.com" && headers == "X-Test: one"
    ));
}

#[test]
fn uot_pool_key_does_not_expose_node_secrets() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "secret.example.com".to_string(),
        server_port: 8388,
        user_id: "super-secret-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin_opts": "host=hidden.example.com"
        }),
    };
    let config = ShadowsocksConfig::from_node(&node).unwrap();
    let key = uot_packet_conn_key(&node, &config);
    assert_eq!(key.len(), 64);
    assert!(!key.contains("super-secret-password"));
    assert!(!key.contains("hidden.example.com"));
    assert!(!key.contains("secret.example.com"));
}

#[test]
fn kcptun_pool_key_does_not_expose_secret_key() {
    let config = KcptunConfig {
        key: "very-secret-kcp-key".to_string(),
        ..KcptunConfig::default()
    };
    let key = config.pool_key("127.0.0.1:29900".parse().unwrap());

    assert!(!key.contains("very-secret-kcp-key"));
    assert!(key.contains("127.0.0.1:29900"));
}

#[test]
fn accepts_shadowsocks_obfuscation_aliases() {
    for (obfuscation, expected) in [
        ("http", "http"),
        ("h1", "http"),
        ("tls", "tls"),
        ("ssl", "tls"),
    ] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm",
                "obfuscation": obfuscation,
                "obfs-host": "cdn.example.com"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node).unwrap();
        match (expected, config.plugin) {
            ("http", ShadowsocksPlugin::SimpleObfsHttp { host, port }) => {
                assert_eq!(host, "cdn.example.com");
                assert_eq!(port, 8388);
            }
            ("tls", ShadowsocksPlugin::SimpleObfsTls { host }) => {
                assert_eq!(host, "cdn.example.com");
            }
            _ => panic!("unexpected obfuscation mapping"),
        }
    }
}

#[test]
fn recognises_external_sip003_plugin() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin": "cloak",
            "plugin_opts": "program=ck-client;config=/tmp/ckclient.json"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::ExternalSip003 { ref program, ref options }
            if program == "ck-client"
                && options == "config=/tmp/ckclient.json"
                && !options.contains("program=")
    ));
}

#[test]
fn external_sip003_defaults_cloak_to_ck_client_and_strips_launcher_options() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin": "cloak",
            "plugin_opts": "program=ck-client;plugin=ignored;path=/usr/local/bin/ignored;config=/tmp/ckclient.json;uid=7"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::ExternalSip003 { ref program, ref options }
            if program == "ck-client"
                && options == "config=/tmp/ckclient.json;uid=7"
    ));
}

#[test]
fn recognises_shadowsocks_xhttp_obfuscation() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "obfuscation": "xhttp",
            "obfs-host": "cdn.example.com",
            "path": "/x",
            "plugin_opts": "mode=packet-up;httpVersion=h3;scMaxEachPostBytes=65536;scMinPostsIntervalMs=5;allowinsecure=true"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::XHttp(XHttpPluginConfig {
            ref host,
            ref path,
            tls: true,
            mode: XHttpMode::PacketUp,
            version: XHttpVersion::H3,
            max_each_post_bytes: 65_536,
            min_posts_interval_ms: 5,
            skip_cert_verify: true,
        }) if host == "cdn.example.com" && path == "/x"
    ));
}

#[test]
fn validate_accepts_one_time_auth() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "one-time-auth": "true"
        }),
    };

    ShadowsocksAdapter.validate(&node).unwrap();
}

#[test]
fn one_time_auth_udp_uses_protocol_wrapper_path() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "one-time-auth": "true",
            "udp-relay": "true"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    config.ensure_udp_supported().unwrap();
    assert!(config.one_time_auth);
}

#[test]
fn recognises_kcptun_plugin() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 29900,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin": "kcptun",
            "plugin_opts": "key=kcp-secret;crypt=aes-256;mode=fast2;conn=2;autoexpire=60;scavengettl=30;mtu=1200;ratelimit=10;sndwnd=64;rcvwnd=256;datashard=8;parityshard=2;dscp=46;nocomp=true;acknodelay=true;nodelay=1;interval=25;resend=3;nc=true;sockbuf=1048576;smuxver=2;smuxbuf=2097152;framesize=4096;streambuf=1048576;keepalive=15"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::Kcptun(KcptunConfig {
            ref key,
            ref crypt,
            ref mode,
            conn: 2,
            auto_expire: 60,
            scavenge_ttl: 30,
            mtu: 1200,
            rate_limit: 10,
            snd_wnd: 64,
            rcv_wnd: 256,
            data_shard: 8,
            parity_shard: 2,
            dscp: 46,
            no_comp: true,
            ack_nodelay: true,
            no_delay: 1,
            interval: 20,
            resend: 2,
            no_congestion: true,
            sock_buf: 1_048_576,
            smux_ver: 2,
            smux_buf: 2_097_152,
            frame_size: 4096,
            stream_buf: 1_048_576,
            keep_alive: 15
        }) if key == "kcp-secret" && crypt == "aes-256" && mode == "fast2"
    ));
}

#[test]
fn recognises_shadow_tls_plugin() {
    for version in [1, 2, 3] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "ss-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm",
                "plugin": "shadow-tls",
                "plugin_opts": format!("host=cdn.example.com;password=shadow-password;version={version};alpn=h2,http/1.1;skip-cert-verify=true")
            }),
        };

        let config = ShadowsocksConfig::from_node(&node).unwrap();
        assert_eq!(
            config.plugin,
            ShadowsocksPlugin::ShadowTls(ShadowTlsConfig {
                host: "cdn.example.com".to_string(),
                password: "shadow-password".to_string(),
                version,
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                skip_cert_verify: true
            })
        );
    }
}

#[test]
fn shadow_tls_records_round_trip_with_auth_tag() {
    let tag = [7_u8; 8];
    let mut mode = ShadowTlsMode::V2 {
        auth_tag: Some(tag),
    };
    let encoded = shadow_tls_encode_records(b"hello", &mut mode);
    assert_eq!(&encoded[..5], &[0x17, 0x03, 0x03, 0x00, 0x0d]);
    assert_eq!(&encoded[5..13], &tag);
    let mut raw = encoded;
    let mut output = BytesMut::new();

    assert!(shadow_tls_drain_records(&mut raw, &mut output, &mut mode).unwrap());
    assert!(raw.is_empty());
    assert_eq!(&output[..], &[tag.as_slice(), b"hello"].concat());
}

#[test]
fn shadow_tls_v3_records_round_trip_with_hmac() {
    let mut hmac_add = <Hmac<Sha1> as Mac>::new_from_slice(b"secret").unwrap();
    hmac_add.update(b"server-random");
    hmac_add.update(b"C");
    let mut hmac_verify = <Hmac<Sha1> as Mac>::new_from_slice(b"secret").unwrap();
    hmac_verify.update(b"server-random");
    hmac_verify.update(b"C");
    let mut write_mode = ShadowTlsMode::V3 {
        hmac_add,
        hmac_verify: <Hmac<Sha1> as Mac>::new_from_slice(b"unused").unwrap(),
        hmac_ignore: None,
    };
    let mut read_mode = ShadowTlsMode::V3 {
        hmac_add: <Hmac<Sha1> as Mac>::new_from_slice(b"unused").unwrap(),
        hmac_verify,
        hmac_ignore: None,
    };
    let mut raw = shadow_tls_encode_records(b"hello-v3", &mut write_mode);
    let mut output = BytesMut::new();

    assert!(shadow_tls_drain_records(&mut raw, &mut output, &mut read_mode).unwrap());
    assert!(raw.is_empty());
    assert_eq!(&output[..], b"hello-v3");
}

#[test]
fn shadow_tls_v3_patches_client_hello_session_id() {
    let mut record = BytesMut::new();
    let mut payload = vec![0_u8; 80];
    payload[0] = 0x01;
    payload[4..6].copy_from_slice(&0x0303_u16.to_be_bytes());
    payload[38] = 32;
    payload[70..72].copy_from_slice(&0x1301_u16.to_be_bytes());
    let payload_len = payload.len();
    payload[1..4].copy_from_slice(&[
        ((payload_len - 4) >> 16) as u8,
        ((payload_len - 4) >> 8) as u8,
        (payload_len - 4) as u8,
    ]);
    record.extend_from_slice(&[0x16, 0x03, 0x01, 0, payload_len as u8]);
    record.extend_from_slice(&payload);

    shadow_tls_v3_patch_client_hello(&mut record, b"secret").unwrap();
    let session = &record[44..76];
    assert!(session[..28].iter().any(|byte| *byte != 0));

    let mut expected_frame = record.clone();
    expected_frame[72..76].fill(0);
    let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(b"secret").unwrap();
    hmac.update(&expected_frame[5..44]);
    hmac.update(&expected_frame[44..76]);
    hmac.update(&expected_frame[76..85]);
    let digest = hmac.finalize().into_bytes();
    assert_eq!(&session[28..32], &digest[..4]);
}

#[test]
fn recognises_v2ray_and_gost_websocket_plugins() {
    for plugin in ["v2ray-plugin", "gost", "gost-plugin"] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm",
                "plugin": plugin,
                "plugin_opts": r"mode=websocket;host=cdn.example.com;path=/a\;b;tls=true"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node).unwrap();
        assert!(matches!(
            config.plugin,
            ShadowsocksPlugin::WebSocket { ref host, ref path, tls: true }
                if host == "cdn.example.com" && path == "/a;b"
        ));
    }
}

#[test]
fn recognises_websocket_shadowsocks_obfuscations() {
    for obfuscation in ["websocket", "ws", "httpupgrade"] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm",
                "obfuscation": obfuscation,
                "obfs-host": "cdn.example.com",
                "path": "/ss"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node).unwrap();
        assert!(matches!(
            config.plugin,
            ShadowsocksPlugin::WebSocket { ref host, ref path, tls: false }
                if host == "cdn.example.com" && path == "/ss"
        ));
    }
}

#[test]
fn shadowsocks_manual_runtime_flags_parse() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "one-time-auth": "true",
            "tcp-fast-open": "true",
            "udp-relay": "false",
            "udp-over-tcp": "true"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(config.one_time_auth);
    assert!(config.tcp_fast_open);
    assert!(!config.udp_relay);
    assert!(config.udp_over_tcp);
    assert!(config.connect_opts().tcp.fastopen);
    assert!(config.ensure_udp_supported().is_err());
    assert!(config.ensure_uot_supported().is_err());
}

#[test]
fn shadowsocks_websocket_obfuscation_tls_can_toggle() {
    for (enabled, expected_tls) in [("true", true), ("false", false)] {
        let node = KernelNode {
            id: None,
            protocol: "ss".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-gcm",
                "obfuscation": "websocket",
                "obfuscation-tls": enabled,
                "obfs-host": "cdn.example.com",
                "path": "/ss"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node).unwrap();
        assert!(matches!(
            config.plugin,
            ShadowsocksPlugin::WebSocket { ref host, ref path, tls }
                if host == "cdn.example.com" && path == "/ss" && tls == expected_tls
        ));
    }
}

#[test]
fn recognises_h2_shadowsocks_obfuscation() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 443,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "obfuscation": "h2",
            "obfs-host": "cdn.example.com",
            "path": "/h2"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::H2 { ref host, ref path, tls: true }
            if host == "cdn.example.com" && path == "/h2"
    ));
}

#[test]
fn shadowsocks_h2_obfuscation_can_disable_tls() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 80,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "obfuscation": "h2",
            "h2c": "true",
            "obfs-host": "cdn.example.com",
            "path": "/h2"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::H2 { ref host, ref path, tls: false }
            if host == "cdn.example.com" && path == "/h2"
    ));
}

#[test]
fn shadowsocksr_manual_runtime_flags_parse() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "origin",
            "obfs": "plain",
            "tcp-fast-open": "true",
            "udp-relay": "false"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(config.tcp_fast_open);
    assert!(!config.udp_relay);
    assert!(config.connect_opts().tcp.fastopen);
    assert!(config.ensure_udp_supported().is_err());
}

#[test]
fn shadowsocksr_native_uot_is_allowed() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "auth_aes128_md5",
            "protocol_param": "42:user-secret",
            "obfs": "plain",
            "udp-over-tcp": "true"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(config.should_use_uot());
    config.ensure_uot_supported().unwrap();
}

#[test]
fn recognises_ssr_tls_ticket_obfs_aliases() {
    for obfs in [
        "tls1.2_ticket_auth",
        "tls1_2_ticket_auth",
        "tls1.2_ticket_fastauth",
        "tls1_2_ticket_fastauth",
    ] {
        let node = KernelNode {
            id: None,
            protocol: "ssr".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-cfb",
                "protocol": "origin",
                "obfs": obfs,
                "obfs_param": "cdn.example.com"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node)
            .unwrap_or_else(|err| panic!("{obfs} should be accepted: {err}"));
        assert!(matches!(
            config.plugin,
            ShadowsocksPlugin::SsrTls { ref host, ref key }
                if host == "cdn.example.com" && !key.is_empty()
        ));
    }
}

#[test]
fn recognises_ssr_random_head_plugin() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "origin",
            "obfs": "random_head"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(config.plugin, ShadowsocksPlugin::RandomHead));
}

#[tokio::test]
async fn random_head_stream_flushes_payload_after_response() {
    let (client_io, mut server_io) = tokio::io::duplex(2048);
    let mut client = RandomHeadStream::new(client_io);
    client.write_all(b"neoncore-random-head").await.unwrap();

    let mut header = vec![0_u8; 128];
    let header_len = server_io.read(&mut header).await.unwrap();
    assert!((8..=103).contains(&header_len));
    let random_len = header_len - 4;
    let checksum = u32::from_le_bytes(header[random_len..header_len].try_into().unwrap());
    assert_eq!(
        checksum,
        0xffff_ffff_u32.wrapping_sub(crc32fast::hash(&header[..random_len]))
    );

    let client_reader = tokio::spawn(async move {
        let mut scratch = [0_u8; 1];
        let _ = timeout(Duration::from_millis(100), client.read(&mut scratch)).await;
    });
    server_io.write_all(b"ok").await.unwrap();
    let mut payload = vec![0_u8; 64];
    let payload_len = timeout(Duration::from_secs(1), server_io.read(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload[..payload_len], b"neoncore-random-head");
    client_reader.await.unwrap();
}

#[test]
fn rejects_bare_tls_as_ssr_obfs() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "origin",
            "obfs": "tls"
        }),
    };

    let err = ShadowsocksConfig::from_node(&node).unwrap_err();
    assert!(err.to_string().contains("unsupported ShadowsocksR obfs"));
}

#[test]
fn accepts_ssr_origin_plain_as_shadowsocks() {
    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "origin",
            "obfs": "plain"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert_eq!(config.plugin, ShadowsocksPlugin::None);
    assert_eq!(config.ssr_protocol, SsrProtocol::Origin);
}

#[test]
fn accepts_ssr_origin_with_aead_and_2022_ciphers() {
    for method in [
        "chacha20-ietf-poly1305",
        "chacha20-poly1305",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        let node = KernelNode {
            id: None,
            protocol: "shadowsocksr".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: if method.contains("2022-blake3-aes-128-gcm") {
                "MDEyMzQ1Njc4OWFiY2RlZg==".to_string()
            } else if method.contains("2022-blake3") {
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string()
            } else {
                "test-password".to_string()
            },
            parameters: json!({
                "method": method,
                "protocol": "origin",
                "obfs": "plain"
            }),
        };

        let config = ShadowsocksConfig::from_node(&node)
            .unwrap_or_else(|err| panic!("{method} should be accepted for SSR origin: {err}"));
        assert_eq!(config.ssr_protocol, SsrProtocol::Origin);
    }
}

#[test]
fn accepts_ssr_auth_sha1_v4_with_stream_cipher() {
    let node = KernelNode {
        id: None,
        protocol: "shadowsocksr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-cfb",
            "protocol": "auth_sha1_v4",
            "obfs": "plain"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert_eq!(config.ssr_protocol, SsrProtocol::AuthSha1V4);
}

#[test]
fn accepts_extended_ssr_native_protocols() {
    for protocol in [
        "verify_simple",
        "verify_sha1",
        "auth_simple",
        "auth_sha1",
        "auth_sha1_v2",
        "auth_sha1_v4",
        "auth-aes128_md5",
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
        "auth_chain_c",
        "auth_chain_d",
        "auth_chain_e",
        "auth_chain_f",
    ] {
        let node = KernelNode {
            id: None,
            protocol: "shadowsocksr".to_string(),
            server: "edge.example.com".to_string(),
            server_port: 8388,
            user_id: "test-password".to_string(),
            parameters: json!({
                "method": "aes-256-cfb",
                "protocol": protocol,
                "protocol_param": "42:user-secret",
                "obfs": "plain"
            }),
        };

        ShadowsocksConfig::from_node(&node).unwrap();
    }
}

#[test]
fn ssr_native_protocol_codecs_emit_wire_data() {
    for protocol in [
        SsrProtocol::VerifySimple,
        SsrProtocol::VerifySha1,
        SsrProtocol::AuthSimple,
        SsrProtocol::AuthSha1,
        SsrProtocol::AuthSha1V2,
        SsrProtocol::AuthSha1V4,
        SsrProtocol::AuthAes128Md5,
        SsrProtocol::AuthAes128Sha1,
        SsrProtocol::AuthChainA,
        SsrProtocol::AuthChainB,
        SsrProtocol::AuthChainC,
        SsrProtocol::AuthChainD,
        SsrProtocol::AuthChainE,
        SsrProtocol::AuthChainF,
    ] {
        let mut codec = SsrProtocolCodec::new(
            protocol,
            b"0123456789abcdef".to_vec(),
            b"12345678".to_vec(),
            "42:user-secret".to_string(),
        );
        let encoded = codec
            .encode(b"\x03\x0bexample.com\x00\x50GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert!(encoded.len() > 16);
    }
}

#[test]
fn auth_chain_f_data_size_key_uses_auth_timestamp() {
    let key = b"0123456789abcdef";
    let before = auth_chain_f_data_size_key(key, 60, 119);
    let after = auth_chain_f_data_size_key(key, 60, 120);
    assert_ne!(before, after);

    let codec = match SsrProtocolCodec::new(
        SsrProtocol::AuthChainF,
        key.to_vec(),
        b"12345678".to_vec(),
        "42:user-secret#60".to_string(),
    ) {
        SsrProtocolCodec::AuthChain(codec) => codec,
        _ => unreachable!("auth_chain_f creates an auth_chain codec"),
    };
    let expected_key = auth_chain_f_data_size_key(key, 60, codec.auth.timestamp);
    let mut expected = AuthChainCodec::new(
        key.to_vec(),
        b"12345678".to_vec(),
        "42:user-secret".to_string(),
        AuthChainProfile::new("auth_chain_f", AuthChainVariant::C),
    );
    expected.init_data_size_c(true, &expected_key);
    assert_eq!(codec.data_size_list, expected.data_size_list);
}

#[test]
fn verify_sha1_uses_independent_send_and_receive_counters() {
    let key = b"0123456789abcdef".to_vec();
    let iv = b"12345678".to_vec();
    let mut codec = VerifySha1Codec::new(key.clone(), iv.clone());
    let request =
        codec.encode(b"\x03\x0bexample.com\x00\x50GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(request.len() > 32);

    let reply = b"HTTP/1.1 200 OK\r\n\r\n";
    let mut frame = Vec::new();
    frame.extend_from_slice(&(reply.len() as u16).to_be_bytes());
    let tag = with_appended_u32_be(&iv, 0, |mac_key| hmac_sha1(mac_key, reply));
    frame.extend_from_slice(&tag[..10]);
    frame.extend_from_slice(reply);

    let mut output = BytesMut::new();
    codec.decode(&frame, &mut output).unwrap();
    assert_eq!(&output[..], reply);
}

#[test]
fn early_ssr_auth_codecs_decode_reference_style_frames() {
    for protocol in [
        SsrProtocol::VerifySimple,
        SsrProtocol::AuthSimple,
        SsrProtocol::AuthSha1,
        SsrProtocol::AuthSha1V2,
        SsrProtocol::AuthSha1V4,
    ] {
        let key = b"0123456789abcdef".to_vec();
        let iv = b"12345678".to_vec();
        let reply = b"HTTP/1.1 200 OK\r\n\r\nneoncore";
        let frame = match protocol {
            SsrProtocol::VerifySimple => verify_simple_response_frame(reply),
            SsrProtocol::AuthSimple | SsrProtocol::AuthSha1 | SsrProtocol::AuthSha1V2 => {
                early_auth_response_frame(reply, 9)
            }
            SsrProtocol::AuthSha1V4 => early_auth_response_frame(reply, 17),
            _ => unreachable!("test protocol is known"),
        };
        let mut codec = SsrProtocolCodec::new(protocol, key, iv, "42:user-secret".to_string());
        let mut output = BytesMut::new();
        codec.decode(&frame, &mut output).unwrap();
        assert_eq!(&output[..], reply);
    }
}

#[test]
fn ssr_golden_vectors_decode_fixed_reference_frames() {
    let key = b"0123456789abcdef".to_vec();
    let iv = b"12345678".to_vec();
    let vectors = [
        (
            SsrProtocol::VerifySimple,
            "0021485454502f312e3120323030204f4b0d0a0d0a6e656f6e636f72651407a65a",
            b"HTTP/1.1 200 OK\r\n\r\nneoncore".as_slice(),
        ),
        (
            SsrProtocol::VerifySha1,
            "00133dae497d1ff9407b4f61485454502f312e3120323030204f4b0d0a0d0a",
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
        ),
        (
            SsrProtocol::AuthSimple,
            "002d8a4e09a5a5a5a5a5a5a5a5a5485454502f312e3120323030204f4b0d0a0d0a6e656f6e636f7265ce0db439",
            b"HTTP/1.1 200 OK\r\n\r\nneoncore".as_slice(),
        ),
        (
            SsrProtocol::AuthSha1,
            "002d8a4e09a5a5a5a5a5a5a5a5a5485454502f312e3120323030204f4b0d0a0d0a6e656f6e636f7265ce0db439",
            b"HTTP/1.1 200 OK\r\n\r\nneoncore".as_slice(),
        ),
        (
            SsrProtocol::AuthSha1V2,
            "002d8a4e09a5a5a5a5a5a5a5a5a5485454502f312e3120323030204f4b0d0a0d0a6e656f6e636f7265ce0db439",
            b"HTTP/1.1 200 OK\r\n\r\nneoncore".as_slice(),
        ),
        (
            SsrProtocol::AuthSha1V4,
            "0035dcd611a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5485454502f312e3120323030204f4b0d0a0d0a6e656f6e636f7265e013753d",
            b"HTTP/1.1 200 OK\r\n\r\nneoncore".as_slice(),
        ),
    ];

    for (protocol, frame, expected) in vectors {
        let mut codec = SsrProtocolCodec::new(
            protocol,
            key.clone(),
            iv.clone(),
            "42:user-secret".to_string(),
        );
        let mut output = BytesMut::new();
        codec.decode(&decode_hex(frame), &mut output).unwrap();
        assert_eq!(&output[..], expected);
    }
}

#[test]
fn ssr_tls_ticket_client_hello_and_finish_validate_hmac() {
    let key = b"0123456789abcdef".to_vec();
    let client_id = [9_u8; 32];
    let hello = ssr_tls_ticket_client_hello("cdn.example.com", &key, &client_id);

    assert_eq!(&hello[..3], &[0x16, 0x03, 0x01]);
    let session_offset = 5 + 4 + 2 + 22 + 10 + 1;
    assert_eq!(&hello[session_offset..session_offset + 32], &client_id);

    let finish = ssr_tls_ticket_finish(&key, &client_id, BytesMut::from(&b"payload"[..]));
    assert_eq!(
        &finish[..11],
        &[0x14, 0x03, 0x03, 0, 1, 1, 0x16, 0x03, 0x03, 0, 0x20]
    );
    let tag = ssr_tls_ticket_hmac(&key, &client_id, &finish[..33]);
    assert_eq!(&finish[33..43], &tag[..10]);
    assert_eq!(&finish[43..], b"payload");
}

#[test]
fn ssr_native_udp_packet_wrappers_round_trip() {
    let key = b"0123456789abcdef".to_vec();
    let body = build_ssr_udp_body(
        &Address::DomainNameAddress("dns.example.com".to_string(), 53),
        b"neoncore-ssr-udp-query",
    );
    for protocol in [
        SsrProtocol::VerifySimple,
        SsrProtocol::VerifySha1,
        SsrProtocol::AuthSimple,
        SsrProtocol::AuthSha1,
        SsrProtocol::AuthSha1V2,
        SsrProtocol::AuthSha1V4,
        SsrProtocol::AuthChainA,
        SsrProtocol::AuthChainB,
        SsrProtocol::AuthChainC,
        SsrProtocol::AuthChainD,
        SsrProtocol::AuthChainE,
        SsrProtocol::AuthChainF,
    ] {
        let mut encoder = ssr_udp_codec(&protocol, &key, "");
        let wrapped = encoder.encode_packet(&body).unwrap();
        if matches!(
            protocol,
            SsrProtocol::AuthChainA
                | SsrProtocol::AuthChainB
                | SsrProtocol::AuthChainC
                | SsrProtocol::AuthChainD
                | SsrProtocol::AuthChainE
                | SsrProtocol::AuthChainF
        ) {
            assert!(wrapped.len() > body.len());
        }
        let decoded = decode_ssr_udp_request_for_server(&protocol, &key, &wrapped);
        let (addr, payload) = parse_ssr_udp_body(decoded).unwrap();
        assert!(matches!(
            addr,
            Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
        ));
        assert_eq!(payload, b"neoncore-ssr-udp-query");
    }

    for protocol in [SsrProtocol::AuthAes128Md5, SsrProtocol::AuthAes128Sha1] {
        let mut encoder = ssr_udp_codec(&protocol, &key, "");
        let wrapped = encoder.encode_packet(&body).unwrap();
        assert!(wrapped.len() > body.len());
        let decoded = decode_ssr_udp_request_for_server(&protocol, &key, &wrapped);
        let (addr, payload) = parse_ssr_udp_body(decoded).unwrap();
        assert!(matches!(
            addr,
            Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
        ));
        assert_eq!(payload, b"neoncore-ssr-udp-query");
    }

    for protocol in [
        SsrProtocol::VerifySimple,
        SsrProtocol::VerifySha1,
        SsrProtocol::AuthSimple,
        SsrProtocol::AuthSha1,
        SsrProtocol::AuthSha1V2,
        SsrProtocol::AuthSha1V4,
        SsrProtocol::AuthAes128Md5,
        SsrProtocol::AuthAes128Sha1,
        SsrProtocol::AuthChainA,
        SsrProtocol::AuthChainB,
        SsrProtocol::AuthChainC,
        SsrProtocol::AuthChainD,
        SsrProtocol::AuthChainE,
        SsrProtocol::AuthChainF,
    ] {
        let wrapped = encode_ssr_udp_response_for_client(&protocol, &key, &body);
        let mut decoder = ssr_udp_codec(&protocol, &key, "");
        let decoded = decoder.decode_packet(&wrapped).unwrap();
        let (addr, payload) = parse_ssr_udp_body(decoded).unwrap();
        assert!(matches!(
            addr,
            Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
        ));
        assert_eq!(payload, b"neoncore-ssr-udp-query");
    }
}

#[test]
fn rejects_ssr_auth_with_aead_cipher() {
    let node = KernelNode {
        id: None,
        protocol: "shadowsocksr".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "protocol": "auth_sha1_v4",
            "obfs": "plain"
        }),
    };

    let err = ShadowsocksConfig::from_node(&node).unwrap_err();
    assert!(err
        .to_string()
        .contains("native protocols require a stream cipher"));
}

#[tokio::test]
async fn udp_relay_round_trips_classic_aead() {
    udp_relay_round_trip("aes-256-gcm", "test-password").await;
}

#[tokio::test]
async fn udp_relay_round_trips_aead_2022() {
    udp_relay_round_trip("2022-blake3-aes-128-gcm", "MDEyMzQ1Njc4OWFiY2RlZg==").await;
}

#[tokio::test]
async fn udp_relay_reuses_direct_packet_connection() {
    let method = parse_shadowsocks_cipher("2022-blake3-aes-128-gcm").unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let password = "MDEyMzQ1Njc4OWFiY2RlZg==".to_string();
    tokio::spawn(async move {
        let ShadowsocksMethod::BuiltIn(kind) = method else {
            unreachable!("test method is built-in");
        };
        let server = ServerConfig::new(server_addr, password, kind).unwrap();
        let context = Context::new(ServerType::Local);
        let mut first_peer = None;
        let mut first_session = None;
        for idx in 0..2 {
            let mut buffer = vec![0_u8; 65_536];
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            buffer.truncate(n);
            if let Some(first_peer) = first_peer {
                assert_eq!(peer, first_peer);
            } else {
                first_peer = Some(peer);
            }
            let (len, addr, control) =
                decrypt_client_payload(&context, kind, server.key(), &mut buffer, None).unwrap();
            let control = control.unwrap_or_default();
            if let Some(first_session) = first_session {
                assert_eq!(control.client_session_id, first_session);
            } else {
                first_session = Some(control.client_session_id);
            }
            assert_eq!(
                &buffer[..len],
                format!("neoncore-udp-query-{idx}").as_bytes()
            );
            let mut reply = BytesMut::new();
            encrypt_server_payload(
                &context,
                kind,
                server.key(),
                &addr,
                &control,
                format!("neoncore-udp-reply-{idx}").as_bytes(),
                &mut reply,
            );
            socket.send_to(&reply, peer).await.unwrap();
        }
    });

    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        user_id: "MDEyMzQ1Njc4OWFiY2RlZg==".to_string(),
        parameters: json!({ "method": "2022-blake3-aes-128-gcm" }),
    };
    let resolver = DnsResolver::new(KernelDnsConfig::default());
    let context = OutboundContext {
        resolver: &resolver,
    };
    let target = TargetAddress {
        host: "dns.example.com".to_string(),
        port: 53,
    };
    for idx in 0..2 {
        let reply = ShadowsocksAdapter
            .send_udp(
                &node,
                &target,
                format!("neoncore-udp-query-{idx}").as_bytes(),
                &context,
            )
            .await
            .unwrap();
        assert_eq!(reply, format!("neoncore-udp-reply-{idx}").as_bytes());
    }
}

#[tokio::test]
async fn direct_udp_packet_connection_demuxes_out_of_order_targets() {
    let method = parse_shadowsocks_cipher("2022-blake3-aes-128-gcm").unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let password = "MDEyMzQ1Njc4OWFiY2RlZg==".to_string();
    tokio::spawn(async move {
        let ShadowsocksMethod::BuiltIn(kind) = method else {
            unreachable!("test method is built-in");
        };
        let server = ServerConfig::new(server_addr, password, kind).unwrap();
        let context = Context::new(ServerType::Local);
        let mut requests = Vec::new();
        for _ in 0..2 {
            let mut buffer = vec![0_u8; 65_536];
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            buffer.truncate(n);
            let (len, addr, control) =
                decrypt_client_payload(&context, kind, server.key(), &mut buffer, None).unwrap();
            requests.push((
                peer,
                addr,
                control.unwrap_or_default(),
                buffer[..len].to_vec(),
            ));
        }
        requests.reverse();
        for (peer, addr, control, payload) in requests {
            let response = if payload == b"query-a" {
                b"reply-a".as_slice()
            } else {
                b"reply-b".as_slice()
            };
            let mut reply = BytesMut::new();
            encrypt_server_payload(
                &context,
                kind,
                server.key(),
                &addr,
                &control,
                response,
                &mut reply,
            );
            socket.send_to(&reply, peer).await.unwrap();
        }
    });

    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        user_id: "MDEyMzQ1Njc4OWFiY2RlZg==".to_string(),
        parameters: json!({ "method": "2022-blake3-aes-128-gcm" }),
    };
    let config = ShadowsocksConfig::from_node(&node).unwrap();
    let conn = DirectUdpPacketConn::new();
    let target_a = TargetAddress {
        host: "a.example.com".to_string(),
        port: 53,
    };
    let target_b = TargetAddress {
        host: "b.example.com".to_string(),
        port: 53,
    };

    let (reply_a, reply_b) = tokio::join!(
        conn.send(&target_a, b"query-a", &config, server_addr),
        conn.send(&target_b, b"query-b", &config, server_addr)
    );
    assert_eq!(reply_a.unwrap(), b"reply-a");
    assert_eq!(reply_b.unwrap(), b"reply-b");
}

#[tokio::test]
async fn udp_relay_round_trips_stream_cipher() {
    udp_relay_round_trip("aes-128-cfb", "test-password").await;
}

#[tokio::test]
async fn udp_relay_round_trips_neon_legacy_stream_cipher() {
    udp_relay_round_trip("bf-cfb", "test-password").await;
}

#[tokio::test]
async fn ssr_udp_relay_round_trips_builtin_stream_cipher() {
    ssr_udp_relay_round_trip("aes-128-cfb", "auth_aes128_md5").await;
}

#[tokio::test]
async fn ssr_udp_relay_round_trips_neon_legacy_stream_cipher() {
    ssr_udp_relay_round_trip("bf-cfb", "auth_chain_a").await;
}

#[tokio::test]
async fn ssr_udp_relay_round_trips_early_protocols() {
    for protocol in [
        "verify_simple",
        "verify_sha1",
        "auth_simple",
        "auth_sha1",
        "auth_sha1_v2",
        "auth_sha1_v4",
    ] {
        ssr_udp_relay_round_trip("aes-128-cfb", protocol).await;
    }
}

#[tokio::test]
async fn ssr_udp_relay_round_trips_all_auth_chain_variants() {
    for protocol in [
        "auth_chain_a",
        "auth_chain_b",
        "auth_chain_c",
        "auth_chain_d",
        "auth_chain_e",
        "auth_chain_f",
    ] {
        ssr_udp_relay_round_trip("bf-cfb", protocol).await;
    }
}

#[test]
fn plugin_options_parser_handles_escaped_values() {
    let parsed = parse_plugin_options(r"path=/a\;b\=c;host=cdn.example.com;flag=1");
    assert_eq!(parsed.get("path").unwrap(), "/a;b=c");
    assert_eq!(parsed.get("host").unwrap(), "cdn.example.com");
    assert_eq!(parsed.get("flag").unwrap(), "1");
}

#[tokio::test]
async fn uot_packet_round_trips_domain_address() {
    let address = Address::DomainNameAddress("dns.example.com".to_string(), 53);
    let packet = encode_uot_packet(&address, b"neoncore-uot-query").unwrap();
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        server.write_all(&packet).await.unwrap();
    });

    let (decoded_address, decoded_payload) = read_uot_packet(&mut client).await.unwrap();
    assert!(matches!(
        decoded_address,
        Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
    ));
    assert_eq!(decoded_payload, b"neoncore-uot-query");
}

#[tokio::test]
async fn uot_matching_reader_skips_wrong_target_packets() {
    let expected = Address::DomainNameAddress("dns.example.com".to_string(), 53);
    let wrong = encode_uot_packet(
        &Address::DomainNameAddress("late.example.com".to_string(), 53),
        b"late-reply",
    )
    .unwrap();
    let right = encode_uot_packet(&expected, b"fresh-reply").unwrap();
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        server.write_all(&wrong).await.unwrap();
        server.write_all(&right).await.unwrap();
    });

    let reply = read_matching_uot_packet(&mut client, &expected)
        .await
        .unwrap();
    assert_eq!(reply, b"fresh-reply");
}

#[tokio::test]
async fn uot_matching_reader_fails_after_wrong_target_budget() {
    let expected = Address::DomainNameAddress("dns.example.com".to_string(), 53);
    let wrong = encode_uot_packet(
        &Address::DomainNameAddress("late.example.com".to_string(), 53),
        b"late-reply",
    )
    .unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        for _ in 0..UOT_MAX_DISCARDED_PACKETS {
            server.write_all(&wrong).await.unwrap();
        }
    });

    let err = read_matching_uot_packet(&mut client, &expected)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("too many packets"));
}

#[tokio::test]
async fn uot_reader_demuxes_out_of_order_targets() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let (reader, _writer) = tokio::io::split(boxed_stream(client_io));
    let pending = PacketSessionDemux::new();
    let target_a = Address::DomainNameAddress("a.example.com".to_string(), 53);
    let target_b = Address::DomainNameAddress("b.example.com".to_string(), 53);
    let key_a = udp_pending_key(&target_a);
    let key_b = udp_pending_key(&target_b);
    let wait_a = pending.register(key_a, 1);
    let wait_b = pending.register(key_b, 2);
    let task = spawn_uot_reader(reader, pending.clone());
    server_io
        .write_all(&encode_uot_packet(&target_b, b"reply-b").unwrap())
        .await
        .unwrap();
    server_io
        .write_all(&encode_uot_packet(&target_a, b"reply-a").unwrap())
        .await
        .unwrap();

    assert_eq!(wait_a.receiver.await.unwrap().unwrap(), b"reply-a");
    assert_eq!(wait_b.receiver.await.unwrap().unwrap(), b"reply-b");
    task.abort();
}

#[tokio::test]
async fn xhttp_post_batch_respects_small_max_post_size() {
    let (mut upload, mut writer) = tokio::io::duplex(16);
    tokio::spawn(async move {
        writer.write_all(b"abcdef").await.unwrap();
    });

    let payload = read_xhttp_post_batch(&mut upload, 2, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload[..], b"ab");
}

#[tokio::test]
async fn xhttp_h1_post_drains_response_body_before_reuse() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream: BoxedProxyStream = boxed_stream(client_io);
    let config = XHttpPluginConfig {
        host: "cdn.example.com".to_string(),
        path: "/x".to_string(),
        tls: false,
        mode: XHttpMode::PacketUp,
        version: XHttpVersion::H1,
        max_each_post_bytes: 1024,
        min_posts_interval_ms: 0,
        skip_cert_verify: false,
    };
    tokio::spawn(async move {
        let first = read_until_contains(&mut server_io, b"first").await;
        assert!(String::from_utf8_lossy(&first).contains("seq=0"));
        server_io
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();
        let second = read_until_contains(&mut server_io, b"second").await;
        let second_text = String::from_utf8_lossy(&second);
        assert!(second_text.starts_with("POST "));
        assert!(second_text.contains("seq=1"));
        server_io
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
    });

    let reusable = send_http1_xhttp_post_on_stream(
        &mut stream,
        &config,
        "session-a",
        0,
        &Bytes::from_static(b"first"),
    )
    .await
    .unwrap();
    assert!(reusable);
    let reusable = send_http1_xhttp_post_on_stream(
        &mut stream,
        &config,
        "session-a",
        1,
        &Bytes::from_static(b"second"),
    )
    .await
    .unwrap();
    assert!(reusable);
}

async fn read_until_contains<R>(reader: &mut R, needle: &[u8]) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut byte = [0_u8; 1];
    while !output.windows(needle.len()).any(|window| window == needle) {
        timeout(Duration::from_secs(1), reader.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        output.push(byte[0]);
    }
    output
}

#[tokio::test]
async fn simple_obfs_tls_skips_dynamic_handshake_response() {
    let (client_io, mut server_io) = tokio::io::duplex(1024);
    let mut client = SimpleObfsTlsStream::new(client_io, "example.com".to_string());
    tokio::spawn(async move {
        server_io
            .write_all(&[0x16, 0x03, 0x03, 0x00, 0x05])
            .await
            .unwrap();
        server_io.write_all(b"hello").await.unwrap();
        server_io
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x04])
            .await
            .unwrap();
        server_io.write_all(b"pong").await.unwrap();
    });

    let mut payload = [0_u8; 4];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"pong");
}

fn verify_simple_response_frame(payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 6;
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    let checksum = adler32(&frame);
    frame.extend_from_slice(&checksum.to_le_bytes());
    frame
}

fn early_auth_response_frame(payload: &[u8], random_len: usize) -> Vec<u8> {
    let length = 2 + 2 + 1 + random_len + payload.len() + 4;
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as u16).to_be_bytes());
    let crc = crc32fast::hash(&frame[..2]) as u16;
    frame.extend_from_slice(&crc.to_le_bytes());
    frame.push(random_len as u8);
    frame.extend(std::iter::repeat(0xa5).take(random_len));
    frame.extend_from_slice(payload);
    let checksum = adler32(&frame);
    frame.extend_from_slice(&checksum.to_le_bytes());
    frame
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

#[test]
fn plugin_takes_precedence_over_obfuscation() {
    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "edge.example.com".to_string(),
        server_port: 8388,
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": "aes-256-gcm",
            "plugin": "v2ray-plugin",
            "obfuscation": "http"
        }),
    };

    let config = ShadowsocksConfig::from_node(&node).unwrap();
    assert!(matches!(
        config.plugin,
        ShadowsocksPlugin::WebSocket { ref host, ref path, tls: false }
            if host == "edge.example.com" && path == "/"
    ));
}

async fn udp_relay_round_trip(method: &str, password: &str) {
    let method_kind = parse_shadowsocks_cipher(method).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server_method = method_kind;
    let server_password = password.to_string();
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
        buffer.truncate(n);
        let target_addr = match server_method {
            ShadowsocksMethod::BuiltIn(kind) => {
                let server = ServerConfig::new(server_addr, server_password, kind).unwrap();
                let context = Context::new(ServerType::Local);
                let (len, addr, control) =
                    decrypt_client_payload(&context, kind, server.key(), &mut buffer, None)
                        .unwrap();
                assert_eq!(&buffer[..len], b"neoncore-udp-query");
                let mut reply = BytesMut::new();
                encrypt_server_payload(
                    &context,
                    kind,
                    server.key(),
                    &addr,
                    &control.unwrap_or_default(),
                    b"neoncore-udp-reply",
                    &mut reply,
                );
                socket.send_to(&reply, peer).await.unwrap();
                addr
            }
            ShadowsocksMethod::NeonLegacy(kind) => {
                let key = legacy_evp_bytes_to_key(server_password.as_bytes(), kind.key_len());
                let (addr, payload) = decrypt_legacy_udp_packet(kind, &key, &mut buffer).unwrap();
                assert_eq!(payload, b"neoncore-udp-query");
                let reply =
                    encrypt_legacy_udp_packet(kind, &key, &addr, b"neoncore-udp-reply").unwrap();
                socket.send_to(&reply, peer).await.unwrap();
                addr
            }
        };
        assert!(matches!(
            target_addr,
            Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
        ));
    });

    let node = KernelNode {
        id: None,
        protocol: "ss".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        user_id: password.to_string(),
        parameters: json!({ "method": method }),
    };
    let resolver = DnsResolver::new(KernelDnsConfig::default());
    let context = OutboundContext {
        resolver: &resolver,
    };
    let target = TargetAddress {
        host: "dns.example.com".to_string(),
        port: 53,
    };
    let reply = ShadowsocksAdapter
        .send_udp(&node, &target, b"neoncore-udp-query", &context)
        .await
        .unwrap();
    assert_eq!(reply, b"neoncore-udp-reply");
}

fn decode_ssr_udp_request_for_server(protocol: &SsrProtocol, key: &[u8], packet: &[u8]) -> Vec<u8> {
    match protocol {
        SsrProtocol::Origin
        | SsrProtocol::VerifySimple
        | SsrProtocol::VerifySha1
        | SsrProtocol::AuthSimple
        | SsrProtocol::AuthSha1
        | SsrProtocol::AuthSha1V2
        | SsrProtocol::AuthSha1V4 => packet.to_vec(),
        SsrProtocol::AuthAes128Md5 | SsrProtocol::AuthAes128Sha1 => {
            assert!(packet.len() >= 8);
            let data_len = packet.len() - 4;
            let user_data_len = data_len - 4;
            let expected = match protocol {
                SsrProtocol::AuthAes128Md5 => hmac_md5(key, &packet[..data_len]).to_vec(),
                SsrProtocol::AuthAes128Sha1 => {
                    let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(key)
                        .expect("HMAC accepts any key length");
                    hmac.update(&packet[..data_len]);
                    hmac.finalize().into_bytes().to_vec()
                }
                _ => unreachable!("matched auth_aes protocols"),
            };
            assert_eq!(&expected[..4], &packet[data_len..]);
            packet[..user_data_len].to_vec()
        }
        SsrProtocol::AuthChainA
        | SsrProtocol::AuthChainB
        | SsrProtocol::AuthChainC
        | SsrProtocol::AuthChainD
        | SsrProtocol::AuthChainE
        | SsrProtocol::AuthChainF => {
            assert!(packet.len() >= 9);
            let mac_pos = packet.len() - 1;
            let mac = hmac_md5(key, &packet[..mac_pos]);
            assert_eq!(mac[0], packet[mac_pos]);
            let auth_start = packet.len() - 8;
            let md5_data = hmac_md5(key, &packet[auth_start..auth_start + 3]);
            let mut random = XorShift128Plus::default();
            random.init_from_bin(&md5_data);
            let rand_len = (random.next() % 127) as usize;
            let data_end = auth_start - rand_len;
            let rc4_key = ssr_chain_udp_rc4_key(key, &md5_data);
            let mut body = packet[..data_end].to_vec();
            let mut rc4 = Rc4::new_from_slice(&rc4_key).unwrap();
            rc4.apply_keystream(&mut body);
            body
        }
    }
}

fn encode_ssr_udp_response_for_client(protocol: &SsrProtocol, key: &[u8], body: &[u8]) -> Vec<u8> {
    match protocol {
        SsrProtocol::Origin
        | SsrProtocol::VerifySimple
        | SsrProtocol::VerifySha1
        | SsrProtocol::AuthSimple
        | SsrProtocol::AuthSha1
        | SsrProtocol::AuthSha1V2
        | SsrProtocol::AuthSha1V4 => body.to_vec(),
        SsrProtocol::AuthAes128Md5 => {
            let mut output = body.to_vec();
            let mac = hmac_md5(key, &output);
            output.extend_from_slice(&mac[..4]);
            output
        }
        SsrProtocol::AuthAes128Sha1 => {
            let mut output = body.to_vec();
            let mut hmac =
                <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            hmac.update(&output);
            let mac = hmac.finalize().into_bytes();
            output.extend_from_slice(&mac[..4]);
            output
        }
        SsrProtocol::AuthChainA
        | SsrProtocol::AuthChainB
        | SsrProtocol::AuthChainC
        | SsrProtocol::AuthChainD
        | SsrProtocol::AuthChainE
        | SsrProtocol::AuthChainF => {
            let mut footer = [0_u8; 7];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut footer);
            let md5_data = hmac_md5(key, &footer);
            let mut random = XorShift128Plus::default();
            random.init_from_bin(&md5_data);
            let rand_len = (random.next() % 127) as usize;
            let rc4_key = ssr_chain_udp_rc4_key(key, &md5_data);
            let mut encrypted = body.to_vec();
            let mut rc4 = Rc4::new_from_slice(&rc4_key).unwrap();
            rc4.apply_keystream(&mut encrypted);
            let mut output = encrypted;
            push_random_bytes(&mut output, rand_len);
            output.extend_from_slice(&footer);
            let mac = hmac_md5(key, &output);
            output.push(mac[0]);
            output
        }
    }
}

async fn ssr_udp_relay_round_trip(method: &str, protocol: &str) {
    let method_kind = parse_shadowsocks_cipher(method).unwrap();
    let ssr_protocol = match protocol {
        "verify_simple" => SsrProtocol::VerifySimple,
        "verify_sha1" => SsrProtocol::VerifySha1,
        "auth_simple" => SsrProtocol::AuthSimple,
        "auth_sha1" => SsrProtocol::AuthSha1,
        "auth_sha1_v2" => SsrProtocol::AuthSha1V2,
        "auth_sha1_v4" => SsrProtocol::AuthSha1V4,
        "auth_aes128_md5" => SsrProtocol::AuthAes128Md5,
        "auth_aes128_sha1" => SsrProtocol::AuthAes128Sha1,
        "auth_chain_a" => SsrProtocol::AuthChainA,
        "auth_chain_b" => SsrProtocol::AuthChainB,
        "auth_chain_c" => SsrProtocol::AuthChainC,
        "auth_chain_d" => SsrProtocol::AuthChainD,
        "auth_chain_e" => SsrProtocol::AuthChainE,
        "auth_chain_f" => SsrProtocol::AuthChainF,
        _ => unreachable!("test protocol is known"),
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server_method = method_kind;
    let server_password = "test-password".to_string();
    let server_protocol = ssr_protocol.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
        buffer.truncate(n);
        let target_addr = match server_method {
            ShadowsocksMethod::BuiltIn(kind) => {
                let server = ServerConfig::new(server_addr, server_password, kind).unwrap();
                let decrypted =
                    decrypt_builtin_stream_udp_body(kind, server.key(), &mut buffer).unwrap();
                let request =
                    decode_ssr_udp_request_for_server(&server_protocol, server.key(), &decrypted);
                let (addr, payload) = parse_ssr_udp_body(request).unwrap();
                assert_eq!(payload, b"neoncore-ssr-udp-query");
                let body = build_ssr_udp_body(&addr, b"neoncore-ssr-udp-reply");
                let wrapped =
                    encode_ssr_udp_response_for_client(&server_protocol, server.key(), &body);
                let reply = encrypt_builtin_stream_udp_body(kind, server.key(), &wrapped).unwrap();
                socket.send_to(&reply, peer).await.unwrap();
                addr
            }
            ShadowsocksMethod::NeonLegacy(kind) => {
                let key = legacy_evp_bytes_to_key(server_password.as_bytes(), kind.key_len());
                let decrypted = decrypt_legacy_udp_body(kind, &key, &mut buffer).unwrap();
                let request = decode_ssr_udp_request_for_server(&server_protocol, &key, &decrypted);
                let (addr, payload) = parse_ssr_udp_body(request).unwrap();
                assert_eq!(payload, b"neoncore-ssr-udp-query");
                let body = build_ssr_udp_body(&addr, b"neoncore-ssr-udp-reply");
                let wrapped = encode_ssr_udp_response_for_client(&server_protocol, &key, &body);
                let reply = encrypt_legacy_udp_body(kind, &key, &wrapped).unwrap();
                socket.send_to(&reply, peer).await.unwrap();
                addr
            }
        };
        assert!(matches!(
            target_addr,
            Address::DomainNameAddress(ref host, 53) if host == "dns.example.com"
        ));
    });

    let node = KernelNode {
        id: None,
        protocol: "ssr".to_string(),
        server: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        user_id: "test-password".to_string(),
        parameters: json!({
            "method": method,
            "protocol": protocol,
            "obfs": "plain"
        }),
    };
    let resolver = DnsResolver::new(KernelDnsConfig::default());
    let context = OutboundContext {
        resolver: &resolver,
    };
    let target = TargetAddress {
        host: "dns.example.com".to_string(),
        port: 53,
    };
    let reply = ShadowsocksAdapter
        .send_udp(&node, &target, b"neoncore-ssr-udp-query", &context)
        .await
        .unwrap();
    assert_eq!(reply, b"neoncore-ssr-udp-reply");
}
