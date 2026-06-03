#[derive(Clone, Copy)]
struct SsrProtocolRegistryEntry {
    canonical: &'static str,
    aliases: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct SsrObfsRegistryEntry {
    canonical: &'static str,
    aliases: &'static [&'static str],
}

const SSR_PROTOCOL_REGISTRY: &[SsrProtocolRegistryEntry] = &[
    SsrProtocolRegistryEntry {
        canonical: "origin",
        aliases: &["", "origin", "plain"],
    },
    SsrProtocolRegistryEntry {
        canonical: "verify_simple",
        aliases: &["verify_simple"],
    },
    SsrProtocolRegistryEntry {
        canonical: "verify_sha1",
        aliases: &["verify_sha1", "ota"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_simple",
        aliases: &["auth_simple"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_sha1",
        aliases: &["auth_sha1"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_sha1_v2",
        aliases: &["auth_sha1_v2"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_sha1_v4",
        aliases: &["auth_sha1_v4"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_aes128_md5",
        aliases: &["auth_aes128_md5", "auth-aes128_md5"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_aes128_sha1",
        aliases: &["auth_aes128_sha1", "auth-aes128_sha1"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_a",
        aliases: &["auth_chain_a"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_b",
        aliases: &["auth_chain_b"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_c",
        aliases: &["auth_chain_c"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_d",
        aliases: &["auth_chain_d"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_e",
        aliases: &["auth_chain_e"],
    },
    SsrProtocolRegistryEntry {
        canonical: "auth_chain_f",
        aliases: &["auth_chain_f"],
    },
];

const SSR_OBFS_REGISTRY: &[SsrObfsRegistryEntry] = &[
    SsrObfsRegistryEntry {
        canonical: "plain",
        aliases: &["", "plain", "none"],
    },
    SsrObfsRegistryEntry {
        canonical: "http_simple",
        aliases: &["http_simple", "http-simple"],
    },
    SsrObfsRegistryEntry {
        canonical: "http_post",
        aliases: &["http_post", "http-post"],
    },
    SsrObfsRegistryEntry {
        canonical: "random_head",
        aliases: &["random_head", "random-head"],
    },
    SsrObfsRegistryEntry {
        canonical: "tls1.2_ticket_auth",
        aliases: &["tls1.2_ticket_auth", "tls1_2_ticket_auth"],
    },
    SsrObfsRegistryEntry {
        canonical: "tls1.2_ticket_fastauth",
        aliases: &["tls1.2_ticket_fastauth", "tls1_2_ticket_fastauth"],
    },
];

fn normalize_ssr_registry_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn canonical_ssr_protocol_name(value: &str) -> Option<&'static str> {
    let normalized = normalize_ssr_registry_name(value);
    SSR_PROTOCOL_REGISTRY
        .iter()
        .find(|entry| {
            entry.canonical == normalized
                || entry
                    .aliases
                    .iter()
                    .any(|alias| normalize_ssr_registry_name(alias) == normalized)
        })
        .map(|entry| entry.canonical)
}

fn canonical_ssr_obfs_name(value: &str) -> Option<&'static str> {
    let normalized = normalize_ssr_registry_name(value);
    SSR_OBFS_REGISTRY
        .iter()
        .find(|entry| {
            entry.canonical == normalized
                || entry
                    .aliases
                    .iter()
                    .any(|alias| normalize_ssr_registry_name(alias) == normalized)
        })
        .map(|entry| entry.canonical)
}
