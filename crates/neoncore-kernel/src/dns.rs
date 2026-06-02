use crate::session::{KernelDnsConfig, TargetAddress};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const MIN_PROXY_TTL: Duration = Duration::from_secs(30);
const MAX_PROXY_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct DnsResolver {
    config: KernelDnsConfig,
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    proxy_server: ProxyServerResolver,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    expires_at: Instant,
    addresses: Vec<SocketAddr>,
}

impl DnsResolver {
    pub fn new(config: KernelDnsConfig) -> Self {
        let proxy_server = ProxyServerResolver::new(config.clone());
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            proxy_server,
        }
    }

    pub async fn resolve(&self, target: &TargetAddress) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }
        if let Some(mapped) = self
            .config
            .hosts
            .iter()
            .find(|entry| entry.hostname.eq_ignore_ascii_case(&target.host))
        {
            let ip: IpAddr = mapped.address.parse()?;
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }
        let cache_key = format!("{}:{}", target.host.to_ascii_lowercase(), target.port);
        if let Some(entry) = self.cache.read().await.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.addresses.clone());
            }
        }
        let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await?
            .collect::<Vec<_>>();
        let addresses = if self.config.prefer_ipv6 {
            let mut sorted = addresses;
            sorted.sort_by_key(|addr| if addr.is_ipv6() { 0 } else { 1 });
            sorted
        } else {
            addresses
        };
        self.cache.write().await.insert(
            cache_key,
            DnsCacheEntry {
                expires_at: Instant::now() + DNS_CACHE_TTL,
                addresses: addresses.clone(),
            },
        );
        Ok(addresses)
    }

    pub async fn resolve_proxy_server(
        &self,
        target: &TargetAddress,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        self.proxy_server.resolve(target).await
    }
}

#[derive(Debug, Clone)]
pub struct ProxyServerResolver {
    config: KernelDnsConfig,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, ProxyDnsCacheEntry>>>,
}

#[derive(Debug, Clone)]
struct ProxyDnsCacheEntry {
    expires_at: Instant,
    addresses: Vec<SocketAddr>,
    source: String,
}

#[derive(Debug, Clone)]
struct BootstrapLookup {
    addresses: Vec<IpAddr>,
    ttl: Duration,
    source: String,
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: Option<u64>,
    data: String,
}

impl ProxyServerResolver {
    pub fn new(config: KernelDnsConfig) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(Duration::from_secs(6))
            .build()
            .expect("proxy server resolver HTTP client must build");
        Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn resolve(&self, target: &TargetAddress) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            let ip = normalize_ip(ip);
            if self.is_usable_ip(ip) {
                return Ok(vec![SocketAddr::new(ip, target.port)]);
            }
            anyhow::bail!("proxy server resolved to blocked address: {ip}");
        }
        if let Some(mapped) = self
            .config
            .hosts
            .iter()
            .find(|entry| entry.hostname.eq_ignore_ascii_case(&target.host))
        {
            let ip = normalize_ip(mapped.address.parse()?);
            if self.is_usable_ip(ip) {
                return Ok(vec![SocketAddr::new(ip, target.port)]);
            }
            anyhow::bail!("proxy server host mapping points to blocked address: {ip}");
        }

        let cache_key = format!("{}:{}", target.host.to_ascii_lowercase(), target.port);
        if let Some(entry) = self.cache.read().await.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                debug!(
                    host = %target.host,
                    source = %entry.source,
                    addresses = ?entry.addresses,
                    "proxy server DNS cache hit"
                );
                return Ok(entry.addresses.clone());
            }
        }

        let lookup = self.lookup_bootstrap(&target.host).await.or_else(|err| {
            warn!(host = %target.host, error = %err, "proxy bootstrap DNS failed; falling back to system DNS");
            self.lookup_system(&target.host)
        })?;
        let mut addresses = lookup
            .addresses
            .into_iter()
            .map(normalize_ip)
            .filter(|ip| self.is_usable_ip(*ip))
            .map(|ip| SocketAddr::new(ip, target.port))
            .collect::<Vec<_>>();
        sort_addresses(&mut addresses, self.config.prefer_ipv6);
        if addresses.is_empty() {
            anyhow::bail!("no usable proxy server address for {}", target.host);
        }

        self.cache.write().await.insert(
            cache_key,
            ProxyDnsCacheEntry {
                expires_at: Instant::now() + lookup.ttl,
                addresses: addresses.clone(),
                source: lookup.source.clone(),
            },
        );
        debug!(
            host = %target.host,
            ttl = lookup.ttl.as_secs(),
            source = %lookup.source,
            addresses = ?addresses,
            "proxy server resolved"
        );
        Ok(addresses)
    }

    async fn lookup_bootstrap(&self, host: &str) -> anyhow::Result<BootstrapLookup> {
        let mut last_error = None;
        for endpoint in self.bootstrap_endpoints() {
            match self.lookup_doh_endpoint(&endpoint, host).await {
                Ok(lookup) => return Ok(lookup),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no proxy bootstrap DNS endpoints")))
    }

    async fn lookup_doh_endpoint(
        &self,
        endpoint: &str,
        host: &str,
    ) -> anyhow::Result<BootstrapLookup> {
        let endpoint = endpoint.trim_end_matches('/');
        let url = if endpoint.ends_with("/resolve") {
            format!("{endpoint}?name={host}&type=A")
        } else {
            format!("{endpoint}?name={host}&type=A")
        };
        let response = self
            .client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await?
            .error_for_status()?
            .json::<DohResponse>()
            .await?;
        let mut ttl = DNS_CACHE_TTL;
        let addresses = response
            .answer
            .unwrap_or_default()
            .into_iter()
            .filter_map(|answer| {
                if answer.record_type != 1 {
                    return None;
                }
                if let Some(value) = answer.ttl {
                    ttl = normalize_ttl(value);
                }
                answer.data.parse::<IpAddr>().ok()
            })
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            anyhow::bail!("DoH endpoint returned no A records: {endpoint}");
        }
        Ok(BootstrapLookup {
            addresses,
            ttl,
            source: endpoint.to_string(),
        })
    }

    fn lookup_system(&self, host: &str) -> anyhow::Result<BootstrapLookup> {
        let addresses = std::net::ToSocketAddrs::to_socket_addrs(&(host, 0))?
            .map(|addr| addr.ip())
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            anyhow::bail!("system DNS returned no records");
        }
        Ok(BootstrapLookup {
            addresses,
            ttl: DNS_CACHE_TTL,
            source: "system-dns".to_string(),
        })
    }

    fn bootstrap_endpoints(&self) -> Vec<String> {
        if self.config.proxy_bootstrap_nameservers.is_empty() {
            return vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://1.0.0.1/dns-query".to_string(),
                "https://8.8.8.8/resolve".to_string(),
            ];
        }
        self.config.proxy_bootstrap_nameservers.clone()
    }

    fn is_usable_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => is_usable_ipv4(ip, &self.config.fake_ip_cidrs),
            IpAddr::V6(ip) => is_usable_ipv6(ip),
        }
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}

fn sort_addresses(addresses: &mut [SocketAddr], prefer_ipv6: bool) {
    addresses.sort_by_key(|addr| {
        if prefer_ipv6 {
            if addr.is_ipv6() {
                0
            } else {
                1
            }
        } else if addr.is_ipv4() {
            0
        } else {
            1
        }
    });
}

fn normalize_ttl(value: u64) -> Duration {
    Duration::from_secs(value)
        .max(MIN_PROXY_TTL)
        .min(MAX_PROXY_TTL)
}

fn is_usable_ipv4(ip: Ipv4Addr, fake_ip_cidrs: &[String]) -> bool {
    let octets = ip.octets();
    if ip.is_unspecified() || ip.is_link_local() || ip.is_broadcast() {
        return false;
    }
    for cidr in fake_ip_cidrs {
        if cidr == "198.18.0.0/15" && octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
            return false;
        }
    }
    true
}

fn is_usable_ipv6(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_unicast_link_local())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::KernelHostMapping;

    #[tokio::test]
    async fn host_mapping_resolves_without_system_lookup() {
        let resolver = DnsResolver::new(KernelDnsConfig {
            hosts: vec![KernelHostMapping {
                hostname: "local.test".to_string(),
                address: "127.0.0.1".to_string(),
            }],
            prefer_ipv6: false,
            ..KernelDnsConfig::default()
        });
        let result = resolver
            .resolve(&TargetAddress {
                host: "local.test".to_string(),
                port: 8080,
            })
            .await
            .unwrap();

        assert_eq!(result[0], "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn hostname_results_are_cached() {
        let resolver = DnsResolver::new(KernelDnsConfig::default());
        let target = TargetAddress {
            host: "localhost".to_string(),
            port: 8080,
        };

        let first = resolver.resolve(&target).await.unwrap();
        let second = resolver.resolve(&target).await.unwrap();

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn proxy_server_resolver_rejects_fake_ip_literals() {
        let resolver = DnsResolver::new(KernelDnsConfig::default());
        let err = resolver
            .resolve_proxy_server(&TargetAddress {
                host: "198.18.0.87".to_string(),
                port: 443,
            })
            .await
            .unwrap_err();

        assert!(err.to_string().contains("blocked address"));
    }
}
