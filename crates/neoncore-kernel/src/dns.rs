use crate::session::{KernelDnsConfig, TargetAddress};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct DnsResolver {
    config: KernelDnsConfig,
}

impl DnsResolver {
    pub fn new(config: KernelDnsConfig) -> Self {
        Self { config }
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
        let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await?
            .collect::<Vec<_>>();
        if self.config.prefer_ipv6 {
            let mut sorted = addresses;
            sorted.sort_by_key(|addr| if addr.is_ipv6() { 0 } else { 1 });
            return Ok(sorted);
        }
        Ok(addresses)
    }
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
}
