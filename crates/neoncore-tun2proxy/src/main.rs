use clap::Parser;
use std::{net::IpAddr, str::FromStr};
use tokio_util::sync::CancellationToken;
use tproxy_config::IpCidr;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args};

#[derive(Debug, Parser)]
#[command(name = "neoncore-tun2proxy")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    proxy_host: String,
    #[arg(long)]
    proxy_port: u16,
    #[arg(long)]
    tun_name: Option<String>,
    #[arg(long, default_value_t = true)]
    setup_routes: bool,
    #[arg(long, default_value_t = true)]
    ipv6: bool,
    #[arg(long, default_value = "over-tcp")]
    dns: DnsMode,
    #[arg(long, default_value = "1.1.1.1")]
    dns_addr: IpAddr,
    #[arg(long, default_value_t = 1500)]
    mtu: u16,
    #[arg(long)]
    bypass: Vec<IpCidr>,
    #[arg(long, default_value_t = 512)]
    max_sessions: usize,
    #[arg(long, default_value = "info")]
    verbosity: ArgVerbosity,
}

#[derive(Clone, Copy, Debug)]
enum DnsMode {
    Direct,
    OverTcp,
    Virtual,
}

impl FromStr for DnsMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(Self::Direct),
            "over-tcp" => Ok(Self::OverTcp),
            "virtual" => Ok(Self::Virtual),
            other => anyhow::bail!("unsupported DNS mode: {other}"),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let proxy =
        ArgProxy::try_from(format!("socks5://{}:{}", cli.proxy_host, cli.proxy_port).as_str())
            .map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut args = Args::default();
    args.proxy(proxy)
        .setup(cli.setup_routes)
        .ipv6_enabled(cli.ipv6)
        .dns(match cli.dns {
            DnsMode::Direct => ArgDns::Direct,
            DnsMode::OverTcp => ArgDns::OverTcp,
            DnsMode::Virtual => ArgDns::Virtual,
        })
        .dns_addr(cli.dns_addr)
        .verbosity(cli.verbosity);
    args.mtu = cli.mtu;
    args.max_sessions = cli.max_sessions;
    if let Some(tun_name) = cli.tun_name {
        args.tun(tun_name);
    }
    for bypass in cli.bypass {
        args.bypass(bypass);
    }

    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });

    log::info!(
        "starting NeonCore TUN bridge: proxy={}:{}, setup_routes={}, ipv6={}",
        cli.proxy_host,
        cli.proxy_port,
        cli.setup_routes,
        cli.ipv6
    );
    tun2proxy::general_run_async(args, cli.mtu, cfg!(target_os = "macos"), shutdown).await?;
    Ok(())
}
