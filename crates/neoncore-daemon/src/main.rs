use clap::{Parser, Subcommand};
use neoncore_api::HealthResponse;
use neoncore_engine::KernelEngine;
use std::{collections::HashMap, thread, time::Duration};

#[derive(Parser)]
#[command(name = "neoncore-daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run,
    Status,
    Health,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let i18n = I18n::from_env();
    match cli.command {
        Command::Run => run_daemon(&i18n)?,
        Command::Status => println!(
            "{}",
            i18n.tr(
                "daemon-status",
                &[("status", i18n.tr("connection-status-disconnected", &[]))]
            )
        ),
        Command::Health => {
            let health = HealthResponse {
                service: "neoncore-daemon".to_string(),
                healthy: true,
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&health)?);
            println!("{}", i18n.tr("daemon-health-ok", &[]));
        }
    }
    Ok(())
}

fn run_daemon(i18n: &I18n) -> anyhow::Result<()> {
    let _engine = KernelEngine::default();
    // Future IPC options:
    // - Unix domain socket on macOS/Linux.
    // - Named pipe on Windows.
    // - Optional localhost HTTP/gRPC for developer tooling later.
    println!(r#"{{"level":"info","target":"neoncore-daemon","event":"startup"}}"#);
    println!("{}", i18n.tr("daemon-running", &[]));
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

struct I18n {
    messages: HashMap<&'static str, &'static str>,
}

impl I18n {
    fn from_env() -> Self {
        let locale = std::env::var("NEONCORE_LOCALE").unwrap_or_else(|_| "en-AU".to_string());
        let source = match locale.as_str() {
            "zh-Hans" => include_str!("../locales/zh-Hans.ftl"),
            "en-XA" => include_str!("../locales/en-XA.ftl"),
            _ => include_str!("../locales/en-AU.ftl"),
        };
        Self {
            messages: parse_ftl(source),
        }
    }

    fn tr(&self, key: &str, vars: &[(&str, String)]) -> String {
        let mut value = self.messages.get(key).copied().unwrap_or(key).to_string();
        for (name, replacement) in vars {
            value = value.replace(&format!("{{ ${} }}", name), replacement);
        }
        value
    }
}

fn parse_ftl(source: &'static str) -> HashMap<&'static str, &'static str> {
    source
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .collect()
}
