use atlas_core::RoutingMode;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "atlas")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Connect {
        node: Option<String>,
    },
    Disconnect,
    Nodes,
    Import {
        url: String,
    },
    Mode {
        mode: ModeArg,
    },
    Logs,
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    Install,
    Start,
    Stop,
}

#[derive(Clone, ValueEnum)]
enum ModeArg {
    Global,
    Rule,
    Direct,
}

impl From<ModeArg> for RoutingMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Global => Self::Global,
            ModeArg::Rule => Self::Rule,
            ModeArg::Direct => Self::Direct,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let i18n = I18n::from_env();

    match cli.command {
        Command::Status => println!(
            "{}",
            i18n.tr(
                "cli-status-line",
                &[("status", i18n.tr("connection-status-disconnected", &[]))]
            )
        ),
        Command::Connect { node } => {
            if let Some(node) = node {
                println!("{}", i18n.tr("cli-connected", &[("node", node)]));
            } else {
                println!("{}", i18n.tr("cli-connected-default", &[]));
            }
        }
        Command::Disconnect => println!("{}", i18n.tr("cli-disconnected", &[])),
        Command::Nodes => println!("{}", i18n.tr("cli-no-nodes", &[])),
        Command::Import { url } => println!("{}", i18n.tr("cli-imported", &[("url", url)])),
        Command::Mode { mode } => {
            let mode: RoutingMode = mode.into();
            println!(
                "{}",
                i18n.tr("cli-mode-set", &[("mode", format!("{:?}", mode))])
            );
        }
        Command::Logs => println!("{}", i18n.tr("cli-logs-empty", &[])),
        Command::Service { command } => match command {
            ServiceCommand::Install => println!("{}", i18n.tr("cli-service-install", &[])),
            ServiceCommand::Start => println!("{}", i18n.tr("cli-service-start", &[])),
            ServiceCommand::Stop => println!("{}", i18n.tr("cli-service-stop", &[])),
        },
    }
    Ok(())
}

struct I18n {
    messages: HashMap<&'static str, &'static str>,
}

impl I18n {
    fn from_env() -> Self {
        let locale = std::env::var("ATLAS_LOCALE").unwrap_or_else(|_| "en-AU".to_string());
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
