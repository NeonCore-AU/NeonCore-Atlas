use clap::{Parser, Subcommand};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

mod adapter;
mod session;

use session::{KernelNode, KernelSession, TargetAddress};

#[derive(Parser)]
#[command(name = "neoncore-kernel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        session: PathBuf,
    },
    Check {
        #[arg(long)]
        session: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { session } => run(session),
        Command::Check { session } => {
            let session = read_session(session)?;
            validate_session(&session)?;
            println!("{}", serde_json::to_string_pretty(&session)?);
            Ok(())
        }
    }
}

fn run(path: PathBuf) -> anyhow::Result<()> {
    let session = read_session(path)?;
    validate_session(&session)?;
    let listener = TcpListener::bind((session.listen_host.as_str(), session.listen_port))?;
    listener.set_nonblocking(true)?;
    let running = Arc::new(AtomicBool::new(true));

    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let node = session.selected_node.clone();
                thread::spawn(move || {
                    let _ = handle_client(stream, node);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn read_session(path: PathBuf) -> anyhow::Result<KernelSession> {
    let data = std::fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

fn validate_session(session: &KernelSession) -> anyhow::Result<()> {
    if session.listen_host != "127.0.0.1" {
        anyhow::bail!("kernel currently only listens on loopback");
    }
    if session.selected_node.server.is_empty() || session.selected_node.server_port == 0 {
        anyhow::bail!("selected node endpoint is invalid");
    }
    adapter::validate_node(&session.selected_node)?;
    Ok(())
}

fn handle_client(mut client: TcpStream, node: KernelNode) -> anyhow::Result<()> {
    let mut header = [0_u8; 2];
    client.read_exact(&mut header)?;
    if header[0] == 0x05 {
        handle_socks5(client, header, node)
    } else {
        anyhow::bail!("unsupported inbound protocol");
    }
}

fn handle_socks5(mut client: TcpStream, header: [u8; 2], node: KernelNode) -> anyhow::Result<()> {
    let methods_len = header[1] as usize;
    let mut methods = vec![0_u8; methods_len];
    client.read_exact(&mut methods)?;
    client.write_all(&[0x05, 0x00])?;

    let mut request_head = [0_u8; 4];
    client.read_exact(&mut request_head)?;
    if request_head[1] != 0x01 {
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        anyhow::bail!("unsupported SOCKS command");
    }

    let target = read_socks_target(&mut client, request_head[3])?;
    let remote = adapter::connect(&node, &target)?;
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    proxy_bidirectional(client, remote)
}

fn read_socks_target(client: &mut TcpStream, atyp: u8) -> anyhow::Result<TargetAddress> {
    let host = match atyp {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets)?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0_u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0_u8; len[0] as usize];
            client.read_exact(&mut name)?;
            String::from_utf8(name)?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets)?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => anyhow::bail!("unsupported SOCKS address type"),
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)?;
    Ok(TargetAddress {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn proxy_bidirectional(mut left: TcpStream, mut right: TcpStream) -> anyhow::Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let upload = thread::spawn(move || std::io::copy(&mut left_reader, &mut right_writer));
    let download = std::io::copy(&mut right, &mut left);
    let _ = upload.join();
    download?;
    Ok(())
}
