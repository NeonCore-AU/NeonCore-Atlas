use serde_json::json;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
struct StrictSsrCase {
    protocol: &'static str,
    obfs: &'static str,
    method: &'static str,
}

const STRICT_CONTAINER_PORT: u16 = 10002;
const STRICT_PASSWORD: &str = "neoncore-password";
const STRICT_PROTOCOL_PARAM: &str = "42:neoncore";
const STRICT_OBFS_PARAM: &str = "strict.neoncore.test";

const STRICT_PROTOCOLS: &[&str] = &[
    "origin",
    "verify_simple",
    "verify_sha1",
    "auth_simple",
    "auth_sha1",
    "auth_sha1_v2",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
    "auth_chain_c",
    "auth_chain_d",
    "auth_chain_e",
    "auth_chain_f",
];

const STRICT_OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

const STRICT_METHODS: &[&str] = &[
    "none",
    "rc4-md5",
    "aes-128-cfb",
    "aes-256-cfb",
    "chacha20-ietf",
];

fn strict_cases() -> Vec<StrictSsrCase> {
    let mut cases = Vec::new();
    for protocol in STRICT_PROTOCOLS {
        for obfs in STRICT_OBFS {
            for method in STRICT_METHODS {
                cases.push(StrictSsrCase {
                    protocol,
                    obfs,
                    method,
                });
            }
        }
    }
    cases
}

#[test]
fn ssr_strict_matrix_covers_all_native_protocol_and_obfs_names() {
    let cases = strict_cases();
    for protocol in STRICT_PROTOCOLS {
        assert!(
            cases.iter().any(|case| case.protocol == *protocol),
            "missing strict SSR protocol case for {protocol}"
        );
    }
    for obfs in STRICT_OBFS {
        assert!(
            cases.iter().any(|case| case.obfs == *obfs),
            "missing strict SSR obfs case for {obfs}"
        );
    }
    for method in STRICT_METHODS {
        assert!(
            cases.iter().any(|case| case.method == *method),
            "missing strict SSR method case for {method}"
        );
    }
}

#[test]
#[ignore = "requires Docker and a strict SSR server image declared by NEONCORE_SSR_STRICT_IMAGE"]
fn docker_strict_server_matrix_interop() {
    let image = env::var("NEONCORE_SSR_STRICT_IMAGE")
        .expect("NEONCORE_SSR_STRICT_IMAGE must point at a strict SSR server image");
    assert!(docker_available(), "Docker daemon is not available");

    let cases = strict_cases();
    let limit = env::var("NEONCORE_SSR_STRICT_CASE_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(cases.len())
        .min(cases.len());

    for (index, case) in cases.into_iter().take(limit).enumerate() {
        run_strict_interop_case(index, case, &image);
    }
}

fn run_strict_interop_case(index: usize, case: StrictSsrCase, image: &str) {
    let target_listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|err| panic!("failed to bind strict target echo server: {err}"));
    let target_port = target_listener
        .local_addr()
        .expect("strict target listener has no local address")
        .port();
    let echo_thread = thread::spawn(move || {
        let (mut stream, _) = target_listener
            .accept()
            .expect("strict target echo server failed to accept");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .expect("strict target echo server failed to read");
        assert_eq!(&request, b"ping");
        stream
            .write_all(b"pong")
            .expect("strict target echo server failed to write");
    });

    let container_name = format!("neoncore-ssr-strict-{}-{index}", std::process::id());
    let _container = StrictContainer::start(&container_name, image, case);
    let server_port = wait_for_container_port(&container_name, STRICT_CONTAINER_PORT)
        .unwrap_or_else(|| {
            panic!("strict SSR container did not publish port {STRICT_CONTAINER_PORT}")
        });

    let kernel_port = pick_free_tcp_port();
    let session_path = write_kernel_session(case, server_port, kernel_port);
    let mut kernel = StrictKernel::start(&session_path);
    wait_for_tcp_port(kernel_port)
        .unwrap_or_else(|| panic!("neoncore-kernel did not listen on port {kernel_port}"));

    let result = socks5_connect_and_echo(kernel_port, "host.docker.internal", target_port);
    if let Err(err) = result {
        let stderr = kernel.stop_and_take_stderr();
        panic!("strict SSR interop case failed {case:?}: {err}\nkernel stderr:\n{stderr}");
    }
    echo_thread
        .join()
        .expect("strict target echo server thread panicked");
}

struct StrictContainer {
    name: String,
}

impl StrictContainer {
    fn start(name: &str, image: &str, case: StrictSsrCase) -> Self {
        let mut command = Command::new("docker");
        command
            .arg("run")
            .arg("-d")
            .arg("--rm")
            .arg("--pull=never")
            .arg("--name")
            .arg(name)
            .arg("-p")
            .arg(format!("127.0.0.1::{STRICT_CONTAINER_PORT}"))
            .arg("--add-host")
            .arg("host.docker.internal:host-gateway")
            .arg("-e")
            .arg("SSR_LISTEN=0.0.0.0")
            .arg("-e")
            .arg(format!("SSR_PORT={STRICT_CONTAINER_PORT}"))
            .arg("-e")
            .arg(format!("SSR_PASSWORD={STRICT_PASSWORD}"))
            .arg("-e")
            .arg(format!("SSR_METHOD={}", case.method))
            .arg("-e")
            .arg(format!("SSR_PROTOCOL={}", case.protocol))
            .arg("-e")
            .arg(format!("SSR_PROTOCOL_PARAM={STRICT_PROTOCOL_PARAM}"))
            .arg("-e")
            .arg(format!("SSR_OBFS={}", case.obfs))
            .arg("-e")
            .arg(format!("SSR_OBFS_PARAM={STRICT_OBFS_PARAM}"))
            .arg(image);

        let entry =
            env::var("NEONCORE_SSR_STRICT_COMMAND").unwrap_or_else(|_| "strict-server".to_string());
        command.args(entry.split_whitespace());

        let output = command
            .output()
            .unwrap_or_else(|err| panic!("failed to start strict SSR container {name}: {err}"));
        assert!(
            output.status.success(),
            "strict SSR container failed to start {name}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            name: name.to_string(),
        }
    }
}

impl Drop for StrictContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct StrictKernel {
    child: Child,
}

impl StrictKernel {
    fn start(session_path: &PathBuf) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_neoncore-kernel"))
            .arg("run")
            .arg("--session")
            .arg(session_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to start neoncore-kernel: {err}"));
        Self { child }
    }

    fn stop_and_take_stderr(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let Some(mut stderr) = self.child.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    }
}

impl Drop for StrictKernel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_for_container_port(name: &str, container_port: u16) -> Option<u16> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let output = Command::new("docker")
            .arg("port")
            .arg(name)
            .arg(format!("{container_port}/tcp"))
            .output()
            .ok()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(port) = stdout
                .lines()
                .filter_map(|line| line.rsplit_once(':'))
                .filter_map(|(_, port)| port.trim().parse::<u16>().ok())
                .next()
            {
                return Some(port);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

fn pick_free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to pick a free local TCP port")
        .local_addr()
        .expect("free TCP listener has no local address")
        .port()
}

fn wait_for_tcp_port(port: u16) -> Option<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn write_kernel_session(case: StrictSsrCase, server_port: u16, kernel_port: u16) -> PathBuf {
    let session = json!({
        "listen_host": "127.0.0.1",
        "listen_port": kernel_port,
        "selected_node": {
            "id": "strict-ssr",
            "protocol": "ssr",
            "server": "127.0.0.1",
            "server_port": server_port,
            "user_id": STRICT_PASSWORD,
            "parameters": {
                "method": case.method,
                "protocol": case.protocol,
                "protocol_param": STRICT_PROTOCOL_PARAM,
                "obfs": case.obfs,
                "obfs_param": STRICT_OBFS_PARAM
            }
        },
        "dns": {
            "hosts": [],
            "prefer_ipv6": false,
            "proxy_bootstrap_nameservers": ["system"],
            "fake_ip_cidrs": ["198.18.0.0/15"]
        }
    });
    let path = env::temp_dir().join(format!(
        "neoncore-ssr-strict-{}-{}-{}-{}.json",
        std::process::id(),
        case.protocol,
        case.obfs,
        case.method
    ));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&session).expect("strict session JSON should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write strict kernel session: {err}"));
    path
}

fn socks5_connect_and_echo(kernel_port: u16, host: &str, port: u16) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", kernel_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;

    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response)?;
    if response != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 greeting failed: {response:?}"),
        ));
    }

    let host_bytes = host.as_bytes();
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    read_socks5_connect_response(&mut stream)?;
    stream.write_all(b"ping")?;
    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply)?;
    if &reply != b"pong" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unexpected echo reply: {reply:?}"),
        ));
    }
    Ok(())
}

fn read_socks5_connect_response(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 connect failed: {header:?}"),
        ));
    }
    match header[3] {
        0x01 => {
            let mut skip = [0_u8; 6];
            stream.read_exact(&mut skip)?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut skip = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut skip)?;
        }
        0x04 => {
            let mut skip = [0_u8; 18];
            stream.read_exact(&mut skip)?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("invalid SOCKS5 bind address type: {other}"),
            ));
        }
    }
    Ok(())
}
