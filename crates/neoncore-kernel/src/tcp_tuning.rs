use socket2::SockRef;
use tokio::net::TcpStream;

const TCP_BUFFER_SIZE: usize = 4 * 1024 * 1024;

pub fn tune_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let socket = SockRef::from(stream);
    let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
}
