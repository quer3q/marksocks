//! Shared helpers for in-process integration tests: run the server, speak raw SOCKS5 bytes.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fast_socks5::util::target_addr::{read_address, TargetAddr};
use marksocks::{Config, Credentials};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// Generous bound for anything a test waits on, so a broken server fails instead of hanging.
pub const WAIT: Duration = Duration::from_secs(5);

/// Defaults, but on an ephemeral loopback port.
pub fn config() -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..Config::default()
    }
}

pub fn creds(user: &str, pass: &str) -> Option<Credentials> {
    Some(Credentials {
        username: user.into(),
        password: pass.into(),
    })
}

pub struct Server {
    pub addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    pub done: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Trigger graceful shutdown; await `done` to see `serve` return.
    pub fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

pub async fn start(cfg: Config) -> Server {
    let listener = TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let done = tokio::spawn(marksocks::serve(listener, Arc::new(cfg), async {
        let _ = stopped.await;
    }));
    Server {
        addr,
        stop: Some(stop),
        done,
    }
}

/// Method negotiation offering only no-auth. Returns the selected method byte.
pub async fn greet_no_auth(s: &mut TcpStream) -> u8 {
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    reply[1]
}

/// Method negotiation offering only username/password, then RFC 1929 sub-negotiation.
/// Returns the auth status byte (0 = success).
pub async fn greet_password(s: &mut TcpStream, user: &str, pass: &str) -> u8 {
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2], "server should select username/password");
    let mut msg = vec![1, user.len() as u8];
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    s.write_all(&msg).await.unwrap();
    let mut status = [0u8; 2];
    s.read_exact(&mut status).await.unwrap();
    assert_eq!(status[0], 1);
    status[1]
}

/// Send a request and read the reply. Returns (REP, BND address).
pub async fn request(s: &mut TcpStream, cmd: u8, target: TargetAddr) -> (u8, TargetAddr) {
    let mut msg = vec![5, cmd, 0];
    msg.extend_from_slice(&target.to_be_bytes().unwrap());
    s.write_all(&msg).await.unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 5);
    let bnd = read_address(s, head[3]).await.unwrap();
    (head[1], bnd)
}

/// Connect to the proxy, negotiate no-auth and CONNECT to `target`.
pub async fn socks_connect(proxy: SocketAddr, target: TargetAddr) -> (TcpStream, u8, TargetAddr) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    assert_eq!(greet_no_auth(&mut s).await, 0);
    let (rep, bnd) = request(&mut s, CMD_CONNECT, target).await;
    (s, rep, bnd)
}

pub fn ip(addr: SocketAddr) -> TargetAddr {
    TargetAddr::Ip(addr)
}

pub fn domain(host: &str, port: u16) -> TargetAddr {
    TargetAddr::Domain(host.into(), port)
}

/// TCP echo server. Each accepted peer address is sent on the returned channel. Echoes until
/// EOF, then shuts down its write half (so half-close is observable end to end).
pub async fn echo_server(
    bind: &str,
) -> std::io::Result<(SocketAddr, mpsc::UnboundedReceiver<SocketAddr>)> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, peer)) = listener.accept().await {
            let _ = tx.send(peer);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    Ok((addr, rx))
}

/// True if the peer closed the connection (EOF or reset) within `WAIT`, having sent nothing.
pub async fn closed_without_data(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    match tokio::time::timeout(WAIT, s.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

/// True when setting SO_MARK fails here (always off Linux; on Linux without CAP_NET_ADMIN or,
/// since 5.17, CAP_NET_RAW).
pub fn marking_fails() -> bool {
    #[cfg(target_os = "linux")]
    {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        s.set_mark(1).is_err()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// UDP echo server. The source address of every datagram is sent on the returned channel.
pub async fn udp_echo(
    bind: &str,
) -> std::io::Result<(SocketAddr, mpsc::UnboundedReceiver<SocketAddr>)> {
    udp_echo_on(UdpSocket::bind(bind).await?)
}

/// `udp_echo` on an already bound socket.
pub fn udp_echo_on(
    sock: UdpSocket,
) -> std::io::Result<(SocketAddr, mpsc::UnboundedReceiver<SocketAddr>)> {
    let addr = sock.local_addr()?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = tx.send(src);
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    Ok((addr, rx))
}

/// Negotiate no-auth and UDP ASSOCIATE with `requested` as DST. Returns the control
/// connection and the relay address from the reply (asserting success).
pub async fn udp_associate(proxy: SocketAddr, requested: TargetAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    assert_eq!(greet_no_auth(&mut s).await, 0);
    let (rep, bnd) = request(&mut s, CMD_UDP_ASSOCIATE, requested).await;
    assert_eq!(rep, 0, "UDP ASSOCIATE must succeed");
    match bnd {
        TargetAddr::Ip(relay) => (s, relay),
        other => panic!("relay address must be an IP, got {other}"),
    }
}

/// SOCKS5 UDP request header (RSV, FRAG = 0, address) followed by `payload`.
pub fn encap(target: TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0, 0, 0];
    d.extend_from_slice(&target.to_be_bytes().unwrap());
    d.extend_from_slice(payload);
    d
}

/// The next datagram on `sock` within `wait`, decapsulated as (source, payload).
pub async fn recv_socks_udp(sock: &UdpSocket, wait: Duration) -> Option<(TargetAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 65_535];
    let (n, _) = tokio::time::timeout(wait, sock.recv_from(&mut buf))
        .await
        .ok()?
        .unwrap();
    let (frag, src, payload) = fast_socks5::parse_udp_request(&buf[..n]).await.unwrap();
    assert_eq!(frag, 0);
    Some((src, payload.to_vec()))
}
