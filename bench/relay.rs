//! Benchmark: what the marksocks wrapper (and marking) cost vs. the bare fast-socks5
//! library, and a `direct` (no proxy) baseline.
//!
//! `harness = false`: this is a plain binary with its own `main`, not `#[bench]` functions
//! (libtest's bench harness is nightly-only and measures single operations, not relay
//! throughput/latency/round-trips with custom percentiles). Run with `cargo bench --locked`.
//!
//! Env overrides (all optional): `BENCH_TCP_MIB` (default 512), `BENCH_CONNECTS` (default
//! 1000), `BENCH_UDP_ROUNDS` (default 20000).
//!
//! External mode: set `MARKSOCKS_BENCH_PROXY=host:port` to a marksocks instance already
//! running elsewhere (e.g. on a router) and `MARKSOCKS_BENCH_TARGET_IP=<ip>` to an address
//! of *this* machine that proxy can reach. The in-process rows are skipped; only `direct`
//! and that one proxy are benched, and the echo/sink servers bind the unspecified address
//! of that IP's family (`0.0.0.0` for IPv4, `[::]` for IPv6) instead of loopback, so the
//! remote proxy can reach them.
//!
//! Rows: `direct` (no proxy), `fast-socks5` (the library's own plain server path, via
//! `run_tcp_proxy`/`run_udp_proxy` — a "pure library" reference; run with `nodelay=true` so
//! it is Nagle-comparable with `marksocks`'s own default, which also defaults to true — the
//! library's own default is false), `marksocks` (our `serve()`, `mark: None`),
//! `marksocks+mark` (`mark: Some(0x10000000)`, Linux only, skipped if a `set_mark` probe
//! fails for lack of CAP_NET_ADMIN/CAP_NET_RAW).
//!
//! Metrics: TCP throughput is measured as a bidirectional echo over a connection that is
//! already established (connect + SOCKS handshake happen before the timer starts) — the
//! client streams N MiB through to an echo sink and reads the same N MiB back concurrently;
//! MiB/s = N / elapsed (elapsed covers the full round trip, so this is a lower bound on
//! one-way throughput, not a doubled number). CONNECT latency is M sequential
//! connect+handshake+CONNECT+first-byte round trips (p50/p99 in microseconds, plus conn/s;
//! this is the one metric that *does* measure connect+handshake cost, deliberately). UDP is
//! K sequential request/response round trips through ASSOCIATE (round-trips/s, p50
//! microseconds, plus a lost count); each round trip has a 1s receive timeout so a dropped
//! datagram can't hang the bench forever — a row aborts with a clear message if losses
//! exceed 1% of its rounds. Every TCP wait (connect + SOCKS handshake, each transfer read or
//! write, each CONNECT round) is bounded by 10s without progress, so a stalled proxy (e.g. an
//! external one) aborts its row with a clear message instead of hanging the bench.

use std::env;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fast_socks5::server::{
    run_tcp_proxy, run_udp_proxy, DnsResolveHelper as _, Socks5ServerProtocol,
};
use fast_socks5::util::target_addr::{read_address, TargetAddr};
use fast_socks5::{ReplyError, Socks5Command};
use marksocks::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const UDP_PAYLOAD_LEN: usize = 64;
// ponytail: fixed chunk size for the throughput writer; not worth tuning per platform.
const CHUNK: usize = 64 * 1024;
/// How long a single UDP round trip waits for its reply before counting it as lost.
const UDP_RECV_TIMEOUT: Duration = Duration::from_secs(1);
/// A row aborts if more than this fraction of its timed UDP round trips are lost.
const MAX_UDP_LOSS_FRACTION: f64 = 0.01;
/// Bound on any single TCP wait: connect + SOCKS handshake, one transfer read/write, one
/// CONNECT round trip.
const TCP_STALL_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("building tokio runtime")
        .block_on(run());
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn run() {
    let tcp_mib = env_u64("BENCH_TCP_MIB", 512);
    let connects = env_u64("BENCH_CONNECTS", 1000);
    let udp_rounds = env_u64("BENCH_UDP_ROUNDS", 20_000);

    let mut rows = Vec::new();

    if let Ok(proxy) = env::var("MARKSOCKS_BENCH_PROXY") {
        let proxy_addr: SocketAddr = proxy
            .parse()
            .unwrap_or_else(|e| panic!("MARKSOCKS_BENCH_PROXY {proxy:?} must be host:port: {e}"));
        let target_ip: IpAddr = env::var("MARKSOCKS_BENCH_TARGET_IP")
            .unwrap_or_else(|_| {
                panic!(
                    "MARKSOCKS_BENCH_TARGET_IP is required when MARKSOCKS_BENCH_PROXY is set \
                     (an address of this machine the remote proxy can reach)"
                )
            })
            .parse()
            .unwrap_or_else(|e| panic!("MARKSOCKS_BENCH_TARGET_IP must be an IP address: {e}"));

        // Bind on the unspecified address of the target IP's family, so the remote proxy
        // (which only knows this machine by `target_ip`) can reach these servers.
        let bind_any = udp_any(SocketAddr::new(target_ip, 0));
        let (tcp_addr, _tcp) = echo_server(bind_any).await.expect("tcp echo bind");
        let (udp_addr, _udp) = udp_echo(bind_any).await.expect("udp echo bind");
        let tcp_target = SocketAddr::new(target_ip, tcp_addr.port());
        let udp_target = SocketAddr::new(target_ip, udp_addr.port());

        rows.push(
            bench_row(
                "direct", None, tcp_target, udp_target, tcp_mib, connects, udp_rounds,
            )
            .await,
        );
        rows.push(
            bench_row(
                "marksocks (external)",
                Some(proxy_addr),
                tcp_target,
                udp_target,
                tcp_mib,
                connects,
                udp_rounds,
            )
            .await,
        );
    } else {
        let (tcp_target, _tcp) = echo_server("127.0.0.1:0").await.expect("tcp echo bind");
        let (udp_target, _udp) = udp_echo("127.0.0.1:0").await.expect("udp echo bind");

        rows.push(
            bench_row(
                "direct", None, tcp_target, udp_target, tcp_mib, connects, udp_rounds,
            )
            .await,
        );

        let lib_addr = start_library_proxy().await;
        rows.push(
            bench_row(
                "fast-socks5",
                Some(lib_addr),
                tcp_target,
                udp_target,
                tcp_mib,
                connects,
                udp_rounds,
            )
            .await,
        );

        let ms_addr = start_marksocks(None).await;
        rows.push(
            bench_row(
                "marksocks",
                Some(ms_addr),
                tcp_target,
                udp_target,
                tcp_mib,
                connects,
                udp_rounds,
            )
            .await,
        );

        if mark_available() {
            let ms_marked_addr = start_marksocks(Some(0x1000_0000)).await;
            rows.push(
                bench_row(
                    "marksocks+mark",
                    Some(ms_marked_addr),
                    tcp_target,
                    udp_target,
                    tcp_mib,
                    connects,
                    udp_rounds,
                )
                .await,
            );
        } else {
            rows.push(RowResult {
                name: "marksocks+mark",
                metrics: None,
                note: Some("skipped (no CAP_NET_ADMIN/CAP_NET_RAW)".to_string()),
            });
        }
    }

    print_table(&rows, tcp_mib, connects, udp_rounds);
}

/// True when setting SO_MARK works here (always false off Linux; on Linux, false without
/// CAP_NET_ADMIN or, since 5.17, CAP_NET_RAW).
#[cfg(target_os = "linux")]
fn mark_available() -> bool {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    sock.set_mark(1).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn mark_available() -> bool {
    false
}

// ---- server setups ---------------------------------------------------------------------

/// TCP echo server: echoes until EOF, then shuts down its write half.
async fn echo_server(bind: &str) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut s, _peer)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    Ok((addr, handle))
}

/// UDP echo server: sends every received datagram back to its source.
async fn udp_echo(bind: &str) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    Ok((addr, handle))
}

/// The library's own plain server path: no marking, no config beyond its own defaults.
// ponytail: no connection cap, no shutdown — a benchmark process with a bounded lifetime.
async fn start_library_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("library proxy bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _peer)) = listener.accept().await else {
                continue;
            };
            // Match marksocks's default (nodelay=true on both the accepted client socket and
            // the outbound one, set on the latter via run_tcp_proxy's argument below).
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let _ = serve_library(socket).await;
            });
        }
    });
    addr
}

async fn serve_library(socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let (proto, cmd, target) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?
        .resolve_dns()
        .await?;
    match cmd {
        Socks5Command::TCPConnect => {
            // nodelay=true: Nagle-comparable with marksocks's own default (also true); the
            // library's own default is false. See the module doc comment.
            run_tcp_proxy(proto, &target, Duration::from_secs(10), true).await?;
        }
        Socks5Command::UDPAssociate => {
            run_udp_proxy(proto, &target, None, IpAddr::V4(Ipv4Addr::LOCALHOST), None).await?;
        }
        Socks5Command::TCPBind => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
        }
    }
    Ok(())
}

/// Our `serve()`, with default config except `mark`. Runs until the process exits.
async fn start_marksocks(mark: Option<u32>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("marksocks bind");
    let addr = listener.local_addr().unwrap();
    let cfg = Arc::new(Config {
        mark,
        ..Config::default()
    });
    tokio::spawn(marksocks::serve(listener, cfg, std::future::pending()));
    addr
}

// ---- SOCKS5 client-side helpers (hand-rolled bytes, cf. tests/common/mod.rs) -------------

async fn greet_no_auth(s: &mut TcpStream) -> io::Result<u8> {
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    Ok(reply[1])
}

/// Send a request and read the reply. Returns (REP, BND address).
async fn socks_request(
    s: &mut TcpStream,
    cmd: u8,
    target: TargetAddr,
) -> io::Result<(u8, TargetAddr)> {
    let mut msg = vec![5, cmd, 0];
    msg.extend_from_slice(
        &target
            .to_be_bytes()
            .map_err(|e| io::Error::other(e.to_string()))?,
    );
    s.write_all(&msg).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    let bnd = read_address(s, head[3])
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok((head[1], bnd))
}

/// SOCKS5 UDP request header (RSV, FRAG = 0, address) followed by `payload`.
fn encap(target: TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0, 0, 0];
    d.extend_from_slice(&target.to_be_bytes().expect("encode target"));
    d.extend_from_slice(payload);
    d
}

fn udp_any(like: SocketAddr) -> &'static str {
    if like.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
}

/// A `UDP_PAYLOAD_LEN`-byte UDP test payload carrying `seq` in its first 8 bytes, so a
/// round can tell its own reply apart from a late or duplicate one for a different round.
fn seq_payload(seq: u64) -> [u8; UDP_PAYLOAD_LEN] {
    let mut p = [0xABu8; UDP_PAYLOAD_LEN];
    p[..8].copy_from_slice(&seq.to_be_bytes());
    p
}

/// `payload`'s leading sequence number, if it's long enough to carry one.
fn payload_seq(payload: &[u8]) -> Option<u64> {
    payload
        .get(..8)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

/// Open a stream ready for data: directly to `target` when `proxy` is `None`, or through a
/// no-auth CONNECT when it is `Some`.
async fn open_tcp(proxy: Option<SocketAddr>, target: SocketAddr) -> io::Result<TcpStream> {
    match proxy {
        None => TcpStream::connect(target).await,
        Some(proxy) => {
            let mut s = TcpStream::connect(proxy).await?;
            let method = greet_no_auth(&mut s).await?;
            if method != 0 {
                return Err(io::Error::other(format!("server selected method {method}")));
            }
            let (rep, _bnd) = socks_request(&mut s, CMD_CONNECT, TargetAddr::Ip(target)).await?;
            if rep != 0 {
                return Err(io::Error::other(format!("CONNECT failed: REP={rep}")));
            }
            Ok(s)
        }
    }
}

// ---- measurements -----------------------------------------------------------------------

/// `fut` bounded by `TCP_STALL_TIMEOUT`; any failure becomes a row-abort message.
async fn bounded<T>(what: &str, fut: impl Future<Output = io::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(TCP_STALL_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!(
            "{what}: stalled (no progress for {}s)",
            TCP_STALL_TIMEOUT.as_secs()
        )),
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Transfer `mib` MiB through an already-open, already-handshaken stream. Connection setup
/// (TCP connect + SOCKS negotiation, for proxied rows) happens before this is called, so it
/// is not included in whatever timer wraps it.
async fn echo_transfer(stream: TcpStream, mib: u64) -> Result<(), String> {
    let (mut r, mut w) = stream.into_split();
    let total = mib * 1024 * 1024;
    let writer = tokio::spawn(async move {
        let chunk = vec![0xCDu8; CHUNK];
        let mut sent = 0u64;
        while sent < total {
            let n = (total - sent).min(chunk.len() as u64) as usize;
            bounded("tcp write", w.write_all(&chunk[..n])).await?;
            sent += n as u64;
        }
        bounded("tcp shutdown", w.shutdown()).await
    });
    let mut buf = vec![0u8; CHUNK];
    let mut received = 0u64;
    while received < total {
        let n = match bounded("tcp read", r.read(&mut buf)).await {
            Ok(n) => n,
            Err(e) => {
                writer.abort();
                return Err(e);
            }
        };
        if n == 0 {
            break;
        }
        received += n as u64;
    }
    writer.await.map_err(|e| format!("writer task: {e}"))??;
    if received != total {
        return Err(format!("echoed {received} of {total} bytes"));
    }
    Ok(())
}

/// Bidirectional-echo throughput: client streams `mib` MiB through to an echo sink and
/// reads the same amount back concurrently. Reports MiB/s = mib / elapsed, where `elapsed`
/// covers only the transfer: the connection (TCP connect + SOCKS handshake, for proxied
/// rows) is established beforehand and excluded from the timer.
async fn tcp_throughput_mib_s(
    proxy: Option<SocketAddr>,
    target: SocketAddr,
    mib: u64,
) -> Result<f64, String> {
    let warmup_stream = bounded("tcp setup (warm-up)", open_tcp(proxy, target)).await?;
    echo_transfer(warmup_stream, mib.clamp(1, 4)).await?; // warm-up

    let stream = bounded("tcp setup", open_tcp(proxy, target)).await?;
    let start = Instant::now();
    echo_transfer(stream, mib).await?;
    Ok(mib as f64 / start.elapsed().as_secs_f64())
}

async fn one_connect(proxy: Option<SocketAddr>, target: SocketAddr) -> io::Result<()> {
    let mut s = open_tcp(proxy, target).await?;
    s.write_all(b"x").await?;
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(())
}

/// `rounds` sequential connect+handshake+CONNECT+first-byte round trips.
/// Returns (p50 us, p99 us, conn/s).
async fn connect_latency(
    proxy: Option<SocketAddr>,
    target: SocketAddr,
    rounds: u64,
) -> Result<(f64, f64, f64), String> {
    let warmup = rounds.min(50);
    for _ in 0..warmup {
        bounded("warm-up connect", one_connect(proxy, target)).await?;
    }
    let mut samples = Vec::with_capacity(rounds as usize);
    let start_all = Instant::now();
    for _ in 0..rounds {
        let t0 = Instant::now();
        bounded("connect round", one_connect(proxy, target)).await?;
        samples.push(t0.elapsed());
    }
    let elapsed_all = start_all.elapsed();
    samples.sort();
    let p50 = percentile(&samples, 0.50).as_micros() as f64;
    let p99 = percentile(&samples, 0.99).as_micros() as f64;
    Ok((p50, p99, rounds as f64 / elapsed_all.as_secs_f64()))
}

/// `Err` if more than `MAX_UDP_LOSS_FRACTION` of `rounds` timed round trips were lost.
fn check_udp_loss(lost: u64, rounds: u64) -> Result<(), String> {
    if rounds > 0 && lost as f64 / rounds as f64 > MAX_UDP_LOSS_FRACTION {
        Err(format!(
            "{lost}/{rounds} UDP round trips lost (over {:.0}%) — aborting this row",
            MAX_UDP_LOSS_FRACTION * 100.0
        ))
    } else {
        Ok(())
    }
}

/// One round trip with a receive timeout. `seq` identifies this round's own payload, so a
/// stale reply to an earlier (e.g. timed-out) round is discarded rather than mistakenly
/// satisfying this one. `Ok(Some(elapsed))` on success; `Ok(None)` if no matching reply
/// arrived within `UDP_RECV_TIMEOUT` (counted as lost by the caller — on a live network this
/// can be an ordinary dropped datagram, not necessarily a failure). `Err` only for an actual
/// send/recv failure (e.g. route gone, relay closed) — those abort the row rather than
/// retrying forever or panicking.
async fn udp_direct_round(
    sock: &UdpSocket,
    target: SocketAddr,
    buf: &mut [u8],
    seq: u64,
) -> Result<Option<Duration>, String> {
    let payload = seq_payload(seq);
    let t0 = Instant::now();
    let round = async {
        sock.send_to(&payload, target)
            .await
            .map_err(|e| e.to_string())?;
        loop {
            let (n, _src) = sock.recv_from(buf).await.map_err(|e| e.to_string())?;
            if payload_seq(&buf[..n]) == Some(seq) {
                return Ok::<(), String>(());
            }
            // Stale or unrelated reply (e.g. a late answer to a timed-out round): discard
            // and keep waiting for this round's own reply within its deadline.
        }
    };
    match tokio::time::timeout(UDP_RECV_TIMEOUT, round).await {
        Ok(Ok(())) => Ok(Some(t0.elapsed())),
        Ok(Err(e)) => Err(format!("udp round trip: {e}")),
        Err(_) => Ok(None),
    }
}

/// Returns (round-trips/s, p50 us, lost count) over the successfully completed round trips.
async fn udp_direct(target: SocketAddr, rounds: u64) -> Result<(f64, f64, u64), String> {
    let sock = UdpSocket::bind(udp_any(target))
        .await
        .map_err(|e| format!("udp client bind: {e}"))?;
    let mut buf = vec![0u8; 65_535];
    let mut seq = 0u64;
    let warmup = rounds.min(200);
    for _ in 0..warmup {
        // Warm-up: a real send/recv failure still aborts the row; a lone timeout doesn't.
        udp_direct_round(&sock, target, &mut buf, seq).await?;
        seq += 1;
    }
    let mut samples = Vec::with_capacity(rounds as usize);
    let mut lost = 0u64;
    let start_all = Instant::now();
    for _ in 0..rounds {
        match udp_direct_round(&sock, target, &mut buf, seq).await? {
            Some(elapsed) => samples.push(elapsed),
            None => lost += 1,
        }
        seq += 1;
    }
    let elapsed_all = start_all.elapsed();
    check_udp_loss(lost, rounds)?;
    samples.sort();
    let p50 = percentile(&samples, 0.50).as_micros() as f64;
    let completed = rounds - lost;
    Ok((completed as f64 / elapsed_all.as_secs_f64(), p50, lost))
}

/// One round trip with a receive timeout, as `udp_direct_round` but through the relay (and
/// also erroring on a malformed/undecodable reply, not just a send/recv failure).
async fn udp_proxied_round(
    sock: &UdpSocket,
    relay: SocketAddr,
    target: SocketAddr,
    buf: &mut [u8],
    seq: u64,
) -> Result<Option<Duration>, String> {
    let datagram = encap(TargetAddr::Ip(target), &seq_payload(seq));
    let t0 = Instant::now();
    let round = async {
        sock.send_to(&datagram, relay)
            .await
            .map_err(|e| e.to_string())?;
        loop {
            let n = sock.recv(buf).await.map_err(|e| e.to_string())?;
            let (_frag, _src, payload) = fast_socks5::parse_udp_request(&buf[..n])
                .await
                .map_err(|e| e.to_string())?;
            if payload_seq(payload) == Some(seq) {
                return Ok::<(), String>(());
            }
            // Stale or unrelated reply: discard and keep waiting (see udp_direct_round).
        }
    };
    match tokio::time::timeout(UDP_RECV_TIMEOUT, round).await {
        Ok(Ok(())) => Ok(Some(t0.elapsed())),
        Ok(Err(e)) => Err(format!("udp round trip: {e}")),
        Err(_) => Ok(None),
    }
}

/// `rounds` sequential request/response round trips through UDP ASSOCIATE.
/// Returns (round-trips/s, p50 us, lost count) over the successfully completed round trips.
async fn udp_proxied(
    proxy: SocketAddr,
    target: SocketAddr,
    rounds: u64,
) -> Result<(f64, f64, u64), String> {
    let unspecified = if target.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let setup = async {
        let mut ctl = TcpStream::connect(proxy).await?;
        let method = greet_no_auth(&mut ctl).await?;
        if method != 0 {
            return Err(io::Error::other(format!("server selected method {method}")));
        }
        let (rep, bnd) =
            socks_request(&mut ctl, CMD_UDP_ASSOCIATE, TargetAddr::Ip(unspecified)).await?;
        if rep != 0 {
            return Err(io::Error::other(format!("REP={rep}")));
        }
        Ok((ctl, bnd))
    };
    let (ctl, bnd) = bounded("UDP ASSOCIATE setup", setup).await?;
    let relay = match bnd {
        TargetAddr::Ip(addr) => addr,
        other => panic!("relay address must be an IP, got {other}"),
    };

    let sock = UdpSocket::bind(udp_any(relay))
        .await
        .map_err(|e| format!("udp client bind: {e}"))?;
    let mut buf = vec![0u8; 65_535];
    let mut seq = 0u64;

    let warmup = rounds.min(200);
    for _ in 0..warmup {
        // Warm-up: a real send/recv/decode failure still aborts the row; a timeout doesn't.
        udp_proxied_round(&sock, relay, target, &mut buf, seq).await?;
        seq += 1;
    }
    let mut samples = Vec::with_capacity(rounds as usize);
    let mut lost = 0u64;
    let start_all = Instant::now();
    for _ in 0..rounds {
        match udp_proxied_round(&sock, relay, target, &mut buf, seq).await? {
            Some(elapsed) => samples.push(elapsed),
            None => lost += 1,
        }
        seq += 1;
    }
    let elapsed_all = start_all.elapsed();
    drop(ctl); // keep the association alive until all rounds are done
    check_udp_loss(lost, rounds)?;
    samples.sort();
    let p50 = percentile(&samples, 0.50).as_micros() as f64;
    let completed = rounds - lost;
    Ok((completed as f64 / elapsed_all.as_secs_f64(), p50, lost))
}

async fn udp_round_trips(
    proxy: Option<SocketAddr>,
    target: SocketAddr,
    rounds: u64,
) -> Result<(f64, f64, u64), String> {
    match proxy {
        None => udp_direct(target, rounds).await,
        Some(proxy) => udp_proxied(proxy, target, rounds).await,
    }
}

// ---- row orchestration and reporting -----------------------------------------------------

struct Metrics {
    tcp_mib_s: f64,
    p50_us: f64,
    p99_us: f64,
    conn_per_s: f64,
    udp_rt_per_s: f64,
    udp_p50_us: f64,
    udp_lost: u64,
}

struct RowResult {
    name: &'static str,
    metrics: Option<Metrics>,
    note: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn bench_row(
    name: &'static str,
    proxy: Option<SocketAddr>,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
    tcp_mib: u64,
    connects: u64,
    udp_rounds: u64,
) -> RowResult {
    // A stalled TCP wait or a lossy UDP path aborts just this row (with a clear message)
    // rather than hanging or panicking the whole bench; its other numbers are discarded.
    let measured = async {
        let tcp_mib_s = tcp_throughput_mib_s(proxy, tcp_target, tcp_mib).await?;
        let (p50_us, p99_us, conn_per_s) = connect_latency(proxy, tcp_target, connects).await?;
        let (udp_rt_per_s, udp_p50_us, udp_lost) =
            udp_round_trips(proxy, udp_target, udp_rounds).await?;
        Ok::<_, String>(Metrics {
            tcp_mib_s,
            p50_us,
            p99_us,
            conn_per_s,
            udp_rt_per_s,
            udp_p50_us,
            udp_lost,
        })
    };
    match measured.await {
        Ok(metrics) => RowResult {
            name,
            metrics: Some(metrics),
            note: None,
        },
        Err(e) => RowResult {
            name,
            metrics: None,
            note: Some(format!("aborted: {e}")),
        },
    }
}

fn print_table(rows: &[RowResult], tcp_mib: u64, connects: u64, udp_rounds: u64) {
    println!(
        "TCP: {tcp_mib} MiB bidirectional echo, timed after connect+handshake. CONNECT: \
         {connects} sequential round trips. UDP: {udp_rounds} sequential round trips, 1s \
         per-round timeout.\n"
    );
    println!(
        "{:<22} {:>10} {:>10} {:>10} {:>10} {:>12} {:>12} {:>9}",
        "row", "tcp MiB/s", "p50 us", "p99 us", "conn/s", "udp rt/s", "udp p50 us", "udp lost"
    );
    for row in rows {
        match &row.metrics {
            Some(m) => println!(
                "{:<22} {:>10.1} {:>10.0} {:>10.0} {:>10.0} {:>12.0} {:>12.0} {:>9}",
                row.name,
                m.tcp_mib_s,
                m.p50_us,
                m.p99_us,
                m.conn_per_s,
                m.udp_rt_per_s,
                m.udp_p50_us,
                m.udp_lost
            ),
            None => println!(
                "{:<22} {}",
                row.name,
                row.note.as_deref().unwrap_or("skipped")
            ),
        }
    }
}
