//! Unprivileged UDP ASSOCIATE integration tests: the server runs in-process with marking
//! disabled (the default), except the mark-failure test, which needs marking to fail.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use fast_socks5::util::target_addr::TargetAddr;
use tokio::net::UdpSocket;

/// How long to wait before concluding a datagram was not relayed (loopback is instant).
const QUIET: Duration = Duration::from_millis(300);

const ANY4: &str = "0.0.0.0:0";

fn any4() -> TargetAddr {
    ip(ANY4.parse().unwrap())
}

/// A fresh client UDP socket on IPv4 loopback.
async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn round_trip(
    c: &UdpSocket,
    relay: SocketAddr,
    target: TargetAddr,
    msg: &[u8],
) -> TargetAddr {
    c.send_to(&encap(target, msg), relay).await.unwrap();
    let (src, payload) = recv_socks_udp(c, WAIT).await.expect("no reply relayed");
    assert_eq!(payload, msg);
    src
}

async fn assert_not_relayed(c: &UdpSocket, relay: SocketAddr, datagram: &[u8]) {
    c.send_to(datagram, relay).await.unwrap();
    assert!(
        recv_socks_udp(c, QUIET).await.is_none(),
        "must not be relayed"
    );
}

/// Wait until nothing is bound to `addr` any more (the relay socket was dropped).
async fn wait_until_released(addr: SocketAddr) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if UdpSocket::bind(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// `[::]:0` with IPV6_V6ONLY explicitly off, so it does not depend on `net.ipv6.bindv6only`.
fn dual_stack_udp_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
    sock.set_only_v6(false)?;
    sock.bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

#[tokio::test]
async fn ipv4_round_trip_with_encapsulated_reply() {
    let server = start(config()).await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    assert_eq!(
        relay.ip(),
        server.addr.ip(),
        "relay binds the IP the client reached"
    );
    assert_ne!(relay.port(), 0);

    let c = client().await;
    let src = round_trip(&c, relay, ip(echo), b"ping v4").await;
    assert_eq!(
        src,
        ip(echo),
        "reply header must carry the echo server's address"
    );
    let outbound = seen.recv().await.unwrap();
    assert_ne!(
        outbound, relay,
        "destination traffic leaves from a separate socket"
    );

    // A second datagram reuses the same outbound socket.
    round_trip(&c, relay, ip(echo), b"again").await;
    assert_eq!(seen.recv().await.unwrap(), outbound);
}

#[tokio::test]
async fn ipv6_destination() {
    let Ok((echo, _seen)) = udp_echo("[::1]:0").await else {
        println!("skipping: IPv6 loopback unavailable");
        return;
    };
    let server = start(config()).await;
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    assert_eq!(round_trip(&c, relay, ip(echo), b"ping v6").await, ip(echo));
}

#[tokio::test]
async fn domain_destination_localhost() {
    // Dual-stack echo, so it answers whichever address `localhost` resolves to first.
    let (echo, _seen) = match dual_stack_udp_socket() {
        Ok(sock) => udp_echo_on(sock).unwrap(),
        Err(_) => udp_echo("127.0.0.1:0").await.unwrap(),
    };
    let server = start(config()).await;
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    // The reply header echoes the requested name (ATYP=3), not the address it resolved to.
    let target = domain("localhost", echo.port());
    assert_eq!(
        round_trip(&c, relay, target.clone(), b"via dns").await,
        target
    );
}

#[tokio::test]
async fn domain_reply_header_uses_the_most_recent_name_for_an_address() {
    let (echo, _seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let server = start(marksocks::Config {
        dns: Some(
            fake_dns(vec![
                ("one.test", Rr::A([127, 0, 0, 1])),
                ("two.test", Rr::A([127, 0, 0, 1])),
            ])
            .await,
        ),
        ..config()
    })
    .await;
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    for target in [
        domain("one.test", echo.port()),
        domain("two.test", echo.port()),
        ip(echo),
        domain("one.test", echo.port()),
    ] {
        assert_eq!(round_trip(&c, relay, target.clone(), b"x").await, target);
    }
}

#[tokio::test]
async fn dns_resolve_false_drops_domain_datagrams() {
    let server = start(marksocks::Config {
        dns_resolve: false,
        ..config()
    })
    .await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;

    assert_not_relayed(&c, relay, &encap(domain("localhost", echo.port()), b"x")).await;
    assert!(seen.try_recv().is_err());
    round_trip(&c, relay, ip(echo), b"ip still works").await;
}

#[tokio::test]
async fn first_datagram_locks_the_client_port() {
    let server = start(config()).await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;

    let first = client().await;
    round_trip(&first, relay, ip(echo), b"locks").await;
    seen.recv().await.unwrap();

    let other = client().await;
    assert_not_relayed(&other, relay, &encap(ip(echo), b"intruder")).await;
    assert!(
        seen.try_recv().is_err(),
        "destination must not see the intruder"
    );

    round_trip(&first, relay, ip(echo), b"still mine").await;
}

#[tokio::test]
async fn requested_client_port_is_enforced_before_any_datagram() {
    let server = start(config()).await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let owner = client().await;
    let (_ctl, relay) = udp_associate(server.addr, ip(owner.local_addr().unwrap())).await;

    // Same IP, different port, and first to send: still not allowed (and does not lock).
    let other = client().await;
    assert_not_relayed(&other, relay, &encap(ip(echo), b"intruder")).await;
    assert!(seen.try_recv().is_err());

    round_trip(&owner, relay, ip(echo), b"owner").await;
}

#[tokio::test]
async fn replies_only_from_destinations_the_client_used() {
    let server = start(config()).await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    round_trip(&c, relay, ip(echo), b"hello").await;
    let outbound = seen.recv().await.unwrap();

    // Someone else sends to the outbound socket: not relayed back to the client.
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger.send_to(b"unsolicited", outbound).await.unwrap();
    assert!(recv_socks_udp(&c, QUIET).await.is_none());
}

#[tokio::test]
async fn fragmented_and_malformed_datagrams_are_dropped_without_ending_the_association() {
    let server = start(config()).await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;

    let mut fragment = encap(ip(echo), b"frag");
    fragment[2] = 1; // FRAG
    let mut bad_rsv = encap(ip(echo), b"rsv");
    bad_rsv[0] = 1;
    let mut bad_atyp = encap(ip(echo), b"atyp");
    bad_atyp[3] = 0x09;
    let truncated = &encap(ip(echo), b"")[..6];
    for datagram in [&fragment[..], &bad_rsv, &bad_atyp, truncated, &[]] {
        assert_not_relayed(&c, relay, datagram).await;
    }
    assert!(
        seen.try_recv().is_err(),
        "nothing may reach the destination"
    );

    round_trip(&c, relay, ip(echo), b"still alive").await;
}

#[tokio::test]
async fn closing_the_control_connection_ends_the_association() {
    let server = start(config()).await;
    let (echo, _seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    round_trip(&c, relay, ip(echo), b"before").await;

    drop(ctl);
    assert!(wait_until_released(relay).await, "relay socket still open");
    c.send_to(&encap(ip(echo), b"after"), relay).await.unwrap();
    assert!(recv_socks_udp(&c, QUIET).await.is_none());
}

#[tokio::test]
async fn idle_association_is_closed() {
    let idle = Duration::from_millis(400);
    let server = start(marksocks::Config {
        idle_timeout: idle,
        ..config()
    })
    .await;
    let (echo, _seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (mut ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;

    // Traffic more often than `idle` keeps it alive well past `idle`.
    for _ in 0..6 {
        round_trip(&c, relay, ip(echo), b"tick").await;
        tokio::time::sleep(idle / 4).await;
    }
    assert!(
        closed_without_data(&mut ctl).await,
        "control connection must be closed"
    );
    assert!(wait_until_released(relay).await);
}

#[tokio::test]
async fn failed_sends_do_not_keep_the_association_alive() {
    let idle = Duration::from_millis(400);
    let server = start(marksocks::Config {
        idle_timeout: idle,
        ..config()
    })
    .await;
    let (mut ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;
    // Broadcast without SO_BROADCAST: every send fails (EACCES) on Linux and macOS.
    let unsendable = encap(ip("255.255.255.255:9".parse().unwrap()), b"x");
    let started = tokio::time::Instant::now();
    let mut closed = false;
    while !closed && started.elapsed() < WAIT {
        c.send_to(&unsendable, relay).await.unwrap();
        let mut buf = [0u8; 1];
        closed = matches!(
            tokio::time::timeout(idle / 4, tokio::io::AsyncReadExt::read(&mut ctl, &mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
    }
    assert!(closed, "failed sends must not count as activity");
}

#[tokio::test]
async fn relay_follows_the_tcp_local_address() {
    let Ok(listener_v6) = tokio::net::TcpListener::bind("[::1]:0").await else {
        println!("skipping: IPv6 loopback unavailable");
        return;
    };
    drop(listener_v6);
    let server = start(marksocks::Config {
        listen: "[::1]:0".parse().unwrap(),
        ..config()
    })
    .await;
    let (echo, _seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    assert_eq!(relay.ip(), server.addr.ip());

    let c = UdpSocket::bind("[::1]:0").await.unwrap();
    assert_eq!(
        round_trip(&c, relay, ip(echo), b"v6 client").await,
        ip(echo)
    );
}

#[tokio::test]
async fn mark_failure_drops_datagrams() {
    if !marking_fails() {
        println!("skipping: SO_MARK can be set here; see the privileged mark tests");
        return;
    }
    let server = start(marksocks::Config {
        mark: Some(0x1000_0000),
        ..config()
    })
    .await;
    let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, any4()).await;
    let c = client().await;

    assert_not_relayed(&c, relay, &encap(ip(echo), b"must not leave unmarked")).await;
    assert!(
        seen.try_recv().is_err(),
        "destination must not see the datagram"
    );
}

/// Run `test` on a runtime with a single blocking thread that is kept busy until `test`
/// returns. `lookup_host` runs on that pool, so every DNS lookup the server starts hangs:
/// a deterministic "slow resolver".
fn with_stuck_dns<F: std::future::Future<Output = ()>>(test: impl FnOnce() -> F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        tokio::task::spawn_blocking(move || {
            let _ = stuck.recv();
        });
        test().await;
        drop(release);
    });
}

#[test]
fn closing_the_control_connection_interrupts_a_datagram_in_progress() {
    with_stuck_dns(|| async {
        let server = start(config()).await; // request_timeout 10s > WAIT
        let (echo, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
        let (ctl, relay) = udp_associate(server.addr, any4()).await;
        let c = client().await;
        round_trip(&c, relay, ip(echo), b"locks").await;
        seen.recv().await.unwrap();

        // Resolution of this one never finishes while the test runs.
        let late = encap(domain("localhost", echo.port()), b"late");
        c.send_to(&late, relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        drop(ctl);
        assert!(
            wait_until_released(relay).await,
            "association outlived its control connection"
        );
        assert!(
            seen.try_recv().is_err(),
            "nothing may be sent after the association ended"
        );
    });
}

#[test]
fn idle_timeout_interrupts_a_datagram_in_progress() {
    with_stuck_dns(|| async {
        let server = start(marksocks::Config {
            idle_timeout: Duration::from_millis(400),
            ..config()
        })
        .await;
        let (mut ctl, relay) = udp_associate(server.addr, any4()).await;
        let c = client().await;
        c.send_to(&encap(domain("localhost", 9), b"stuck"), relay)
            .await
            .unwrap();
        assert!(
            closed_without_data(&mut ctl).await,
            "idle timeout not enforced"
        );
        assert!(wait_until_released(relay).await);
    });
}

#[test]
fn flood_of_rejected_datagrams_does_not_starve_the_runtime() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let stop = Arc::new(AtomicBool::new(false));
    let (done, finished) = std::sync::mpsc::channel();
    let flag = stop.clone();
    // A single-threaded runtime: if the association never yields, nothing else runs, not even
    // its own TCP-close detection or the test's timers.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = start(config()).await;
            let owner = client().await;
            let (ctl, relay) = udp_associate(server.addr, ip(owner.local_addr().unwrap())).await;
            for _ in 0..4 {
                let flag = flag.clone();
                std::thread::spawn(move || {
                    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    while !flag.load(Ordering::Relaxed) {
                        let _ = s.send_to(b"rejected: wrong client port", relay);
                    }
                });
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(ctl);
            let released = wait_until_released(relay).await;
            let _ = done.send(released);
        });
    });
    let outcome = finished.recv_timeout(Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    assert_eq!(
        outcome,
        Ok(true),
        "association starved the runtime or outlived TCP"
    );
}
