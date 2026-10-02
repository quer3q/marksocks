//! Unprivileged TCP integration tests: the server runs in-process with marking disabled
//! (the default), except the mark-failure test, which needs marking to fail.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

async fn assert_echo(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    timeout(WAIT, s.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf, msg);
}

#[tokio::test]
async fn connect_ipv4_relays_and_replies_with_outbound_local_addr() {
    let server = start(config()).await;
    let (echo, mut peers) = echo_server("127.0.0.1:0").await.unwrap();

    let (mut s, rep, bnd) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);
    let seen_by_destination = timeout(WAIT, peers.recv()).await.unwrap().unwrap();
    assert_eq!(
        bnd,
        ip(seen_by_destination),
        "BND must be the outbound local address"
    );
    assert_echo(&mut s, b"hello over ipv4").await;
}

#[tokio::test]
async fn connect_ipv6() {
    let Ok((echo, mut peers)) = echo_server("[::1]:0").await else {
        println!("skipping: IPv6 loopback unavailable");
        return;
    };
    let server = start(config()).await;

    let (mut s, rep, bnd) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);
    assert_eq!(bnd, ip(timeout(WAIT, peers.recv()).await.unwrap().unwrap()));
    assert_echo(&mut s, b"hello over ipv6").await;
}

#[tokio::test]
async fn connect_domain_localhost() {
    let server = start(config()).await;
    let (echo, mut peers) = echo_server("127.0.0.1:0").await.unwrap();

    // localhost may resolve to ::1 first (nothing listens there): the next address is tried.
    let (mut s, rep, bnd) = socks_connect(server.addr, domain("localhost", echo.port())).await;
    assert_eq!(rep, 0);
    assert_eq!(bnd, ip(timeout(WAIT, peers.recv()).await.unwrap().unwrap()));
    assert_echo(&mut s, b"hello via dns").await;
}

#[tokio::test]
async fn half_close_lets_destination_answer_after_client_eof() {
    let server = start(config()).await;
    // Destination reads until EOF, then answers and closes.
    let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = dest.accept().await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        s.write_all(format!("got {} bytes", got.len()).as_bytes())
            .await
            .unwrap();
    });

    let (mut s, rep, _) = socks_connect(server.addr, ip(dest_addr)).await;
    assert_eq!(rep, 0);
    s.write_all(b"12345").await.unwrap();
    s.shutdown().await.unwrap();
    let mut answer = Vec::new();
    timeout(WAIT, s.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, b"got 5 bytes");
}

#[tokio::test]
async fn password_auth_accepts_correct_credentials() {
    let server = start(marksocks::Config {
        auth: creds("alice", "s3cret"),
        ..config()
    })
    .await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();

    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_password(&mut s, "alice", "s3cret").await, 0);
    let (rep, _) = request(&mut s, CMD_CONNECT, ip(echo)).await;
    assert_eq!(rep, 0);
    assert_echo(&mut s, b"authenticated").await;
}

#[tokio::test]
async fn password_auth_rejects_wrong_password() {
    let server = start(marksocks::Config {
        auth: creds("alice", "s3cret"),
        ..config()
    })
    .await;

    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert_ne!(greet_password(&mut s, "alice", "wrong").await, 0);
    assert!(closed_without_data(&mut s).await);
}

#[tokio::test]
async fn password_auth_rejects_no_auth_client() {
    let server = start(marksocks::Config {
        auth: creds("alice", "s3cret"),
        ..config()
    })
    .await;

    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut s).await, 0xff, "no acceptable methods");
    assert!(closed_without_data(&mut s).await);
}

#[tokio::test]
async fn allow_no_auth_accepts_no_auth_clients_alongside_password() {
    let server = start(marksocks::Config {
        auth: creds("alice", "s3cret"),
        allow_no_auth: true,
        ..config()
    })
    .await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();

    let mut anon = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut anon).await, 0);
    assert_eq!(request(&mut anon, CMD_CONNECT, ip(echo)).await.0, 0);
    assert_echo(&mut anon, b"anonymous").await;

    let mut wrong = TcpStream::connect(server.addr).await.unwrap();
    assert_ne!(greet_password(&mut wrong, "alice", "wrong").await, 0);

    // A client offering both methods is asked for the password first.
    let mut both = TcpStream::connect(server.addr).await.unwrap();
    both.write_all(&[5, 2, 0, 2]).await.unwrap();
    let mut reply = [0u8; 2];
    both.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
}

#[tokio::test]
async fn skip_auth_reads_the_request_without_negotiation() {
    let server = start(marksocks::Config {
        skip_auth: true,
        ..config()
    })
    .await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();

    let mut s = TcpStream::connect(server.addr).await.unwrap();
    let (rep, _) = request(&mut s, CMD_CONNECT, ip(echo)).await;
    assert_eq!(rep, 0);
    assert_echo(&mut s, b"no handshake").await;
}

#[tokio::test]
async fn dns_resolve_false_rejects_domains_but_not_ips() {
    let server = start(marksocks::Config {
        dns_resolve: false,
        ..config()
    })
    .await;
    let (echo, mut peers) = echo_server("127.0.0.1:0").await.unwrap();

    let (_s, rep, _) = socks_connect(server.addr, domain("localhost", echo.port())).await;
    assert_eq!(rep, 0x08, "address type not supported");
    let (mut s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);
    assert_echo(&mut s, b"ip still works").await;
    // Only the IP request reached the destination.
    peers.recv().await.unwrap();
    assert!(peers.try_recv().is_err());
}

#[tokio::test]
async fn udp_associate_is_not_supported_when_disabled() {
    let server = start(marksocks::Config {
        allow_udp: false,
        ..config()
    })
    .await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut s).await, 0);
    let (rep, _) = request(&mut s, CMD_UDP_ASSOCIATE, ip("0.0.0.0:0".parse().unwrap())).await;
    assert_eq!(rep, 0x07);
}

#[tokio::test]
async fn bind_is_not_supported() {
    let server = start(config()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut s).await, 0);
    let (rep, _) = request(&mut s, CMD_BIND, ip("127.0.0.1:9".parse().unwrap())).await;
    assert_eq!(rep, 0x07);
}

#[tokio::test]
async fn connect_to_closed_port_is_refused() {
    let server = start(config()).await;
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (_s, rep, _) = socks_connect(server.addr, ip(closed)).await;
    assert_eq!(rep, 0x05);
}

#[tokio::test]
async fn unresolvable_domain_is_host_unreachable() {
    let server = start(config()).await;
    let (_s, rep, _) = socks_connect(server.addr, domain("does-not-exist.invalid", 80)).await;
    assert_eq!(rep, 0x04);
}

#[tokio::test]
async fn handshake_timeout_closes_silent_and_stalled_clients() {
    let server = start(marksocks::Config {
        handshake_timeout: Duration::from_millis(300),
        ..config()
    })
    .await;

    // Sends nothing at all.
    let started = Instant::now();
    let mut silent = TcpStream::connect(server.addr).await.unwrap();
    assert!(closed_without_data(&mut silent).await);
    assert!(started.elapsed() >= Duration::from_millis(250));

    // Finishes method negotiation, then never sends the request.
    let mut stalled = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut stalled).await, 0);
    assert!(closed_without_data(&mut stalled).await);
}

#[tokio::test]
async fn idle_relay_is_closed_after_idle_timeout() {
    let idle = Duration::from_millis(400);
    let server = start(marksocks::Config {
        idle_timeout: idle,
        ..config()
    })
    .await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();
    let (mut s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);

    // Traffic more often than `idle` keeps the relay alive well past `idle`.
    for _ in 0..6 {
        assert_echo(&mut s, b"tick").await;
        tokio::time::sleep(idle / 4).await;
    }
    let quiet_since = Instant::now();
    assert!(closed_without_data(&mut s).await);
    assert!(quiet_since.elapsed() >= idle / 2);
}

#[tokio::test]
async fn connection_limit_closes_extra_clients_without_reply() {
    let server = start(marksocks::Config {
        max_connections: 1,
        ..config()
    })
    .await;

    let mut first = TcpStream::connect(server.addr).await.unwrap();
    assert_eq!(greet_no_auth(&mut first).await, 0); // the slot is now held

    let mut second = TcpStream::connect(server.addr).await.unwrap();
    let _ = second.write_all(&[5, 1, 0]).await;
    assert!(closed_without_data(&mut second).await);

    // Releasing the slot lets a new client in.
    drop(first);
    let deadline = Instant::now() + WAIT;
    loop {
        let mut third = TcpStream::connect(server.addr).await.unwrap();
        third.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        if third.read_exact(&mut reply).await.is_ok() {
            assert_eq!(reply, [5, 0]);
            break;
        }
        assert!(Instant::now() < deadline, "slot was never released");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn graceful_shutdown_waits_for_in_flight_connections() {
    let mut server = start(config()).await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();
    let (mut s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);

    server.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!server.done.is_finished(), "must wait for the open relay");
    assert!(
        TcpStream::connect(server.addr).await.is_err(),
        "listener must be closed"
    );
    assert_echo(&mut s, b"still relaying").await;

    drop(s);
    timeout(WAIT, &mut server.done).await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_closes_connections_still_open_after_grace_period() {
    let mut server = start(marksocks::Config {
        idle_timeout: Duration::ZERO, // the relay would otherwise live forever
        ..config()
    })
    .await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();
    let (mut s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0);
    assert_echo(&mut s, b"idle from now on").await;

    server.shutdown();
    // serve() must return after its 5s grace period, closing the relay.
    timeout(Duration::from_secs(8), &mut server.done)
        .await
        .expect("serve did not return after the grace period")
        .unwrap();
    assert!(closed_without_data(&mut s).await);
}

#[tokio::test]
async fn mark_failure_rejects_connect_and_never_reaches_destination() {
    if !marking_fails() {
        println!("skipping: SO_MARK can be set here; see the privileged mark tests");
        return;
    }
    let server = start(marksocks::Config {
        mark: Some(0x1000_0000),
        ..config()
    })
    .await;
    let (echo, mut peers) = echo_server("127.0.0.1:0").await.unwrap();

    let (_s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0x01, "general failure");
    assert!(
        timeout(Duration::from_millis(300), peers.recv())
            .await
            .is_err(),
        "destination must not see a connection"
    );
}
