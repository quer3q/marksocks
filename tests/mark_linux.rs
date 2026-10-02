//! Linux proofs that only destination-facing sockets carry the configured `SO_MARK`.
//!
//! The server runs in-process, so every socket it creates is visible in `/proc/self/fd`; each
//! test finds the sockets by address and reads their mark with `getsockopt(SO_MARK)`.
//!
//! The `#[ignore]`d tests need permission to set SO_MARK (CAP_NET_ADMIN, or CAP_NET_RAW on
//! Linux >= 5.17). Run them with either of:
//!
//!   sudo -E cargo test --locked --test mark_linux -- --ignored
//!   docker run --rm --cap-add NET_ADMIN -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/t \
//!       rust:1.96 cargo test --locked --test mark_linux -- --ignored
//!
//! `marking_failure_rejects_requests` is the unprivileged counterpart: it runs by default and
//! skips itself when marking is permitted. To exercise it in docker (whose default
//! capabilities include NET_RAW), add `--cap-drop NET_RAW --cap-drop NET_ADMIN`.
#![cfg(target_os = "linux")]

mod common;

use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, RawFd};
use std::time::Duration;

use common::*;
use fast_socks5::util::target_addr::TargetAddr;
use socket2::{SockRef, Type};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const MARKS: [u32; 2] = [0x1000_0000, 0x2a];
const PRIVILEGED: &str = "requires CAP_NET_ADMIN; see README";

struct Sock {
    ty: Type,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    mark: u32,
}

/// Every inet socket this process currently has open.
fn sockets() -> Vec<Sock> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() else {
            continue;
        };
        let is_socket = std::fs::read_link(entry.path())
            .is_ok_and(|target| target.to_string_lossy().starts_with("socket:"));
        if !is_socket {
            continue;
        }
        // SAFETY: the fd is only queried, never closed. If another test closes it meanwhile,
        // the queries fail or describe an unrelated socket, which the address match ignores.
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let sock = SockRef::from(&fd);
        let (Ok(ty), Ok(mark)) = (sock.r#type(), sock.mark()) else {
            continue;
        };
        found.push(Sock {
            ty,
            local: sock.local_addr().ok().and_then(|a| a.as_socket()),
            peer: sock.peer_addr().ok().and_then(|a| a.as_socket()),
            mark,
        });
    }
    found
}

/// The mark of the one socket with this type and these addresses.
fn mark_of(socks: &[Sock], ty: Type, local: SocketAddr, peer: Option<SocketAddr>) -> u32 {
    let matching: Vec<_> = socks
        .iter()
        .filter(|s| s.ty == ty && s.local == Some(local) && s.peer == peer)
        .collect();
    assert_eq!(matching.len(), 1, "{ty:?} socket {local} -> {peer:?}");
    matching[0].mark
}

fn ip_of(addr: TargetAddr) -> SocketAddr {
    match addr {
        TargetAddr::Ip(addr) => addr,
        other => panic!("expected an IP, got {other}"),
    }
}

fn marked(mark: u32) -> marksocks::Config {
    marksocks::Config {
        mark: Some(mark),
        ..config()
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN; see README"]
async fn tcp_connect_marks_only_the_outbound_socket() {
    for mark in MARKS {
        let server = start(marked(mark)).await;
        let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();
        let (client, rep, bnd) = socks_connect(server.addr, ip(echo)).await;
        assert_eq!(rep, 0, "{PRIVILEGED}");
        let client = client.local_addr().unwrap();

        let socks = sockets();
        let outbound = mark_of(&socks, Type::STREAM, ip_of(bnd), Some(echo));
        assert_eq!(outbound, mark, "outbound TCP socket");
        let listener = mark_of(&socks, Type::STREAM, server.addr, None);
        assert_eq!(listener, 0, "listener");
        let accepted = mark_of(&socks, Type::STREAM, server.addr, Some(client));
        assert_eq!(accepted, 0, "accepted client socket");
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN; see README"]
async fn udp_associate_marks_only_the_outbound_sockets() {
    for mark in MARKS {
        let server = start(marked(mark)).await;
        let (ctl, relay) = udp_associate(server.addr, ip("0.0.0.0:0".parse().unwrap())).await;
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // (echo address, wildcard address the outbound socket of that family is bound to)
        let mut families = vec![("127.0.0.1:0", "0.0.0.0")];
        if UdpSocket::bind("[::1]:0").await.is_ok() {
            families.push(("[::1]:0", "::"));
        }
        let mut outbound = Vec::new();
        for (bind, any) in families {
            let (echo, mut seen) = udp_echo(bind).await.unwrap();
            c.send_to(&encap(ip(echo), b"mark me"), relay)
                .await
                .unwrap();
            let reply = recv_socks_udp(&c, WAIT).await;
            assert!(
                reply.is_some(),
                "datagram to {echo} not relayed; {PRIVILEGED}"
            );
            let port = seen.recv().await.unwrap().port();
            outbound.push(SocketAddr::new(any.parse().unwrap(), port));
        }

        let socks = sockets();
        for local in outbound {
            assert_eq!(mark_of(&socks, Type::DGRAM, local, None), mark, "{local}");
        }
        assert_eq!(
            mark_of(&socks, Type::DGRAM, relay, None),
            0,
            "client-facing relay"
        );
        let control = Some(ctl.local_addr().unwrap());
        let accepted = mark_of(&socks, Type::STREAM, server.addr, control);
        assert_eq!(accepted, 0, "accepted control connection");
        assert_eq!(
            mark_of(&socks, Type::STREAM, server.addr, None),
            0,
            "listener"
        );
    }
}

#[tokio::test]
async fn marking_failure_rejects_requests() {
    if !marking_fails() {
        println!("skipping: SO_MARK can be set here; the #[ignore]d tests cover this case");
        return;
    }
    let server = start(marked(MARKS[0])).await;

    let (echo, mut peers) = echo_server("127.0.0.1:0").await.unwrap();
    let (_s, rep, _) = socks_connect(server.addr, ip(echo)).await;
    assert_eq!(rep, 0x01, "general failure");
    let quiet = Duration::from_millis(300);
    assert!(
        timeout(quiet, peers.recv()).await.is_err(),
        "TCP destination reached"
    );

    let (udp_echo_addr, mut seen) = udp_echo("127.0.0.1:0").await.unwrap();
    let (_ctl, relay) = udp_associate(server.addr, ip("0.0.0.0:0".parse().unwrap())).await;
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&encap(ip(udp_echo_addr), b"unmarked?"), relay)
        .await
        .unwrap();
    assert!(recv_socks_udp(&c, quiet).await.is_none());
    assert!(seen.try_recv().is_err(), "UDP destination reached");
}
