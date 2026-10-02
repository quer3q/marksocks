//! The `dns` setting: A lookups against a fake DNS server, through `outbound::resolve` and
//! through a CONNECT.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use marksocks::outbound::{resolve, ConnectError};
use marksocks::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn with_zone(zone: Vec<(&'static str, Rr)>) -> Config {
    Config {
        dns: Some(fake_dns(zone).await),
        ..config()
    }
}

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|a| a.parse().unwrap()).collect()
}

#[tokio::test]
async fn a_records_in_answer_order() {
    let cfg = with_zone(vec![
        ("two.test", Rr::A([192, 0, 2, 1])),
        ("two.test", Rr::A([192, 0, 2, 2])),
    ])
    .await;
    let got = resolve(&domain("Two.Test.", 443), &cfg).await.unwrap();
    assert_eq!(got, addrs(&["192.0.2.1:443", "192.0.2.2:443"]));
}

#[tokio::test]
async fn cname_chain_is_followed() {
    let cfg = with_zone(vec![
        ("www.test", Rr::Cname("edge.test")),
        ("edge.test", Rr::Cname("node.cdn.test")),
        ("node.cdn.test", Rr::A([198, 51, 100, 7])),
    ])
    .await;
    let got = resolve(&domain("www.test", 80), &cfg).await.unwrap();
    assert_eq!(got, addrs(&["198.51.100.7:80"]));
}

#[tokio::test]
async fn nxdomain_and_no_a_record_mean_no_addresses() {
    let cfg = with_zone(vec![
        ("gone.test", Rr::NxDomain),
        ("dangling.test", Rr::Cname("nowhere.test")),
    ])
    .await;
    for name in ["gone.test", "dangling.test", "unknown.test"] {
        let err = resolve(&domain(name, 80), &cfg).await.unwrap_err();
        assert!(matches!(err, ConnectError::NoAddresses), "{name}: {err}");
    }
}

#[tokio::test]
async fn silent_server_times_out_within_request_timeout() {
    let cfg = Config {
        request_timeout: Duration::from_secs(1),
        ..with_zone(vec![("slow.test", Rr::Silent)]).await
    };
    let started = tokio::time::Instant::now();
    let err = resolve(&domain("slow.test", 80), &cfg).await.unwrap_err();
    assert!(matches!(err, ConnectError::Timeout), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn truncated_answer_is_retried_over_tcp() {
    let cfg = with_zone(vec![
        ("big.test", Rr::Truncated),
        ("big.test", Rr::A([203, 0, 113, 9])),
    ])
    .await;
    let got = resolve(&domain("big.test", 53), &cfg).await.unwrap();
    assert_eq!(got, addrs(&["203.0.113.9:53"]));
}

#[tokio::test]
async fn answers_are_cached_per_dns_cache_size() {
    let zone = vec![
        ("cached.test", Rr::A([192, 0, 2, 3])),
        ("gone.test", Rr::NxDomain),
    ];
    let (server, queries) = fake_dns_counting(zone.clone()).await;
    let cfg = Config {
        dns: Some(server),
        ..config()
    };
    for name in ["cached.test", "CACHED.test.", "cached.test"] {
        let got = resolve(&domain(name, 80), &cfg).await.unwrap();
        assert_eq!(got, addrs(&["192.0.2.3:80"]));
    }
    assert_eq!(queries.load(Ordering::SeqCst), 1);
    for _ in 0..2 {
        assert!(resolve(&domain("gone.test", 80), &cfg).await.is_err());
    }
    assert_eq!(queries.load(Ordering::SeqCst), 3, "NXDOMAIN is not cached");

    // cached.test is cached by now; size 0 must not read it.
    let cfg = Config {
        dns_cache_size: 0,
        ..cfg
    };
    for _ in 0..2 {
        resolve(&domain("cached.test", 80), &cfg).await.unwrap();
    }
    assert_eq!(
        queries.load(Ordering::SeqCst),
        5,
        "dns_cache_size = 0 disables the cache"
    );
}

#[tokio::test]
async fn ip_literals_and_disabled_resolution_skip_the_server() {
    let cfg = with_zone(vec![]).await;
    let got = resolve(&domain("192.0.2.5", 80), &cfg).await.unwrap();
    assert_eq!(got, addrs(&["192.0.2.5:80"]));
    let cfg = Config {
        dns_resolve: false,
        ..cfg
    };
    let err = resolve(&domain("a.test", 80), &cfg).await.unwrap_err();
    assert!(matches!(err, ConnectError::DnsDisabled), "{err}");
}

#[tokio::test]
async fn connect_to_a_domain_resolved_by_the_dns_server() {
    // 127.0.0.2 would be wrong: the echo server only listens on 127.0.0.1.
    let server = start(with_zone(vec![("echo.test", Rr::A([127, 0, 0, 1]))]).await).await;
    let (echo, _peers) = echo_server("127.0.0.1:0").await.unwrap();

    let (mut s, rep, _) = socks_connect(server.addr, domain("echo.test", echo.port())).await;
    assert_eq!(rep, 0);
    s.write_all(b"via fake dns").await.unwrap();
    let mut buf = [0u8; 12];
    tokio::time::timeout(WAIT, s.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"via fake dns");

    let (_s, rep, _) = socks_connect(server.addr, domain("missing.test", echo.port())).await;
    assert_eq!(rep, 0x04, "host unreachable");
}
