//! marksocks: a small SOCKS5 proxy that can set `SO_MARK` on destination-facing sockets.
//!
//! The library half exists so integration tests can run the server in-process.

pub mod outbound;
pub mod socks;
mod udp;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn, LevelFilter};
use serde::{Deserialize, Deserializer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

// ponytail: fixed grace period; make it configurable only if someone needs it.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Username/password the client must present. Deliberately not `Debug`.
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Runtime configuration, read from a TOML file. Durations are integer seconds in TOML.
/// For `handshake_timeout`, `idle_timeout` and `max_connections`, 0 disables the limit.
/// Deliberately not `Debug` (holds the password).
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub listen: SocketAddr,
    pub log_level: LevelFilter,
    /// `SO_MARK` for destination-facing sockets; `None` leaves them unmarked. When set,
    /// failing to mark a socket rejects the request.
    pub mark: Option<u32>,
    pub auth: Option<Credentials>,
    #[serde(deserialize_with = "secs")]
    pub handshake_timeout: Duration,
    #[serde(deserialize_with = "secs")]
    pub idle_timeout: Duration,
    pub max_connections: u32,

    // Inherited from `fast_socks5::server::Config`: same names and defaults, except
    // `allow_udp` and `nodelay`.
    /// Bounds DNS resolution plus all outbound connection attempts.
    #[serde(deserialize_with = "secs")]
    pub request_timeout: Duration,
    pub skip_auth: bool,
    pub dns_resolve: bool,
    /// Defaults to true, unlike fast-socks5.
    pub allow_udp: bool,
    pub allow_no_auth: bool,
    /// Defaults to true, unlike fast-socks5; applies to client and outbound TCP sockets.
    pub nodelay: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 1080)),
            log_level: LevelFilter::Off,
            mark: None,
            auth: None,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_connections: 512,
            request_timeout: Duration::from_secs(10),
            skip_auth: false,
            dns_resolve: true,
            allow_udp: true,
            allow_no_auth: false,
            nodelay: true,
        }
    }
}

impl Config {
    /// Parse and validate a TOML config.
    pub fn from_toml(text: &str) -> Result<Config, String> {
        // Errors end up in the system log, so never echo config text: report only line and
        // message (toml's Display quotes the source line, which could be the password), and
        // check [auth] first so its values can't appear in a type-error message either.
        let at_line = |e: toml::de::Error| match e.span() {
            Some(span) => {
                let line = text[..span.start].matches('\n').count() + 1;
                format!("line {line}: {}", e.message())
            }
            None => e.message().to_string(),
        };
        let table: toml::Table = toml::from_str(text).map_err(at_line)?;
        if let Some(auth) = table.get("auth") {
            if auth.clone().try_into::<Credentials>().is_err() {
                return Err(
                    "invalid [auth] section: it must contain exactly `username` and \
                            `password`, both strings"
                        .into(),
                );
            }
        }
        let cfg: Config = toml::from_str(text).map_err(at_line)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.mark == Some(0) {
            return Err("mark = 0 is not allowed; omit `mark` to disable marking".into());
        }
        if self.request_timeout.is_zero() {
            return Err("request_timeout must be at least 1 second".into());
        }
        if let Some(auth) = &self.auth {
            // RFC 1929 length fields are one byte, and empty values are not allowed.
            let bad = |s: &str| s.is_empty() || s.len() > 255;
            if bad(&auth.username) || bad(&auth.password) {
                return Err("auth.username and auth.password must be 1..=255 bytes".into());
            }
            if self.skip_auth {
                return Err("skip_auth = true cannot be combined with [auth]".into());
            }
        }
        Ok(())
    }
}

fn secs<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    u64::deserialize(d).map(Duration::from_secs)
}

/// Accept SOCKS5 clients on `listener` until `shutdown` resolves, then stop accepting and
/// wait up to a short grace period for in-flight connections; any still open after it are
/// aborted (their sockets closed) before returning.
pub async fn serve(listener: TcpListener, cfg: Arc<Config>, shutdown: impl Future<Output = ()>) {
    let limit =
        (cfg.max_connections > 0).then(|| Arc::new(Semaphore::new(cfg.max_connections as usize)));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    // ponytail: fixed back-off for EMFILE and friends.
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        while tasks.try_join_next().is_some() {} // reap finished connections
        let permit = match &limit {
            None => None,
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    warn!("connection limit reached, closing {peer}");
                    continue; // `stream` is dropped here, closing the connection.
                }
            },
        };
        let cfg = cfg.clone();
        tasks.spawn(async move {
            socks::handle(stream, peer, cfg).await;
            drop(permit);
        });
    }
    drop(listener);

    while tasks.try_join_next().is_some() {}
    if !tasks.is_empty() {
        info!(
            "shutting down: waiting up to {SHUTDOWN_GRACE:?} for {} connection(s)",
            tasks.len()
        );
        let drain = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
            warn!("shutdown grace period expired, closing remaining connections");
            tasks.shutdown().await; // aborts the tasks, dropping (closing) their sockets
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_has_documented_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(cfg.log_level, LevelFilter::Off);
        assert_eq!(cfg.mark, None);
        assert!(cfg.auth.is_none());
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(10));
        assert_eq!(cfg.idle_timeout, Duration::from_secs(300));
        assert_eq!(cfg.max_connections, 512);
        // fast_socks5::server::Config::default(), except allow_udp and nodelay.
        assert_eq!(cfg.request_timeout, Duration::from_secs(10));
        assert!(!cfg.skip_auth);
        assert!(cfg.dns_resolve);
        assert!(cfg.allow_udp);
        assert!(!cfg.allow_no_auth);
        assert!(cfg.nodelay);
    }

    #[test]
    fn example_config_documents_the_defaults() {
        let example = Config::from_toml(include_str!("../config.example.toml")).unwrap();
        assert!(example == Config::default());
    }

    #[test]
    fn zero_disables_limits() {
        let cfg = Config::from_toml("handshake_timeout = 0\nidle_timeout = 0\nmax_connections = 0")
            .unwrap();
        assert!(cfg.handshake_timeout.is_zero() && cfg.idle_timeout.is_zero());
        assert_eq!(cfg.max_connections, 0);
    }

    #[test]
    fn full_config_parses() {
        let cfg = Config::from_toml(
            r#"
            listen = "0.0.0.0:1081"
            log_level = "debug"
            mark = 0x10000000
            handshake_timeout = 10
            idle_timeout = 300
            max_connections = 256
            request_timeout = 5
            dns_resolve = false
            allow_udp = false
            allow_no_auth = true
            nodelay = false

            [auth]
            username = "alice"
            password = "s3cret"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:1081".parse().unwrap());
        assert_eq!(cfg.log_level, LevelFilter::Debug);
        assert_eq!(cfg.mark, Some(0x1000_0000));
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(10));
        assert_eq!(cfg.idle_timeout, Duration::from_secs(300));
        assert_eq!(cfg.max_connections, 256);
        assert_eq!(cfg.request_timeout, Duration::from_secs(5));
        assert!(!cfg.dns_resolve && !cfg.allow_udp && cfg.allow_no_auth && !cfg.nodelay);
        let auth = cfg.auth.unwrap();
        assert_eq!(
            (auth.username.as_str(), auth.password.as_str()),
            ("alice", "s3cret")
        );
    }

    #[test]
    fn mark_accepts_decimal_and_hex() {
        assert_eq!(Config::from_toml("mark = 42").unwrap().mark, Some(42));
        assert_eq!(Config::from_toml("mark = 0x2a").unwrap().mark, Some(42));
        assert_eq!(
            Config::from_toml("mark = 0xffffffff").unwrap().mark,
            Some(u32::MAX)
        );
    }

    #[test]
    fn invalid_configs_are_rejected() {
        for bad in [
            "mark = 0",
            "mark = 0x0",
            "mark = -1",
            "mark = 0x100000000",
            "mark = \"0x10\"",
            "max_connections = -1",
            "request_timeout = 0",
            "idle_timeout = -5",
            "listen = \"not an address\"",
            "log_level = \"loud\"",
            "unknown_key = 1",
            "connect_timeout = 10",
            "execute_command = false",
            "skip_auth = true\n[auth]\nusername = \"a\"\npassword = \"b\"",
            "[auth]\nusername = \"a\"",
            "[auth]\npassword = \"b\"",
            "[auth]\nusername = \"\"\npassword = \"b\"",
            "[auth]\nusername = \"a\"\npassword = \"b\"\nextra = 1",
        ] {
            assert!(
                Config::from_toml(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        let err = Config::from_toml("[auth]\nusername = \"a\"\npassword = \"hunter2")
            .err()
            .unwrap();
        assert!(
            !err.contains("hunter2"),
            "errors must not echo config lines: {err}"
        );
        assert!(err.contains("line 3"), "{err}");
        for leaky in [
            "[auth]\nusername = \"a\"\npassword = 12345678",
            "[auth]\nusername = 12345678\npassword = \"b\"",
            "auth = { username = \"a\", password = 12345678 }",
            "auth.username = \"a\"\nauth.password = 12345678.5",
            "auth = 12345678",
        ] {
            let err = Config::from_toml(leaky).err().unwrap();
            assert!(!err.contains("12345678"), "{leaky:?} leaked: {err}");
        }

        let long = "x".repeat(256);
        let text = format!("[auth]\nusername = \"a\"\npassword = \"{long}\"");
        assert!(Config::from_toml(&text).is_err());
    }
}
