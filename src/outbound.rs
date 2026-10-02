//! Destination-facing sockets: DNS resolution, connection attempts and `SO_MARK`.
//!
//! Every socket that talks to a destination is created here, and marked here (when a mark
//! is configured) before it connects or sends anything.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};

use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::ReplyError;
use log::debug;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::{timeout_at, Instant};

// ponytail: the system resolver gives no TTL, so its answers are cached for a fixed time.
const SYSTEM_RESOLVER_TTL: u32 = 60;

use crate::{dns, Config};

/// Why an outbound TCP connection could not be established.
#[derive(Debug)]
pub enum ConnectError {
    /// Setting the mark failed. Never retried with another address (it would fail the same
    /// way, and an unmarked attempt is never acceptable).
    Mark(io::Error),
    /// Creating the socket failed (e.g. address family unavailable); the next address is tried.
    Socket(io::Error),
    /// Domain destination while `dns_resolve = false`.
    DnsDisabled,
    Resolve(io::Error),
    NoAddresses,
    Timeout,
    Connect(io::Error),
}

impl ConnectError {
    /// The SOCKS reply code to send for this failure.
    pub fn reply(&self) -> ReplyError {
        match self {
            ConnectError::DnsDisabled => ReplyError::AddressTypeNotSupported,
            ConnectError::Resolve(_) | ConnectError::NoAddresses => ReplyError::HostUnreachable,
            ConnectError::Timeout => ReplyError::ConnectionTimeout,
            ConnectError::Mark(_) | ConnectError::Socket(_) => ReplyError::GeneralFailure,
            ConnectError::Connect(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => ReplyError::ConnectionRefused,
                io::ErrorKind::NetworkUnreachable => ReplyError::NetworkUnreachable,
                io::ErrorKind::HostUnreachable => ReplyError::HostUnreachable,
                io::ErrorKind::TimedOut => ReplyError::ConnectionTimeout,
                _ => ReplyError::GeneralFailure,
            },
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::Mark(e) => write!(f, "marking failed: {e}"),
            ConnectError::Socket(e) => write!(f, "creating socket failed: {e}"),
            ConnectError::DnsDisabled => f.write_str("domain destinations disabled (dns_resolve)"),
            ConnectError::Resolve(e) => write!(f, "DNS resolution failed: {e}"),
            ConnectError::NoAddresses => f.write_str("DNS returned no addresses"),
            ConnectError::Timeout => f.write_str("timed out"),
            ConnectError::Connect(e) => write!(f, "{e}"),
        }
    }
}

/// Resolve and connect to `target`, marking every attempt. DNS plus all attempts share one
/// overall deadline of `cfg.request_timeout`.
pub async fn connect_tcp(target: &TargetAddr, cfg: &Config) -> Result<TcpStream, ConnectError> {
    let deadline = Instant::now() + cfg.request_timeout;
    let addrs = match timeout_at(deadline, resolve(target, cfg)).await {
        Ok(res) => res?,
        Err(_) => return Err(ConnectError::Timeout),
    };

    let mut last_err = ConnectError::NoAddresses;
    for (i, addr) in addrs.iter().enumerate() {
        let sock = match outbound_socket(Domain::for_address(*addr), Type::STREAM, cfg.mark) {
            Ok(sock) => TcpSocket::from_std_stream(sock.into()),
            Err(e @ ConnectError::Mark(_)) => return Err(e),
            Err(e) => {
                debug!("socket for {addr} failed: {e}");
                last_err = e;
                continue;
            }
        };

        // ponytail: split the remaining budget evenly over the remaining addresses so one
        // black-holed address can't eat it all; no Happy Eyeballs.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_deadline = Instant::now() + remaining / (addrs.len() - i) as u32;
        last_err = match timeout_at(attempt_deadline, sock.connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => ConnectError::Connect(e),
            Err(_) => ConnectError::Timeout,
        };
        debug!("connect to {addr} failed: {last_err}");
    }
    Err(last_err)
}

/// All addresses for `target`, in resolver order. Domains are looked up on the router (the
/// system resolver, or A records from `cfg.dns` when set), bounded by `cfg.request_timeout`,
/// and refused when `cfg.dns_resolve` is false. Answers are cached (`cfg.dns_cache_size`):
/// `dns` ones for their TTL, system resolver ones for `SYSTEM_RESOLVER_TTL`.
pub async fn resolve(target: &TargetAddr, cfg: &Config) -> Result<Vec<SocketAddr>, ConnectError> {
    let (host, port) = match target {
        TargetAddr::Ip(addr) => return Ok(vec![*addr]),
        TargetAddr::Domain(_, _) if !cfg.dns_resolve => return Err(ConnectError::DnsDisabled),
        TargetAddr::Domain(host, port) => (host.as_str(), *port),
    };
    // Port 0 until the end, so cached addresses serve any port. SocketAddr, not IpAddr: the
    // system resolver can return scoped IPv6 (`fe80::1%eth0`).
    let cache_size = cfg.dns_cache_size as usize;
    let lookup = async {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, 0)]);
        }
        if let Some(addrs) = dns::cached(cfg.dns, host).filter(|_| cache_size > 0) {
            return Ok(addrs);
        }
        let (addrs, ttl): (Vec<SocketAddr>, u32) = match cfg.dns {
            Some(server) => {
                let (ips, ttl) = dns::lookup_a(server, host).await?;
                (ips.into_iter().map(|ip| (ip, 0).into()).collect(), ttl)
            }
            None => {
                let addrs = tokio::net::lookup_host((host, 0)).await?;
                (addrs.collect(), SYSTEM_RESOLVER_TTL)
            }
        };
        dns::remember(cfg.dns, host, &addrs, ttl, cache_size);
        Ok(addrs)
    };
    let mut addrs = match tokio::time::timeout(cfg.request_timeout, lookup).await {
        Ok(res) => res.map_err(ConnectError::Resolve)?,
        Err(_) => return Err(ConnectError::Timeout),
    };
    if addrs.is_empty() {
        return Err(ConnectError::NoAddresses);
    }
    addrs.iter_mut().for_each(|a| a.set_port(port));
    Ok(addrs)
}

/// Create an unconnected UDP socket for `family` (`Domain::IPV4` / `Domain::IPV6`), marked
/// when a mark is configured, bound to the unspecified address on an ephemeral port.
pub fn bind_udp(family: Domain, cfg: &Config) -> io::Result<UdpSocket> {
    let sock = outbound_socket(family, Type::DGRAM, cfg.mark).map_err(|e| match e {
        ConnectError::Mark(e) | ConnectError::Socket(e) => e,
        other => io::Error::other(other.to_string()),
    })?;
    let any: SocketAddr = if family == Domain::IPV6 {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    sock.bind(&any.into())?;
    UdpSocket::from_std(sock.into())
}

/// The single place destination-facing sockets are created: mark first, then hand it out.
/// Returns only `ConnectError::Mark` or `ConnectError::Socket`.
fn outbound_socket(family: Domain, ty: Type, mark: Option<u32>) -> Result<Socket, ConnectError> {
    let proto = if ty == Type::DGRAM {
        Protocol::UDP
    } else {
        Protocol::TCP
    };
    let sock = Socket::new(family, ty, Some(proto)).map_err(ConnectError::Socket)?;
    if let Some(mark) = mark {
        set_mark(&sock, mark).map_err(|e| {
            ConnectError::Mark(io::Error::new(
                e.kind(),
                format!("setting SO_MARK {mark:#x}: {e}"),
            ))
        })?;
    }
    sock.set_nonblocking(true).map_err(ConnectError::Socket)?;
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn set_mark(sock: &Socket, mark: u32) -> io::Result<()> {
    sock.set_mark(mark)
}

#[cfg(not(target_os = "linux"))]
fn set_mark(_sock: &Socket, _mark: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_MARK is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_errors_map_to_socks_replies() {
        let io = |k| ConnectError::Connect(io::Error::from(k));
        let code = |e: ConnectError| e.reply().as_u8();
        assert_eq!(code(io(io::ErrorKind::ConnectionRefused)), 0x05);
        assert_eq!(code(io(io::ErrorKind::NetworkUnreachable)), 0x03);
        assert_eq!(code(io(io::ErrorKind::HostUnreachable)), 0x04);
        assert_eq!(code(io(io::ErrorKind::TimedOut)), 0x06);
        assert_eq!(code(io(io::ErrorKind::Other)), 0x01);
        assert_eq!(code(ConnectError::Timeout), 0x06);
        assert_eq!(code(ConnectError::NoAddresses), 0x04);
        assert_eq!(code(ConnectError::DnsDisabled), 0x08);
        assert_eq!(
            code(ConnectError::Resolve(io::Error::other("nxdomain"))),
            0x04
        );
        let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(code(ConnectError::Mark(denied())), 0x01);
        assert_eq!(code(ConnectError::Socket(denied())), 0x01);
    }

    #[tokio::test]
    async fn system_resolver_answers_are_cached() {
        let cfg = Config::default();
        let got = resolve(&TargetAddr::Domain("LocalHost".into(), 80), &cfg).await;
        assert!(got.unwrap().iter().all(|a| a.port() == 80));
        let cached = dns::cached(None, "localhost").unwrap();
        assert!(cached.iter().all(|a| a.port() == 0));
        assert!(
            dns::cached(None, "LOCALHOST.").is_some(),
            "same key as for `dns`"
        );
    }
}
