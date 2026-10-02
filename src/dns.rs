//! A minimal DNS client for the `dns` setting: one A query to one server, CNAME chain
//! followed in the answer, TCP retry when the UDP answer is truncated. Also the answer
//! cache shared by every resolver path (see `outbound::resolve`).
//!
//! These sockets talk to the configured resolver, not to a destination, so they are never
//! marked. The caller bounds the whole lookup with `request_timeout`.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;
// ponytail: chain length cap; real chains (e.g. googlevideo) are 2-3 hops.
const MAX_CNAME_HOPS: usize = 16;
// ponytail: fixed cap so a long TTL cannot pin a stale address; make it a key if needed.
const MAX_TTL: u32 = 600;

// ponytail: one process-wide cache keyed by (server, name); concurrent misses for the same
// name each do their own lookup.
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(Default::default);

type Key = (Option<SocketAddr>, String);

/// (server, lowercased name without the trailing dot), the same for every source. `None` is
/// the system resolver.
// ponytail: so with the system resolver `svc` and `svc.` share an entry even when a search
// domain would make them differ.
fn key(server: Option<SocketAddr>, host: &str) -> Key {
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    (server, name)
}

/// Unexpired cached addresses (port 0) of `host` as resolved by `server` (`None` = system
/// resolver).
pub(crate) fn cached(server: Option<SocketAddr>, host: &str) -> Option<Vec<SocketAddr>> {
    CACHE
        .lock()
        .unwrap()
        .get(&key(server, host), Instant::now())
}

/// Cache `addrs` of `host` for `ttl` seconds in a cache of at most `cache_size` names.
/// Empty answers, TTL 0 and `cache_size` 0 cache nothing.
pub(crate) fn remember(
    server: Option<SocketAddr>,
    host: &str,
    addrs: &[SocketAddr],
    ttl: u32,
    cache_size: usize,
) {
    if cache_size == 0 || addrs.is_empty() || ttl == 0 {
        return;
    }
    let now = Instant::now();
    let expires = now + Duration::from_secs(ttl.into());
    CACHE
        .lock()
        .unwrap()
        .put(key(server, host), addrs.to_vec(), expires, now, cache_size);
}

/// Cached answers: `Key` -> (addresses, expiry).
#[derive(Default)]
struct Cache(HashMap<Key, (Vec<SocketAddr>, Instant)>);

impl Cache {
    fn get(&mut self, key: &Key, now: Instant) -> Option<Vec<SocketAddr>> {
        let (addrs, expires) = self.0.get(key)?;
        if *expires > now {
            return Some(addrs.clone());
        }
        self.0.remove(key);
        None
    }

    // ponytail: a full cache drops expired entries, then those expiring soonest: O(size) per
    // insert while full, fine for thousands of entries. Use an LRU crate if it ever shows up.
    fn put(
        &mut self,
        key: Key,
        addrs: Vec<SocketAddr>,
        expires: Instant,
        now: Instant,
        cap: usize,
    ) {
        if !self.0.contains_key(&key) && self.0.len() >= cap {
            self.0.retain(|_, (_, exp)| *exp > now);
            while self.0.len() >= cap {
                let soonest = self.0.iter().min_by_key(|(_, (_, exp))| *exp);
                let soonest = soonest.map(|(k, _)| k.clone()).unwrap();
                self.0.remove(&soonest);
            }
        }
        self.0.insert(key, (addrs, expires));
    }
}

/// IPv4 addresses of `host` according to `server`, and the TTL (seconds) of the records
/// that gave them. NXDOMAIN or no A record gives an empty list; any other failure is an
/// error. Not cached here.
pub(crate) async fn lookup_a(server: SocketAddr, host: &str) -> io::Result<(Vec<Ipv4Addr>, u32)> {
    // ponytail: ID from std's random hasher keys; enough against stray replies on a local link.
    let id = RandomState::new().hash_one(host) as u16;
    let query = build_query(id, host)?;

    let any: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(any).await?;
    sock.connect(server).await?; // the kernel drops datagrams from anyone else
    sock.send(&query).await?;
    let mut buf = vec![0u8; 512]; // no EDNS, so a UDP answer is at most 512 bytes
    loop {
        let n = sock.recv(&mut buf).await?;
        match parse_answer(id, host, &buf[..n]) {
            Ok(Answer::Truncated) => break,
            Ok(Answer::Addrs(addrs, ttl)) => return Ok((addrs, ttl)),
            Err(Stray) => continue, // not our answer; keep waiting (the caller's timeout bounds it)
            Err(Failed(e)) => return Err(e),
        }
    }

    let mut tcp = TcpStream::connect(server).await?;
    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&query);
    tcp.write_all(&msg).await?;
    let len = tcp.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    tcp.read_exact(&mut buf).await?;
    match parse_answer(id, host, &buf) {
        Ok(Answer::Addrs(addrs, ttl)) => Ok((addrs, ttl)),
        Ok(Answer::Truncated) => Err(bad("truncated answer over TCP")),
        Err(Stray) => Err(bad("answer does not match the query")),
        Err(Failed(e)) => Err(e),
    }
}

enum Answer {
    /// The addresses and the smallest TTL along the CNAME chain to them (0 when empty).
    Addrs(Vec<Ipv4Addr>, u32),
    Truncated,
}

enum ParseError {
    /// A message that is not the answer to our query (wrong ID or not a response).
    Stray,
    Failed(io::Error),
}
use ParseError::{Failed, Stray};

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        Failed(e)
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("DNS: {msg}"))
}

/// Header (ID, RD, one question) plus the question `host` IN A.
fn build_query(id: u16, host: &str) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(18 + host.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; QDCOUNT 1
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid domain name",
        ));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid domain name",
            ));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_A.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(q)
}

fn parse_answer(id: u16, host: &str, msg: &[u8]) -> Result<Answer, ParseError> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return Err(Stray);
    }
    // The echoed question must be ours (RFC 5452), checked before TC and RCODE are trusted.
    let qname = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let question = match read_name(msg, 12) {
        Ok((name, end)) if name == qname && msg.get(end..end + 4) == Some(&[0, 1, 0, 1]) => end,
        _ => return Err(Stray),
    };
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(Stray);
    }
    if msg[2] & 0x02 != 0 {
        return Ok(Answer::Truncated);
    }
    match msg[3] & 0x0f {
        0 => {}
        RCODE_NXDOMAIN => return Ok(Answer::Addrs(Vec::new(), 0)),
        rcode => return Err(Failed(bad(&format!("server answered with RCODE {rcode}")))),
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = question + 4; // QTYPE, QCLASS

    // (owner, type, TTL, rdata start, rdata length) of every IN answer record.
    let mut records = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = read_name(msg, pos)?;
        let fixed = msg
            .get(next..next + 10)
            .ok_or_else(|| bad("truncated record"))?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let ttl = if ttl >> 31 != 0 { 0 } else { ttl.min(MAX_TTL) }; // RFC 2181 §8
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let start = next + 10;
        if msg.len() < start + rdlen {
            return Err(Failed(bad("truncated record")));
        }
        if class == CLASS_IN {
            records.push((owner, rtype, ttl, start, rdlen));
        }
        pos = start + rdlen;
    }

    let mut name = qname;
    let mut ttl = MAX_TTL;
    for _ in 0..=MAX_CNAME_HOPS {
        let mut addrs = Vec::new();
        for &(_, _, rttl, at, _) in records
            .iter()
            .filter(|(owner, rtype, _, _, len)| *rtype == TYPE_A && *len == 4 && *owner == name)
        {
            addrs.push(Ipv4Addr::new(
                msg[at],
                msg[at + 1],
                msg[at + 2],
                msg[at + 3],
            ));
            ttl = ttl.min(rttl);
        }
        if !addrs.is_empty() {
            return Ok(Answer::Addrs(addrs, ttl));
        }
        match records
            .iter()
            .find(|(owner, rtype, _, _, _)| *rtype == TYPE_CNAME && *owner == name)
        {
            Some(&(_, _, rttl, at, _)) => {
                ttl = ttl.min(rttl);
                name = read_name(msg, at)?.0;
            }
            None => return Ok(Answer::Addrs(Vec::new(), 0)),
        }
    }
    Err(Failed(bad("CNAME chain too long")))
}

/// The (lowercased, dot-separated) name at `pos`, and the position just after it in place.
/// Follows compression pointers.
fn read_name(msg: &[u8], mut pos: usize) -> io::Result<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos).ok_or_else(|| bad("truncated name"))? as usize;
        match len {
            0 => return Ok((name, end.unwrap_or(pos + 1))),
            1..=63 => {
                let label = msg
                    .get(pos + 1..pos + 1 + len)
                    .ok_or_else(|| bad("truncated name"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                pos += 1 + len;
            }
            0xc0..=0xff => {
                let low = *msg.get(pos + 1).ok_or_else(|| bad("truncated name"))? as usize;
                end.get_or_insert(pos + 2);
                pos = (len & 0x3f) << 8 | low;
            }
            _ => return Err(bad("bad label")),
        }
    }
    Err(bad("name too long or pointer loop"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encodes_labels_and_rejects_bad_names() {
        let q = build_query(0x1234, "a.bc.").unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 1, 0]);
        assert_eq!(&q[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        for bad in ["", ".", "a..b", &"x".repeat(64), &["a"; 128].join(".")] {
            assert!(build_query(1, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn answers_to_another_question_are_stray() {
        let nxdomain = |id, name| {
            let mut msg = build_query(id, name).unwrap();
            msg[2] |= 0x80; // QR
            msg[3] = RCODE_NXDOMAIN;
            msg
        };
        let ours = nxdomain(7, "A.test");
        assert!(
            matches!(parse_answer(7, "a.TEST.", &ours), Ok(Answer::Addrs(a, _)) if a.is_empty())
        );
        assert!(matches!(parse_answer(8, "a.test", &ours), Err(Stray)));
        assert!(matches!(parse_answer(7, "b.test", &ours), Err(Stray)));
        let mut aaaa = ours.clone();
        aaaa[ours.len() - 3] = 28;
        assert!(matches!(parse_answer(7, "a.test", &aaaa), Err(Stray)));
    }

    #[test]
    fn ttl_is_the_smallest_along_the_chain() {
        let mut msg = build_query(7, "www.test").unwrap();
        msg[2] |= 0x80; // QR
        msg[7] = 2; // ANCOUNT
        let mut cname = vec![0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 6];
        cname.extend_from_slice(&[3, b'c', b'd', b'n', 0xc0, 16]); // cdn.test
        let cname_at = msg.len();
        let target = (cname_at + 12) as u8; // the CNAME's rdata
        let a = [0xc0, target, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 192, 0, 2, 1];
        msg.extend_from_slice(&cname);
        msg.extend_from_slice(&a);
        match parse_answer(7, "www.test", &msg) {
            Ok(Answer::Addrs(addrs, ttl)) => {
                assert_eq!((addrs, ttl), (vec![Ipv4Addr::new(192, 0, 2, 1)], 30))
            }
            _ => panic!("expected addresses"),
        }
        // The CNAME's TTL with the MSB set counts as 0.
        msg[cname_at + 6..cname_at + 10].copy_from_slice(&[0x80, 0, 0, 1]);
        assert!(matches!(
            parse_answer(7, "www.test", &msg),
            Ok(Answer::Addrs(_, 0))
        ));
    }

    #[test]
    fn cache_expires_and_evicts_the_soonest_expiring() {
        let t0 = Instant::now();
        let s = |n| t0 + Duration::from_secs(n);
        let key = |name: &str| (None, name.to_string());
        let ip = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))];
        let mut c = Cache::default();
        c.put(key("a"), ip.clone(), s(10), t0, 2);
        c.put(key("b"), ip.clone(), s(5), t0, 2);
        assert_eq!(c.get(&key("a"), s(9)), Some(ip.clone()));
        c.put(key("c"), ip.clone(), s(20), t0, 2); // full: b expires first
        assert!(c.get(&key("b"), t0).is_none());
        assert!(c.get(&key("a"), t0).is_some() && c.get(&key("c"), t0).is_some());
        assert!(c.get(&key("a"), s(10)).is_none(), "expired");
        assert_eq!(c.0.len(), 1, "expired entries are removed on lookup");
        c.put(key("d"), ip.clone(), s(40), t0, 2);
        c.put(key("e"), ip.clone(), s(30), s(25), 2); // full: c (expired) goes, not e or d
        assert!(c.get(&key("d"), s(25)).is_some() && c.get(&key("e"), s(25)).is_some());
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 12]);
        assert!(read_name(&msg, 12).is_err());
    }
}
