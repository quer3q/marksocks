//! A minimal DNS client for the `dns` setting: one A query to one server, CNAME chain
//! followed in the answer, TCP retry when the UDP answer is truncated. No cache.
//!
//! These sockets talk to the configured resolver, not to a destination, so they are never
//! marked. The caller bounds the whole lookup with `request_timeout`.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;
// ponytail: chain length cap; real chains (e.g. googlevideo) are 2-3 hops.
const MAX_CNAME_HOPS: usize = 16;

/// IPv4 addresses of `host` according to `server`. NXDOMAIN or no A record gives an empty
/// list; any other failure is an error.
pub(crate) async fn lookup_a(server: SocketAddr, host: &str) -> io::Result<Vec<Ipv4Addr>> {
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
            Ok(Answer::Addrs(addrs)) => return Ok(addrs),
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
        Ok(Answer::Addrs(addrs)) => Ok(addrs),
        Ok(Answer::Truncated) => Err(bad("truncated answer over TCP")),
        Err(Stray) => Err(bad("answer does not match the query")),
        Err(Failed(e)) => Err(e),
    }
}

enum Answer {
    Addrs(Vec<Ipv4Addr>),
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
        RCODE_NXDOMAIN => return Ok(Answer::Addrs(Vec::new())),
        rcode => return Err(Failed(bad(&format!("server answered with RCODE {rcode}")))),
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = question + 4; // QTYPE, QCLASS

    // (owner, type, rdata) of every IN answer record.
    let mut records = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = read_name(msg, pos)?;
        let fixed = msg
            .get(next..next + 10)
            .ok_or_else(|| bad("truncated record"))?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let start = next + 10;
        if msg.len() < start + rdlen {
            return Err(Failed(bad("truncated record")));
        }
        if class == CLASS_IN {
            records.push((owner, rtype, start, rdlen));
        }
        pos = start + rdlen;
    }

    let mut name = qname;
    for _ in 0..=MAX_CNAME_HOPS {
        let addrs: Vec<Ipv4Addr> = records
            .iter()
            .filter(|(owner, rtype, _, len)| *rtype == TYPE_A && *len == 4 && *owner == name)
            .map(|&(_, _, at, _)| Ipv4Addr::new(msg[at], msg[at + 1], msg[at + 2], msg[at + 3]))
            .collect();
        if !addrs.is_empty() {
            return Ok(Answer::Addrs(addrs));
        }
        match records
            .iter()
            .find(|(owner, rtype, _, _)| *rtype == TYPE_CNAME && *owner == name)
        {
            Some(&(_, _, at, _)) => name = read_name(msg, at)?.0,
            None => return Ok(Answer::Addrs(Vec::new())),
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
        assert!(matches!(parse_answer(7, "a.TEST.", &ours), Ok(Answer::Addrs(a)) if a.is_empty()));
        assert!(matches!(parse_answer(8, "a.test", &ours), Err(Stray)));
        assert!(matches!(parse_answer(7, "b.test", &ours), Err(Stray)));
        let mut aaaa = ours.clone();
        aaaa[ours.len() - 3] = 28;
        assert!(matches!(parse_answer(7, "a.test", &aaaa), Err(Stray)));
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 12]);
        assert!(read_name(&msg, 12).is_err());
    }
}
