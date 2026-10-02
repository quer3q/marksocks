//! UDP ASSOCIATE: an unmarked client-facing relay socket plus at most one marked outbound
//! socket per address family, created on first use.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{new_udp_header, parse_udp_request, ReplyError};
use log::{debug, info, warn};
use socket2::Domain;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::socks::CommandRead;
use crate::{outbound, Config};

// ponytail: one maximum-size datagram buffer per association.
const BUF: usize = 65_535;
// ponytail: destinations remembered per association for accepting replies; the oldest is
// forgotten first, so a client juggling more peers than this loses replies from the oldest.
const MAX_REMOTES: usize = 256;

/// Serve one UDP ASSOCIATE request. `local` is the control connection's local address (where
/// the client reached us); `requested` is the request's DST (where the client says it will
/// send from).
pub(crate) async fn associate(
    proto: CommandRead,
    peer: SocketAddr,
    local: SocketAddr,
    requested: TargetAddr,
    cfg: &Config,
) {
    let local = relay_bind_addr(local);
    let bound = async {
        let relay = UdpSocket::bind(local).await?;
        let addr = relay.local_addr()?;
        io::Result::Ok((relay, addr))
    };
    let (relay, relay_addr) = match bound.await {
        Ok(bound) => bound,
        Err(e) => {
            warn!("{peer}: UDP relay bind on {local} failed: {e}");
            let _ = proto.reply_error(&ReplyError::GeneralFailure).await;
            return;
        }
    };
    let control = match proto.reply_success(relay_addr).await {
        Ok(control) => control,
        Err(e) => {
            debug!("{peer}: writing UDP ASSOCIATE reply failed: {e}");
            return;
        }
    };
    // The client is always the TCP peer's IP; a DST port, if given, is enforced too. A DST IP
    // is not used: behind NAT it is often the client's private address.
    let port = match requested {
        TargetAddr::Ip(addr) => addr.port(),
        TargetAddr::Domain(_, port) => port,
    };
    info!("{peer}: UDP associate via {relay_addr}");
    let mut assoc = Association {
        cfg,
        peer,
        relay,
        port: (port != 0).then_some(port),
        client: None,
        out4: None,
        out6: None,
        remotes: VecDeque::new(),
        buf: vec![0; BUF],
    };
    let why = assoc.run(control).await;
    debug!("{peer}: UDP associate via {relay_addr} ended: {why}");
}

struct Association<'a> {
    cfg: &'a Config,
    peer: SocketAddr,
    relay: UdpSocket,
    /// Client port required by the request, if it named one.
    port: Option<u16>,
    /// The client's address, locked by its first valid datagram.
    client: Option<SocketAddr>,
    out4: Option<UdpSocket>,
    out6: Option<UdpSocket>,
    /// Destinations the client sent to (`reply_key` of the resolved address, and the address
    /// the client asked for); only these may answer.
    remotes: VecDeque<(SocketAddr, TargetAddr)>,
    buf: Vec<u8>,
}

impl Association<'_> {
    /// Relay until the control connection closes or the association is idle. Both are
    /// watched while a datagram is being processed too (DNS can take `request_timeout`).
    async fn run(&mut self, mut control: TcpStream) -> &'static str {
        let idle_timeout = self.cfg.idle_timeout;
        let mut last = Instant::now();
        loop {
            // Readiness waits don't consume tokio's coop budget, so a flood of datagrams we drop
            // would otherwise never yield, starving the runtime (and our own close/idle checks).
            tokio::task::coop::consume_budget().await;
            tokio::select! {
                why = closed(&mut control) => return why,
                _ = idle(last, idle_timeout) => return "idle timeout",
                relayed = self.next_datagram() => if relayed {
                    last = Instant::now();
                },
            }
        }
    }

    /// Wait for the next datagram on any socket and handle it. Returns whether it was relayed.
    async fn next_datagram(&mut self) -> bool {
        // Each branch only waits for readiness; the handlers then read into `self.buf`.
        tokio::select! {
            Ok(()) = self.relay.readable() => self.client_datagram().await,
            Ok(()) = readable(&self.out4) => self.remote_datagram(false).await,
            Ok(()) = readable(&self.out6) => self.remote_datagram(true).await,
            else => std::future::pending().await,
        }
    }

    /// Decapsulate one client datagram and send it on. Returns whether it was relayed.
    async fn client_datagram(&mut self) -> bool {
        let peer = self.peer;
        let Some((n, src)) = try_recv(&self.relay, &mut self.buf) else {
            return false;
        };
        if !self.is_client(src) {
            debug!("{peer}: UDP datagram from {src} dropped: not the associated client");
            return false;
        }
        let (frag, target, header_len) = match parse_udp_request(&self.buf[..n]).await {
            Ok((frag, target, payload)) => (frag, target, n - payload.len()),
            Err(e) => {
                debug!("{peer}: malformed UDP datagram dropped: {e}");
                return false;
            }
        };
        if frag != 0 {
            debug!("{peer}: UDP datagram with FRAG {frag} dropped: fragmentation is unsupported");
            return false;
        }
        self.client.get_or_insert(reply_key(src));

        let addrs = match outbound::resolve(&target, self.cfg).await {
            Ok(addrs) => addrs,
            Err(e) => {
                debug!("{peer}: UDP datagram to {target} dropped: {e}");
                return false;
            }
        };
        // Resolved addresses in order, until one is sent. Each family's socket is marked when
        // created; if that fails no socket exists, so nothing is ever sent unmarked.
        for addr in addrs {
            let (slot, family) = if addr.is_ipv4() {
                (&mut self.out4, Domain::IPV4)
            } else {
                (&mut self.out6, Domain::IPV6)
            };
            let sock = match slot {
                Some(sock) => sock,
                None => match outbound::bind_udp(family, self.cfg) {
                    Ok(sock) => slot.insert(sock),
                    Err(e) => {
                        warn!("{peer}: UDP to {target} via {addr}: {e}");
                        continue;
                    }
                },
            };
            if let Err(e) = sock.send_to(&self.buf[header_len..n], addr).await {
                debug!("{peer}: UDP send to {addr} failed: {e}");
                continue;
            }
            let key = reply_key(addr);
            // Two names on one address: the most recent one is echoed in replies.
            match self.remotes.iter_mut().find(|(k, _)| *k == key) {
                Some((_, requested)) => *requested = target,
                None => {
                    if self.remotes.len() == MAX_REMOTES {
                        self.remotes.pop_front();
                    }
                    self.remotes.push_back((key, target));
                }
            }
            return true;
        }
        debug!("{peer}: UDP datagram to {target} dropped: no address could be used");
        false
    }

    /// Encapsulate one reply from a destination and send it to the client.
    async fn remote_datagram(&mut self, v6: bool) -> bool {
        let peer = self.peer;
        let sock = if v6 { &self.out6 } else { &self.out4 };
        let Some((n, src)) = sock.as_ref().and_then(|s| try_recv(s, &mut self.buf)) else {
            return false;
        };
        let key = reply_key(src);
        let (Some(client), Some((_, requested))) =
            (self.client, self.remotes.iter().find(|(k, _)| *k == key))
        else {
            debug!("{peer}: UDP datagram from {src} dropped: client never sent to it");
            return false;
        };
        // Echo what the client asked for: a domain target gets its name back (clients map
        // replies by it, e.g. to a FakeDNS address); an IP target gets the real source.
        let header = match requested {
            TargetAddr::Domain(..) => new_udp_header(requested.clone()),
            TargetAddr::Ip(_) => new_udp_header(src),
        };
        let mut reply = match header {
            Ok(header) => header,
            Err(e) => {
                debug!("{peer}: UDP header for {src} failed: {e}");
                return false;
            }
        };
        reply.extend_from_slice(&self.buf[..n]);
        match self.relay.send_to(&reply, client).await {
            Ok(_) => true,
            Err(e) => {
                debug!("{peer}: UDP send to client {client} failed: {e}");
                false
            }
        }
    }

    fn is_client(&self, src: SocketAddr) -> bool {
        match self.client {
            Some(client) => reply_key(src) == client,
            None => {
                src.ip().to_canonical() == self.peer.ip().to_canonical()
                    && self.port.is_none_or(|port| port == src.port())
            }
        }
    }
}

/// Resolves when the control connection closes; stray bytes on it are ignored.
async fn closed(control: &mut TcpStream) -> &'static str {
    let mut buf = [0u8; 64];
    loop {
        match control.read(&mut buf).await {
            Ok(0) => return "control connection closed",
            Err(_) => return "control connection failed",
            Ok(_) => {}
        }
    }
}

/// One datagram if one is ready. Errors (e.g. ICMP-induced ones) only drop that read.
fn try_recv(sock: &UdpSocket, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    match sock.try_recv_from(buf) {
        Ok(res) => Some(res),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
        Err(e) => {
            debug!("UDP receive failed: {e}");
            None
        }
    }
}

/// Readiness of an outbound socket; never ready while it does not exist.
async fn readable(sock: &Option<UdpSocket>) -> io::Result<()> {
    match sock {
        Some(sock) => sock.readable().await,
        None => std::future::pending().await,
    }
}

async fn idle(last: Instant, timeout: Duration) {
    if timeout.is_zero() {
        std::future::pending().await
    } else {
        tokio::time::sleep_until(last + timeout).await
    }
}

/// Where to bind the relay: the control connection's local address on port 0, keeping the
/// IPv6 scope id (needed for link-local) but unmapping IPv4-mapped addresses (dual-stack).
fn relay_bind_addr(local: SocketAddr) -> SocketAddr {
    match local.ip().to_canonical() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), 0),
        IpAddr::V6(_) => {
            let mut addr = local;
            addr.set_port(0);
            addr
        }
    }
}

/// An address for comparing sent-to and received-from peers: IPv6 flow info is per packet so
/// it is cleared; the scope id identifies the link, so it is kept.
fn reply_key(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(mut v6) => {
            v6.set_flowinfo(0);
            v6.into()
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    #[test]
    fn relay_binds_the_control_connections_address() {
        let v4: SocketAddr = "192.168.1.1:1080".parse().unwrap();
        assert_eq!(relay_bind_addr(v4), "192.168.1.1:0".parse().unwrap());

        let mapped: SocketAddr = "[::ffff:192.168.1.1]:1080".parse().unwrap();
        assert_eq!(relay_bind_addr(mapped), "192.168.1.1:0".parse().unwrap());

        let link_local = SocketAddrV6::new("fe80::1".parse().unwrap(), 1080, 7, 3);
        assert_eq!(
            relay_bind_addr(link_local.into()),
            SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 7, 3).into(),
            "scope id (and flow info) must survive"
        );
    }

    #[test]
    fn reply_key_ignores_flow_info_but_not_the_link() {
        let ll = |flow, scope| {
            SocketAddr::from(SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                53,
                flow,
                scope,
            ))
        };
        assert_eq!(reply_key(ll(9, 2)), reply_key(ll(0, 2)));
        assert_ne!(reply_key(ll(0, 2)), reply_key(ll(0, 3)));
        assert_eq!(reply_key(ll(9, 2)), ll(0, 2), "scope id kept");
        let v4: SocketAddr = "10.0.0.1:53".parse().unwrap();
        assert_eq!(reply_key(v4), v4);
    }
}
