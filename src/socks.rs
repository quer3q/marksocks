//! Per-connection SOCKS5 handling: negotiation, command dispatch and the TCP relay.
//! UDP ASSOCIATE lives in `udp.rs`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use fast_socks5::server::{
    states, AuthMethodSuccessState, Socks5ServerProtocol, SocksServerError, StandardAuthentication,
    StandardAuthenticationStarted,
};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use log::{debug, info, warn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::{outbound, udp, Config};

pub(crate) type CommandRead = Socks5ServerProtocol<TcpStream, states::CommandRead>;

/// Handle one accepted client connection until it is done.
pub async fn handle(stream: TcpStream, peer: SocketAddr, cfg: Arc<Config>) {
    if cfg.nodelay {
        let _ = stream.set_nodelay(true);
    }
    // The UDP relay binds the address the client reached us on.
    let local = match stream.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            debug!("{peer}: local_addr failed: {e}");
            return;
        }
    };
    let negotiated = if cfg.handshake_timeout.is_zero() {
        Ok(negotiate(stream, &cfg).await)
    } else {
        tokio::time::timeout(cfg.handshake_timeout, negotiate(stream, &cfg)).await
    };
    let (proto, cmd, target) = match negotiated {
        Ok(Ok(request)) => request,
        Ok(Err(SocksServerError::AuthenticationRejected)) => {
            warn!("{peer}: authentication rejected");
            return;
        }
        Ok(Err(e)) => {
            debug!("{peer}: handshake failed: {e}");
            return;
        }
        Err(_) => {
            debug!("{peer}: handshake timed out");
            return;
        }
    };

    match cmd {
        Socks5Command::TCPConnect => connect(proto, peer, target, &cfg).await,
        Socks5Command::UDPAssociate if cfg.allow_udp => {
            udp::associate(proto, peer, local, target, &cfg).await
        }
        Socks5Command::TCPBind | Socks5Command::UDPAssociate => {
            debug!("{peer}: {cmd:?} not supported");
            let _ = proto.reply_error(&ReplyError::CommandNotSupported).await;
        }
    }
}

async fn negotiate(
    stream: TcpStream,
    cfg: &Config,
) -> Result<(CommandRead, Socks5Command, TargetAddr), SocksServerError> {
    let proto = match &cfg.auth {
        _ if cfg.skip_auth => Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(stream),
        None => Socks5ServerProtocol::accept_no_auth(stream).await?,
        Some(creds) => {
            let methods = StandardAuthentication::allow_no_auth(cfg.allow_no_auth);
            match Socks5ServerProtocol::start(stream)
                .negotiate_auth(methods)
                .await?
            {
                StandardAuthenticationStarted::NoAuthentication(auth) => auth.finish_auth(),
                StandardAuthenticationStarted::PasswordAuthentication(auth) => {
                    let (user, pass, auth) = auth.read_username_password().await?;
                    if user != creds.username || pass != creds.password {
                        auth.reject().await?;
                        return Err(SocksServerError::AuthenticationRejected);
                    }
                    auth.accept().await?.finish_auth()
                }
            }
        }
    };
    proto.read_command().await
}

async fn connect(proto: CommandRead, peer: SocketAddr, target: TargetAddr, cfg: &Config) {
    let outbound = match outbound::connect_tcp(&target, cfg).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("{peer} -> {target}: connect failed: {e}");
            let _ = proto.reply_error(&e.reply()).await;
            return;
        }
    };
    if cfg.nodelay {
        let _ = outbound.set_nodelay(true);
    }
    let bound = match outbound.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("{peer} -> {target}: local_addr failed: {e}");
            let _ = proto.reply_error(&ReplyError::GeneralFailure).await;
            return;
        }
    };
    let client = match proto.reply_success(bound).await {
        Ok(client) => client,
        Err(e) => {
            debug!("{peer} -> {target}: writing reply failed: {e}");
            return;
        }
    };
    info!("{peer} -> {target}: connected from {bound}");
    match relay(client, outbound, cfg.idle_timeout).await {
        Ok(()) => debug!("{peer} -> {target}: closed"),
        Err(e) => debug!("{peer} -> {target}: closed: {e}"),
    }
}

/// Copy both directions until both reach EOF, an error occurs, or nothing moves in either
/// direction for `idle` (zero = no idle limit). EOF on one side shuts down the write half
/// of the other, so half-closed connections keep working.
// ponytail: tokio's copy_bidirectional (8 KiB per direction, pipelined, half-close) — the
// same relay fast-socks5 uses; we only add the activity stamps for the idle watchdog.
async fn relay<A, B>(a: A, b: B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last_activity_ms = AtomicU64::new(0);
    let mut a = Tracked {
        inner: a,
        start,
        last: &last_activity_ms,
    };
    let mut b = Tracked {
        inner: b,
        start,
        last: &last_activity_ms,
    };
    tokio::select! {
        res = tokio::io::copy_bidirectional(&mut a, &mut b) => res.map(|_| ()),
        _ = idle_watchdog(start, &last_activity_ms, idle) => {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))
        }
    }
}

/// A stream that records when it last made progress: a read or a write (even a partial one
/// under backpressure) that moved at least one byte.
struct Tracked<'a, S> {
    inner: S,
    start: Instant,
    last: &'a AtomicU64,
}

impl<S> Tracked<'_, S> {
    fn touch(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last.store(ms, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.touch();
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            if n > 0 {
                self.touch();
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn idle_watchdog(start: Instant, last: &AtomicU64, idle: Duration) {
    if idle.is_zero() {
        return std::future::pending().await;
    }
    loop {
        let deadline = start + Duration::from_millis(last.load(Ordering::Relaxed)) + idle;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// A slow destination drains one small chunk at a time for much longer than `idle`; the
    /// only progress the relay makes is partial writes (the client sent everything at once),
    /// and that must keep it alive. Once nothing moves, it times out.
    #[tokio::test]
    async fn partial_writes_count_as_activity() {
        let idle = Duration::from_millis(200);
        let (mut client, relay_a) = duplex(4096);
        let (relay_b, mut dest) = duplex(64);
        let relay = tokio::spawn(relay(relay_a, relay_b, idle));

        let sent = vec![7u8; 2048];
        client.write_all(&sent).await.unwrap(); // fits the pipe: one read on the relay side
        let started = Instant::now();
        let mut got = Vec::new();
        let mut chunk = [0u8; 64];
        while got.len() < sent.len() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let n = dest.read(&mut chunk).await.unwrap();
            assert!(n > 0, "relay closed mid-drain: partial writes must count");
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, sent);
        assert!(started.elapsed() >= idle * 4, "the drain must outlast idle");
        assert!(
            !relay.is_finished(),
            "partial writes must keep the relay alive"
        );

        let err = tokio::time::timeout(idle * 5, relay)
            .await
            .expect("relay must time out once quiet")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        drop(client);
    }
}
