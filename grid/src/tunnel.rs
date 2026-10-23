//! Computers outside the company network reach the hub through a Cloudflare Tunnel. The tunnel
//! carries only WebSocket frames, and inside them runs the same pinned TLS a member uses on the
//! LAN: Cloudflare relays encrypted bytes, never prompts or replies, and the password proofs
//! stay bound to the hub's own certificate. The hub answers the tunnel on a loopback port that
//! `cloudflared` forwards to. Cloudflare names the real caller in `CF-Connecting-IP`, so wrong
//! passwords lock out the address they came from, not every computer behind the tunnel.
use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use std::{
    fmt,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};
use tokio_tungstenite::{
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http, Message,
    },
    WebSocketStream,
};

/// The one path the hub's tunnel entry answers.
pub const PATH: &str = "/grid/v1/tunnel";
/// Cloudflare closes WebSockets that stay quiet too long; a ping keeps a slow reply alive.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// One WebSocket message per write, at most this many bytes.
const MESSAGE: usize = 64 * 1024;
const STEP: Duration = Duration::from_secs(8);

/// A hub reached through a tunnel: `https://HOST`, or `http://127.0.0.1:PORT` on this computer
/// for tests and local checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    secure: bool,
    host: String,
    port: u16,
}

impl Endpoint {
    pub fn parse(text: &str) -> Result<Self, String> {
        let invalid = || "A tunnel address looks like https://grid.example.com or https://NAME.trycloudflare.com".to_owned();
        let text = text.trim().trim_end_matches('/');
        let (secure, rest) = match (text.strip_prefix("https://"), text.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            _ => return Err(invalid()),
        };
        if rest.is_empty() || rest.contains(['/', '?', '#', '@', '[', ']', ' ']) {
            return Err(invalid());
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok().filter(|port| *port > 0).ok_or_else(invalid)?)),
            None => (rest, None),
        };
        let host = host.to_ascii_lowercase();
        if secure {
            if !crate::net::valid_hostname(&host) {
                return Err(invalid());
            }
            Ok(Self { secure, host, port: port.unwrap_or(443) })
        } else {
            // Plain WebSockets only on this computer, where nothing travels a network.
            if host != "127.0.0.1" && host != "localhost" {
                return Err("A tunnel address must start with https://".into());
            }
            Ok(Self { secure, host, port: port.ok_or_else(invalid)? })
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    fn authority(&self) -> String {
        if self.secure && self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", if self.secure { "https" } else { "http" }, self.authority())
    }
}

/// A connection the grid's TLS runs over: a TCP socket on the LAN, or WebSocket frames
/// through a tunnel.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Publicly trusted roots, for Cloudflare's side of the tunnel only. The hub itself is still
/// checked against its pinned certificate inside.
pub(crate) fn web() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// The tunnel's addresses from this computer's resolver or, when it has none yet, from
/// Cloudflare's public DNS: a Quick Tunnel created a moment ago may not be known locally, and
/// Windows then remembers "not found" for minutes.
async fn addresses(host: &str, port: u16) -> Vec<SocketAddr> {
    if let Ok(Ok(found)) = tokio::time::timeout(STEP, tokio::net::lookup_host((host, port))).await {
        let found: Vec<SocketAddr> = found.collect();
        if !found.is_empty() {
            return found;
        }
    }
    match tokio::time::timeout(STEP, public_dns(host)).await {
        Ok(Ok(ips)) => ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(),
        _ => Vec::new(),
    }
}

/// `host`'s IPv4 addresses from Cloudflare's DNS-over-HTTPS service, reached by its IP address so
/// this works even when the local resolver is the problem. Its certificate is still verified.
async fn public_dns(host: &str) -> Result<Vec<IpAddr>, ()> {
    use http_body_util::BodyExt;
    let socket = tokio::net::TcpStream::connect(("1.1.1.1", 443)).await.map_err(|_| ())?;
    let name = ServerName::try_from("cloudflare-dns.com").map_err(|_| ())?;
    let stream = TlsConnector::from(web()).connect(name, socket).await.map_err(|_| ())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.map_err(|_| ())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::get(format!("/dns-query?name={host}&type=A"))
        .header(hyper::header::HOST, "cloudflare-dns.com")
        .header(hyper::header::ACCEPT, "application/dns-json")
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|_| ())?;
    let response = sender.send_request(request).await.map_err(|_| ())?;
    let body = http_body_util::Limited::new(response.into_body(), 64 * 1024).collect().await.map_err(|_| ())?.to_bytes();
    let answer: serde_json::Value = serde_json::from_slice(&body).map_err(|_| ())?;
    Ok(answer["Answer"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|record| record["type"] == 1)
        .filter_map(|record| record["data"].as_str()?.parse::<IpAddr>().ok())
        .collect())
}

/// Opens a byte stream to the hub through the tunnel. The caller runs the grid's pinned TLS on
/// it, exactly as on a LAN connection.
pub(crate) async fn connect(endpoint: &Endpoint) -> Result<Box<dyn Io>, String> {
    let unreachable = || format!("Cannot reach the grid hub through {endpoint}. Check that the hub computer is on and that its tunnel is connected.");
    let found = addresses(&endpoint.host, endpoint.port).await;
    if found.is_empty() {
        return Err(unreachable());
    }
    let socket = tokio::time::timeout(STEP, tokio::net::TcpStream::connect(found.as_slice()))
        .await
        .map_err(|_| unreachable())?
        .map_err(|_| unreachable())?;
    let _ = socket.set_nodelay(true);
    let url = format!("{}://{}{PATH}", if endpoint.secure { "wss" } else { "ws" }, endpoint.authority());
    if !endpoint.secure {
        let (socket, _) = tokio::time::timeout(STEP, tokio_tungstenite::client_async(url, socket)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
        return Ok(Box::new(Frames::new(socket)));
    }
    let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| unreachable())?;
    let outer = tokio::time::timeout(STEP, TlsConnector::from(web()).connect(name, socket)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
    let (socket, _) = tokio::time::timeout(STEP, tokio_tungstenite::client_async(url, outer)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
    Ok(Box::new(Frames::new(socket)))
}

/// Accepts one connection that `cloudflared` forwards, and returns its byte stream with the
/// address of the computer behind Cloudflare. Anything other than a WebSocket on [`PATH`] is
/// refused.
pub(crate) async fn accept(socket: tokio::net::TcpStream) -> Result<(Box<dyn Io>, IpAddr), String> {
    let _ = socket.set_nodelay(true);
    let mut caller = None;
    let check = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
        if request.uri().path() != PATH {
            let mut refused = ErrorResponse::new(None);
            *refused.status_mut() = http::StatusCode::NOT_FOUND;
            return Err(refused);
        }
        caller = request
            .headers()
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok());
        Ok(response)
    };
    let socket = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::accept_hdr_async(socket, check))
        .await
        .map_err(|_| "The tunnel connection did not finish its handshake".to_owned())?
        .map_err(|_| "The tunnel connection is not a grid WebSocket".to_owned())?;
    // Without Cloudflare's header the caller is on this computer, as in tests.
    Ok((Box::new(Frames::new(socket)), caller.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))))
}

/// WebSocket messages as a byte stream: each write becomes a binary message, and reads return
/// the bytes of binary messages in order. A close or the end of the socket reads as EOF.
pub(crate) struct Frames<S> {
    socket: WebSocketStream<S>,
    unread: Bytes,
    ended: bool,
    keepalive: tokio::time::Interval,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Frames<S> {
    fn new(socket: WebSocketStream<S>) -> Self {
        let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self { socket, unread: Bytes::new(), ended: false, keepalive }
    }

    /// Queues a ping when the socket has room; the next flush or write sends it.
    fn ping(&mut self, cx: &mut Context<'_>) {
        if let Poll::Ready(Ok(())) = Pin::new(&mut self.socket).poll_ready(cx) {
            if Pin::new(&mut self.socket).start_send(Message::Ping(Bytes::new())).is_ok() {
                let _ = Pin::new(&mut self.socket).poll_flush(cx);
            }
        }
    }
}

/// A closed socket is the end of the stream, not a failure.
fn gone(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error;
    matches!(error, Error::ConnectionClosed | Error::AlreadyClosed)
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Frames<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.unread.has_remaining() {
                let take = this.unread.len().min(buf.remaining());
                buf.put_slice(&this.unread[..take]);
                this.unread.advance(take);
                return Poll::Ready(Ok(()));
            }
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            // Polled until Pending, so the timer wakes this read for the next ping.
            while this.keepalive.poll_tick(cx).is_ready() {
                this.ping(cx);
            }
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.unread = data,
                Some(Ok(Message::Close(_))) | None => this.ended = true,
                // Pings are answered by the WebSocket itself; nothing else carries grid bytes.
                Some(Ok(_)) => {}
                Some(Err(error)) if gone(&error) => this.ended = true,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Frames<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(io::Error::other)?;
        let take = data.len().min(MESSAGE);
        Pin::new(&mut this.socket).start_send(Message::Binary(Bytes::copy_from_slice(&data[..take]))).map_err(io::Error::other)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.get_mut().socket).poll_close(cx)) {
            Err(error) if !gone(&error) => Poll::Ready(Err(io::Error::other(error))),
            _ => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn only_https_tunnels_and_this_computer_are_accepted() {
        let quick = Endpoint::parse("https://Bright-Lake-42.trycloudflare.com/").unwrap();
        assert_eq!((quick.to_string(), quick.host()), ("https://bright-lake-42.trycloudflare.com".to_owned(), "bright-lake-42.trycloudflare.com"));
        assert_eq!(Endpoint::parse("https://grid.acme.com:8443").unwrap().to_string(), "https://grid.acme.com:8443");
        assert_eq!(Endpoint::parse("http://127.0.0.1:7461").unwrap().to_string(), "http://127.0.0.1:7461");
        for bad in ["grid.acme.com", "http://grid.acme.com", "https://10.0.0.5", "https://grid.acme.com/v1", "https://user@grid.acme.com", "ftp://grid", "http://127.0.0.1", "https://", "https://a b"] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn frames_carry_bytes_both_ways_and_close_as_end_of_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut stream, caller) = accept(socket).await.unwrap();
            assert_eq!(caller, IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut request = vec![0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            // Larger than one message, so the reply arrives in several.
            stream.write_all(&vec![7u8; 3 * MESSAGE + 11]).await.unwrap();
            stream.shutdown().await.unwrap();
            request
        });
        let mut client = connect(&Endpoint::parse(&format!("http://127.0.0.1:{port}")).unwrap()).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!((reply.len(), reply.iter().all(|byte| *byte == 7)), (3 * MESSAGE + 11, true));
        assert_eq!(server.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn the_caller_behind_cloudflare_is_named_by_its_header() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accept(socket).await.unwrap().1
        });
        let mut request = format!("ws://127.0.0.1:{port}{PATH}").into_client_request().unwrap();
        request.headers_mut().insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        let socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _open = tokio_tungstenite::client_async(request, socket).await.unwrap();
        assert_eq!(server.await.unwrap(), "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn other_paths_are_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accept(socket).await.err()
        });
        let socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/somewhere-else"), socket).await.is_err());
        assert!(server.await.unwrap().is_some());
    }
}
