//! A desk session carried through the hub.
//!
//! A desk is shared by the computer that hosts it on a private LAN or VPN address, which a person
//! away from the company network cannot reach. The hub can be reached from wherever the admin
//! published it, so it passes the bytes along: the host keeps a few connections open to the hub,
//! and a person's computer asks the hub to join one of them to its desk.
//!
//! The hub copies bytes and nothing else. The desk's own TLS, pinned to the certificate in its
//! invitation, is negotiated end to end inside this relay, so what passes through the hub is
//! ciphertext the hub cannot read, exactly as a Cloudflare tunnel only ever relays the grid's
//! own encrypted connections.
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

/// Pieces still to be sent one way before the writer waits for the far side to catch up.
pub(crate) const WINDOW: usize = 16;
/// The largest piece written in one go.
const PIECE: usize = 64 * 1024;
/// How long a relayed session may last.
pub const SESSION: std::time::Duration = std::time::Duration::from_secs(12 * 60 * 60);

pub(crate) type Sending = mpsc::Sender<Result<Frame<Bytes>, io::Error>>;
pub(crate) type Sent = mpsc::Receiver<Result<Frame<Bytes>, io::Error>>;

/// A streamed body fed by its `Sending` half.
pub(crate) fn body(received: Sent) -> crate::net::Body {
    let stream = futures_util::stream::unfold(received, |mut received| async move { received.recv().await.map(|item| (item, received)) });
    StreamBody::new(stream).boxed_unsync()
}

/// One side of a relayed connection: an HTTP body read from the far side, and a channel written
/// to it. Together they are an ordinary byte stream, so TLS and HTTP can run inside.
pub struct Stream {
    incoming: Incoming,
    pending: Bytes,
    finished: bool,
    outgoing: Option<Sending>,
    reserving: Option<Pin<Box<dyn std::future::Future<Output = Option<mpsc::OwnedPermit<Result<Frame<Bytes>, io::Error>>>> + Send>>>,
}

impl Stream {
    pub(crate) fn new(incoming: Incoming, outgoing: Sending) -> Stream {
        Stream { incoming, pending: Bytes::new(), finished: false, outgoing: Some(outgoing), reserving: None }
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes themselves: a relayed session is the person's own.
        formatter.debug_struct("RelayedSession").field("open", &self.outgoing.is_some()).finish()
    }
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buffer.remaining());
                let piece = self.pending.split_to(take);
                buffer.put_slice(&piece);
                return Poll::Ready(Ok(()));
            }
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.incoming).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.pending = data;
                    }
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let take = data.len().min(PIECE);
        // No loop here, unlike the read side: every way out of the match below returns, because a
        // write either gets its place in the queue, finds the queue gone, or waits to be polled
        // again. Writing it as a loop told a reader it could go round, and it never could.
        if self.reserving.is_none() {
            let Some(sender) = self.outgoing.clone() else {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the relayed connection is closed")));
            };
            self.reserving = Some(Box::pin(async move { sender.reserve_owned().await.ok() }));
        }
        let reserving = self.reserving.as_mut().expect("just set");
        match reserving.as_mut().poll(context) {
            Poll::Ready(Some(permit)) => {
                self.reserving = None;
                permit.send(Ok(Frame::data(Bytes::copy_from_slice(&data[..take]))));
                Poll::Ready(Ok(take))
            }
            Poll::Ready(None) => {
                self.reserving = None;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the relayed connection closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reserving = None;
        // Dropping the sender ends the far side's body, which is this stream's close.
        self.outgoing = None;
        Poll::Ready(Ok(()))
    }
}

/// Copies between the two sides of a relayed session until either closes.
pub(crate) async fn join(left: Stream, right: Stream) {
    use tokio::io::AsyncWriteExt;
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let forward = async {
        let _ = tokio::io::copy(&mut left_read, &mut right_write).await;
        let _ = right_write.shutdown().await;
    };
    let backward = async {
        let _ = tokio::io::copy(&mut right_read, &mut left_write).await;
        let _ = left_write.shutdown().await;
    };
    tokio::join!(forward, backward);
}

/// Copies between a relayed session and an ordinary socket: what a host does between the hub
/// and the desk's own listener.
pub async fn join_socket<S>(relayed: Stream, socket: S)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    use tokio::io::AsyncWriteExt;
    let (mut relayed_read, mut relayed_write) = tokio::io::split(relayed);
    let (mut socket_read, mut socket_write) = tokio::io::split(socket);
    let forward = async {
        let _ = tokio::io::copy(&mut relayed_read, &mut socket_write).await;
        let _ = socket_write.shutdown().await;
    };
    let backward = async {
        let _ = tokio::io::copy(&mut socket_read, &mut relayed_write).await;
        let _ = relayed_write.shutdown().await;
    };
    tokio::join!(forward, backward);
}

/// Reads one `\n`-terminated line: the short header saying which desk a relay is for.
pub(crate) async fn read_line(stream: &mut Stream, limit: usize) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return Err("The relayed connection closed before it said what it wanted".into()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return String::from_utf8(line).map_err(|_| "The relay header is not text".to_owned());
                }
                line.push(byte[0]);
                if line.len() > limit {
                    return Err("The relay header is too long".into());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
