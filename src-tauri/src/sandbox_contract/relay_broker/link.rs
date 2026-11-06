//! The link loop: the broker's end of a relay link, thin over the exchange core and the
//! transport (M09D; VM part §3.1; VM-W11).
//!
//! [`RelayBroker::serve`] reads the relay's messages from a [`LinkPort`], opens each
//! forwarded request in its own [`ExchangeBook`], runs up to
//! [`MAX_OPEN_EXCHANGES`](crate::sandbox_contract::relay_link::MAX_OPEN_EXCHANGES)
//! exchanges concurrently, and answers each once, in the order they complete. It ends
//! when the relay closes the link, the link fails, or the caller's stop signal asks the
//! broker to close (the exchanges in flight are answered first). Exchanges still in
//! flight when the link ends run to their end, so every reservation settles; their
//! answers are recorded but cannot be sent.
//!
//! Two link ports are provided: [`StreamLink`] carries sealed frames over any async byte
//! stream with a [`BrokerLink`] session and a [`FrameDecoder`]; [`BridgedLink`] runs a
//! blocking link end ([`BlockingLink`], implemented for M09C's Windows named-pipe
//! [`LinkPipe`](crate::sandbox_contract::relay_link::LinkPipe)) on its own thread.
//!
//! The link carries no TLS facts: the relay has no TLS. The facts of the guest's TLS
//! connection come from the broker's side through [`GuestTlsSource`] (the guest
//! transport, M06), never from the relay; an exchange without them is refused.

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::mpsc::{self as std_mpsc, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time::timeout;

use super::exchange::{
    BrokerExchange, ExchangeAnswer, ExchangeBook, ExchangeConfig, ExchangeOutcome, ExchangeSlot,
};
use super::refusal::BrokerRefusal;
use super::transport::{lock_broker, SharedBroker, UpstreamTransport};
use crate::foundation::ids::Clock;
use crate::sandbox_contract::destinations::{RouteId, TlsFacts};
use crate::sandbox_contract::relay_link::{
    BrokerLink, BrokerMessage, CloseReason, ExchangeId, FrameDecoder, LinkRefusal, LinkState,
    RelayMessage, WireBytes,
};

/// The most bytes one read from the link's stream takes.
const LINK_READ_BYTES: usize = 64 * 1024;

/// Where the facts of the guest's TLS connection come from: the broker's own guest-facing
/// endpoint (M06), never the relay.
pub trait GuestTlsSource: Send + Sync {
    /// The facts of the guest connection that `exchange` on `route` arrived on, or `None`
    /// when they are not known, which refuses the exchange.
    fn facts(&self, exchange: ExchangeId, route: &RouteId) -> Option<TlsFacts>;
}

/// Why a link port failed.
#[derive(Debug)]
pub enum LinkFailure {
    /// The session refused a frame or a message.
    Link(LinkRefusal),
    /// The other end went away.
    Disconnected,
    /// A frame could not be written in time.
    TimedOut,
    Io(io::ErrorKind),
    #[cfg(windows)]
    Pipe(crate::sandbox_contract::relay_link::PipeError),
}

impl fmt::Display for LinkFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(refusal) => fmt::Display::fmt(refusal, f),
            Self::Disconnected => f.write_str("the relay's end of the link is gone"),
            Self::TimedOut => f.write_str("a link frame could not be written in time"),
            Self::Io(kind) => write!(f, "the link's stream failed ({kind:?})"),
            #[cfg(windows)]
            Self::Pipe(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for LinkFailure {}

/// The broker's end of a link, as the loop uses it.
pub trait LinkPort: Send {
    /// The relay's next message. Dropping the future before it finishes loses nothing.
    fn receive(&mut self) -> BoxFuture<'_, Result<RelayMessage, LinkFailure>>;

    /// Seals and sends one message.
    fn send(&mut self, message: BrokerMessage) -> BoxFuture<'_, Result<(), LinkFailure>>;
}

/// Sealed frames over an async byte stream (see the module notes).
pub struct StreamLink<S> {
    stream: S,
    session: BrokerLink,
    decoder: FrameDecoder,
    /// Bytes read and not yet taken by the decoder.
    pending: Vec<u8>,
    buffer: Vec<u8>,
    send_within: Duration,
}

impl<S> fmt::Debug for StreamLink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamLink")
            .field("session", &self.session)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> StreamLink<S> {
    /// The broker's end over `stream`; each frame must be written within `send_within`.
    pub fn new(stream: S, session: BrokerLink, send_within: Duration) -> Self {
        Self {
            stream,
            session,
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
            buffer: vec![0_u8; LINK_READ_BYTES],
            send_within,
        }
    }

    pub fn session(&self) -> &BrokerLink {
        &self.session
    }

    async fn next_message(&mut self) -> Result<RelayMessage, LinkFailure> {
        loop {
            match self.session.state() {
                LinkState::Open => {}
                LinkState::Closed { .. } => return Err(LinkFailure::Link(LinkRefusal::Closed)),
                LinkState::Failed(_) => return Err(LinkFailure::Link(LinkRefusal::Failed)),
            }
            if let Some(frame) = self.decoder.take() {
                return self.session.accept(&frame).map_err(LinkFailure::Link);
            }
            if !self.pending.is_empty() {
                match self.decoder.feed(&self.pending) {
                    Ok(used) => {
                        self.pending.drain(..used);
                        continue;
                    }
                    Err(refusal) => {
                        self.session.fail(refusal.clone());
                        return Err(LinkFailure::Link(refusal));
                    }
                }
            }
            // The only await: a read that has not finished has taken no byte.
            let read = self.stream.read(&mut self.buffer).await;
            match read {
                Ok(0) => {
                    self.session.fail(LinkRefusal::Interrupted);
                    return Err(LinkFailure::Disconnected);
                }
                Ok(count) => {
                    let bytes = self.buffer.get(..count).unwrap_or_default();
                    self.pending.extend_from_slice(bytes);
                }
                Err(error) => {
                    self.session.fail(LinkRefusal::Interrupted);
                    return Err(LinkFailure::Io(error.kind()));
                }
            }
        }
    }

    async fn write_message(&mut self, message: BrokerMessage) -> Result<(), LinkFailure> {
        let bytes = self.session.seal(message).map_err(LinkFailure::Link)?;
        let stream = &mut self.stream;
        let written = timeout(self.send_within, async move {
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await;
        let failure = match written {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => LinkFailure::Io(error.kind()),
            Err(_) => LinkFailure::TimedOut,
        };
        // The frame may be cut short; nothing after it can be read in step.
        self.session.fail(LinkRefusal::Interrupted);
        Err(failure)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> LinkPort for StreamLink<S> {
    fn receive(&mut self) -> BoxFuture<'_, Result<RelayMessage, LinkFailure>> {
        Box::pin(self.next_message())
    }

    fn send(&mut self, message: BrokerMessage) -> BoxFuture<'_, Result<(), LinkFailure>> {
        Box::pin(self.write_message(message))
    }
}

/// A blocking end of a link, such as M09C's named pipe.
pub trait BlockingLink: Send + 'static {
    /// Waits at most `within` for the relay's next message; `Ok(None)` when none came.
    fn receive(&mut self, within: Duration) -> Result<Option<RelayMessage>, LinkFailure>;

    /// Seals and writes one message within `within`.
    fn send(&mut self, message: BrokerMessage, within: Duration) -> Result<(), LinkFailure>;
}

#[cfg(windows)]
impl BlockingLink
    for crate::sandbox_contract::relay_link::LinkPipe<
        crate::sandbox_contract::relay_link::BrokerSide,
    >
{
    fn receive(&mut self, within: Duration) -> Result<Option<RelayMessage>, LinkFailure> {
        use crate::sandbox_contract::relay_link::PipeError;
        match crate::sandbox_contract::relay_link::LinkPipe::receive(self, within) {
            Ok(message) => Ok(Some(message)),
            Err(PipeError::TimedOut) => Ok(None),
            Err(error) => Err(pipe_failure(error)),
        }
    }

    fn send(&mut self, message: BrokerMessage, within: Duration) -> Result<(), LinkFailure> {
        crate::sandbox_contract::relay_link::LinkPipe::send(self, message, within)
            .map_err(pipe_failure)
    }
}

#[cfg(windows)]
fn pipe_failure(error: crate::sandbox_contract::relay_link::PipeError) -> LinkFailure {
    use crate::sandbox_contract::relay_link::PipeError;
    match error {
        PipeError::Link(refusal) => LinkFailure::Link(refusal),
        PipeError::Disconnected => LinkFailure::Disconnected,
        PipeError::TimedOut => LinkFailure::TimedOut,
        other => LinkFailure::Pipe(other),
    }
}

/// How the bridge thread waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BridgeTiming {
    /// The longest one receive waits before queued messages are written; it bounds how
    /// long an answer waits.
    pub poll: Duration,
    /// The longest one message takes to write.
    pub send_within: Duration,
}

/// A [`BlockingLink`] on its own thread, as an async [`LinkPort`]. A message is written
/// by the thread after [`LinkPort::send`] returns; a failure to write it ends the link
/// and arrives at the next receive.
#[derive(Debug)]
pub struct BridgedLink {
    inbound: tokio_mpsc::Receiver<Result<RelayMessage, LinkFailure>>,
    outbound: std_mpsc::Sender<BrokerMessage>,
}

impl BridgedLink {
    /// Starts the thread that drives `link`. The thread ends when the link ends or this
    /// value is dropped (after at most one `poll`).
    pub fn spawn<B: BlockingLink>(link: B, timing: BridgeTiming) -> io::Result<Self> {
        let (inbound_tx, inbound) = tokio_mpsc::channel(1);
        let (outbound, outbound_rx) = std_mpsc::channel();
        thread::Builder::new()
            .name("relay-link-bridge".to_owned())
            .spawn(move || bridge(link, timing, &inbound_tx, &outbound_rx))?;
        Ok(Self { inbound, outbound })
    }
}

fn bridge<B: BlockingLink>(
    mut link: B,
    timing: BridgeTiming,
    inbound: &tokio_mpsc::Sender<Result<RelayMessage, LinkFailure>>,
    outbound: &std_mpsc::Receiver<BrokerMessage>,
) {
    loop {
        loop {
            match outbound.try_recv() {
                Ok(message) => {
                    if let Err(failure) = link.send(message, timing.send_within) {
                        let _ = inbound.blocking_send(Err(failure));
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        match link.receive(timing.poll) {
            Ok(Some(message)) => {
                if inbound.blocking_send(Ok(message)).is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(failure) => {
                let _ = inbound.blocking_send(Err(failure));
                return;
            }
        }
    }
}

impl LinkPort for BridgedLink {
    fn receive(&mut self) -> BoxFuture<'_, Result<RelayMessage, LinkFailure>> {
        Box::pin(async move {
            self.inbound
                .recv()
                .await
                .unwrap_or(Err(LinkFailure::Disconnected))
        })
    }

    fn send(&mut self, message: BrokerMessage) -> BoxFuture<'_, Result<(), LinkFailure>> {
        let queued = self
            .outbound
            .send(message)
            .map_err(|_| LinkFailure::Disconnected);
        Box::pin(async move { queued })
    }
}

/// How a link ended.
#[derive(Debug)]
pub enum LinkEnd {
    ClosedByRelay(CloseReason),
    /// The stop signal closed it after the exchanges in flight were answered.
    ClosedByBroker(CloseReason),
    Failed(LinkFailure),
    /// The broker's book refused an exchange the link had accepted; nothing more is read.
    Inconsistent(BrokerRefusal),
}

/// One exchange of a served link, for the broker's own record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeRecord {
    pub exchange: ExchangeId,
    /// The route the relay forwarded it on.
    pub route: RouteId,
    pub outcome: ExchangeOutcome,
    /// Whether the answer reached the link.
    pub delivered: bool,
}

/// What serving a link did.
#[derive(Debug)]
pub struct LinkReport {
    pub end: LinkEnd,
    /// Every exchange, in the order it was answered.
    pub exchanges: Vec<ExchangeRecord>,
}

/// The broker's side of one sandbox's relay link (see the module notes).
pub struct RelayBroker<C: Clock> {
    broker: SharedBroker<C>,
    config: ExchangeConfig<C>,
    transport: UpstreamTransport,
    guest_tls: Arc<dyn GuestTlsSource>,
    /// Told of every exchange record as it is made (the relay host feeds the response
    /// path from it); `None` keeps the records for the report alone.
    observer: Option<ExchangeObserver>,
}

/// What sees every exchange record of a served link as it is made.
pub type ExchangeObserver = Arc<dyn Fn(&ExchangeRecord) + Send + Sync>;

impl<C: Clock> fmt::Debug for RelayBroker<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayBroker")
            .field("config", &self.config)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> RelayBroker<C> {
    pub fn new(
        broker: SharedBroker<C>,
        config: ExchangeConfig<C>,
        transport: UpstreamTransport,
        guest_tls: Arc<dyn GuestTlsSource>,
    ) -> Self {
        Self {
            broker,
            config,
            transport,
            guest_tls,
            observer: None,
        }
    }

    /// The broker with `observer` told of every exchange record as it is made.
    pub fn with_observer(mut self, observer: ExchangeObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn broker(&self) -> &SharedBroker<C> {
        &self.broker
    }

    fn observe(&self, record: &ExchangeRecord) {
        if let Some(observer) = &self.observer {
            observer(record);
        }
    }

    /// Runs one forwarded request, opened as `slot`, to its one answer.
    pub async fn exchange(
        &self,
        slot: ExchangeSlot,
        route: RouteId,
        request: WireBytes,
    ) -> ExchangeAnswer {
        let Some(tls) = self.guest_tls.facts(slot.exchange(), &route) else {
            return ExchangeAnswer::refused(slot, BrokerRefusal::GuestTlsUnknown);
        };
        let admitted = {
            let mut broker = lock_broker(&self.broker);
            BrokerExchange::admit(&self.config, &mut broker, slot, route, &request, &tls)
        };
        match admitted {
            Ok((exchange, plan)) => self.transport.run(&self.broker, exchange, plan).await,
            Err(answer) => *answer,
        }
    }

    /// Serves `link` until the relay closes it, it fails, or `stop` resolves with the
    /// reason the broker closes it for (see the module notes).
    pub async fn serve<L: LinkPort, F: Future<Output = CloseReason>>(
        &self,
        link: &mut L,
        stop: F,
    ) -> LinkReport {
        let mut book = ExchangeBook::new();
        let mut in_flight = FuturesUnordered::new();
        let mut records = Vec::new();
        let mut stop = std::pin::pin!(stop);
        let end = loop {
            tokio::select! {
                received = link.receive() => match received {
                    Ok(RelayMessage::Forward { exchange, route, request }) => {
                        match book.open(exchange) {
                            Ok(slot) => {
                                let answered_on = route.clone();
                                in_flight.push(async move {
                                    (answered_on, self.exchange(slot, route, request).await)
                                });
                            }
                            Err(refusal @ BrokerRefusal::TooManyOpenExchanges { .. }) => {
                                // The link holds the exchange open, so it is answered.
                                let message = BrokerMessage::Refused {
                                    exchange,
                                    refusal: refusal.exchange_refusal(),
                                };
                                let delivered = link.send(message).await;
                                let record = ExchangeRecord {
                                    exchange,
                                    route,
                                    outcome: ExchangeOutcome::Refused(refusal),
                                    delivered: delivered.is_ok(),
                                };
                                self.observe(&record);
                                records.push(record);
                                if let Err(failure) = delivered {
                                    break LinkEnd::Failed(failure);
                                }
                            }
                            Err(refusal) => break LinkEnd::Inconsistent(refusal),
                        }
                    }
                    Ok(RelayMessage::Close { reason }) => break LinkEnd::ClosedByRelay(reason),
                    Err(failure) => break LinkEnd::Failed(failure),
                },
                Some(answer) = in_flight.next() => {
                    if let Err(failure) =
                        deliver(link, &mut book, answer, &mut records, self.observer.as_ref()).await
                    {
                        break LinkEnd::Failed(failure);
                    }
                }
                reason = &mut stop => {
                    let mut failed = None;
                    while let Some(answer) = in_flight.next().await {
                        if failed.is_some() {
                            record(&mut book, answer, &mut records, self.observer.as_ref());
                        } else if let Err(failure) =
                            deliver(link, &mut book, answer, &mut records, self.observer.as_ref())
                                .await
                        {
                            failed = Some(failure);
                        }
                    }
                    if let Some(failure) = failed {
                        break LinkEnd::Failed(failure);
                    }
                    break match link.send(BrokerMessage::Close { reason }).await {
                        Ok(()) => LinkEnd::ClosedByBroker(reason),
                        Err(failure) => LinkEnd::Failed(failure),
                    };
                }
            }
        };
        // The link has ended; the exchanges in flight still settle their reservations.
        while let Some(answer) = in_flight.next().await {
            record(&mut book, answer, &mut records, self.observer.as_ref());
        }
        LinkReport {
            end,
            exchanges: records,
        }
    }
}

/// Sends an answer and records it.
async fn deliver<L: LinkPort>(
    link: &mut L,
    book: &mut ExchangeBook,
    (route, answer): (RouteId, ExchangeAnswer),
    records: &mut Vec<ExchangeRecord>,
    observer: Option<&ExchangeObserver>,
) -> Result<(), LinkFailure> {
    let (slot, message, outcome) = answer.into_parts();
    let exchange = book.answer(slot);
    let sent = link.send(message).await;
    let record = ExchangeRecord {
        exchange,
        route,
        outcome,
        delivered: sent.is_ok(),
    };
    if let Some(observer) = observer {
        observer(&record);
    }
    records.push(record);
    sent
}

/// Records an answer that cannot be sent.
fn record(
    book: &mut ExchangeBook,
    (route, answer): (RouteId, ExchangeAnswer),
    records: &mut Vec<ExchangeRecord>,
    observer: Option<&ExchangeObserver>,
) {
    let (slot, _, outcome) = answer.into_parts();
    let record = ExchangeRecord {
        exchange: book.answer(slot),
        route,
        outcome,
        delivered: false,
    };
    if let Some(observer) = observer {
        observer(&record);
    }
    records.push(record);
}
