//! The HTTPS source of the release metadata and artifacts, over the engine's `reqwest`
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §8.3 lines 2451–2457; VM-W45, line
//! 2668; the update threat-model paragraph, line 2677; VM-D13, line 3207; M18E in
//! docs/combined-plan-leftover-tasks.md, lines 346–350: "a thin HTTPS source over the
//! engine's `reqwest`: streamed bound, no cross-origin redirect, no credentials").
//!
//! The update cycle and its fetch port live in `sandbox::trust` (VT3's `FetchPort`,
//! `FetchItem`, `FetchError` and `UpdateClient::refresh`, `f9ffd77`). This module only
//! fetches: [`SourceItem`] and [`SourceError`] mirror `FetchItem` and `FetchError` variant
//! for variant and convert from and into them, and `HttpsSource` is the client's
//! `FetchPort` through [`HttpsSource::open`]. Verification, bounds judgement, persistence
//! and every decision stay with the client.
//!
//! - **Location.** The base is the update configuration's `metadata_location`, a
//!   [`PublicUrl`]: `https` to a public host, with no user information, port, query or
//!   fragment. It is checked again when the source is built ([`HttpsSourceError`]).
//! - **Layout.** Under the base each item has one name, made only from typed values:
//!   metadata at a version as `<N>.<role>.json` (`3.root.json`, `7.snapshot.json`,
//!   `7.targets.json`), the newest metadata of a role as `<role>.json` (`timestamp.json`,
//!   `revocation.json`), and an artifact as `artifacts/<content key>`, the 64 hexadecimal
//!   digits of its content key; its target name is not part of the name
//!   ([`SourceItem::path`]). Each metadata file holds one `MetadataFile` as JSON; the
//!   snapshot and targets are served in the canonical form their reference is computed
//!   over. The publishing side (signing tooling, `resources/security/trust/`, plan line
//!   3100) does not exist yet and must follow this layout.
//! - **Client.** HTTPS only; redirects are followed only within the base's scheme, host
//!   and port and without user information, at most [`MAX_REDIRECTS`] times
//!   ([`may_follow`]); no cookie store, though the engine builds `reqwest` with cookies; no
//!   `Authorization` or other credential header and no `Referer`; no proxy, so none taken
//!   from the environment with its credentials; a connect timeout and a per-request timeout
//!   ([`SourceTimeouts`]). No decompression: the engine's `reqwest` has none built in.
//! - **A synchronous reader over async `reqwest`.** [`HttpsSource::open`] spawns the
//!   request on the caller's Tokio runtime and blocks until the status is known: 404 is
//!   [`SourceError::NotFound`], any other failure [`SourceError::Unavailable`] with a short
//!   fixed detail that never echoes a body or the URL. The returned reader takes the body
//!   from a bounded channel of [`CHANNEL_CHUNKS`] chunks that the task fills as the reader
//!   drains it, so the body is never buffered whole; the task pulls at most `max_bytes + 1`
//!   bytes from the network and then stops, for the client to judge; each read waits at
//!   most what is left of the request's deadline; and dropping the reader cancels the task.
//!
//! `open` blocks the calling thread. It must not be called on a runtime worker thread
//! (inside an async task) except through `spawn_blocking`: on a current-thread runtime the
//! request could not run at all and would time out.
//!
//! Live validation against the real location is open (E05): this source is compiled and
//! its parts are tested without any network, but it has not fetched from a real server.

use std::fmt;
use std::future::Future;
use std::io::{self, Read};
use std::pin::pin;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{Stream, StreamExt};
use reqwest::{redirect, Client, Request, StatusCode, Url};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::AbortHandle;

use crate::foundation::ids::ContentKey;
use crate::foundation::report::PublicUrl;
use crate::sandbox::trust::{
    FetchError, FetchItem, FetchPort, FetchRequest, MetadataVersion, Role, TargetName,
};

/// Default time to establish a connection, TLS included.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default time for one request, from connecting until the body has been read.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest per-request timeout accepted.
pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(3_600);
/// Redirects followed within the base's origin.
pub const MAX_REDIRECTS: usize = 3;
/// Body chunks the channel between the transfer task and the reader holds at most.
pub const CHANNEL_CHUNKS: usize = 8;

const TIMED_OUT: &str = "the metadata location did not answer in time";
const ENDED_EARLY: &str = "the transfer ended early";

/// One item at the metadata location; mirrors `sandbox::trust::FetchItem`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceItem {
    /// A role's metadata at `version`, or the newest (the timestamp and the revocation
    /// list) when `None`.
    Metadata {
        role: Role,
        version: Option<MetadataVersion>,
    },
    /// A release artifact, by its content key.
    Artifact {
        name: TargetName,
        content_key: ContentKey,
    },
}

impl SourceItem {
    /// The item's name under the base, as the module documentation lays them out.
    pub fn path(&self) -> String {
        match self {
            Self::Metadata {
                role,
                version: Some(version),
            } => format!("{version}.{}.json", role.tag()),
            Self::Metadata {
                role,
                version: None,
            } => format!("{}.json", role.tag()),
            Self::Artifact { content_key, .. } => format!("artifacts/{content_key}"),
        }
    }
}

/// Why an item was not delivered; mirrors `sandbox::trust::FetchError`, into which it
/// converts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The location has no such item (404).
    NotFound,
    /// Anything else: another status, TLS, connect, timeout or a broken body. The detail
    /// is short and fixed; it names no body and no URL.
    Unavailable { detail: String },
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("the metadata location has no such item"),
            Self::Unavailable { detail } => f.write_str(detail),
        }
    }
}

impl std::error::Error for SourceError {}

impl From<&FetchItem> for SourceItem {
    fn from(item: &FetchItem) -> Self {
        match item {
            FetchItem::Metadata { role, version } => Self::Metadata {
                role: *role,
                version: *version,
            },
            FetchItem::Artifact { name, content_key } => Self::Artifact {
                name: name.clone(),
                content_key: *content_key,
            },
        }
    }
}

impl From<SourceError> for FetchError {
    fn from(error: SourceError) -> Self {
        match error {
            SourceError::NotFound => Self::NotFound,
            SourceError::Unavailable { detail } => Self::Unavailable { detail },
        }
    }
}

/// The trust client's fetch port over HTTPS: [`HttpsSource::open`] for the item asked, with
/// the client's bound. The client reads at most the bound and one byte more, which is all
/// the reader yields; it must run off the runtime's worker threads, as `open` says.
impl FetchPort for HttpsSource {
    fn open(&mut self, request: &FetchRequest) -> Result<Box<dyn Read + '_>, FetchError> {
        HttpsSource::open(self, &SourceItem::from(&request.item), request.max_bytes)
            .map_err(FetchError::from)
    }
}

/// Why the source was not built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpsSourceError {
    /// The location does not parse as a URL that can hold paths.
    Malformed,
    /// The location is not `https`.
    NotHttps,
    /// The location has user information, a port, a query or a fragment.
    NotPlain,
    /// A timeout is zero, or the request timeout is above [`MAX_REQUEST_TIMEOUT`].
    Timeout,
    /// The HTTP client could not be built (its TLS backend did not start).
    Client,
}

impl fmt::Display for HttpsSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the metadata location is not a URL that can hold paths",
            Self::NotHttps => "the metadata location is not https",
            Self::NotPlain => {
                "the metadata location has user information, a port, a query or a fragment"
            }
            Self::Timeout => "a fetch timeout is zero or too long",
            Self::Client => "the HTTP client could not be built",
        })
    }
}

impl std::error::Error for HttpsSourceError {}

/// The source's timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceTimeouts {
    /// To establish a connection, TLS included.
    pub connect: Duration,
    /// For one request, from connecting until the body has been read; the reader's
    /// deadline too.
    pub request: Duration,
}

impl Default for SourceTimeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            request: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

/// Fetches items from the metadata location over HTTPS, as the module documentation
/// describes.
#[derive(Clone, Debug)]
pub struct HttpsSource {
    client: Client,
    base: Url,
    runtime: Handle,
    timeouts: SourceTimeouts,
}

impl HttpsSource {
    /// A source for `location` (the update configuration's `metadata_location`) whose
    /// requests run on `runtime`.
    pub fn new(
        location: &PublicUrl,
        runtime: Handle,
        timeouts: SourceTimeouts,
    ) -> Result<Self, HttpsSourceError> {
        let base = base_url(location.as_str())?;
        if timeouts.connect.is_zero()
            || timeouts.request.is_zero()
            || timeouts.request > MAX_REQUEST_TIMEOUT
        {
            return Err(HttpsSourceError::Timeout);
        }
        let origin = base.clone();
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > MAX_REDIRECTS || !may_follow(&origin, attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        });
        let client = Client::builder()
            .https_only(true)
            .redirect(policy)
            .referer(false)
            .cookie_store(false)
            .no_proxy()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.request)
            .build()
            .map_err(|_| HttpsSourceError::Client)?;
        Ok(Self {
            client,
            base,
            runtime,
            timeouts,
        })
    }

    /// The base every item's name is joined to; it ends with `/`.
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Where `item` is fetched from.
    pub fn url(&self, item: &SourceItem) -> Result<Url, SourceError> {
        self.base
            .join(&item.path())
            .ok()
            .filter(|url| url.as_str().starts_with(self.base.as_str()))
            .ok_or_else(|| unavailable("the item has no name under the metadata location"))
    }

    /// The request for `item`: a plain GET that carries no credential.
    pub(super) fn request(&self, item: &SourceItem) -> Result<Request, SourceError> {
        self.client
            .get(self.url(item)?)
            .build()
            .map_err(|_| unavailable("the request could not be built"))
    }

    /// Opens `item` for reading, blocking until the location answers or the request's
    /// timeout passes. The reader yields at most `max_bytes + 1` bytes, then ends; each
    /// read waits at most what is left of the timeout; dropping it cancels the transfer.
    /// Must not be called inside an async task except through `spawn_blocking`.
    pub fn open(
        &mut self,
        item: &SourceItem,
        max_bytes: u64,
    ) -> Result<Box<dyn Read + '_>, SourceError> {
        let request = self.request(item)?;
        let deadline = Instant::now()
            .checked_add(self.timeouts.request)
            .ok_or_else(|| unavailable("the request timeout is out of range"))?;
        let limit = max_bytes.saturating_add(1);
        let client = self.client.clone();
        let (head_sender, head) = sync_channel(1);
        // Made before waiting, so that every return below without it drops it, which
        // cancels the transfer.
        let reader = spawn_reader(&self.runtime, deadline, move |sender, permits| {
            transfer(client, request, head_sender, sender, permits, limit)
        });
        match head.recv_timeout(reader.time_left()) {
            Ok(Ok(())) => Ok(Box::new(reader)),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(unavailable(TIMED_OUT)),
            Err(RecvTimeoutError::Disconnected) => {
                Err(unavailable("the request ended without an answer"))
            }
        }
    }
}

/// The base for `location`: `https`, a host, no user information, port, query or
/// fragment, and a path ending with `/` so that names join beneath it.
pub(super) fn base_url(location: &str) -> Result<Url, HttpsSourceError> {
    let mut base = Url::parse(location).map_err(|_| HttpsSourceError::Malformed)?;
    if base.scheme() != "https" {
        return Err(HttpsSourceError::NotHttps);
    }
    if base.cannot_be_a_base() || base.host_str().is_none() {
        return Err(HttpsSourceError::Malformed);
    }
    if !base.username().is_empty()
        || base.password().is_some()
        || base.port().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(HttpsSourceError::NotPlain);
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    Ok(base)
}

/// Whether a redirect from the location at `base` to `target` is followed: `https`, the
/// same host and port, and no user information.
pub(super) fn may_follow(base: &Url, target: &Url) -> bool {
    target.scheme() == "https"
        && target.scheme() == base.scheme()
        && target.host() == base.host()
        && target.port_or_known_default() == base.port_or_known_default()
        && target.username().is_empty()
        && target.password().is_none()
}

/// What the location's `status` means: success, [`SourceError::NotFound`] for 404, and
/// [`SourceError::Unavailable`] for any other status, a redirect not followed included.
pub(super) fn status_outcome(status: StatusCode) -> Result<(), SourceError> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::NOT_FOUND {
        Err(SourceError::NotFound)
    } else if status.is_redirection() {
        Err(unavailable(
            "the metadata location redirected to another origin, or too often",
        ))
    } else {
        Err(SourceError::Unavailable {
            detail: format!("the metadata location answered {}", status.as_u16()),
        })
    }
}

/// A short fixed detail for a `reqwest` error, whose own text may hold the URL.
fn transport_detail(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        TIMED_OUT
    } else if error.is_connect() {
        "no connection to the metadata location"
    } else if error.is_redirect() {
        "the metadata location redirected too often"
    } else if error.is_body() || error.is_decode() {
        "the body broke off"
    } else {
        "the request to the metadata location failed"
    }
}

fn unavailable(detail: &str) -> SourceError {
    SourceError::Unavailable {
        detail: detail.to_owned(),
    }
}

/// What the transfer task sends the reader.
pub(super) enum Message {
    Chunk(Vec<u8>),
    /// The body broke off.
    Failed(&'static str),
    /// The body ended, or the bound was reached: nothing more comes.
    End,
}

/// The transfer task of [`HttpsSource::open`]: sends `request`, reports the status on
/// `head`, then pumps the body.
async fn transfer(
    client: Client,
    request: Request,
    head: SyncSender<Result<(), SourceError>>,
    sender: SyncSender<Message>,
    permits: Arc<Semaphore>,
    limit: u64,
) {
    let answer = match client.execute(request).await {
        Ok(response) => status_outcome(response.status()).map(|()| response),
        Err(error) => Err(unavailable(transport_detail(&error))),
    };
    let response = match answer {
        Ok(response) => response,
        Err(error) => {
            // Nobody waits for it once `open` gave up.
            let _ = head.try_send(Err(error));
            return;
        }
    };
    if head.try_send(Ok(())).is_err() {
        return;
    }
    let chunks = response
        .bytes_stream()
        .map(|chunk| chunk.map_err(|error| transport_detail(&error)));
    pump(chunks, sender, permits, limit).await;
}

/// Spawns the task `start` makes on `runtime` with the sending half of a bounded channel and returns
/// the reader of the receiving half, which cancels the task when dropped.
pub(super) fn spawn_reader<F>(
    runtime: &Handle,
    deadline: Instant,
    start: impl FnOnce(SyncSender<Message>, Arc<Semaphore>) -> F,
) -> ChannelReader
where
    F: Future<Output = ()> + Send + 'static,
{
    let (sender, receiver) = sync_channel(CHANNEL_CHUNKS);
    let permits = Arc::new(Semaphore::new(CHANNEL_CHUNKS));
    let task = runtime.spawn(start(sender, Arc::clone(&permits)));
    ChannelReader {
        receiver,
        permits,
        task: task.abort_handle(),
        deadline,
        chunk: Vec::new(),
        offset: 0,
        state: ReaderState::Open,
    }
}

/// Pulls `chunks` into the channel until they end, break off or reach `limit` bytes, then
/// stops pulling. A chunk is sent only once the channel has room for it (one permit per
/// slot, returned by the reader as it takes a message), so the task never blocks its
/// runtime and never runs ahead of the reader by more than [`CHANNEL_CHUNKS`] chunks.
pub(super) async fn pump<B, S>(
    chunks: S,
    sender: SyncSender<Message>,
    permits: Arc<Semaphore>,
    limit: u64,
) where
    B: AsRef<[u8]>,
    S: Stream<Item = Result<B, &'static str>>,
{
    let mut chunks = pin!(chunks);
    let mut pulled: u64 = 0;
    while pulled < limit {
        let message = match chunks.next().await {
            None => break,
            Some(Err(detail)) => Message::Failed(detail),
            Some(Ok(chunk)) => {
                let bytes = chunk.as_ref();
                let room = usize::try_from(limit.saturating_sub(pulled)).unwrap_or(usize::MAX);
                let taken = bytes.get(..room.min(bytes.len())).unwrap_or(bytes);
                if taken.is_empty() {
                    continue;
                }
                pulled = pulled.saturating_add(u64::try_from(taken.len()).unwrap_or(u64::MAX));
                Message::Chunk(taken.to_vec())
            }
        };
        let failed = matches!(message, Message::Failed(_));
        if !deliver(&sender, &permits, message).await || failed {
            return;
        }
    }
    deliver(&sender, &permits, Message::End).await;
}

/// Sends `message` once the channel has room; `false` if the reader is gone.
async fn deliver(sender: &SyncSender<Message>, permits: &Semaphore, message: Message) -> bool {
    match permits.acquire().await {
        Ok(permit) => permit.forget(),
        Err(_) => return false,
    }
    sender.try_send(message).is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReaderState {
    Open,
    Ended,
    Failed(io::ErrorKind, &'static str),
}

/// The synchronous reader of a body the transfer task streams.
pub(super) struct ChannelReader {
    receiver: Receiver<Message>,
    permits: Arc<Semaphore>,
    task: AbortHandle,
    deadline: Instant,
    /// The chunk being read, and how much of it was.
    chunk: Vec<u8>,
    offset: usize,
    state: ReaderState,
}

impl ChannelReader {
    /// What is left of the deadline.
    fn time_left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let mut rest: &[u8] = self.chunk.get(self.offset..).unwrap_or_default();
            if !rest.is_empty() {
                let read = rest.read(buf)?;
                self.offset = self.offset.saturating_add(read);
                return Ok(read);
            }
            match self.state {
                ReaderState::Open => {}
                ReaderState::Ended => return Ok(0),
                ReaderState::Failed(kind, detail) => return Err(io::Error::new(kind, detail)),
            }
            match self.receiver.recv_timeout(self.time_left()) {
                Ok(message) => {
                    self.permits.add_permits(1);
                    match message {
                        Message::Chunk(chunk) => {
                            self.chunk = chunk;
                            self.offset = 0;
                        }
                        Message::End => self.state = ReaderState::Ended,
                        Message::Failed(detail) => {
                            self.state = ReaderState::Failed(io::ErrorKind::Other, detail);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.task.abort();
                    self.state = ReaderState::Failed(io::ErrorKind::TimedOut, TIMED_OUT);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.state = ReaderState::Failed(io::ErrorKind::UnexpectedEof, ENDED_EARLY);
                }
            }
        }
    }
}

impl Drop for ChannelReader {
    fn drop(&mut self) {
        self.permits.close();
        self.task.abort();
    }
}
