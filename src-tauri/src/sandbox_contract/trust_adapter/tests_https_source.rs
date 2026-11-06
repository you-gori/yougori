//! The HTTPS source without any network (VM-W45, plan line 2668; M18E in
//! docs/combined-plan-leftover-tasks.md, lines 346–350): item names under the configured
//! base and the refusal of a base that is not plain `https`, the redirect rule and the
//! status mapping as pure functions, a request that carries no credential, and the bounded
//! synchronous reader over fake chunk streams on a real Tokio runtime: the bound, the
//! deadline, cancellation on drop and a body that breaks off. Nothing here resolves a name
//! or opens a connection; `HttpsSource::open` itself is left to live validation (E05).

use std::io::{ErrorKind, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{self, Stream};
use reqwest::{header, Method, StatusCode, Url};
use tokio::runtime::Runtime;

use super::https_source::{
    base_url, may_follow, pump, spawn_reader, status_outcome, ChannelReader,
};
use super::tests::location;
use super::*;
use crate::foundation::ids::ContentKey;
use crate::sandbox::trust::{MetadataVersion, Role, TargetName};

const BASE: &str = "https://yougori.com/releases/sandbox/trust/";

/// A runtime whose one worker runs the transfer task while the test thread reads.
fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap()
}

fn source(runtime: &Runtime) -> HttpsSource {
    HttpsSource::new(
        &location(),
        runtime.handle().clone(),
        SourceTimeouts::default(),
    )
    .unwrap()
}

fn metadata(role: Role, version: Option<u64>) -> SourceItem {
    SourceItem::Metadata {
        role,
        version: version.map(MetadataVersion::new),
    }
}

/// Reports when the fake stream holding it is dropped, as it is when the transfer task
/// stops pulling or is cancelled.
struct Dropped(Sender<()>);

impl Drop for Dropped {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// A body of `items`, counting each item pulled; it then ends, or hangs if `hang`.
fn body(
    items: Vec<Result<Vec<u8>, &'static str>>,
    hang: bool,
    pulled: &Arc<AtomicUsize>,
) -> (
    impl Stream<Item = Result<Vec<u8>, &'static str>> + Send + 'static,
    Receiver<()>,
) {
    let (dropped, released) = channel();
    let pulled = Arc::clone(pulled);
    let stream = stream::unfold(
        (items.into_iter(), Dropped(dropped)),
        move |(mut rest, guard)| {
            let pulled = Arc::clone(&pulled);
            async move {
                match rest.next() {
                    Some(item) => {
                        pulled.fetch_add(1, Ordering::SeqCst);
                        Some((item, (rest, guard)))
                    }
                    None if hang => std::future::pending().await,
                    None => None,
                }
            }
        },
    );
    (stream, released)
}

/// The reader of `chunks` with the bound `max_bytes` and `timeout` left.
fn reader_of<S>(runtime: &Runtime, chunks: S, max_bytes: u64, timeout: Duration) -> ChannelReader
where
    S: Stream<Item = Result<Vec<u8>, &'static str>> + Send + 'static,
{
    let deadline = Instant::now() + timeout;
    spawn_reader(runtime.handle(), deadline, move |sender, permits| {
        pump(chunks, sender, permits, max_bytes.saturating_add(1))
    })
}

const WAIT: Duration = Duration::from_secs(10);

/// Waits until `pulled` reaches `count`, for at most [`WAIT`].
fn wait_for(pulled: &AtomicUsize, count: usize) {
    let started = Instant::now();
    while pulled.load(Ordering::SeqCst) < count {
        assert!(started.elapsed() < WAIT, "{count} chunks never pulled");
        std::thread::yield_now();
    }
}

#[test]
fn items_are_named_under_the_configured_https_base_from_typed_values_only() {
    let runtime = runtime();
    let source = source(&runtime);
    assert_eq!(source.base().as_str(), BASE);
    assert_eq!(base_url(BASE).unwrap(), *source.base());
    let at = |item: SourceItem| source.url(&item).unwrap().to_string();
    assert_eq!(
        at(metadata(Role::Root, Some(3))),
        format!("{BASE}3.root.json")
    );
    assert_eq!(
        at(metadata(Role::Timestamp, None)),
        format!("{BASE}timestamp.json")
    );
    assert_eq!(
        at(metadata(Role::Snapshot, Some(7))),
        format!("{BASE}7.snapshot.json")
    );
    assert_eq!(
        at(metadata(Role::Targets, Some(7))),
        format!("{BASE}7.targets.json")
    );
    assert_eq!(
        at(metadata(Role::Revocation, None)),
        format!("{BASE}revocation.json")
    );
    // An artifact is named by its content key alone, never by its target name.
    let content_key = ContentKey::of(b"vmlinuz-6.6.52-yougori");
    let artifact = SourceItem::Artifact {
        name: TargetName::new("guest-kernel").unwrap(),
        content_key,
    };
    let hex = content_key.to_string();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(at(artifact.clone()), format!("{BASE}artifacts/{hex}"));
    assert_eq!(artifact.path(), format!("artifacts/{hex}"));
    assert!(!at(artifact).contains("guest-kernel"));
}

#[test]
fn a_base_that_is_not_plain_https_and_unusable_timeouts_are_refused() {
    for (location, refusal) in [
        ("http://yougori.com/releases", HttpsSourceError::NotHttps),
        ("file:///C:/releases", HttpsSourceError::NotHttps),
        ("ftp://yougori.com/releases", HttpsSourceError::NotHttps),
        (
            "https://user:token@yougori.com/releases",
            HttpsSourceError::NotPlain,
        ),
        (
            "https://user@yougori.com/releases",
            HttpsSourceError::NotPlain,
        ),
        (
            "https://yougori.com:8443/releases",
            HttpsSourceError::NotPlain,
        ),
        (
            "https://yougori.com/releases?token=abc",
            HttpsSourceError::NotPlain,
        ),
        (
            "https://yougori.com/releases#top",
            HttpsSourceError::NotPlain,
        ),
        ("yougori.com/releases", HttpsSourceError::Malformed),
        ("", HttpsSourceError::Malformed),
    ] {
        assert_eq!(base_url(location), Err(refusal), "{location}");
    }
    // The default port is no port.
    assert_eq!(
        base_url("https://yougori.com:443/releases/sandbox/trust")
            .unwrap()
            .as_str(),
        BASE
    );

    let runtime = runtime();
    let build = |timeouts| HttpsSource::new(&location(), runtime.handle().clone(), timeouts);
    for timeouts in [
        SourceTimeouts {
            connect: Duration::ZERO,
            ..SourceTimeouts::default()
        },
        SourceTimeouts {
            request: Duration::ZERO,
            ..SourceTimeouts::default()
        },
        SourceTimeouts {
            request: MAX_REQUEST_TIMEOUT + Duration::from_secs(1),
            ..SourceTimeouts::default()
        },
    ] {
        assert_eq!(build(timeouts).map(|_| ()), Err(HttpsSourceError::Timeout));
    }
    assert!(build(SourceTimeouts {
        connect: Duration::from_secs(1),
        request: MAX_REQUEST_TIMEOUT,
    })
    .is_ok());
}

#[test]
fn redirects_are_followed_only_within_the_base_scheme_host_and_port() {
    let base = base_url(location().as_str()).unwrap();
    for (target, followed) in [
        (
            "https://yougori.com/releases/sandbox/trust/3.root.json",
            true,
        ),
        ("https://yougori.com/mirror/timestamp.json", true),
        ("https://yougori.com:443/releases/timestamp.json", true),
        ("http://yougori.com/releases/timestamp.json", false),
        ("https://cdn.yougori.com/releases/timestamp.json", false),
        ("https://yougori.com.example.org/timestamp.json", false),
        ("https://yougori.com:8443/releases/timestamp.json", false),
        ("https://203.0.113.7/releases/timestamp.json", false),
        ("https://user@yougori.com/releases/timestamp.json", false),
        (
            "https://user:token@yougori.com/releases/timestamp.json",
            false,
        ),
        ("ftp://yougori.com/releases/timestamp.json", false),
    ] {
        assert_eq!(
            may_follow(&base, &Url::parse(target).unwrap()),
            followed,
            "{target}"
        );
    }
}

#[test]
fn statuses_map_to_not_found_or_a_short_unavailable_detail() {
    let outcome = |code| status_outcome(StatusCode::from_u16(code).unwrap());
    assert_eq!(outcome(200), Ok(()));
    assert_eq!(outcome(404), Err(SourceError::NotFound));
    for code in [400, 401, 403, 410, 429, 500, 502, 503] {
        assert_eq!(
            outcome(code),
            Err(SourceError::Unavailable {
                detail: format!("the metadata location answered {code}")
            }),
            "{code}"
        );
    }
    for code in [301, 302, 303, 307, 308] {
        assert_eq!(
            outcome(code),
            Err(SourceError::Unavailable {
                detail: "the metadata location redirected to another origin, or too often"
                    .to_owned()
            }),
            "{code}"
        );
    }
}

#[test]
fn a_request_is_a_plain_get_without_credentials_or_cookies() {
    let runtime = runtime();
    let source = source(&runtime);
    for item in [
        metadata(Role::Timestamp, None),
        metadata(Role::Root, Some(2)),
        SourceItem::Artifact {
            name: TargetName::new("guest-image").unwrap(),
            content_key: ContentKey::of(b"rootfs"),
        },
    ] {
        let request = source.request(&item).unwrap();
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.url().as_str(), source.url(&item).unwrap().as_str());
        assert!(request.url().username().is_empty());
        assert!(request.url().password().is_none());
        assert!(request.url().query().is_none());
        for name in [
            header::AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            header::COOKIE,
            header::REFERER,
        ] {
            assert!(request.headers().get(&name).is_none(), "{name}");
        }
        assert!(request.headers().is_empty());
        assert!(request.body().is_none());
    }
}

#[test]
fn the_reader_yields_at_most_one_byte_past_the_bound_and_pulls_no_more() {
    let runtime = runtime();
    let chunks = || vec![Ok(vec![1; 10]), Ok(vec![2; 10]), Ok(vec![3; 10])];

    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, released) = body(chunks(), false, &pulled);
    let mut over = reader_of(&runtime, stream, 15, WAIT);
    let mut read = Vec::new();
    over.read_to_end(&mut read).unwrap();
    // Sixteen bytes, for the client to judge as over its bound of fifteen.
    assert_eq!(read, [vec![1; 10], vec![2; 6]].concat());
    // The transfer stopped there: the third chunk was never pulled, and the body was let go.
    released.recv_timeout(WAIT).unwrap();
    assert_eq!(pulled.load(Ordering::SeqCst), 2);
    assert_eq!(over.read(&mut [0; 4]).unwrap(), 0);

    // A body within its bound is read whole, and ends.
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, _released) = body(chunks(), false, &pulled);
    let mut within = reader_of(&runtime, stream, 30, WAIT);
    let mut read = Vec::new();
    within.read_to_end(&mut read).unwrap();
    assert_eq!(read, [vec![1; 10], vec![2; 10], vec![3; 10]].concat());
    assert_eq!(pulled.load(Ordering::SeqCst), 3);
}

#[test]
fn the_transfer_runs_at_most_the_channel_ahead_of_the_reader() {
    let runtime = runtime();
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, _released) = body(
        (0..100).map(|byte| Ok(vec![byte])).collect(),
        false,
        &pulled,
    );
    let mut reader = reader_of(&runtime, stream, 1_000, WAIT);
    // Nothing is read yet: the task fills the channel, pulls one chunk more and waits for
    // room, however long the reader takes.
    wait_for(&pulled, CHANNEL_CHUNKS + 1);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(pulled.load(Ordering::SeqCst), CHANNEL_CHUNKS + 1);
    let mut read = Vec::new();
    reader.read_to_end(&mut read).unwrap();
    assert_eq!(read, (0..100).collect::<Vec<u8>>());
}

#[test]
fn a_read_waits_no_longer_than_the_deadline_and_then_cancels_the_transfer() {
    let runtime = runtime();
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, released) = body(vec![Ok(vec![7; 4])], true, &pulled);
    let mut reader = reader_of(&runtime, stream, 1_000, Duration::from_millis(300));
    let mut buffer = [0; 16];
    assert_eq!(reader.read(&mut buffer).unwrap(), 4);
    assert_eq!(buffer[..4], [7; 4]);
    let started = Instant::now();
    let error = reader.read(&mut buffer).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(started.elapsed() < WAIT);
    // The transfer was cancelled, and the reader stays failed.
    released.recv_timeout(WAIT).unwrap();
    assert_eq!(
        reader.read(&mut buffer).unwrap_err().kind(),
        ErrorKind::TimedOut
    );
}

#[test]
fn dropping_the_reader_cancels_the_transfer() {
    let runtime = runtime();
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, released) = body(vec![Ok(vec![7; 4])], true, &pulled);
    let mut reader = reader_of(&runtime, stream, 1_000, WAIT);
    assert_eq!(reader.read(&mut [0; 16]).unwrap(), 4);
    assert_eq!(released.try_recv(), Err(TryRecvError::Empty));
    drop(reader);
    released.recv_timeout(WAIT).unwrap();

    // Also while the task waits for room in a full channel.
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, released) = body((0..100).map(|byte| Ok(vec![byte])).collect(), true, &pulled);
    let reader = reader_of(&runtime, stream, 1_000, WAIT);
    wait_for(&pulled, CHANNEL_CHUNKS + 1);
    drop(reader);
    released.recv_timeout(WAIT).unwrap();
}

#[test]
fn a_body_that_breaks_off_is_an_error_after_the_bytes_before_it() {
    let runtime = runtime();
    let pulled = Arc::new(AtomicUsize::new(0));
    let (stream, released) = body(
        vec![
            Ok(b"abc".to_vec()),
            Err("the body broke off"),
            Ok(b"never".to_vec()),
        ],
        false,
        &pulled,
    );
    let mut reader = reader_of(&runtime, stream, 1_000, WAIT);
    let mut read = Vec::new();
    let error = reader.read_to_end(&mut read).unwrap_err();
    assert_eq!(read, b"abc");
    assert_eq!(error.kind(), ErrorKind::Other);
    assert_eq!(error.to_string(), "the body broke off");
    // The transfer stopped at the break.
    released.recv_timeout(WAIT).unwrap();
    assert_eq!(pulled.load(Ordering::SeqCst), 2);
    assert_eq!(
        reader.read(&mut [0; 4]).unwrap_err().kind(),
        ErrorKind::Other
    );

    // A transfer that stops without saying the body ended is an early end, not an end.
    let deadline = Instant::now() + WAIT;
    let mut cut = spawn_reader(runtime.handle(), deadline, |sender, _permits| async move {
        drop(sender);
    });
    assert_eq!(
        cut.read(&mut [0; 4]).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
}

#[test]
fn the_source_is_the_trust_clients_fetch_port_with_items_and_errors_mapped_one_to_one() {
    use crate::sandbox::trust::{FetchError, FetchItem, FetchPort};

    fn is_fetch_port<P: FetchPort>() {}
    is_fetch_port::<HttpsSource>();

    let version = MetadataVersion::new(4);
    let key = ContentKey::of(b"artifact");
    let name = TargetName::new("guest-image").unwrap();
    let pairs = [
        (
            FetchItem::Metadata {
                role: Role::Root,
                version: Some(version),
            },
            SourceItem::Metadata {
                role: Role::Root,
                version: Some(version),
            },
        ),
        (
            FetchItem::Metadata {
                role: Role::Timestamp,
                version: None,
            },
            SourceItem::Metadata {
                role: Role::Timestamp,
                version: None,
            },
        ),
        (
            FetchItem::Artifact {
                name: name.clone(),
                content_key: key,
            },
            SourceItem::Artifact {
                name,
                content_key: key,
            },
        ),
    ];
    for (asked, fetched) in pairs {
        assert_eq!(SourceItem::from(&asked), fetched);
    }
    assert_eq!(
        FetchError::from(SourceError::NotFound),
        FetchError::NotFound
    );
    assert_eq!(
        FetchError::from(SourceError::Unavailable {
            detail: "the metadata location timed out".into()
        }),
        FetchError::Unavailable {
            detail: "the metadata location timed out".into()
        }
    );
}
