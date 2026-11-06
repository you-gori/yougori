//! The file protocol and its dispatcher against a real file service on temporary trees
//! (VM part §3.2, §5.1; VM-W14).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::dispatch::REPLY_RESERVE_BYTES;
use super::*;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{ExecutionCategory, ManualClock, MonotonicTime, TrustScope};
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantRefusal, GrantedRoot,
    GuestName, ListedEntry, ListedKind, Listing, NameRefusal, ResolveRefusal, ServiceRefusal,
    MAX_LISTED_ENTRIES, MAX_NAME_BYTES, MAX_READ_BYTES,
};

const ALL: [FileOperation; 7] = [
    FileOperation::Read,
    FileOperation::List,
    FileOperation::Create,
    FileOperation::Write,
    FileOperation::Delete,
    FileOperation::Rename,
    FileOperation::SetExecutable,
];

const SECRET: &[u8] = b"host secret beside the root";
const LIMIT: u64 = DEFAULT_MAX_MESSAGE_BYTES;

fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

fn scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

fn id(value: u64) -> RequestId {
    RequestId::new(value)
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

/// The smallest window the default limits accept.
fn tight() -> ChannelLimits {
    let base = ChannelLimits::default();
    ChannelLimits {
        max_window_bytes: base.listing_reservation(),
        ..base
    }
}

/// A dispatcher over a fresh root with a secret file beside it. The dispatcher is dropped
/// first, closing the service's handles before the temporary directory goes.
struct Channel {
    dispatcher: FileDispatcher<Arc<ManualClock>>,
    clock: Arc<ManualClock>,
    dir: tempfile::TempDir,
}

impl Channel {
    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    /// Sends every message of a request; only the last may be answered.
    fn send(&mut self, request_id: u64, operation: GuestOperation) -> FileResponse {
        let limit = self.dispatcher.limits().max_message_bytes;
        let messages = GuestRequest {
            id: id(request_id),
            operation,
        }
        .encode(limit)
        .unwrap();
        let (last, earlier) = messages.split_last().unwrap();
        for message in earlier {
            assert!(matches!(
                self.dispatcher.receive(message),
                Received::Buffered
            ));
        }
        self.reply(last)
    }

    /// The response to one message that must be answered.
    fn reply(&mut self, payload: &[u8]) -> FileResponse {
        self.dispatcher.dispatch(payload).unwrap()
    }
}

/// The parts of a grant to "sandbox-a" on session 1 that expires at 100 s, over a fresh
/// root with a secret beside it.
fn served(operations: &[FileOperation]) -> (FileService, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let root_path = dir.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(dir.path().join("secret.txt"), SECRET).unwrap();
    let root = GrantedRoot::open(&root_path).unwrap();
    let grant = FileGrant::new(
        root.handle(),
        GrantMode::QuarantineOutput,
        operations.iter().copied().collect::<BTreeSet<_>>(),
        scope("sandbox-a"),
        session(1),
        at(100),
        FileQuota {
            max_total_bytes: 1 << 26,
            max_entries: 1_000,
            max_file_bytes: 1 << 25,
        },
    )
    .unwrap();
    (FileService::new(grant, root).unwrap(), dir)
}

/// A channel authenticated as "sandbox-a" on a clock of `channel_session`; the clock starts
/// at 1 s.
fn channel_with(channel_session: ClockSession, limits: ChannelLimits) -> Channel {
    let (service, dir) = served(&ALL);
    let clock = Arc::new(ManualClock::new(at(1)));
    let dispatcher = FileDispatcher::new(
        service,
        scope("sandbox-a"),
        Arc::clone(&clock),
        channel_session,
        limits,
    )
    .unwrap();
    Channel {
        dispatcher,
        clock,
        dir,
    }
}

fn channel() -> Channel {
    channel_with(session(1), ChannelLimits::default())
}

/// The one message of a request that fits one.
fn message(request_id: u64, operation: GuestOperation) -> Vec<u8> {
    let mut messages = GuestRequest {
        id: id(request_id),
        operation,
    }
    .encode(LIMIT)
    .unwrap();
    assert_eq!(messages.len(), 1);
    messages.remove(0)
}

/// A header written as text, ended by its newline.
fn line(header: &str) -> Vec<u8> {
    format!("{header}\n").into_bytes()
}

/// A hand-written header line followed by `content`.
fn raw(header: &Value, content: &[u8]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(header).unwrap();
    bytes.push(b'\n');
    bytes.extend_from_slice(content);
    bytes
}

/// A message's header, parsed, and its content.
fn split(message: &[u8]) -> (Value, &[u8]) {
    let end = message.iter().position(|byte| *byte == b'\n').unwrap();
    (
        serde_json::from_slice(&message[..end]).unwrap(),
        &message[end + 1..],
    )
}

fn completed(response: FileResponse, request_id: u64) -> Completed {
    match response {
        FileResponse::Answer {
            request_id: answered,
            outcome: ResponseOutcome::Completed(completed),
        } if answered == id(request_id) => completed,
        other => panic!("{other:?}"),
    }
}

fn service_refusal(response: FileResponse) -> ServiceRefusal {
    match response {
        FileResponse::Answer {
            outcome: ResponseOutcome::ServiceRefused(refusal),
            ..
        } => refusal,
        other => panic!("{other:?}"),
    }
}

/// A protocol refusal and the id it claimed.
fn refused(response: &FileResponse) -> (Option<RequestId>, ProtocolRefusal) {
    match response {
        FileResponse::Refusal {
            claimed_request_id,
            refusal,
        } => (*claimed_request_id, refusal.clone()),
        other => panic!("{other:?}"),
    }
}

fn refusal(response: &FileResponse) -> ProtocolRefusal {
    refused(response).1
}

/// The admission of one message that must be admitted.
fn admitted(dispatcher: &mut FileDispatcher<Arc<ManualClock>>, payload: &[u8]) -> Admitted {
    match dispatcher.receive(payload) {
        Received::Admitted(admitted) => admitted,
        other => panic!("{other:?}"),
    }
}

fn is_malformed(refusal: &ProtocolRefusal) -> bool {
    matches!(refusal, ProtocolRefusal::Malformed { .. })
}

fn read(text: &str, max_bytes: u64) -> GuestOperation {
    GuestOperation::Read {
        name: name(text),
        max_bytes,
    }
}

fn create(text: &str, content: &[u8]) -> GuestOperation {
    GuestOperation::Create {
        name: name(text),
        content: content.to_vec(),
    }
}

fn create_directory(text: &str) -> GuestOperation {
    GuestOperation::CreateDirectory { name: name(text) }
}

fn list_root() -> GuestOperation {
    GuestOperation::List { name: None }
}

fn patterned(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn every_operation() -> Vec<GuestOperation> {
    vec![
        read("out/a.txt", 64),
        list_root(),
        GuestOperation::List {
            name: Some(name("out")),
        },
        create("out/a.txt", b"hello"),
        create_directory("out"),
        GuestOperation::Write {
            name: name("out/a.txt"),
            content: b"changed\n".to_vec(),
        },
        GuestOperation::Delete {
            name: name("out/a.txt"),
        },
        GuestOperation::Rename {
            from: name("out/a.txt"),
            to: name("out/b.txt"),
            replace: false,
        },
        GuestOperation::SetExecutable {
            name: name("out/a.txt"),
            executable: true,
        },
    ]
}

#[test]
fn every_request_encodes_and_decodes_exactly() {
    for operation in every_operation() {
        let declared_length = length(operation.content().unwrap_or_default());
        let encoded = message(42, operation.clone());
        assert_eq!(
            RequestPart::decode(&encoded),
            Ok(RequestPart::Opening {
                id: id(42),
                operation,
                declared_length,
            })
        );
    }
    let write = message(
        7,
        GuestOperation::Write {
            name: name("out/a.txt"),
            content: b"hello".to_vec(),
        },
    );
    let mut expected = line(concat!(
        r#"{"version":1,"request_id":7,"part":0,"request":"#,
        r#"{"operation":"write","name":"out/a.txt","length":5}}"#
    ));
    expected.extend_from_slice(b"hello");
    assert_eq!(write, expected);
    // A root listing may leave its name out.
    let root = raw(
        &json!({"version": 1, "request_id": 3, "part": 0, "request": {"operation": "list"}}),
        b"",
    );
    assert!(matches!(
        RequestPart::decode(&root),
        Ok(RequestPart::Opening {
            operation: GuestOperation::List { name: None },
            ..
        })
    ));
    assert!(serde_json::from_str::<FileProtocolVersion>("1").is_ok());
    assert!(serde_json::from_str::<FileProtocolVersion>("2").is_err());
}

#[test]
fn large_content_travels_in_numbered_parts_both_ways() {
    let mut channel = channel();
    let content = patterned(200_000);
    let parts = GuestRequest {
        id: id(1),
        operation: create("big.bin", &content),
    }
    .encode(LIMIT)
    .unwrap();
    assert!(parts.len() >= 4);
    assert!(parts.iter().all(|part| length(part) <= LIMIT));
    let (first, _) = split(&parts[0]);
    assert_eq!(first["request"]["length"], json!(200_000));
    assert_eq!(
        split(&parts[1]).0,
        json!({"version": 1, "request_id": 1, "part": 1})
    );
    let (last, earlier) = parts.split_last().unwrap();
    for part in earlier {
        assert!(matches!(
            channel.dispatcher.receive(part),
            Received::Buffered
        ));
    }
    assert_eq!(channel.dispatcher.buffered_bytes(), 200_000);
    assert_eq!(channel.dispatcher.incomplete().collect::<Vec<_>>(), [id(1)]);
    let Received::Admitted(admitted) = channel.dispatcher.receive(last) else {
        panic!("the last part completes the request");
    };
    assert_eq!(channel.dispatcher.buffered_bytes(), 0);
    assert_eq!(
        admitted.request().operation.content(),
        Some(content.as_slice())
    );
    assert_eq!(
        completed(channel.dispatcher.perform(admitted), 1),
        Completed::Created
    );
    assert_eq!(fs::read(channel.root().join("big.bin")).unwrap(), content);

    // One service read, split on the way out.
    let response = channel.send(2, read("big.bin", 200_000));
    let messages = channel.dispatcher.encode(&response).unwrap();
    assert!(messages.len() >= 4);
    let mut body = Vec::new();
    for (part, message) in messages.iter().enumerate() {
        assert!(length(message) <= LIMIT);
        let (header, chunk) = split(message);
        assert_eq!(header["request_id"], json!(2));
        assert_eq!(header["part"], json!(part));
        if part == 0 {
            assert_eq!(
                header["outcome"],
                json!({"kind": "read", "length": 200_000})
            );
        } else {
            assert_eq!(header.as_object().unwrap().len(), 3);
        }
        body.extend_from_slice(chunk);
    }
    assert_eq!(body, content);
    let total: u64 = messages.iter().map(|message| length(message)).sum();
    assert_eq!(response.encoded_len(LIMIT), Ok(total));
}

#[test]
fn parts_must_continue_a_request_in_order_within_the_buffer() {
    let limits = ChannelLimits {
        max_message_bytes: MIN_MESSAGE_BYTES,
        max_buffered_bytes: 50_000,
        ..ChannelLimits::default()
    };
    let mut channel = channel_with(session(1), limits);
    let continuation = |request_id: u64, part: u64, content: &[u8]| {
        raw(
            &json!({"version": 1, "request_id": request_id, "part": part}),
            content,
        )
    };
    assert_eq!(
        refused(&channel.reply(&continuation(9, 1, b"orphan"))),
        (Some(id(9)), ProtocolRefusal::UnexpectedPart)
    );

    let parts = GuestRequest {
        id: id(1),
        operation: create("a.bin", &patterned(40_000)),
    }
    .encode(MIN_MESSAGE_BYTES)
    .unwrap();
    assert!(parts.len() >= 3);
    assert!(channel.dispatcher.dispatch(&parts[0]).is_none());
    // The same id cannot open a second request while the first is being received.
    assert_eq!(
        refused(&channel.reply(&message(1, create_directory("x")))),
        (Some(id(1)), ProtocolRefusal::DuplicateRequestId)
    );
    assert_eq!(
        refusal(&channel.reply(&parts[2])),
        ProtocolRefusal::PartOutOfOrder {
            expected: 1,
            received: 2
        }
    );
    assert_eq!(channel.dispatcher.buffered_bytes(), 0);
    assert_eq!(channel.dispatcher.incomplete().count(), 0);
    assert_eq!(
        refusal(&channel.reply(&parts[1])),
        ProtocolRefusal::UnexpectedPart
    );

    let opening = |request_id: u64, declared: u64, content: &[u8]| {
        raw(
            &json!({"version": 1, "request_id": request_id, "part": 0,
                    "request": {"operation": "write", "name": "a.bin", "length": declared}}),
            content,
        )
    };
    assert!(channel
        .dispatcher
        .dispatch(&opening(2, 20_000, &[1; 10_000]))
        .is_none());
    assert_eq!(
        refusal(&channel.reply(&continuation(2, 1, b""))),
        ProtocolRefusal::EmptyPart
    );
    assert_eq!(
        refusal(&channel.reply(&continuation(2, 1, &[1; 15_000]))),
        ProtocolRefusal::LengthMismatch {
            declared: 20_000,
            actual: 25_000
        }
    );
    assert_eq!(channel.dispatcher.incomplete().count(), 0);
    assert_eq!(
        refusal(&channel.reply(&opening(3, 5, b"too long"))),
        ProtocolRefusal::LengthMismatch {
            declared: 5,
            actual: 8
        }
    );

    // The buffer bounds one request's content and the content received together.
    assert_eq!(
        refusal(&channel.reply(&opening(4, 50_001, b""))),
        ProtocolRefusal::ContentTooLarge {
            length: 50_001,
            limit: 50_000
        }
    );
    assert!(channel
        .dispatcher
        .dispatch(&opening(5, 30_000, b"start"))
        .is_none());
    assert_eq!(
        refusal(&channel.reply(&opening(6, 30_000, b"start"))),
        ProtocolRefusal::BufferFull {
            declared: 30_000,
            buffered: 30_000,
            limit: 50_000
        }
    );
    assert_eq!(
        channel.dispatcher.cancel_incomplete(id(5)),
        Some(FileResponse::Answer {
            request_id: id(5),
            outcome: ResponseOutcome::Cancelled
        })
    );
    assert_eq!(channel.dispatcher.cancel_incomplete(id(5)), None);
    assert_eq!(channel.dispatcher.buffered_bytes(), 0);
    assert!(channel
        .dispatcher
        .dispatch(&opening(6, 30_000, b"start"))
        .is_none());
    assert_eq!(channel.dispatcher.counters().performed, 0);
    assert_eq!(fs::read_dir(channel.root()).unwrap().count(), 0);
}

#[test]
fn every_operation_round_trips_through_the_dispatcher() {
    let mut channel = channel();
    let root = channel.root();

    assert_eq!(
        completed(channel.send(1, create_directory("out")), 1),
        Completed::DirectoryCreated
    );
    assert!(root.join("out").is_dir());
    assert_eq!(
        completed(channel.send(2, create("out/a.txt", b"hello")), 2),
        Completed::Created
    );
    assert_eq!(fs::read(root.join("out/a.txt")).unwrap(), b"hello");
    assert_eq!(
        completed(channel.send(3, read("out/a.txt", 64)), 3),
        Completed::Read {
            content: b"hello".to_vec()
        }
    );
    let rewrite = GuestOperation::Write {
        name: name("out/a.txt"),
        content: b"changed\n".to_vec(),
    };
    assert_eq!(completed(channel.send(4, rewrite), 4), Completed::Written);
    assert_eq!(fs::read(root.join("out/a.txt")).unwrap(), b"changed\n");
    let listed = GuestOperation::List {
        name: Some(name("out")),
    };
    assert_eq!(
        completed(channel.send(5, listed), 5),
        Completed::Listed {
            listing: Listing {
                entries: vec![ListedEntry {
                    name: name("a.txt"),
                    kind: ListedKind::File {
                        size_bytes: 8,
                        executable: false,
                    },
                }],
                unaddressable: 0,
                truncated: false,
            }
        }
    );
    let executable = GuestOperation::SetExecutable {
        name: name("out/a.txt"),
        executable: true,
    };
    assert_eq!(
        completed(channel.send(6, executable), 6),
        Completed::ExecutableSet
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("out/a.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
    let rename = GuestOperation::Rename {
        from: name("out/a.txt"),
        to: name("out/b.txt"),
        replace: false,
    };
    assert_eq!(completed(channel.send(7, rename), 7), Completed::Renamed);
    assert!(!root.join("out/a.txt").exists());
    assert_eq!(fs::read(root.join("out/b.txt")).unwrap(), b"changed\n");
    assert_eq!(
        completed(channel.send(8, list_root()), 8),
        Completed::Listed {
            listing: Listing {
                entries: vec![ListedEntry {
                    name: name("out"),
                    kind: ListedKind::Directory,
                }],
                unaddressable: 0,
                truncated: false,
            }
        }
    );
    let delete_file = GuestOperation::Delete {
        name: name("out/b.txt"),
    };
    assert_eq!(
        completed(channel.send(9, delete_file), 9),
        Completed::Deleted
    );
    let delete_directory = GuestOperation::Delete { name: name("out") };
    assert_eq!(
        completed(channel.send(10, delete_directory), 10),
        Completed::Deleted
    );
    assert!(!root.join("out").exists());
    // A refusal of the service's own comes back as it is.
    assert_eq!(
        service_refusal(channel.send(11, read("out/b.txt", 64))),
        ServiceRefusal::Resolve {
            refusal: ResolveRefusal::NotFound { at: name("out") }
        }
    );
    let counters = channel.dispatcher.counters();
    assert_eq!(counters.received, 11);
    assert_eq!(counters.admitted, 11);
    assert_eq!(counters.performed, 11);
    assert_eq!(counters.message_refusals, 0);
    assert_eq!(channel.dispatcher.in_flight(), 0);
}

#[test]
fn responses_are_header_lines_and_refusals_name_no_request() {
    let mut channel = channel();
    completed(channel.send(1, create("a.txt", b"two\nlines")), 1);
    let response = channel.send(2, read("a.txt", 64));
    let encoded = channel.dispatcher.encode(&response).unwrap();
    assert_eq!(encoded.len(), 1);
    let (header, content) = split(&encoded[0]);
    assert_eq!(
        header,
        json!({"version": 1, "request_id": 2, "part": 0,
               "outcome": {"kind": "read", "length": 9}})
    );
    assert_eq!(content, b"two\nlines");

    let missing = channel.send(3, read("missing.txt", 64));
    let expected = serde_json::to_value(ServiceRefusal::Resolve {
        refusal: ResolveRefusal::NotFound {
            at: name("missing.txt"),
        },
    })
    .unwrap();
    let encoded = channel.dispatcher.encode(&missing).unwrap();
    assert_eq!(
        split(&encoded[0]),
        (
            json!({"version": 1, "request_id": 3, "part": 0,
                   "outcome": {"kind": "service_refused", "refusal": expected}}),
            &b""[..]
        )
    );

    let unknown = channel.reply(&raw(
        &json!({"version": 1, "request_id": 4, "part": 0,
                "request": {"operation": "exec", "name": "a"}}),
        b"",
    ));
    let encoded = channel.dispatcher.encode(&unknown).unwrap();
    assert_eq!(
        split(&encoded[0]).0,
        json!({"version": 1, "request_id": null, "part": 0,
               "outcome": {"kind": "protocol_refused", "claimed_request_id": 4,
                           "refusal": {"kind": "unknown_operation"}}})
    );
    let anonymous = channel.reply(b"not json\n");
    let (header, _) = split(&channel.dispatcher.encode(&anonymous).unwrap()[0]);
    assert_eq!(header["request_id"], Value::Null);
    assert_eq!(header["outcome"]["claimed_request_id"], Value::Null);
    assert_eq!(header["outcome"]["refusal"]["kind"], json!("malformed"));
}

#[test]
fn protocol_refusals_cannot_be_attributed_to_a_request_in_flight() {
    let mut channel = channel();
    let Received::Admitted(pending) = channel.dispatcher.receive(&message(5, list_root())) else {
        panic!("the listing is admitted");
    };
    // A malformed message naming the id in flight (a value keeps the last of two).
    let spoof = line(concat!(
        r#"{"version":1,"request_id":9,"request_id":5,"part":0,"#,
        r#""request":{"operation":"list"}}"#
    ));
    let response = channel.reply(&spoof);
    let (claimed, reason) = refused(&response);
    assert_eq!(claimed, Some(id(5)));
    assert!(is_malformed(&reason));
    let (header, _) = split(&channel.dispatcher.encode(&response).unwrap()[0]);
    assert_eq!(header["request_id"], Value::Null);
    assert_eq!(header["outcome"]["claimed_request_id"], json!(5));

    let unknown = line(r#"{"version":1,"request_id":5,"part":0,"request":{"operation":"exec"}}"#);
    assert_eq!(
        refused(&channel.reply(&unknown)),
        (Some(id(5)), ProtocolRefusal::UnknownOperation)
    );
    let duplicate = channel.reply(&message(5, list_root()));
    assert_eq!(
        duplicate,
        FileResponse::Refusal {
            claimed_request_id: Some(id(5)),
            refusal: ProtocolRefusal::DuplicateRequestId
        }
    );
    let (header, _) = split(&channel.dispatcher.encode(&duplicate).unwrap()[0]);
    assert_eq!(header["request_id"], Value::Null);
    // Only the real answer carries the id.
    assert!(matches!(
        completed(channel.dispatcher.perform(pending), 5),
        Completed::Listed { .. }
    ));

    // A request refused for the window keeps the id it claimed apart as well.
    let mut tight = channel_with(session(1), tight());
    let greedy = read("a.txt", tight.dispatcher.limits().content_limit());
    let (claimed, reason) = refused(&tight.reply(&message(7, greedy)));
    assert_eq!(claimed, Some(id(7)));
    assert!(matches!(reason, ProtocolRefusal::ByteWindowExceeded { .. }));
}

#[test]
fn a_message_cannot_claim_a_scope_time_session_or_root() {
    let mut channel = channel();
    let base = json!({"version": 1, "request_id": 1, "part": 0,
                      "request": {"operation": "create_directory", "name": "out"}});
    let claims = [
        ("scope", serde_json::to_value(scope("sandbox-b")).unwrap()),
        ("now", json!(0)),
        ("session", json!(uuid::Uuid::from_u128(2).to_string())),
        ("root", json!("C:/Users")),
        ("expires_at", json!(u64::MAX)),
    ];
    for (field, value) in claims {
        for inside in [false, true] {
            let mut header = base.clone();
            let target = if inside {
                &mut header["request"]
            } else {
                &mut header
            };
            target[field] = value.clone();
            let (claimed, reason) = refused(&channel.reply(&raw(&header, b"")));
            assert_eq!(claimed, Some(id(1)));
            assert!(is_malformed(&reason), "{field}");
        }
    }
    assert_eq!(channel.dispatcher.counters().performed, 0);
    assert!(!channel.root().join("out").exists());
    // The same request without a claim is served.
    assert_eq!(
        completed(channel.reply(&raw(&base, b"")), 1),
        Completed::DirectoryCreated
    );
}

#[test]
fn only_the_channel_scope_and_the_host_clock_decide() {
    // A channel authenticated as another scope is refused before it serves anything.
    let (service, _dir) = served(&ALL);
    let other = FileDispatcher::new(
        service,
        scope("sandbox-b"),
        ManualClock::new(at(1)),
        session(1),
        ChannelLimits::default(),
    );
    assert!(matches!(other, Err(ChannelProblem::ScopeMismatch)));

    // A host clock of another session, such as after a restart.
    let mut restarted = channel_with(session(2), ChannelLimits::default());
    assert_eq!(
        service_refusal(restarted.send(1, list_root())),
        ServiceRefusal::Grant {
            refusal: GrantRefusal::OtherClock
        }
    );

    // The same message is refused once the host clock passes the grant's expiry.
    let mut channel = channel();
    let listing = message(1, list_root());
    assert!(matches!(
        completed(channel.reply(&listing), 1),
        Completed::Listed { .. }
    ));
    channel.clock.advance(Duration::from_secs(99));
    assert_eq!(
        service_refusal(channel.reply(&listing)),
        ServiceRefusal::Grant {
            refusal: GrantRefusal::Expired {
                expired_at: at(100)
            }
        }
    );
}

#[test]
fn unknown_and_duplicate_fields_are_refused_before_the_service() {
    let mut channel = channel();
    let mut malformed: Vec<Vec<u8>> = vec![
        raw(
            &json!({"version": 1, "request_id": 1, "part": 0, "extra": true,
                    "request": {"operation": "create_directory", "name": "out"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 1, "part": 0,
                    "request": {"operation": "create_directory", "name": "out", "mode": "live"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 1, "part": 0,
                    "request": {"operation": "read", "name": "a.txt", "max_bytes": "64"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 1, "part": 0,
                    "request": {"operation": "read", "name": "a.txt"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "part": 0,
                    "request": {"operation": "create_directory", "name": "out"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 1,
                    "request": {"operation": "create_directory", "name": "out"}}),
            b"",
        ),
        raw(&json!({"version": 1, "request_id": 1, "part": 0}), b""),
        raw(
            &json!({"version": 1, "request_id": 1, "part": 1,
                    "request": {"operation": "create_directory", "name": "out"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 1, "part": 1, "extra": 1}),
            b"x",
        ),
        line(concat!(
            r#"{"version":1,"request_id":1,"part":0,"request":"#,
            r#"{"operation":"create_directory","name":"out","name":"other"}}"#
        )),
        line(concat!(
            r#"{"version":1,"request_id":1,"request_id":2,"part":0,"request":"#,
            r#"{"operation":"create_directory","name":"out"}}"#
        )),
        line(concat!(
            r#"{"version":1,"request_id":1,"part":0,"request":"#,
            r#"{"operation":"create_directory","operation":"delete","name":"out"}}"#
        )),
        line(concat!(
            r#"{"version":1,"request_id":1,"part":0,"request":"#,
            r#"{"operation":"create_directory","name":"out"}} trailing"#
        )),
    ];
    // A number past every integer type, and nesting past the parser's depth.
    let digits = "9".repeat(10_000);
    malformed.push(line(&format!(
        "{{\"version\":1,\"request_id\":1,\"part\":0,\"request\":{{\"operation\":\"create\",\
         \"name\":\"a\",\"length\":{digits}}}}}"
    )));
    malformed.push(line(&"[".repeat(10_000)));
    for payload in &malformed {
        assert!(
            is_malformed(&refusal(&channel.reply(payload))),
            "{}",
            String::from_utf8_lossy(payload)
        );
    }
    let counters = channel.dispatcher.counters();
    assert_eq!(counters.performed, 0);
    assert_eq!(
        counters.message_refusals,
        u64::try_from(malformed.len()).unwrap()
    );
    assert!(!channel.root().join("out").exists());
}

#[test]
fn malformed_details_are_escaped_and_bounded() {
    let mut channel = channel();
    let field = format!("\u{1b}]52;c;{}\u{202e}\n", "x".repeat(4096));
    let mut header = json!({"version": 1, "request_id": 1, "part": 0,
                            "request": {"operation": "create_directory", "name": "out"}});
    header[field.as_str()] = json!(1);
    let response = channel.reply(&raw(&header, b""));
    let ProtocolRefusal::Malformed { detail } = refusal(&response) else {
        panic!("{response:?}");
    };
    assert!(detail.contains("unknown field"));
    assert!(!detail.contains('\u{1b}'));
    assert!(!detail.contains('\u{202e}'));
    assert!(!detail.contains('\n'));
    assert!(response.encoded_len(LIMIT).unwrap() <= REPLY_RESERVE_BYTES);
}

#[test]
fn oversized_messages_and_content_are_refused_before_the_service() {
    let mut channel = channel();
    let longest = usize::try_from(LIMIT).unwrap();
    assert_eq!(
        refused(&channel.reply(&vec![b' '; longest + 1])),
        (
            None,
            ProtocolRefusal::MessageTooLarge {
                bytes: LIMIT + 1,
                limit: LIMIT
            }
        )
    );
    let header_limit = usize::try_from(MAX_HEADER_BYTES).unwrap();
    assert_eq!(
        refusal(&channel.reply(&vec![b' '; header_limit + 1])),
        ProtocolRefusal::HeaderTooLarge {
            limit: MAX_HEADER_BYTES
        }
    );
    let content_limit = channel.dispatcher.limits().content_limit();
    assert_eq!(content_limit, DEFAULT_MAX_BUFFERED_BYTES);
    let declared_too_much = raw(
        &json!({"version": 1, "request_id": 2, "part": 0,
                "request": {"operation": "create", "name": "big.bin",
                            "length": content_limit + 1}}),
        b"small",
    );
    assert_eq!(
        refused(&channel.reply(&declared_too_much)),
        (
            Some(id(2)),
            ProtocolRefusal::ContentTooLarge {
                length: content_limit + 1,
                limit: content_limit
            }
        )
    );
    let past_every_channel = raw(
        &json!({"version": 1, "request_id": 3, "part": 0,
                "request": {"operation": "write", "name": "a",
                            "length": MAX_CONTENT_BYTES + 1}}),
        b"",
    );
    assert_eq!(
        RequestPart::decode(&past_every_channel)
            .unwrap_err()
            .refusal,
        ProtocolRefusal::ContentTooLarge {
            length: MAX_CONTENT_BYTES + 1,
            limit: MAX_CONTENT_BYTES
        }
    );
    let smuggled = raw(
        &json!({"version": 1, "request_id": 4, "part": 0,
                "request": {"operation": "create_directory", "name": "out"}}),
        b"tail",
    );
    assert_eq!(
        refusal(&channel.reply(&smuggled)),
        ProtocolRefusal::LengthMismatch {
            declared: 0,
            actual: 4
        }
    );
    assert_eq!(
        refusal(&channel.reply(&message(5, read("a.txt", content_limit + 1)))),
        ProtocolRefusal::ReadLimitTooLarge {
            max_bytes: content_limit + 1,
            limit: content_limit
        }
    );
    let greedy = raw(
        &json!({"version": 1, "request_id": 6, "part": 0,
                "request": {"operation": "read", "name": "a.txt",
                            "max_bytes": MAX_READ_BYTES + 1}}),
        b"",
    );
    assert_eq!(
        refusal(&channel.reply(&greedy)),
        ProtocolRefusal::ReadLimitTooLarge {
            max_bytes: MAX_READ_BYTES + 1,
            limit: MAX_READ_BYTES
        }
    );
    assert_eq!(channel.dispatcher.counters().performed, 0);
    assert_eq!(fs::read_dir(channel.root()).unwrap().count(), 0);
}

#[test]
fn content_up_to_the_buffer_is_written() {
    let mut channel = channel();
    let largest = usize::try_from(channel.dispatcher.limits().content_limit()).unwrap();
    let content = patterned(largest);
    assert_eq!(
        completed(channel.send(1, create("big.bin", &content)), 1),
        Completed::Created
    );
    assert_eq!(
        fs::metadata(channel.root().join("big.bin")).unwrap().len(),
        length(&content)
    );
}

#[test]
fn names_are_checked_by_the_existing_name_rules_before_the_service() {
    let mut channel = channel();
    let cases = [
        ("../secret.txt", NameRefusal::Traversal { index: 0 }),
        ("a/../../secret.txt", NameRefusal::Traversal { index: 1 }),
        ("..", NameRefusal::Traversal { index: 0 }),
        ("/etc/passwd", NameRefusal::AbsolutePath),
        ("C:\\Windows", NameRefusal::DrivePath),
        ("\\\\server\\share", NameRefusal::UncPath),
        (
            "a\\..\\secret.txt",
            NameRefusal::Backslash { byte_offset: 1 },
        ),
        (
            "file.txt:stream",
            NameRefusal::AlternateDataStream { byte_offset: 8 },
        ),
        ("dir/NUL", NameRefusal::ReservedName { index: 1 }),
        ("", NameRefusal::Empty),
    ];
    for (request_id, (text, name_refusal)) in (1..).zip(cases) {
        let header = json!({"version": 1, "request_id": request_id, "part": 0,
                            "request": {"operation": "read", "name": text, "max_bytes": 64}});
        assert_eq!(
            refused(&channel.reply(&raw(&header, b""))),
            (
                Some(id(request_id)),
                ProtocolRefusal::InvalidName {
                    field: NameField::Name,
                    refusal: name_refusal
                }
            ),
            "{text}"
        );
    }
    let rename_out = json!({"version": 1, "request_id": 20, "part": 0,
                            "request": {"operation": "rename", "from": "a.txt", "to": "../a.txt"}});
    assert_eq!(
        refusal(&channel.reply(&raw(&rename_out, b""))),
        ProtocolRefusal::InvalidName {
            field: NameField::To,
            refusal: NameRefusal::Traversal { index: 0 }
        }
    );
    let rename_in = json!({"version": 1, "request_id": 21, "part": 0,
                           "request": {"operation": "rename", "from": "../secret.txt",
                                       "to": "a.txt"}});
    assert_eq!(
        refusal(&channel.reply(&raw(&rename_in, b""))),
        ProtocolRefusal::InvalidName {
            field: NameField::From,
            refusal: NameRefusal::Traversal { index: 0 }
        }
    );
    let list_up = json!({"version": 1, "request_id": 22, "part": 0,
                         "request": {"operation": "list", "name": "../"}});
    assert!(matches!(
        refusal(&channel.reply(&raw(&list_up, b""))),
        ProtocolRefusal::InvalidName {
            field: NameField::Name,
            ..
        }
    ));
    assert_eq!(channel.dispatcher.counters().performed, 0);
    assert!(!channel.root().join("a.txt").exists());
    assert_eq!(
        fs::read(channel.dir.path().join("secret.txt")).unwrap(),
        SECRET
    );
}

#[test]
fn unknown_operations_and_versions_are_refused_before_the_service() {
    let mut channel = channel();
    for (request_id, operation) in (1..).zip(["exec", "chmod", "mount", "READ", "", "read "]) {
        let header = json!({"version": 1, "request_id": request_id, "part": 0,
                            "request": {"operation": operation, "name": "a.txt"}});
        assert_eq!(
            refused(&channel.reply(&raw(&header, b""))),
            (Some(id(request_id)), ProtocolRefusal::UnknownOperation)
        );
    }
    for version in [0, 2, u64::MAX] {
        let header = json!({"version": version, "request_id": 9, "part": 0,
                            "request": {"operation": "list"}});
        assert_eq!(
            refused(&channel.reply(&raw(&header, b""))),
            (
                Some(id(9)),
                ProtocolRefusal::UnsupportedVersion {
                    version,
                    supported: FILE_PROTOCOL_VERSION
                }
            )
        );
    }
    let malformed: Vec<Vec<u8>> = vec![
        raw(
            &json!({"request_id": 9, "part": 0, "request": {"operation": "list"}}),
            b"",
        ),
        raw(
            &json!({"version": "1", "request_id": 9, "part": 0,
                    "request": {"operation": "list"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 9, "part": 0, "request": {"name": "a"}}),
            b"",
        ),
        raw(
            &json!({"version": 1, "request_id": 9, "part": 0, "request": "list"}),
            b"",
        ),
        // serde reads a struct written as an array; the protocol does not.
        raw(&json!([1, 9, 0, {"operation": "list"}]), b""),
        raw(
            &json!({"version": 1, "request_id": 9, "part": 0, "request": ["list", null]}),
            b"",
        ),
        b"not json\n".to_vec(),
        br#"{"version":1,"request_id":9,"part":0,"request":{"operation":"list"}}"#.to_vec(),
        Vec::new(),
    ];
    for payload in &malformed {
        assert!(
            is_malformed(&refusal(&channel.reply(payload))),
            "{}",
            String::from_utf8_lossy(payload)
        );
    }
    assert_eq!(channel.dispatcher.counters().performed, 0);
}

#[test]
fn requests_in_flight_are_bounded_and_released() {
    let limits = ChannelLimits {
        max_in_flight: 2,
        ..ChannelLimits::default()
    };
    let mut channel = channel_with(session(1), limits);
    let root = channel.root();
    let dispatcher = &mut channel.dispatcher;
    let first = admitted(dispatcher, &message(1, create_directory("one")));
    let second = admitted(dispatcher, &message(2, create_directory("two")));
    assert_eq!(dispatcher.in_flight(), 2);
    assert_eq!(second.request().id, id(2));
    let Received::Refused(full) = dispatcher.receive(&message(3, create_directory("three"))) else {
        panic!("the channel is full");
    };
    assert_eq!(
        refused(&full),
        (Some(id(3)), ProtocolRefusal::TooManyInFlight { limit: 2 })
    );
    // Admitted is not performed.
    assert!(!root.join("one").exists());
    assert_eq!(
        completed(dispatcher.perform(first), 1),
        Completed::DirectoryCreated
    );
    assert!(root.join("one").is_dir());
    let Received::Refused(duplicate) = dispatcher.receive(&message(2, create_directory("again")))
    else {
        panic!("the id is in flight");
    };
    assert_eq!(
        refused(&duplicate),
        (Some(id(2)), ProtocolRefusal::DuplicateRequestId)
    );
    assert_eq!(
        dispatcher.cancel(second),
        FileResponse::Answer {
            request_id: id(2),
            outcome: ResponseOutcome::Cancelled
        }
    );
    assert!(!root.join("two").exists());
    assert_eq!(dispatcher.in_flight(), 0);
    // A finished id may be used again.
    let again = admitted(dispatcher, &message(2, create_directory("two")));
    assert_eq!(
        completed(dispatcher.perform(again), 2),
        Completed::DirectoryCreated
    );
    let counters = dispatcher.counters();
    assert_eq!(counters.admitted, 3);
    assert_eq!(counters.performed, 2);
    assert_eq!(counters.cancelled, 1);
    assert_eq!(counters.in_flight_refusals, 1);
    assert_eq!(counters.message_refusals, 1);

    // An admission is honoured only by the dispatcher that made it.
    let mut other = channel_with(session(1), ChannelLimits::default());
    let foreign = admitted(
        &mut other.dispatcher,
        &message(9, create_directory("foreign")),
    );
    assert_eq!(
        refused(&channel.dispatcher.perform(foreign)),
        (Some(id(9)), ProtocolRefusal::NotAdmitted)
    );
    assert!(!channel.root().join("foreign").exists());
    assert!(!other.root().join("foreign").exists());
    assert_eq!(other.dispatcher.in_flight(), 1);
}

#[test]
fn empty_messages_cost_the_minimum_and_every_reply_is_counted() {
    let limits = tight();
    let mut channel = channel_with(session(1), limits);
    let mut answered = 0u64;
    let mut sent = 0u64;
    let mut largest = 0u64;
    for _ in 0..10_000 {
        match channel.dispatcher.receive(b"") {
            Received::Refused(response) => {
                answered += 1;
                let bytes = response.encoded_len(LIMIT).unwrap();
                sent += bytes;
                largest = largest.max(bytes);
            }
            Received::Dropped => {}
            other => panic!("{other:?}"),
        }
    }
    let counters = channel.dispatcher.counters();
    assert_eq!(counters.sent_bytes, sent);
    assert_eq!(counters.byte_window_refusals, 1);
    assert_eq!(counters.message_refusals, answered - 1);
    assert_eq!(counters.dropped + answered, 10_000);
    assert!(counters.dropped > 5_000);
    assert_eq!(
        counters.received_bytes,
        (answered - 1) * MIN_MESSAGE_COST_BYTES
    );
    // One window: its bound, one refusal of a message that fit and the window's refusal.
    assert_eq!(
        channel.dispatcher.window_bytes(),
        counters.received_bytes + counters.sent_bytes
    );
    assert!(channel.dispatcher.window_bytes() <= limits.max_window_bytes + 2 * largest);
    // A new window answers again.
    channel.clock.advance(limits.window);
    let Received::Refused(response) = channel.dispatcher.receive(b"") else {
        panic!("a new window answers");
    };
    assert!(is_malformed(&refusal(&response)));
}

#[test]
fn bytes_per_window_are_counted_and_refused() {
    let limits = tight();
    let mut channel = channel_with(session(1), limits);
    let messages = GuestRequest {
        id: id(1),
        operation: create("a.bin", &patterned(1_000_000)),
    }
    .encode(LIMIT)
    .unwrap();
    let (last, earlier) = messages.split_last().unwrap();
    for message in earlier {
        assert!(channel.dispatcher.dispatch(message).is_none());
    }
    let created = channel.reply(last);
    let costs: u64 = messages
        .iter()
        .map(|message| length(message).max(MIN_MESSAGE_COST_BYTES))
        .sum();
    let used = costs + created.encoded_len(LIMIT).unwrap();
    assert_eq!(completed(created, 1), Completed::Created);
    assert_eq!(channel.dispatcher.window_bytes(), used);

    // A read reserves the most its answer takes when it is admitted.
    let reading = read("a.bin", 1_000_000);
    let reservation = limits.reply_reservation(&reading);
    let greedy = message(2, reading.clone());
    let cost = length(&greedy).max(MIN_MESSAGE_COST_BYTES);
    assert_eq!(
        refused(&channel.reply(&greedy)),
        (
            Some(id(2)),
            ProtocolRefusal::ByteWindowExceeded {
                used_bytes: used + cost,
                requested_bytes: reservation,
                limit_bytes: limits.max_window_bytes,
                retry_after_ms: 1_000
            }
        )
    );
    // Messages until the window is spent: one refusal, then drops.
    let spending = GuestRequest {
        id: id(3),
        operation: create("b.bin", &patterned(700_000)),
    }
    .encode(LIMIT)
    .unwrap();
    let outcome: Vec<Received> = spending
        .iter()
        .map(|message| channel.dispatcher.receive(message))
        .collect();
    let refusals: Vec<_> = outcome
        .iter()
        .filter_map(|received| match received {
            Received::Refused(response) => Some(refused(response)),
            _ => None,
        })
        .collect();
    // The part that first did not fit got the window's refusal; the next was dropped; the
    // short last part fit again, came out of order and discarded the request.
    assert!(matches!(
        refusals.as_slice(),
        [
            (None, ProtocolRefusal::ByteWindowExceeded { .. }),
            (Some(claimed), ProtocolRefusal::PartOutOfOrder { .. }),
        ] if *claimed == id(3)
    ));
    assert!(outcome
        .iter()
        .any(|received| matches!(received, Received::Dropped)));
    assert_eq!(channel.dispatcher.incomplete().count(), 0);
    assert_eq!(channel.dispatcher.buffered_bytes(), 0);
    channel.clock.advance(Duration::from_millis(400));
    assert!(matches!(
        channel
            .dispatcher
            .receive(&message(4, create("c.bin", &[0; 60_000]))),
        Received::Dropped
    ));
    let counters = channel.dispatcher.counters();
    assert_eq!(counters.byte_window_refusals, 2);
    assert!(counters.dropped >= 2);

    // The window ends on the host clock; the answer then replaces the reservation.
    channel.clock.advance(Duration::from_millis(600));
    let Received::Admitted(admitted) = channel.dispatcher.receive(&greedy) else {
        panic!("a new window admits the read");
    };
    assert_eq!(channel.dispatcher.window_bytes(), cost + reservation);
    let response = channel.dispatcher.perform(admitted);
    let answer = response.encoded_len(LIMIT).unwrap();
    assert!(answer <= reservation);
    assert_eq!(channel.dispatcher.window_bytes(), cost + answer);
    assert_eq!(
        completed(response, 2),
        Completed::Read {
            content: patterned(1_000_000)
        }
    );
}

#[test]
fn listings_reserve_their_worst_case() {
    let base = ChannelLimits::default();
    let reservation = base.listing_reservation();
    let limits = ChannelLimits {
        max_window_bytes: 2 * reservation + 4 * MIN_MESSAGE_COST_BYTES,
        ..base
    };
    let mut channel = channel_with(session(1), limits);
    for index in 0..50 {
        fs::write(channel.root().join(format!("{index:0>200}")), b"x").unwrap();
    }
    let admitted: Vec<Admitted> = (1..=2)
        .map(|request_id| {
            match channel
                .dispatcher
                .receive(&message(request_id, list_root()))
            {
                Received::Admitted(admitted) => admitted,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    let (claimed, reason) = refused(&channel.reply(&message(3, list_root())));
    assert_eq!(claimed, Some(id(3)));
    assert!(matches!(
        reason,
        ProtocolRefusal::ByteWindowExceeded {
            requested_bytes,
            ..
        } if requested_bytes == reservation
    ));
    for admitted in admitted {
        let response = channel.dispatcher.perform(admitted);
        assert!(response.encoded_len(LIMIT).unwrap() <= reservation);
    }
    assert!(channel.dispatcher.window_bytes() <= limits.max_window_bytes);
}

#[test]
fn a_full_listing_travels_in_pages_within_its_reservation() {
    let longest = ListedEntry {
        name: name(&"n".repeat(255)),
        kind: ListedKind::File {
            size_bytes: u64::MAX,
            executable: false,
        },
    };
    assert!(length(&serde_json::to_vec(&longest).unwrap()) <= MAX_LISTED_ENTRY_BYTES);
    let entries: Vec<ListedEntry> = (0..MAX_LISTED_ENTRIES)
        .map(|index| ListedEntry {
            name: name(&format!("{index:0>255}")),
            kind: ListedKind::File {
                size_bytes: u64::MAX,
                executable: false,
            },
        })
        .collect();
    let listing = Listing {
        entries: entries.clone(),
        unaddressable: u64::MAX,
        truncated: true,
    };
    let response = FileResponse::Answer {
        request_id: id(u64::MAX),
        outcome: ResponseOutcome::Completed(Completed::Listed { listing }),
    };
    let messages = response.encode(LIMIT).unwrap();
    assert!(messages.len() > 1);
    let mut received = Vec::new();
    for (part, message) in messages.iter().enumerate() {
        assert!(length(message) <= LIMIT);
        let (header, content) = split(message);
        assert!(content.is_empty());
        assert_eq!(header["request_id"], json!(u64::MAX));
        assert_eq!(header["part"], json!(part));
        let page = if part == 0 {
            assert_eq!(header["outcome"]["entry_count"], json!(MAX_LISTED_ENTRIES));
            assert_eq!(header["outcome"]["truncated"], json!(true));
            &header["outcome"]["entries"]
        } else {
            &header["entries"]
        };
        received.extend(page.as_array().unwrap().iter().cloned());
    }
    assert_eq!(
        Value::Array(received),
        serde_json::to_value(&entries).unwrap()
    );
    let total: u64 = messages.iter().map(|message| length(message)).sum();
    assert_eq!(response.encoded_len(LIMIT), Ok(total));
    assert!(total <= ChannelLimits::default().listing_reservation());

    let empty = FileResponse::Answer {
        request_id: id(1),
        outcome: ResponseOutcome::Completed(Completed::Listed {
            listing: Listing {
                entries: Vec::new(),
                unaddressable: 0,
                truncated: false,
            },
        }),
    };
    let messages = empty.encode(LIMIT).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(split(&messages[0]).0["outcome"]["entries"], json!([]));
}

#[test]
fn encoding_never_passes_the_message_bound() {
    let component = "w".repeat(255);
    let wide = name(&format!(
        "{component}/{component}/{component}/{}",
        "w".repeat(252)
    ));
    assert_eq!(wide.as_str().len(), MAX_NAME_BYTES - 4);
    let alias = FileResponse::Answer {
        request_id: id(u64::MAX),
        outcome: ResponseOutcome::ServiceRefused(ServiceRefusal::Resolve {
            refusal: ResolveRefusal::CaseAlias {
                requested: wide.clone(),
                stored: wide,
            },
        }),
    };
    assert!(alias.encoded_len(LIMIT).unwrap() <= REPLY_RESERVE_BYTES);
    assert!(matches!(
        alias.encode(1_000),
        Err(EncodeError::DoesNotFit { limit: 1_000, .. })
    ));
    assert!(matches!(
        alias.encoded_len(1_000),
        Err(EncodeError::DoesNotFit { .. })
    ));
    let request = GuestRequest {
        id: id(1),
        operation: create("a.bin", b"content"),
    };
    assert!(matches!(
        request.encode(40),
        Err(EncodeError::DoesNotFit { limit: 40, .. })
    ));
    // Each message of a split stays within a bound just above its headers.
    let content = patterned(5_000);
    let reading = FileResponse::Answer {
        request_id: id(3),
        outcome: ResponseOutcome::Completed(Completed::Read {
            content: content.clone(),
        }),
    };
    let messages = reading.encode(200).unwrap();
    assert!(messages.iter().all(|message| length(message) <= 200));
    let body: Vec<u8> = messages
        .iter()
        .flat_map(|message| split(message).1.to_vec())
        .collect();
    assert_eq!(body, content);
}

#[test]
fn channel_limits_are_checked_and_strict() {
    let base = ChannelLimits::default();
    assert_eq!(base.validate(), Ok(()));
    assert_eq!(base.max_message_bytes, 65_472);
    assert_eq!(base.max_buffered_bytes, 8 * 1024 * 1024);
    let cases = [
        (
            ChannelLimits {
                max_in_flight: 0,
                ..base
            },
            ChannelProblem::ZeroInFlight,
        ),
        (
            ChannelLimits {
                window: Duration::ZERO,
                ..base
            },
            ChannelProblem::ZeroWindow,
        ),
        (
            ChannelLimits {
                max_message_bytes: MIN_MESSAGE_BYTES - 1,
                ..base
            },
            ChannelProblem::MessageBoundOutOfRange {
                max_message_bytes: MIN_MESSAGE_BYTES - 1,
                minimum: MIN_MESSAGE_BYTES,
                maximum: MAX_MESSAGE_BYTES,
            },
        ),
        (
            ChannelLimits {
                max_message_bytes: MAX_MESSAGE_BYTES + 1,
                ..base
            },
            ChannelProblem::MessageBoundOutOfRange {
                max_message_bytes: MAX_MESSAGE_BYTES + 1,
                minimum: MIN_MESSAGE_BYTES,
                maximum: MAX_MESSAGE_BYTES,
            },
        ),
        (
            ChannelLimits {
                max_buffered_bytes: 0,
                ..base
            },
            ChannelProblem::ZeroBuffer,
        ),
        (
            ChannelLimits {
                max_window_bytes: base.listing_reservation() - 1,
                ..base
            },
            ChannelProblem::WindowTooSmall {
                max_window_bytes: base.listing_reservation() - 1,
                minimum: base.listing_reservation(),
            },
        ),
    ];
    for (limits, problem) in cases {
        assert_eq!(limits.validate(), Err(problem));
    }
    let (service, _dir) = served(&[FileOperation::Read]);
    let made = FileDispatcher::new(
        service,
        scope("sandbox-a"),
        ManualClock::new(at(1)),
        session(1),
        ChannelLimits {
            max_in_flight: 0,
            ..base
        },
    );
    assert!(matches!(made, Err(ChannelProblem::ZeroInFlight)));

    let text = serde_json::to_string(&base).unwrap();
    assert_eq!(serde_json::from_str::<ChannelLimits>(&text).unwrap(), base);
    let mut extra: Value = serde_json::from_str(&text).unwrap();
    extra["max_requests"] = json!(1);
    assert!(serde_json::from_value::<ChannelLimits>(extra).is_err());
}

#[test]
fn the_longest_header_fits_the_header_bound() {
    // A rename between two of the longest names, every character a six-byte JSON escape.
    let wide = "a".repeat(255);
    let text = format!("{wide}/{wide}/{wide}/{}/b", "a".repeat(254));
    assert_eq!(text.len(), MAX_NAME_BYTES);
    let escaped: String = text.bytes().map(|byte| format!("\\u{byte:04x}")).collect();
    let header = format!(
        "{{\"version\":1,\"request_id\":{},\"part\":0,\"request\":{{\"operation\":\"rename\",\
         \"from\":\"{escaped}\",\"to\":\"{escaped}\"}}}}",
        u64::MAX
    );
    assert!(length(header.as_bytes()) <= MAX_HEADER_BYTES);
    assert!(matches!(
        RequestPart::decode(&line(&header)),
        Ok(RequestPart::Opening {
            operation: GuestOperation::Rename { .. },
            ..
        })
    ));
}
