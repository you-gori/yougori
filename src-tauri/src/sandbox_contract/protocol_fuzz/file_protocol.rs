//! The guest file protocol under the fuzzer (M12P; VM part §3.2, VM-W14, VM-R58;
//! VM-W50): `RequestPart::decode` on mutated guest messages, `GuestRequest::encode` on
//! random requests, and the dispatcher's bounds over random message scripts.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - Decoding: a decoded message has its header newline within [`MAX_HEADER_BYTES`]; an
//!   opening declares at most [`MAX_CONTENT_BYTES`], carries exactly the bytes after the
//!   header and no more than it declares (nothing at all for an operation without
//!   content), reads at most [`MAX_READ_BYTES`] and holds names that parse back to
//!   themselves; a continuation has a part number from 1 and carries the bytes after the
//!   header, never none. A message without a header newline within the window is refused
//!   as a too large header or as malformed; one over [`MAX_MESSAGE_BYTES`] as too large.
//! - Claims stay claims: a refused message's `claimed_request_id` is exactly the
//!   `request_id` its header shows, and the refusal's answer is one message within the
//!   smallest message bound whose top-level `request_id` is null.
//! - Encoding: a decoded whole request, and random requests, encode at any message bound
//!   into messages within it that decode back to the same request.
//! - The dispatcher: requests being received or in flight never exceed `max_in_flight`,
//!   buffered content never exceeds `max_buffered_bytes`, received message bytes counted
//!   in one window never exceed `max_window_bytes`, a window answers at most one message
//!   with its byte-window refusal and drops later messages only after it, no message over
//!   the bound is admitted or buffered, no admitted request carries or reads more than the
//!   content limit, every refusal is one message within the bound naming no request, and
//!   the same script on a fresh channel gives the same results and counters.

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{runs, variant, Encoding, Field, Grammar};
use super::rng::SplitMix64;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{ExecutionCategory, ManualClock, MonotonicTime, TrustScope};
use crate::sandbox_contract::file_protocol::{
    Admitted, ChannelCounters, ChannelLimits, FileDispatcher, FileResponse, GuestOperation,
    GuestRequest, ProtocolRefusal, Received, RequestId, RequestPart, UndecodedRequest,
    DEFAULT_MAX_MESSAGE_BYTES, FILE_PROTOCOL_VERSION, MAX_CONTENT_BYTES, MAX_HEADER_BYTES,
    MAX_MESSAGE_BYTES, MIN_MESSAGE_BYTES, MIN_MESSAGE_COST_BYTES,
};
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, GuestName,
    MAX_COMPONENT_BYTES, MAX_NAME_BYTES, MAX_RANGE_BYTES, MAX_READ_BYTES,
};

/// Mutated messages per decoding run.
const ITERATIONS: u64 = 30_000;
/// Random requests per encoding run.
const ROUND_TRIPS: u64 = 1_000;
/// Dispatcher scripts per run, each run twice, and steps per script.
const SCRIPTS: u64 = 300;
const STEPS: usize = 40;
/// Request ids drawn for scripts: few, so duplicates happen.
const IDS: usize = 6;
/// The most content a generated create or write carries, so scripts stay small.
const MAX_GENERATED_CONTENT: u64 = 70_000;

fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap()
}

fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

/// The one message of a request that fits the default bound.
fn single(id: u64, operation: GuestOperation) -> Vec<u8> {
    let mut messages = GuestRequest {
        id: RequestId::new(id),
        operation,
    }
    .encode(DEFAULT_MAX_MESSAGE_BYTES)
    .unwrap();
    assert_eq!(messages.len(), 1);
    messages.remove(0)
}

/// A write split at the smallest message bound into an opening that carries part of its
/// content and a continuation carrying the last ten bytes.
fn split_write() -> Vec<Vec<u8>> {
    let limit = usize::try_from(MIN_MESSAGE_BYTES).unwrap();
    let request = |length: usize| GuestRequest {
        id: RequestId::new(10),
        operation: GuestOperation::Write {
            name: name("big.bin"),
            content: (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect(),
        },
    };
    let probe = request(limit).encode(MIN_MESSAGE_BYTES).unwrap();
    let header = probe[0].iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let messages = request(limit - header + 10)
        .encode(MIN_MESSAGE_BYTES)
        .unwrap();
    assert_eq!(messages.len(), 2);
    let newline = messages[1].iter().position(|byte| *byte == b'\n').unwrap();
    assert_eq!(messages[1].len() - newline - 1, 10);
    messages
}

fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![
        single(
            1,
            GuestOperation::Read {
                name: name("src/main.rs"),
                max_bytes: 4096,
            },
        ),
        single(2, GuestOperation::List { name: None }),
        single(
            3,
            GuestOperation::List {
                name: Some(name("src")),
            },
        ),
        single(
            4,
            GuestOperation::Create {
                name: name("notes.txt"),
                content: b"hello".to_vec(),
            },
        ),
        single(
            5,
            GuestOperation::CreateDirectory {
                name: name("build"),
            },
        ),
        single(
            6,
            GuestOperation::Write {
                name: name("a.txt"),
                content: b"0123456789".to_vec(),
            },
        ),
        single(
            7,
            GuestOperation::Delete {
                name: name("old.log"),
            },
        ),
        single(
            8,
            GuestOperation::Rename {
                from: name("a.txt"),
                to: name("b/c.txt"),
                replace: false,
            },
        ),
        single(
            9,
            GuestOperation::SetExecutable {
                name: name("run.sh"),
                executable: true,
            },
        ),
        single(
            u64::MAX,
            GuestOperation::Write {
                name: name("empty"),
                content: Vec::new(),
            },
        ),
    ];
    seeds.extend(split_write());
    seeds
}

/// The decimal numbers of the header line.
fn fields(input: &[u8]) -> Vec<Field> {
    let end = input
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(input.len());
    runs(input, 0, end, u8::is_ascii_digit, Encoding::Decimal)
}

fn grammar() -> Grammar {
    let tokens: [&[u8]; 34] = [
        b"\"version\":1,",
        b"\"request_id\":1,",
        b"\"part\":0,",
        b"\"part\":1,",
        b"\"request\":null,",
        b"\"operation\":\"read\",",
        b"\"operation\":\"list\",",
        b"\"operation\":\"create\",",
        b"\"operation\":\"create_directory\",",
        b"\"operation\":\"write\",",
        b"\"operation\":\"delete\",",
        b"\"operation\":\"rename\",",
        b"\"operation\":\"set_executable\",",
        b"\"name\":\"a\",",
        b"\"name\":null,",
        b"\"from\":\"a\",\"to\":\"b\",",
        b"\"length\":0,",
        b"\"max_bytes\":0,",
        b"\"executable\":true,",
        b"\"scope\":\"host\",",
        b"{",
        b"}",
        b"[",
        b"]",
        b"\n",
        b"\"",
        b"\\u0000",
        b"\\ud800",
        b"1e3",
        b"-1",
        b"1.0",
        b"null",
        b"../",
        b"C:/",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            MAX_READ_BYTES,
            MAX_CONTENT_BYTES,
            u64::from(u32::MAX),
            MAX_HEADER_BYTES,
            u64::from(FILE_PROTOCOL_VERSION),
            bytes_of(MAX_NAME_BYTES),
            bytes_of(MAX_COMPONENT_BYTES),
        ],
        fields,
        max_len: 20_000,
    }
}

/// The names an operation holds.
fn names(operation: &GuestOperation) -> Vec<&GuestName> {
    match operation {
        GuestOperation::Read { name, .. }
        | GuestOperation::ReadRange { name, .. }
        | GuestOperation::Create { name, .. }
        | GuestOperation::CreateDirectory { name }
        | GuestOperation::Write { name, .. }
        | GuestOperation::UploadBegin { name, .. }
        | GuestOperation::UploadWrite { name, .. }
        | GuestOperation::UploadTruncate { name, .. }
        | GuestOperation::UploadCommit { name, .. }
        | GuestOperation::UploadAbort { name, .. }
        | GuestOperation::Delete { name }
        | GuestOperation::SetExecutable { name, .. } => vec![name],
        GuestOperation::List { name } => name.iter().collect(),
        GuestOperation::Rename { from, to, .. } => vec![from, to],
    }
}

/// `operation` holding `content` in place of what it carries; unchanged without content.
fn with_content(operation: GuestOperation, content: Vec<u8>) -> GuestOperation {
    match operation {
        GuestOperation::Create { name, .. } => GuestOperation::Create { name, content },
        GuestOperation::Write { name, .. } => GuestOperation::Write { name, content },
        GuestOperation::UploadWrite {
            name,
            upload,
            offset,
            ..
        } => GuestOperation::UploadWrite {
            name,
            upload,
            offset,
            content,
        },
        other => other,
    }
}

/// Encodes `request` at `limit` and decodes every message back into the same request.
fn round_trip(request: &GuestRequest, limit: u64) -> Result<(), String> {
    let messages = request
        .encode(limit)
        .map_err(|error| format!("a request did not encode at {limit}: {error}"))?;
    let mut opening = None;
    let mut content = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        ensure!(
            bytes_of(message.len()) <= limit,
            "message {index} has {} bytes, over the bound {limit}",
            message.len()
        );
        match RequestPart::decode(message) {
            Ok(RequestPart::Opening {
                id,
                operation,
                declared_length,
            }) if index == 0 => {
                ensure!(id == request.id, "the opening names request {id}");
                let expected = request.operation.content().map_or(0, <[u8]>::len);
                ensure!(
                    declared_length == bytes_of(expected),
                    "the opening declares {declared_length} of {expected} bytes"
                );
                content.extend_from_slice(operation.content().unwrap_or_default());
                opening = Some(operation);
            }
            Ok(RequestPart::Continuation {
                id,
                part,
                content: carried,
            }) if index > 0 => {
                ensure!(
                    id == request.id && usize::try_from(part).unwrap() == index,
                    "message {index} continues request {id} as part {part}"
                );
                content.extend_from_slice(&carried);
            }
            other => {
                return Err(format!(
                    "message {index} of an encoded request decoded as {other:?}"
                ))
            }
        }
    }
    let rebuilt = with_content(opening.ok_or_else(|| "no opening".to_owned())?, content);
    ensure!(
        rebuilt == request.operation,
        "the request decoded back as another operation"
    );
    Ok(())
}

fn check_part(input: &[u8], newline: Option<usize>, part: &RequestPart) -> Verdict {
    let Some(end) = newline else {
        return Err("a message without a header newline in the window decoded".to_owned());
    };
    ensure!(
        bytes_of(end) <= MAX_HEADER_BYTES,
        "a {end}-byte header decoded"
    );
    ensure!(
        bytes_of(input.len()) <= MAX_MESSAGE_BYTES,
        "a {}-byte message decoded",
        input.len()
    );
    let after = &input[end + 1..];
    match part {
        RequestPart::Opening {
            id,
            operation,
            declared_length,
        } => {
            ensure!(
                *declared_length <= MAX_CONTENT_BYTES,
                "{declared_length} content bytes declared"
            );
            match operation.content() {
                Some(carried) => {
                    ensure!(
                        carried == after,
                        "the opening carries other bytes than follow"
                    );
                    ensure!(
                        bytes_of(carried.len()) <= *declared_length,
                        "{} bytes carried of {declared_length} declared",
                        carried.len()
                    );
                }
                None => ensure!(
                    after.is_empty() && *declared_length == 0,
                    "an operation without content carries {} bytes and declares \
                     {declared_length}",
                    after.len()
                ),
            }
            if let GuestOperation::Read { max_bytes, .. } = operation {
                ensure!(*max_bytes <= MAX_READ_BYTES, "a read of {max_bytes} bytes");
            }
            for name in names(operation) {
                ensure!(
                    GuestName::parse(name.as_str()).as_ref() == Ok(name),
                    "the name {:?} does not parse back to itself",
                    name.as_str()
                );
            }
            let whole = operation
                .content()
                .is_none_or(|carried| bytes_of(carried.len()) == *declared_length);
            if whole {
                let request = GuestRequest {
                    id: *id,
                    operation: operation.clone(),
                };
                round_trip(&request, MAX_MESSAGE_BYTES)?;
                round_trip(&request, MIN_MESSAGE_BYTES)?;
            }
            Ok(format!("accepted:{}", variant(&format!("{operation:?}"))))
        }
        RequestPart::Continuation {
            part,
            content: carried,
            ..
        } => {
            ensure!(*part >= 1, "a continuation numbered {part}");
            ensure!(!carried.is_empty(), "a continuation carries nothing");
            ensure!(
                carried == after,
                "a continuation carries other bytes than follow"
            );
            Ok("accepted:continuation".to_owned())
        }
    }
}

/// Checks the one message answering a refusal: within the bound, naming no request, with
/// the claimed id kept apart.
fn check_refusal_message(message: &[u8], claimed: Option<RequestId>) -> Result<(), String> {
    let line = message
        .strip_suffix(b"\n")
        .ok_or_else(|| "a refusal without its newline".to_owned())?;
    let value: Value = serde_json::from_slice(line)
        .map_err(|error| format!("a refusal that is not JSON: {error}"))?;
    ensure!(
        value["request_id"].is_null(),
        "a refusal names request {}",
        value["request_id"]
    );
    let expected = claimed.map_or(Value::Null, |id| Value::from(id.get()));
    ensure!(
        value["outcome"]["kind"] == "protocol_refused"
            && value["outcome"]["claimed_request_id"] == expected,
        "the refusal's outcome is {}",
        value["outcome"]
    );
    Ok(())
}

fn check_undecoded(input: &[u8], newline: Option<usize>, undecoded: &UndecodedRequest) -> Verdict {
    let refusal = &undecoded.refusal;
    let claimed = undecoded.claimed_request_id;
    if bytes_of(input.len()) > MAX_MESSAGE_BYTES {
        ensure!(
            matches!(refusal, ProtocolRefusal::MessageTooLarge { .. }) && claimed.is_none(),
            "a {}-byte message refused with {refusal:?}",
            input.len()
        );
    } else if let Some(end) = newline {
        let shown = serde_json::from_slice::<Value>(&input[..end])
            .ok()
            .and_then(|header| header.get("request_id").and_then(Value::as_u64))
            .map(RequestId::new);
        ensure!(
            claimed == shown,
            "the refusal claims {claimed:?}; the header shows {shown:?}"
        );
    } else {
        let expected = if bytes_of(input.len()) > MAX_HEADER_BYTES {
            matches!(refusal, ProtocolRefusal::HeaderTooLarge { .. })
        } else {
            matches!(refusal, ProtocolRefusal::Malformed { .. })
        };
        ensure!(
            claimed.is_none() && expected,
            "a message without a header newline refused with {refusal:?}"
        );
    }
    let messages = FileResponse::refusal(claimed, refusal.clone())
        .encode(MIN_MESSAGE_BYTES)
        .map_err(|error| format!("the refusal {refusal:?} did not encode: {error}"))?;
    ensure!(
        messages.len() == 1,
        "a refusal in {} messages",
        messages.len()
    );
    check_refusal_message(&messages[0], claimed)?;
    Ok(format!("refused:{}", variant(&format!("{refusal:?}"))))
}

fn check(input: &[u8]) -> Verdict {
    let first = RequestPart::decode(input);
    ensure!(
        first == RequestPart::decode(input),
        "two decodings of one message differ"
    );
    let window = usize::try_from(MAX_HEADER_BYTES).unwrap() + 1;
    let newline = input.iter().take(window).position(|byte| *byte == b'\n');
    match &first {
        Ok(part) => check_part(input, newline, part),
        Err(undecoded) => check_undecoded(input, newline, undecoded),
    }
}

/// Messages that reach each refusal and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "accepted:Read",
        input: b"{\"version\":1,\"request_id\":1,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"a\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "accepted:List",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"list\",\
                 \"name\":null}}\n",
    },
    Regression {
        expect: "accepted:continuation",
        input: b"{\"version\":1,\"request_id\":5,\"part\":1}\nabc",
    },
    Regression {
        expect: "accepted:continuation",
        input: b"{\"version\":1,\"request_id\":18446744073709551615,\"part\":4294967295}\nx",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"list\",\
                 \"name\":null}}",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"\n",
    },
    Regression {
        expect: "refused:UnsupportedVersion",
        input: b"{\"version\":2,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"a\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "refused:UnknownOperation",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"chmod\",\
                 \"name\":\"a\"}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"a\",\"max_bytes\":1,\"root\":\"/\"}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"scope\":\"host\",\"request\":\
                 {\"operation\":\"list\",\"name\":null}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"list\",\
                 \"name\":null,\"x\":1}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"version\":1,\"request_id\":5,\"part\":0,\"request\":\
                 {\"operation\":\"list\",\"name\":null}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"[1,5,0,{\"operation\":\"list\",\"name\":null}]\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":[\"list\",null]}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1.0,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\
                 \"list\",\"name\":null}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":1,\"request\":{\"operation\":\"list\",\
                 \"name\":null}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":4294967296}\nx",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":18446744073709551616,\"part\":1}\nx",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\
                 \"set_executable\",\"name\":\"run.sh\",\"executable\":1}}\n",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"\\ud800\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "refused:InvalidName",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"../etc/passwd\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "refused:InvalidName",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"C:/x\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "refused:InvalidName",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"a\\u0000\",\"max_bytes\":1}}\n",
    },
    Regression {
        expect: "refused:LengthMismatch",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"write\",\
                 \"name\":\"a\",\"length\":2}}\nabc",
    },
    Regression {
        expect: "refused:LengthMismatch",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\
                 \"delete\",\"name\":\"a\"}}\nx",
    },
    Regression {
        expect: "refused:ReadLimitTooLarge",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\"read\",\
                 \"name\":\"a\",\"max_bytes\":67108865}}\n",
    },
    Regression {
        expect: "refused:ContentTooLarge",
        input: b"{\"version\":1,\"request_id\":5,\"part\":0,\"request\":{\"operation\":\
                 \"create\",\"name\":\"a\",\"length\":67108865}}\n",
    },
    Regression {
        expect: "refused:EmptyPart",
        input: b"{\"version\":1,\"request_id\":5,\"part\":1}\n",
    },
];

#[test]
fn mutated_guest_messages_keep_every_decoder_property() {
    let run = Run {
        target: "file_protocol",
        seed: 0x00E0_1F00_0000_0001,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "file_protocol",
        &[
            "accepted:Read",
            "accepted:List",
            "accepted:Write",
            "accepted:Rename",
            "accepted:continuation",
            "refused:Malformed",
            "refused:UnsupportedVersion",
            "refused:UnknownOperation",
            "refused:InvalidName",
            "refused:LengthMismatch",
            "refused:EmptyPart",
            "refused:HeaderTooLarge",
        ],
    );
}

#[test]
fn file_protocol_size_limits_hold_at_their_boundaries() {
    let header = |request: &str| {
        format!("{{\"version\":1,\"request_id\":3,\"part\":0,\"request\":{request}}}")
    };
    // The longest message decodes; one byte more is refused before it is read.
    let max = usize::try_from(MAX_MESSAGE_BYTES).unwrap();
    let write = |length: usize| {
        format!(
            "{}\n",
            header(&format!(
                "{{\"operation\":\"write\",\"name\":\"a\",\"length\":{length}}}"
            ))
        )
    };
    // Both lengths have seven digits, so the header has the same length for either.
    let content = max - write(max).len();
    let mut message = write(content).into_bytes();
    assert_eq!(message.len() + content, max);
    message.resize(max, b'x');
    assert_eq!(check(&message).unwrap(), "accepted:Write");
    message.push(b'x');
    assert_eq!(check(&message).unwrap(), "refused:MessageTooLarge");
    // A header of exactly MAX_HEADER_BYTES before its newline decodes; one byte longer is
    // refused without being parsed.
    let longest = usize::try_from(MAX_HEADER_BYTES).unwrap();
    let mut line = header("{\"operation\":\"list\",\"name\":null}").into_bytes();
    line.resize(longest, b' ');
    line.push(b'\n');
    assert_eq!(check(&line).unwrap(), "accepted:List");
    line.insert(0, b' ');
    assert_eq!(check(&line).unwrap(), "refused:HeaderTooLarge");
    // Two names of MAX_NAME_BYTES with every character escaped fit the header.
    let component = |byte: u8, length: usize| vec![byte; length];
    let long_name = [
        component(b'a', MAX_COMPONENT_BYTES),
        component(b'b', MAX_COMPONENT_BYTES),
        component(b'c', MAX_COMPONENT_BYTES),
        component(b'd', MAX_COMPONENT_BYTES - 1),
        component(b'e', 1),
    ]
    .join(&b'/');
    assert_eq!(long_name.len(), MAX_NAME_BYTES);
    let escaped: String = long_name
        .iter()
        .map(|byte| format!("\\u{:04x}", u32::from(*byte)))
        .collect();
    let rename = header(&format!(
        "{{\"operation\":\"rename\",\"from\":\"{escaped}\",\"to\":\"{escaped}\"}}"
    ));
    assert!(bytes_of(rename.len()) < MAX_HEADER_BYTES);
    assert_eq!(
        check(format!("{rename}\n").as_bytes()).unwrap(),
        "accepted:Rename"
    );
    // Content and read limits at their edges.
    for (operation, expect) in [
        (
            format!("{{\"operation\":\"read\",\"name\":\"a\",\"max_bytes\":{MAX_READ_BYTES}}}"),
            "accepted:Read",
        ),
        (
            format!(
                "{{\"operation\":\"read\",\"name\":\"a\",\"max_bytes\":{}}}",
                MAX_READ_BYTES + 1
            ),
            "refused:ReadLimitTooLarge",
        ),
        (
            format!("{{\"operation\":\"create\",\"name\":\"a\",\"length\":{MAX_CONTENT_BYTES}}}"),
            "accepted:Create",
        ),
        (
            format!(
                "{{\"operation\":\"create\",\"name\":\"a\",\"length\":{}}}",
                MAX_CONTENT_BYTES + 1
            ),
            "refused:ContentTooLarge",
        ),
    ] {
        assert_eq!(
            check(format!("{}\n", header(&operation)).as_bytes()).unwrap(),
            expect
        );
    }
    // Nesting past serde_json's recursion limit is refused, not followed.
    let mut nested = vec![b'['; 16_000];
    nested.push(b'\n');
    assert_eq!(check(&nested).unwrap(), "refused:Malformed");
}

/// A random name of one to three short components.
fn random_name(rng: &mut SplitMix64) -> GuestName {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_-";
    loop {
        let components: Vec<String> = (0..rng.between(1, 3))
            .map(|_| {
                (0..rng.between(1, 12))
                    .map(|_| char::from(*rng.pick(LETTERS)))
                    .collect()
            })
            .collect();
        if let Ok(name) = GuestName::parse(&components.join("/")) {
            return name;
        }
    }
}

/// A random operation whose content and read limit sit around `content_limit`.
fn random_operation(rng: &mut SplitMix64, content_limit: u64) -> GuestOperation {
    let sizes = [0, 10, 16_000, 30_000, content_limit, content_limit + 1];
    let content = |rng: &mut SplitMix64| -> Vec<u8> {
        let length = usize::try_from(*rng.pick(&sizes)).unwrap();
        (0..length)
            .map(|index| u8::try_from(index % 241).unwrap())
            .collect()
    };
    match rng.below(14) {
        0 => GuestOperation::Read {
            name: random_name(rng),
            max_bytes: *rng.pick(&[0, 1, 4096, content_limit, content_limit + 1, MAX_READ_BYTES]),
        },
        1 => GuestOperation::List {
            name: if rng.one_in(2) {
                None
            } else {
                Some(random_name(rng))
            },
        },
        2 => GuestOperation::Create {
            name: random_name(rng),
            content: content(rng),
        },
        3 => GuestOperation::CreateDirectory {
            name: random_name(rng),
        },
        4 => GuestOperation::Write {
            name: random_name(rng),
            content: content(rng),
        },
        5 => GuestOperation::Delete {
            name: random_name(rng),
        },
        6 => GuestOperation::Rename {
            from: random_name(rng),
            to: random_name(rng),
            replace: false,
        },
        7 => GuestOperation::ReadRange {
            name: random_name(rng),
            offset: *rng.pick(&[0, 1, 1 << 20, u64::MAX]),
            max_bytes: *rng.pick(&[0, 1, 4096, MAX_RANGE_BYTES]),
            upload: if rng.one_in(2) { None } else { Some(*rng.pick(&[1, 7, u64::MAX])) },
        },
        8 => GuestOperation::UploadBegin {
            name: random_name(rng),
            from_existing: rng.one_in(2),
        },
        9 => GuestOperation::UploadWrite {
            name: random_name(rng),
            upload: *rng.pick(&[1, 2, u64::MAX]),
            offset: *rng.pick(&[0, 1, 1 << 30, u64::MAX]),
            content: {
                let mut bytes = content(rng);
                bytes.truncate(usize::try_from(MAX_RANGE_BYTES).unwrap_or(usize::MAX));
                bytes
            },
        },
        10 => GuestOperation::UploadTruncate {
            name: random_name(rng),
            upload: *rng.pick(&[1, u64::MAX]),
            length: *rng.pick(&[0, 1, 1 << 30]),
        },
        11 => GuestOperation::UploadCommit {
            name: random_name(rng),
            upload: *rng.pick(&[1, u64::MAX]),
        },
        12 => GuestOperation::UploadAbort {
            name: random_name(rng),
            upload: *rng.pick(&[1, u64::MAX]),
        },
        _ => GuestOperation::SetExecutable {
            name: random_name(rng),
            executable: rng.one_in(2),
        },
    }
}

#[test]
fn random_requests_encode_within_the_bound_and_decode_back() {
    let mut rng = SplitMix64::new(0x00E0_1F00_0000_0002);
    for iteration in 0..ROUND_TRIPS {
        let request = GuestRequest {
            id: RequestId::new(rng.next_u64()),
            operation: random_operation(&mut rng, MAX_GENERATED_CONTENT),
        };
        let low = usize::try_from(MIN_MESSAGE_BYTES).unwrap();
        let limit = bytes_of(rng.between(low, low + 50_000));
        let outcome = catch_unwind(AssertUnwindSafe(|| round_trip(&request, limit)));
        let content = request.operation.content().map_or(0, <[u8]>::len);
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(message)) => panic!(
                "file_protocol encoder: iteration {iteration}: {message}\n  request {:?} \
                 with {content} content bytes, bound {limit}",
                with_content(request.operation.clone(), Vec::new())
            ),
            Err(_) => panic!(
                "file_protocol encoder: iteration {iteration} panicked\n  request {:?} \
                 with {content} content bytes, bound {limit}",
                with_content(request.operation.clone(), Vec::new())
            ),
        }
    }
}

/// One step of a dispatcher script.
#[derive(Debug)]
enum Step {
    /// A message from the guest.
    Receive(Vec<u8>),
    /// Performs (a read or listing) or cancels the held admission at this index, modulo
    /// how many are held.
    Finish(usize),
    /// Cancels the request with this id if its content is still arriving.
    CancelIncomplete(RequestId),
    /// Moves the clock past the window, so the next count opens a new one.
    NextWindow,
}

/// What one step produced, comparable across runs.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Admitted(GuestRequest),
    Buffered,
    Refused(FileResponse),
    Dropped,
    Finished(FileResponse),
    Incomplete(Option<FileResponse>),
    Nothing,
}

/// What the script runner tracks of the current window.
#[derive(Default)]
struct WindowWatch {
    /// Received message bytes counted before the window started.
    base: u64,
    /// Whether the window's byte-window refusal of a message was sent.
    refused: bool,
}

fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-fuzz")
}

fn session() -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(0xE01F))
}

/// A file service over an empty root in a fresh scratch directory; the directory must
/// outlive the service.
fn service() -> (FileService, tempfile::TempDir) {
    let directory = tempfile::Builder::new()
        .prefix("protocol-fuzz-")
        .tempdir()
        .unwrap();
    let root_path = directory.path().join("root");
    std::fs::create_dir(&root_path).unwrap();
    let root = GrantedRoot::open(&root_path).unwrap();
    let operations: BTreeSet<FileOperation> = [
        FileOperation::Read,
        FileOperation::List,
        FileOperation::Create,
        FileOperation::Write,
        FileOperation::Delete,
        FileOperation::Rename,
        FileOperation::SetExecutable,
    ]
    .into_iter()
    .collect();
    let grant = FileGrant::new(
        root.handle(),
        GrantMode::QuarantineOutput,
        operations,
        scope(),
        session(),
        MonotonicTime::from_nanos(1_000 * 1_000_000_000),
        FileQuota {
            max_total_bytes: 1 << 20,
            max_entries: 100,
            max_file_bytes: 1 << 20,
        },
    )
    .unwrap();
    (FileService::new(grant, root).unwrap(), directory)
}

/// Bounds small enough for short scripts to reach: three requests at once, the smallest
/// message bound, a 48 KiB buffer and the smallest window a listing allows.
fn tight_limits() -> ChannelLimits {
    let base = ChannelLimits {
        max_in_flight: 3,
        max_window_bytes: 0,
        window: Duration::from_secs(1),
        max_message_bytes: MIN_MESSAGE_BYTES,
        max_buffered_bytes: 48 * 1024,
    };
    ChannelLimits {
        max_window_bytes: base.listing_reservation(),
        ..base
    }
}

/// Bounds whose window can be filled within a short script: reads may ask for as much
/// as the window holds, since the buffer bound is above it.
fn window_limits() -> ChannelLimits {
    let base = ChannelLimits {
        max_buffered_bytes: 2 * 1024 * 1024,
        ..tight_limits()
    };
    ChannelLimits {
        max_window_bytes: base.listing_reservation(),
        ..base
    }
}

/// The largest read limit whose reservation leaves at most `room` bytes of an empty
/// window after its own message's least cost, if the content limit allows one.
fn filling_read(limits: &ChannelLimits, room: u64) -> Option<u64> {
    let target = limits
        .max_window_bytes
        .checked_sub(MIN_MESSAGE_COST_BYTES + room)?;
    let reservation = |max_bytes: u64| {
        limits.reply_reservation(&GuestOperation::Read {
            name: name("fill"),
            max_bytes,
        })
    };
    let (mut low, mut high) = (0, limits.content_limit());
    if reservation(high) <= target {
        return None;
    }
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if reservation(middle) <= target {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Some(low)
}

/// A random script: messages of six random requests (half of them reads) in and out of
/// order, mutated messages, finished and cancelled requests and new windows; where the
/// limits allow, now and then a new window filled by one read to within a message's cost,
/// followed by more messages.
fn script(rng: &mut SplitMix64, grammar: &Grammar, limits: &ChannelLimits) -> Vec<Step> {
    let content_limit = limits.content_limit();
    let groups: Vec<Vec<Vec<u8>>> = (0..6)
        .map(|_| {
            let operation = if rng.one_in(2) {
                GuestOperation::Read {
                    name: random_name(rng),
                    max_bytes: bytes_of(rng.below(usize::try_from(content_limit).unwrap() + 2)),
                }
            } else {
                random_operation(rng, content_limit.min(MAX_GENERATED_CONTENT))
            };
            GuestRequest {
                id: RequestId::new(bytes_of(rng.below(IDS))),
                operation,
            }
            .encode(limits.max_message_bytes)
            .unwrap()
        })
        .collect();
    let mut next = vec![0; groups.len()];
    let mut steps = Vec::with_capacity(STEPS + 3);
    while steps.len() < STEPS {
        if rng.one_in(20) {
            let room = bytes_of(rng.below(400));
            if let Some(max_bytes) = filling_read(limits, room) {
                let fill = GuestRequest {
                    id: RequestId::new(bytes_of(rng.below(IDS))),
                    operation: GuestOperation::Read {
                        name: name("fill"),
                        max_bytes,
                    },
                };
                steps.push(Step::NextWindow);
                steps.push(Step::Receive(
                    fill.encode(limits.max_message_bytes).unwrap().remove(0),
                ));
                for _ in 0..2 {
                    let group = rng.pick(&groups);
                    steps.push(Step::Receive(rng.pick(group).clone()));
                }
                continue;
            }
        }
        let step = match rng.below(20) {
            0..=10 => {
                let group = rng.below(groups.len());
                if next[group] >= groups[group].len() {
                    next[group] = 0;
                }
                let index = if rng.one_in(10) {
                    rng.below(groups[group].len())
                } else {
                    next[group]
                };
                next[group] = index + 1;
                Step::Receive(groups[group][index].clone())
            }
            11..=14 => {
                let group = rng.pick(&groups);
                let mut message = rng.pick(group).clone();
                for _ in 0..rng.between(1, 2) {
                    grammar.mutate(rng, &mut message);
                }
                Step::Receive(message)
            }
            15..=17 => Step::Finish(rng.below(4)),
            18 => Step::CancelIncomplete(RequestId::new(bytes_of(rng.below(IDS)))),
            _ => Step::NextWindow,
        };
        steps.push(step);
    }
    steps
}

/// Checks what `receive` made of `message` and records it.
fn observe(
    dispatcher: &FileDispatcher<Arc<ManualClock>>,
    limits: &ChannelLimits,
    message: &[u8],
    received: Received,
    held: &mut Vec<Admitted>,
    window: &mut WindowWatch,
) -> Result<Seen, String> {
    let length = bytes_of(message.len());
    let fits = length <= limits.max_message_bytes;
    Ok(match received {
        Received::Admitted(admitted) => {
            ensure!(fits, "a {length}-byte message was admitted");
            let request = admitted.request().clone();
            let content = bytes_of(request.operation.content().map_or(0, <[u8]>::len));
            ensure!(
                content <= limits.content_limit(),
                "an admitted request carries {content} bytes"
            );
            if let GuestOperation::Read { max_bytes, .. } = &request.operation {
                ensure!(
                    *max_bytes <= limits.content_limit(),
                    "an admitted read of {max_bytes} bytes"
                );
            }
            held.push(admitted);
            Seen::Admitted(request)
        }
        Received::Buffered => {
            ensure!(fits, "a {length}-byte message was buffered");
            Seen::Buffered
        }
        Received::Refused(response) => {
            let FileResponse::Refusal {
                claimed_request_id,
                refusal,
            } = &response
            else {
                return Err(format!("receive answered a request: {response:?}"));
            };
            let window_refusal = matches!(refusal, ProtocolRefusal::ByteWindowExceeded { .. });
            if window_refusal && claimed_request_id.is_none() {
                ensure!(
                    !window.refused,
                    "a second byte-window refusal in one window"
                );
                window.refused = true;
            }
            ensure!(
                fits || window_refusal
                    || matches!(refusal, ProtocolRefusal::MessageTooLarge { .. }),
                "a {length}-byte message refused with {refusal:?}"
            );
            let messages = dispatcher
                .encode(&response)
                .map_err(|error| format!("a refusal did not encode: {error}"))?;
            ensure!(
                messages.len() == 1 && bytes_of(messages[0].len()) <= limits.max_message_bytes,
                "a refusal in {} messages",
                messages.len()
            );
            check_refusal_message(&messages[0], *claimed_request_id)?;
            Seen::Refused(response)
        }
        Received::Dropped => {
            ensure!(
                window.refused,
                "a message was dropped before its window's refusal"
            );
            Seen::Dropped
        }
    })
}

/// Runs `script` on a fresh channel over `service`, checking the bounds after every step;
/// returns the service, what every step produced and the final counters.
fn run_script(
    service: FileService,
    limits: ChannelLimits,
    script: &[Step],
) -> Result<(FileService, Vec<Seen>, ChannelCounters), String> {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
    let mut dispatcher =
        FileDispatcher::new(service, scope(), Arc::clone(&clock), session(), limits)
            .map_err(|problem| format!("the channel was refused: {problem}"))?;
    let mut held: Vec<Admitted> = Vec::new();
    let mut seen = Vec::with_capacity(script.len());
    let mut window = WindowWatch::default();
    let mut receives = 0;
    for (index, step) in script.iter().enumerate() {
        let observed = match step {
            Step::Receive(message) => {
                receives += 1;
                let received = dispatcher.receive(message);
                observe(
                    &dispatcher,
                    &limits,
                    message,
                    received,
                    &mut held,
                    &mut window,
                )
                .map_err(|problem| format!("step {index}: {problem}"))?
            }
            Step::Finish(choice) if !held.is_empty() => {
                let admitted = held.remove(choice % held.len());
                let id = admitted.request().id;
                let response = match admitted.request().operation {
                    GuestOperation::Read { .. } | GuestOperation::List { .. } => {
                        dispatcher.perform(admitted)
                    }
                    _ => dispatcher.cancel(admitted),
                };
                let answered = matches!(
                    &response,
                    FileResponse::Answer { request_id, .. } if *request_id == id
                );
                ensure!(
                    answered,
                    "step {index}: request {id} was answered with {response:?}"
                );
                let messages = dispatcher
                    .encode(&response)
                    .map_err(|error| format!("step {index}: an answer did not encode: {error}"))?;
                ensure!(
                    messages
                        .iter()
                        .all(|message| bytes_of(message.len()) <= limits.max_message_bytes),
                    "step {index}: an answer message is over the bound"
                );
                Seen::Finished(response)
            }
            Step::Finish(_) => Seen::Nothing,
            Step::CancelIncomplete(id) => Seen::Incomplete(dispatcher.cancel_incomplete(*id)),
            Step::NextWindow => {
                clock.advance(limits.window * 2);
                window = WindowWatch {
                    base: dispatcher.counters().received_bytes,
                    refused: false,
                };
                Seen::Nothing
            }
        };
        let held_now = dispatcher.in_flight() + dispatcher.incomplete().count();
        ensure!(
            held_now <= usize::try_from(limits.max_in_flight).unwrap(),
            "step {index}: {held_now} requests held"
        );
        ensure!(
            dispatcher.buffered_bytes() <= limits.max_buffered_bytes,
            "step {index}: {} bytes buffered",
            dispatcher.buffered_bytes()
        );
        let counters = dispatcher.counters();
        let counted = counters.received_bytes - window.base;
        ensure!(
            counted <= limits.max_window_bytes,
            "step {index}: {counted} message bytes counted in one window"
        );
        ensure!(
            counters.received == receives,
            "step {index}: {} messages counted of {receives}",
            counters.received
        );
        seen.push(observed);
    }
    for admitted in held {
        let _ = dispatcher.cancel(admitted);
    }
    let counters = dispatcher.counters();
    Ok((dispatcher.into_service(), seen, counters))
}

/// The script's steps, one per line, with every message in hex.
fn script_hex(script: &[Step]) -> String {
    script
        .iter()
        .enumerate()
        .map(|(index, step)| match step {
            Step::Receive(message) => format!("  {index}: receive {}\n", hex::encode(message)),
            other => format!("  {index}: {other:?}\n"),
        })
        .collect()
}

#[test]
fn random_scripts_keep_the_dispatcher_within_its_bounds() {
    let grammar = grammar();
    let profiles = [tight_limits(), window_limits()];
    for limits in &profiles {
        limits.validate().unwrap();
    }
    let (mut service, _directory) = service();
    let mut rng = SplitMix64::new(0x00E0_1F00_0000_0003);
    let mut totals = ChannelCounters::default();
    for number in 0..SCRIPTS {
        let limits = profiles[usize::try_from(number % 2).unwrap()];
        let script = script(&mut rng, &grammar, &limits);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let (service, first, counters) = run_script(service, limits, &script)?;
            let (service, second, again) = run_script(service, limits, &script)?;
            ensure!(
                first == second && counters == again,
                "two runs of one script differ"
            );
            Ok((service, counters))
        }));
        let (returned, counters) = match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(message)) => panic!(
                "file_protocol dispatcher: script {number}: {message}\n{}",
                script_hex(&script)
            ),
            Err(_) => panic!(
                "file_protocol dispatcher: script {number} panicked\n{}",
                script_hex(&script)
            ),
        };
        service = returned;
        totals.admitted += counters.admitted;
        totals.buffered_parts += counters.buffered_parts;
        totals.performed += counters.performed;
        totals.cancelled += counters.cancelled;
        totals.message_refusals += counters.message_refusals;
        totals.in_flight_refusals += counters.in_flight_refusals;
        totals.byte_window_refusals += counters.byte_window_refusals;
        totals.dropped += counters.dropped;
    }
    // Every bound was reached somewhere in the run.
    for (what, count) in [
        ("admitted", totals.admitted),
        ("buffered parts", totals.buffered_parts),
        ("performed", totals.performed),
        ("cancelled", totals.cancelled),
        ("message refusals", totals.message_refusals),
        ("in-flight refusals", totals.in_flight_refusals),
        ("byte-window refusals", totals.byte_window_refusals),
        ("dropped", totals.dropped),
    ] {
        assert!(
            count > 0,
            "file_protocol dispatcher: no {what} in {totals:?}"
        );
    }
}
