//! Tests of the link's sans-IO core: frames, messages and the two session ends. Nothing
//! here touches the OS; the pipe adapter has its own tests.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::*;
use crate::foundation::ids::{digest, Digest, ExecutionId};
use crate::foundation::process::ProcessIdentity;
use crate::foundation::transfer::KeyError;
use crate::sandbox_contract::destinations::RouteId;

const REQUEST: &[u8] = b"GET /v1/models HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

fn key(byte: u8) -> LinkKey {
    LinkKey::new(vec![byte; 32]).unwrap()
}

fn relay_process() -> ProcessIdentity {
    ProcessIdentity {
        pid: 4242,
        start_time_ticks: 133_000_000_000_000_000,
    }
}

fn session_id(n: u8) -> LinkSessionId {
    LinkSessionId::from_digest(digest("yougori/test/relay-link/v1", &[&[n]]))
}

fn binding() -> LinkBinding {
    LinkBinding {
        sandbox: ExecutionId::new("exe-sandbox-a").unwrap(),
        relay: relay_process(),
        session: session_id(1),
    }
}

fn relay_end() -> RelayLink {
    RelayLink::open(binding(), key(1))
}

fn broker_end() -> BrokerLink {
    BrokerLink::open(binding(), key(1))
}

fn forward(exchange: u64) -> RelayMessage {
    RelayMessage::Forward {
        exchange: ExchangeId::new(exchange),
        route: RouteId::new("provider-api").unwrap(),
        request: WireBytes::new(REQUEST.to_vec()),
    }
}

fn response(exchange: u64) -> BrokerMessage {
    BrokerMessage::Response {
        exchange: ExchangeId::new(exchange),
        status: 200,
        response: WireBytes::new(RESPONSE.to_vec()),
    }
}

fn close(reason: CloseReason) -> RelayMessage {
    RelayMessage::Close { reason }
}

/// Exactly one whole frame from `bytes`.
fn frame(bytes: &[u8]) -> RawFrame {
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.feed(bytes).unwrap(), bytes.len());
    let frame = decoder.take().unwrap();
    assert!(decoder.is_between_frames());
    frame
}

/// The JSON body of a frame, to forge variants of it.
fn body_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(frame(bytes).body()).unwrap()
}

/// A frame no session would write, sealed under `key`.
fn forged(key: &LinkKey, body: &Value) -> RawFrame {
    frame(&key.forge(&serde_json::to_vec(body).unwrap()).unwrap())
}

/// A broker's first frame, answering `exchange`, forged: no broker session seals an
/// answer to an exchange it never saw.
fn forged_answer(exchange: u64) -> RawFrame {
    forged(
        &key(1),
        &json!({
            "sandbox": "exe-sandbox-a",
            "relay": relay_process(),
            "session": session_id(1),
            "direction": "broker_to_relay",
            "sequence": 0,
            "message": serde_json::to_value(response(exchange)).unwrap(),
        }),
    )
}

#[test]
fn a_round_trip_carries_each_message_once_and_in_order() {
    let (mut relay, mut broker) = (relay_end(), broker_end());
    let sent = relay.seal(forward(0)).unwrap();
    assert_eq!(broker.accept(&frame(&sent)).unwrap(), forward(0));
    assert_eq!(broker.open_exchanges(), 1);
    let answer = broker.seal(response(0)).unwrap();
    assert_eq!(relay.accept(&frame(&answer)).unwrap(), response(0));
    assert_eq!(relay.open_exchanges(), 0);

    let refusal = BrokerMessage::Refused {
        exchange: ExchangeId::new(1),
        refusal: ExchangeRefusal::NotPermitted,
    };
    assert_eq!(
        broker
            .accept(&frame(&relay.seal(forward(1)).unwrap()))
            .unwrap(),
        forward(1)
    );
    assert_eq!(
        relay
            .accept(&frame(&broker.seal(refusal.clone()).unwrap()))
            .unwrap(),
        refusal
    );

    let closing = relay.seal(close(CloseReason::Finished)).unwrap();
    assert_eq!(
        broker.accept(&frame(&closing)).unwrap(),
        close(CloseReason::Finished)
    );
    let closed = LinkState::Closed {
        by: LinkDirection::RelayToBroker,
        reason: CloseReason::Finished,
    };
    assert_eq!(relay.state(), &closed);
    assert_eq!(broker.state(), &closed);
    assert_eq!(broker.binding(), &binding());
}

#[test]
fn frames_read_alike_however_the_bytes_are_split() {
    let mut relay = relay_end();
    let stream: Vec<u8> = [forward(0), forward(1), close(CloseReason::Stopping)]
        .into_iter()
        .flat_map(|message| relay.seal(message).unwrap())
        .collect();
    let whole: Vec<RawFrame> = {
        let mut decoder = FrameDecoder::new();
        let mut rest = &stream[..];
        let mut frames = Vec::new();
        while !rest.is_empty() {
            let used = decoder.feed(rest).unwrap();
            rest = &rest[used..];
            frames.extend(decoder.take());
        }
        frames
    };
    assert_eq!(whole.len(), 3);
    for chunk in [1, 2, 5, 37, 4096] {
        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        for piece in stream.chunks(chunk) {
            let mut rest = piece;
            while !rest.is_empty() {
                let used = decoder.feed(rest).unwrap();
                rest = &rest[used..];
                frames.extend(decoder.take());
            }
        }
        assert_eq!(frames, whole, "chunks of {chunk}");
        assert!(decoder.is_between_frames());
    }
    // A complete frame waits to be taken; nothing more is taken meanwhile.
    let mut decoder = FrameDecoder::new();
    let first = decoder.feed(&stream).unwrap();
    assert!(first < stream.len());
    assert_eq!(decoder.feed(&stream[first..]).unwrap(), 0);
    assert!(decoder.take().is_some());
    let mut broker = broker_end();
    for frame in &whole {
        broker.accept(frame).unwrap();
    }
    assert!(matches!(broker.state(), LinkState::Closed { .. }));
}

#[test]
fn a_replayed_frame_is_refused_and_ends_the_link() {
    let (mut relay, mut broker) = (relay_end(), broker_end());
    let first = relay.seal(forward(0)).unwrap();
    broker.accept(&frame(&first)).unwrap();
    assert_eq!(
        broker.accept(&frame(&first)),
        Err(LinkRefusal::Replayed {
            sequence: 0,
            expected: 1
        })
    );
    assert_eq!(
        broker.state(),
        &LinkState::Failed(LinkRefusal::Replayed {
            sequence: 0,
            expected: 1
        })
    );
    // Nothing is read after the refusal, not even the right next frame.
    let next = relay.seal(forward(1)).unwrap();
    assert_eq!(broker.accept(&frame(&next)), Err(LinkRefusal::Failed));
    assert_eq!(broker.seal(response(0)), Err(LinkRefusal::Failed));
}

#[test]
fn a_reordered_frame_is_refused() {
    let (mut relay, mut broker) = (relay_end(), broker_end());
    let first = relay.seal(forward(0)).unwrap();
    let second = relay.seal(forward(1)).unwrap();
    assert_eq!(
        broker.accept(&frame(&second)),
        Err(LinkRefusal::OutOfOrder {
            sequence: 1,
            expected: 0
        })
    );
    assert_eq!(broker.accept(&frame(&first)), Err(LinkRefusal::Failed));
}

#[test]
fn a_changed_byte_of_the_body_or_tag_is_refused() {
    let sent = relay_end().seal(forward(0)).unwrap();
    for at in FRAME_HEADER_BYTES..sent.len() {
        let mut changed = sent.clone();
        changed[at] ^= 0x01;
        let mut broker = broker_end();
        assert_eq!(
            broker.accept(&frame(&changed)),
            Err(LinkRefusal::Tampered),
            "byte {at}"
        );
        assert!(matches!(broker.state(), LinkState::Failed(_)));
    }
    // A changed length cuts the frame elsewhere, so its tag no longer matches.
    let mut shorter = sent.clone();
    shorter[5] -= 1;
    let mut decoder = FrameDecoder::new();
    decoder.feed(&shorter).unwrap();
    assert_eq!(
        broker_end().accept(&decoder.take().unwrap()),
        Err(LinkRefusal::Tampered)
    );
}

#[test]
fn a_frame_sealed_under_another_key_is_refused() {
    let mut other = RelayLink::open(binding(), key(2));
    let sent = other.seal(forward(0)).unwrap();
    assert_eq!(
        broker_end().accept(&frame(&sent)),
        Err(LinkRefusal::Tampered)
    );
}

#[test]
fn a_frame_for_another_sandbox_relay_or_session_is_refused() {
    let elsewhere = ExecutionId::new("exe-sandbox-b").unwrap();
    let other_relay = ProcessIdentity {
        start_time_ticks: relay_process().start_time_ticks + 1,
        ..relay_process()
    };
    let cases = [
        (
            LinkBinding {
                sandbox: elsewhere.clone(),
                ..binding()
            },
            LinkRefusal::OtherSandbox { found: elsewhere },
        ),
        (
            LinkBinding {
                relay: other_relay,
                ..binding()
            },
            LinkRefusal::OtherRelay { found: other_relay },
        ),
        (
            LinkBinding {
                session: session_id(2),
                ..binding()
            },
            LinkRefusal::OtherSession,
        ),
    ];
    for (bound, refusal) in cases {
        // Even under the same key, a frame of another binding is refused.
        let sent = RelayLink::open(bound, key(1)).seal(forward(0)).unwrap();
        assert_eq!(broker_end().accept(&frame(&sent)), Err(refusal));
    }
}

#[test]
fn a_frame_reflected_to_its_sender_is_refused() {
    let mut relay = relay_end();
    let own = relay.seal(close(CloseReason::Stopping)).unwrap();
    // A close reads as a broker message too; only its direction gives it away.
    let mut fresh = relay_end();
    assert_eq!(
        fresh.accept(&frame(&own)),
        Err(LinkRefusal::WrongDirection {
            found: LinkDirection::RelayToBroker
        })
    );
}

#[test]
fn nothing_moves_after_a_close_either_way() {
    let (mut relay, mut broker) = (relay_end(), broker_end());
    broker
        .accept(&frame(&relay.seal(forward(0)).unwrap()))
        .unwrap();
    broker
        .accept(&frame(&relay.seal(close(CloseReason::Finished)).unwrap()))
        .unwrap();
    assert_eq!(relay.seal(forward(1)), Err(LinkRefusal::Closed));
    assert_eq!(broker.seal(response(0)), Err(LinkRefusal::Closed));
    // A correctly sealed frame with the next sequence number is refused after the close.
    let mut late = relay_end();
    let _ = late.seal(forward(0)).unwrap();
    let _ = late.seal(forward(1)).unwrap();
    let third = late.seal(forward(2)).unwrap();
    assert_eq!(broker.accept(&frame(&third)), Err(LinkRefusal::Closed));

    // The broker's close ends the relay's end the same way.
    let (mut relay, mut broker) = (relay_end(), broker_end());
    let revoked = broker
        .seal(BrokerMessage::Close {
            reason: CloseReason::Revoked,
        })
        .unwrap();
    relay.accept(&frame(&revoked)).unwrap();
    assert_eq!(
        relay.state(),
        &LinkState::Closed {
            by: LinkDirection::BrokerToRelay,
            reason: CloseReason::Revoked
        }
    );
    assert_eq!(relay.seal(forward(0)), Err(LinkRefusal::Closed));
}

#[test]
fn an_unknown_version_is_refused_from_its_first_two_bytes() {
    let mut decoder = FrameDecoder::new();
    assert_eq!(
        decoder.feed(&[0x00, 0x02]),
        Err(LinkRefusal::UnknownVersion { found: 2 })
    );
    // The refusal is final.
    assert_eq!(
        decoder.feed(&relay_end().seal(forward(0)).unwrap()),
        Err(LinkRefusal::UnknownVersion { found: 2 })
    );
    assert_eq!(
        decoder.refusal(),
        Some(&LinkRefusal::UnknownVersion { found: 2 })
    );
    assert!(!decoder.is_between_frames());
    let mut sent = relay_end().seal(forward(0)).unwrap();
    sent[1] = 0x00;
    assert_eq!(
        FrameDecoder::new().feed(&sent),
        Err(LinkRefusal::UnknownVersion { found: 0 })
    );
    assert_eq!(LINK_PROTOCOL_VERSION, 1);
}

#[test]
fn an_oversize_frame_is_refused_from_its_header_and_never_sealed() {
    let max = u64::try_from(MAX_FRAME_BYTES).unwrap();
    let over = u32::try_from(MAX_BODY_BYTES + 1).unwrap();
    let mut header = LINK_PROTOCOL_VERSION.to_be_bytes().to_vec();
    header.extend_from_slice(&over.to_be_bytes());
    assert_eq!(
        FrameDecoder::new().feed(&header),
        Err(LinkRefusal::Oversize {
            declared: max + 1,
            max
        })
    );
    let mut largest = LINK_PROTOCOL_VERSION.to_be_bytes().to_vec();
    largest.extend_from_slice(&u32::try_from(MAX_BODY_BYTES).unwrap().to_be_bytes());
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.feed(&largest), Ok(FRAME_HEADER_BYTES));
    assert!(decoder.take().is_none());
    let mut empty = LINK_PROTOCOL_VERSION.to_be_bytes().to_vec();
    empty.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        FrameDecoder::new().feed(&empty),
        Err(LinkRefusal::EmptyBody)
    );

    // A message whose frame would pass the bound is refused, and nothing changes.
    let mut relay = relay_end();
    let huge = RelayMessage::Forward {
        exchange: ExchangeId::FIRST,
        route: RouteId::new("provider-api").unwrap(),
        request: WireBytes::new(vec![b'a'; MAX_FRAME_BYTES]),
    };
    assert!(matches!(
        relay.seal(huge),
        Err(LinkRefusal::Oversize { max: bound, .. }) if bound == max
    ));
    assert_eq!(relay.state(), &LinkState::Open);
    assert_eq!(relay.open_exchanges(), 0);
    let sent = relay.seal(forward(0)).unwrap();
    assert_eq!(broker_end().accept(&frame(&sent)).unwrap(), forward(0));
}

#[test]
fn exchanges_are_numbered_upwards_answered_once_and_bounded() {
    let (mut relay, mut broker) = (relay_end(), broker_end());
    broker
        .accept(&frame(&relay.seal(forward(5)).unwrap()))
        .unwrap();
    // Outbound mistakes are refused and change nothing.
    let not_increasing = LinkRefusal::ExchangeNotIncreasing {
        exchange: ExchangeId::new(5),
        last: ExchangeId::new(5),
    };
    assert_eq!(relay.seal(forward(5)), Err(not_increasing));
    assert_eq!(
        broker.seal(response(4)),
        Err(LinkRefusal::UnknownExchange {
            exchange: ExchangeId::new(4)
        })
    );
    assert_eq!(relay.state(), &LinkState::Open);
    let answer = broker.seal(response(5)).unwrap();
    relay.accept(&frame(&answer)).unwrap();
    assert_eq!(
        broker.seal(response(5)),
        Err(LinkRefusal::UnknownExchange {
            exchange: ExchangeId::new(5)
        })
    );

    // Inbound, they end the link: a forward not above the last one...
    let mut body = body_of(&relay.seal(forward(6)).unwrap());
    body["message"]["exchange"] = json!(3);
    assert_eq!(
        broker.accept(&forged(&key(1), &body)),
        Err(LinkRefusal::ExchangeNotIncreasing {
            exchange: ExchangeId::new(3),
            last: ExchangeId::new(5)
        })
    );
    // ... and an answer to an exchange that is not open.
    let mut relay = relay_end();
    assert_eq!(
        relay.accept(&forged_answer(9)),
        Err(LinkRefusal::UnknownExchange {
            exchange: ExchangeId::new(9)
        })
    );

    let mut relay = relay_end();
    for exchange in 0..u64::try_from(MAX_OPEN_EXCHANGES).unwrap() {
        relay.seal(forward(exchange)).unwrap();
    }
    assert_eq!(
        relay.seal(forward(100)),
        Err(LinkRefusal::TooManyOpenExchanges {
            max: MAX_OPEN_EXCHANGES
        })
    );
    assert_eq!(relay.open_exchanges(), MAX_OPEN_EXCHANGES);
}

#[test]
fn an_authenticated_body_is_still_read_strictly() {
    let sent = relay_end().seal(forward(0)).unwrap();
    let base = body_of(&sent);
    let mut variants = Vec::new();
    let mut push = |change: &dyn Fn(&mut Value)| {
        let mut body = base.clone();
        change(&mut body);
        variants.push(body);
    };
    push(&|body| body["note"] = json!("x"));
    push(&|body| body["message"]["proxy"] = json!("https://example.com"));
    push(&|body| body["message"]["kind"] = json!("connect"));
    push(&|body| body["message"]["request"] = json!("not base64!"));
    push(&|body| body["message"]["route"] = json!("https://example.com/"));
    push(&|body| body["relay"]["handle"] = json!(1));
    push(&|body| {
        body.as_object_mut().unwrap().remove("session");
    });
    push(&|body| body["direction"] = json!("sideways"));
    push(&|body| body["sequence"] = json!(-1));
    for body in &variants {
        assert_eq!(
            broker_end().accept(&forged(&key(1), body)),
            Err(LinkRefusal::Malformed),
            "{body}"
        );
    }
    // The unchanged body, forged the same way, is read: only the changes were refused.
    assert_eq!(broker_end().accept(&forged(&key(1), &base)), Ok(forward(0)));
    // A broker message never reads as a relay message.
    assert_eq!(
        broker_end().accept(&forged_answer(0)),
        Err(LinkRefusal::Malformed)
    );
}

#[test]
fn messages_read_back_strictly() {
    let messages = [
        serde_json::to_value(forward(0)).unwrap(),
        serde_json::to_value(close(CloseReason::Finished)).unwrap(),
    ];
    for json in &messages {
        let back: RelayMessage = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(&serde_json::to_value(back).unwrap(), json);
        let mut extra = json.clone();
        extra["credential"] = json!("secret");
        assert!(serde_json::from_value::<RelayMessage>(extra).is_err());
    }
    let answers = [
        serde_json::to_value(response(0)).unwrap(),
        serde_json::to_value(BrokerMessage::Refused {
            exchange: ExchangeId::FIRST,
            refusal: ExchangeRefusal::BudgetExhausted,
        })
        .unwrap(),
        serde_json::to_value(BrokerMessage::Close {
            reason: CloseReason::Revoked,
        })
        .unwrap(),
    ];
    for json in &answers {
        let back: BrokerMessage = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(&serde_json::to_value(back).unwrap(), json);
        let mut extra = json.clone();
        extra["token"] = json!("secret");
        assert!(serde_json::from_value::<BrokerMessage>(extra).is_err());
    }
    assert_eq!(
        serde_json::to_value(forward(0)).unwrap()["request"],
        json!("R0VUIC92MS9tb2RlbHMgSFRUUC8xLjENCmhvc3Q6IGFwaS5leGFtcGxlLmNvbQ0KDQo=")
    );
    for bad in ["R0VU\n", "R0V", "R0VV=", "R0VU===", " R0VU"] {
        assert!(
            serde_json::from_value::<WireBytes>(json!(bad)).is_err(),
            "{bad:?}"
        );
    }
    assert!(serde_json::from_value::<CloseReason>(json!("forever")).is_err());
    assert!(serde_json::from_value::<ExchangeRefusal>(json!("secret_leaked")).is_err());
    let binding_json = serde_json::to_value(binding()).unwrap();
    assert_eq!(
        serde_json::from_value::<LinkBinding>(binding_json.clone()).unwrap(),
        binding()
    );
    let mut widened = binding_json;
    widened["pipe"] = json!("x");
    assert!(serde_json::from_value::<LinkBinding>(widened).is_err());
}

/// Every key any message or frame body can have, across every variant.
fn keys(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                into.insert(key.clone());
                keys(inner, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| keys(item, into)),
        _ => {}
    }
}

#[test]
fn no_message_has_a_field_that_can_hold_a_credential() {
    let mut relay = relay_end();
    let mut broker = broker_end();
    let mut found = BTreeSet::new();
    for message in [forward(0), close(CloseReason::Finished)] {
        let sent = relay.seal(message).unwrap();
        keys(&body_of(&sent), &mut found);
        broker.accept(&frame(&sent)).unwrap();
    }
    let mut broker = broker_end();
    broker
        .accept(&frame(&relay_end().seal(forward(0)).unwrap()))
        .unwrap();
    for answer in [
        response(0),
        BrokerMessage::Close {
            reason: CloseReason::Stopping,
        },
    ] {
        keys(&body_of(&broker.seal(answer).unwrap()), &mut found);
    }
    keys(
        &serde_json::to_value(BrokerMessage::Refused {
            exchange: ExchangeId::FIRST,
            refusal: ExchangeRefusal::RequestRefused,
        })
        .unwrap(),
        &mut found,
    );
    let expected: BTreeSet<String> = [
        "direction",
        "exchange",
        "kind",
        "message",
        "pid",
        "reason",
        "refusal",
        "relay",
        "request",
        "response",
        "route",
        "sandbox",
        "sequence",
        "session",
        "start_time_ticks",
        "status",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(found, expected);
    for key in &found {
        for word in ["credential", "secret", "token", "vault", "password", "auth"] {
            assert!(!key.contains(word), "{key}");
        }
    }
    // Nothing prints the bytes it carries.
    assert_eq!(
        format!("{:?}", WireBytes::new(b"Bearer abc".to_vec())),
        "WireBytes(10 bytes)"
    );
}

#[test]
fn keys_are_long_enough_and_never_shown() {
    assert!(matches!(
        LinkKey::new(vec![1; 31]),
        Err(KeyError::TooShort {
            min_bytes: 32,
            found_bytes: 31
        })
    ));
    let key = LinkKey::new(vec![0xab; 40]).unwrap();
    assert_eq!(format!("{key:?}"), "LinkKey(redacted)");
    let shown = format!("{:?}", RelayLink::open(binding(), key));
    assert!(
        !shown.contains("171") && !shown.contains("ab, ab"),
        "{shown}"
    );
}

/// Changing the layout changes every frame. The tag was computed independently with
/// Python's `hmac` and `hashlib` over the same domain-separated digest.
#[test]
fn the_frame_layout_and_tag_are_pinned() {
    let pinned = LinkBinding {
        session: LinkSessionId::from_digest(Digest::from_bytes([7; 32])),
        ..binding()
    };
    let mut relay = RelayLink::open(pinned, LinkKey::new(vec![0x0b; 32]).unwrap());
    let sent = relay.seal(close(CloseReason::Finished)).unwrap();
    let body = format!(
        "{{\"sandbox\":\"exe-sandbox-a\",\"relay\":{{\"pid\":4242,\"start_time_ticks\":\
         133000000000000000}},\"session\":\"{}\",\"direction\":\"relay_to_broker\",\
         \"sequence\":0,\"message\":{{\"kind\":\"close\",\"reason\":\"finished\"}}}}",
        "07".repeat(32)
    );
    assert_eq!(body.len(), 253);
    assert_eq!(&sent[..FRAME_HEADER_BYTES], &[0, 1, 0, 0, 0, 253]);
    assert_eq!(
        &sent[FRAME_HEADER_BYTES..sent.len() - FRAME_TAG_BYTES],
        body.as_bytes()
    );
    assert_eq!(
        hex::encode(&sent[sent.len() - FRAME_TAG_BYTES..]),
        "d6a9741d81fc38ee2877e5a77995feeecae1f22c37a75a8649c8287da7bfec85"
    );
    assert_eq!(LINK_FRAME_DOMAIN, "yougori/sandbox/relay-link/frame/v1");
    assert_eq!(frame(&sent).to_bytes().unwrap(), sent);
}

#[test]
fn sessions_are_random_and_exchanges_count_up() {
    assert_ne!(LinkSessionId::generate(), LinkSessionId::generate());
    assert_eq!(ExchangeId::FIRST.next(), Some(ExchangeId::new(1)));
    assert_eq!(ExchangeId::new(u64::MAX).next(), None);
}

#[test]
fn link_messages_read_only_their_written_form_with_a_string_kind_and_no_repeated_key() {
    let written = serde_json::to_value(close(CloseReason::Finished)).unwrap();
    assert_eq!(
        serde_json::from_value::<RelayMessage>(written.clone()).unwrap(),
        close(CloseReason::Finished)
    );
    // A kind written as a number reads as no variant, nested in a buffered record or not.
    let mut numbered = written.clone();
    numbered["kind"] = json!(1);
    assert!(serde_json::from_value::<RelayMessage>(numbered.clone()).is_err());
    assert!(serde_json::from_value::<Vec<RelayMessage>>(json!([numbered])).is_err());
    // A repeated key is refused, the tag and a field alike.
    for text in [
        r#"{"kind":"close","kind":"close","reason":"finished"}"#,
        r#"{"kind":"close","reason":"finished","reason":"stopping"}"#,
    ] {
        assert!(
            serde_json::from_str::<RelayMessage>(text).is_err(),
            "{text}"
        );
    }
    let answer = serde_json::to_value(response(3)).unwrap();
    let mut numbered = answer.clone();
    numbered["kind"] = json!(0);
    assert!(serde_json::from_value::<BrokerMessage>(numbered).is_err());
    assert_eq!(
        serde_json::from_value::<BrokerMessage>(answer).unwrap(),
        response(3)
    );
}
