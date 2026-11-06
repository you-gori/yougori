//! The adapter over a real host link driven by a scripted guest end, with a real file
//! protocol dispatcher over the real file service on temporary roots and the CORE-05 fakes
//! (VM part §3.2 lines 2059–2077, §5.1 lines 2218–2232; VM-W06, VM-W14; S2 CORE-05 row line
//! 214; INT-02 line 270, INT-08 line 276; tracker S05).

use std::fs;
use std::sync::Arc;

use serde_json::json;

use super::fakes::*;
use super::*;
use crate::foundation::ids::{ContentKey, ManualClock};
use crate::foundation::transfer::fakes::{parent, EPOCH};
use crate::foundation::transfer::{
    ByteBudgetRefusal, Endpoint, ProgressPhase, StopReason, TransferRefusal, TransferStatus,
};
use crate::sandbox::link::{
    CancelCause, Channel, ChannelCloseCause, FileMode, GrantHandle, GuestRequest as LinkRequest,
    HostLink, LinkEvent, LinkLimits, LinkMessage, OpenRefusalCause,
};
use crate::sandbox_contract::file_protocol::{ChannelLimits, GuestOperation, ProtocolRefusal};

type Files = GuestFiles<Arc<ManualClock>>;

fn create(file: &str, content: &[u8]) -> GuestOperation {
    GuestOperation::Create {
        name: name(file),
        content: content.to_vec(),
    }
}

fn list() -> GuestOperation {
    GuestOperation::List { name: None }
}

fn listed_names(messages: &[LinkMessage], stream_id: u32) -> Vec<String> {
    let listing = outcome(messages, stream_id);
    assert_eq!(listing["kind"], "listed", "{listing}");
    listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_small_create_and_read_travel_on_their_own_streams() {
    let mut rig = Rig::new();
    let text = b"notes from the guest".to_vec();
    let events = rig.call(1, 7, create("notes.txt", &text));
    assert_eq!(
        events,
        vec![
            FilesEvent::Opened {
                grant: GRANT,
                stream: stream(1)
            },
            FilesEvent::Performed {
                grant: GRANT,
                stream: stream(1),
                request: id(7)
            },
        ]
    );
    let messages = rig.drain();
    assert!(opened(&messages, 1));
    assert_eq!(outcome(&messages, 1), json!({"kind": "created"}));
    assert!(ended(&messages, 1));
    assert_eq!(fs::read(rig.root().join("notes.txt")).unwrap(), text);
    // Once both ends ended the stream, the channel holds nothing of it.
    assert!(rig.end(1).is_empty());
    assert_eq!(rig.files.streams(), 0);

    rig.call(
        3,
        8,
        GuestOperation::Read {
            name: name("notes.txt"),
            max_bytes: 1024,
        },
    );
    let messages = rig.drain();
    assert_eq!(
        outcome(&messages, 3),
        json!({"kind": "read", "length": text.len()})
    );
    assert_eq!(content(&messages, 3), text);
    // Each processed message's bytes went back into the guest's window.
    assert_eq!(rig.link.channel(Channel::File).buffered_bytes, 0);
    assert!(messages.iter().any(|message| matches!(
        message,
        LinkMessage::WindowUpdate {
            channel: Channel::File,
            ..
        }
    )));
    assert_eq!(rig.files.counters().performed, 2);
    // No body moved, so no transfer grant was asked for.
    assert!(rig.issuer.requests().is_empty());
}

#[test]
fn operations_without_content_ride_streams_named_by_their_operation() {
    let mut rig = Rig::new();
    fs::write(rig.root().join("a.txt"), b"a").unwrap();
    rig.call(1, 1, GuestOperation::CreateDirectory { name: name("out") });
    rig.call(3, 2, list());
    rig.call(
        5,
        3,
        GuestOperation::Rename {
            from: name("a.txt"),
            to: name("out/b.txt"),
            replace: false,
        },
    );
    rig.call(
        7,
        4,
        GuestOperation::Delete {
            name: name("out/b.txt"),
        },
    );
    let messages = rig.drain();
    assert_eq!(outcome(&messages, 1), json!({"kind": "directory_created"}));
    let mut names = listed_names(&messages, 3);
    names.sort();
    assert_eq!(names, vec!["a.txt", "out"]);
    assert_eq!(outcome(&messages, 5), json!({"kind": "renamed"}));
    assert_eq!(outcome(&messages, 7), json!({"kind": "deleted"}));
    assert!(rig.root().join("out").is_dir());
    assert!(!rig.root().join("a.txt").exists());
    assert!(!rig.root().join("out/b.txt").exists());
    assert_eq!(rig.files.counters().performed, 4);
}

#[test]
fn scope_session_and_time_come_from_the_channel_never_from_the_guest() {
    let mut rig = Rig::new();
    // A dispatcher made for another scope is not attached, and is handed back.
    let other = rig.dir.path().join("other");
    fs::create_dir(&other).unwrap();
    let refused = rig
        .files
        .add_grant(
            GrantHandle(42),
            dispatcher(
                &other,
                &rig.clock,
                other_scope(),
                channel_limits(&LinkLimits::default()),
            ),
        )
        .unwrap_err();
    assert_eq!(refused.error, GrantError::ScopeMismatch);
    assert_eq!(refused.dispatcher.scope(), other_scope());
    assert_eq!(rig.files.grants().collect::<Vec<_>>(), vec![GRANT]);

    // A header claiming a scope is refused by the protocol before the service is asked.
    rig.open(1, entry("list"), FileMode::Read);
    let claim = format!(
        "{}\n",
        json!({"version": 1, "request_id": 5, "part": 0,
               "request": {"operation": "list", "name": null}, "scope": "sandbox-b"})
    );
    let events = rig.data(1, claim.as_bytes());
    assert!(
        matches!(
            &events[..],
            [FilesEvent::ProtocolRefused {
                refusal: ProtocolRefusal::Malformed { .. },
                ..
            }]
        ),
        "{events:?}"
    );
    let messages = rig.drain();
    assert_eq!(outcome(&messages, 1)["kind"], "protocol_refused");
    assert!(ended(&messages, 1));

    // A name outside the granted root never reaches the service either.
    rig.open(3, entry("read"), FileMode::Read);
    let escape = format!(
        "{}\n",
        json!({"version": 1, "request_id": 6, "part": 0,
               "request": {"operation": "read", "name": "../secret.txt", "max_bytes": 64}})
    );
    let events = rig.data(3, escape.as_bytes());
    assert!(matches!(
        &events[..],
        [FilesEvent::ProtocolRefused {
            refusal: ProtocolRefusal::InvalidName { .. },
            ..
        }]
    ));
    let messages = rig.drain();
    let answer = data_on(&messages, 3).concat();
    assert!(!answer.windows(SECRET.len()).any(|window| window == SECRET));

    // Every request is made at the host clock's reading: past the grant's expiry the
    // service refuses it.
    rig.clock.advance(2 * HOUR);
    rig.call(5, 7, list());
    let messages = rig.drain();
    let refusal = outcome(&messages, 5);
    assert_eq!(refusal["kind"], "service_refused");
    assert_eq!(refusal["refusal"]["kind"], "grant");
    assert_eq!(refusal["refusal"]["refusal"]["refusal"], "expired");
}

#[test]
fn events_of_other_channels_are_refused_without_effect() {
    let mut rig = Rig::new();
    let before = rig.files.counters();
    let egress = LinkEvent::Request(LinkRequest::Data {
        channel: Channel::Egress,
        stream: stream(1),
        bytes: vec![1, 2, 3],
    });
    assert!(!Files::is_file_event(&egress));
    let events = rig.files.handle(&mut rig.link, egress).unwrap();
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::WrongChannel {
            channel: Channel::Egress
        }]
    );
    let ping = LinkEvent::Request(LinkRequest::Ping { nonce: 9 });
    let events = rig.files.handle(&mut rig.link, ping).unwrap();
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::WrongChannel {
            channel: Channel::Control
        }]
    );
    let report = rig.other_events[0].clone();
    assert!(matches!(report, LinkEvent::Report(_)));
    assert!(!Files::is_file_event(&report));
    let events = rig.files.handle(&mut rig.link, report).unwrap();
    assert_eq!(refusals(&events), vec![FilesRefusal::NotFileEvent]);
    // An answer to an open on the file channel, which this adapter never makes.
    let answer = LinkEvent::Request(LinkRequest::Opened {
        channel: Channel::File,
        stream: stream(2),
    });
    assert!(Files::is_file_event(&answer));
    let events = rig.files.handle(&mut rig.link, answer).unwrap();
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::UnexpectedAnswer { stream: stream(2) }]
    );
    let after = rig.files.counters();
    assert_eq!(after.opened, before.opened);
    assert_eq!(after.refusals, before.refusals + 4);
    assert_eq!(rig.files.streams(), 0);
    assert!(rig.drain().is_empty());
}

#[test]
fn links_of_another_instance_boot_or_limits_are_refused() {
    let mut rig = Rig::new();
    let event = LinkEvent::Request(LinkRequest::WindowUpdate {
        channel: Channel::File,
        credit_bytes: 1,
    });
    let mut stranger = HostLink::new(
        binding(other_vm(), boot()),
        LinkLimits::default(),
        Arc::clone(&rig.clock),
    )
    .unwrap();
    assert_eq!(
        rig.files.handle(&mut stranger, event.clone()).unwrap_err(),
        LinkMismatch::OtherInstance {
            expected: vm(),
            bound: other_vm()
        }
    );
    let mut rebooted = HostLink::new(
        binding(vm(), other_boot()),
        LinkLimits::default(),
        Arc::clone(&rig.clock),
    )
    .unwrap();
    assert_eq!(
        rig.files.pump(&mut rebooted).unwrap_err(),
        LinkMismatch::OtherBoot {
            expected: boot(),
            bound: other_boot()
        }
    );
    let tighter = LinkLimits {
        max_refusals: 5,
        ..LinkLimits::default()
    };
    let mut other = HostLink::new(binding(vm(), boot()), tighter, Arc::clone(&rig.clock)).unwrap();
    assert_eq!(
        rig.files.handle(&mut other, event).unwrap_err(),
        LinkMismatch::OtherLimits
    );
    // Nothing changed: the channel still serves its own link.
    rig.call(1, 1, list());
    assert!(listed_names(&rig.drain(), 1).is_empty());
    assert_eq!(rig.files.counters().links_lost, 0);
}

#[test]
fn opens_naming_an_unknown_grant_or_a_malformed_declaration_are_refused() {
    let mut rig = Rig::new();
    let events = rig.open_with(1, STRANGER, entry("list"), FileMode::Read);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::UnknownGrant { grant: STRANGER }]
    );
    let malformed = [
        (3, entry("hello"), FileMode::Read),
        (5, entry("read"), FileMode::Write),
        (7, content_entry(b"x"), FileMode::Read),
        (9, entry("content-abc"), FileMode::Write),
        (
            11,
            entry(&format!("content-{}", "A".repeat(64))),
            FileMode::Write,
        ),
        (13, entry("create"), FileMode::Write),
    ];
    for (stream_id, name, mode) in malformed {
        let events = rig.open(stream_id, name.clone(), mode);
        let expected = match stream_id {
            5 => DeclarationRefusal::ModeMismatch {
                declared: FileMode::Write,
                needed: FileMode::Read,
            },
            7 => DeclarationRefusal::ModeMismatch {
                declared: FileMode::Read,
                needed: FileMode::Write,
            },
            _ => DeclarationRefusal::UnknownEntry { entry: name },
        };
        assert_eq!(
            refusals(&events),
            vec![FilesRefusal::Declaration(expected)],
            "{stream_id}"
        );
    }
    let messages = rig.drain();
    assert_eq!(
        open_refused(&messages, 1),
        Some(OpenRefusalCause::NotAuthorized)
    );
    for stream_id in [3, 5, 7, 9, 11, 13] {
        assert_eq!(
            open_refused(&messages, stream_id),
            Some(OpenRefusalCause::Unsupported)
        );
    }
    assert_eq!(rig.files.streams(), 0);
    assert_eq!(rig.files.counters().open_refusals, 7);
}

#[test]
fn a_request_other_than_its_streams_declaration_cancels_the_stream() {
    let mut rig = Rig::new();
    fs::write(rig.root().join("a.txt"), b"a").unwrap();
    rig.open(1, entry("delete"), FileMode::Write);
    let events = rig.request(
        1,
        1,
        GuestOperation::Rename {
            from: name("a.txt"),
            to: name("b.txt"),
            replace: false,
        },
    );
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::Declaration(
            DeclarationRefusal::OperationMismatch {
                declared: Declaration::Operation {
                    kind: OperationKind::Delete
                },
                received: OperationKind::Rename,
            }
        )]
    );
    rig.open(3, content_entry(b"x"), FileMode::Write);
    let events = rig.request(
        3,
        2,
        GuestOperation::Delete {
            name: name("a.txt"),
        },
    );
    assert!(matches!(
        &refusals(&events)[..],
        [FilesRefusal::Declaration(
            DeclarationRefusal::OperationMismatch {
                declared: Declaration::Content { .. },
                received: OperationKind::Delete,
            }
        )]
    ));
    let messages = rig.drain();
    assert_eq!(cancel_of(&messages, 1), Some(CancelCause::Failed));
    assert_eq!(cancel_of(&messages, 3), Some(CancelCause::Failed));
    assert!(rig.root().join("a.txt").exists());
    // The dispatcher was never given either message.
    assert_eq!(rig.files.dispatcher(GRANT).unwrap().counters().received, 0);
}

#[test]
fn a_small_body_that_is_not_its_declared_content_is_never_written() {
    let mut rig = Rig::new();
    rig.open(1, content_entry(b"declared"), FileMode::Write);
    let events = rig.request(1, 1, create("x.txt", b"received"));
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::ContentMismatch {
            declared: ContentKey::of(b"declared"),
            received: ContentKey::of(b"received"),
        }]
    );
    let messages = rig.drain();
    assert_eq!(cancel_of(&messages, 1), Some(CancelCause::Failed));
    assert!(!rig.root().join("x.txt").exists());
    assert!(rig.issuer.requests().is_empty());
}

#[test]
fn a_large_body_moves_as_a_core05_transfer_verified_before_it_is_written() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 1);
    let messages = Rig::messages(9, create("big.bin", &body));
    assert!(messages.len() >= 4);
    rig.open(1, content_entry(&body), FileMode::Write);
    let first = rig.data(1, &messages[0]);
    assert_eq!(
        phases(&first),
        vec![BodyPhase::Opened {
            length_bytes: 200_000
        }]
    );
    // The whole budget was reserved before any later part was kept.
    assert_eq!(rig.ledger.held_bytes(), 200_000);
    let asked = &rig.issuer.requests()[0];
    assert_eq!(asked.object, ContentKey::of(&body));
    assert_eq!(asked.length_bytes, 200_000);
    assert_eq!(asked.request, id(9));
    assert_eq!(asked.kind, OperationKind::Create);
    assert_eq!(asked.name, name("big.bin"));
    assert_eq!(asked.tenant, identity().tenant);
    assert_eq!(asked.source, guest_route(vm(), boot(), GRANT));
    assert_eq!(
        asked.recipient,
        Endpoint::Execution {
            execution: parent()
        }
    );
    assert_eq!(
        asked.operation,
        body_operation(&identity().operation, GRANT, 1).unwrap()
    );
    let view = rig.files.body(GRANT, id(9)).unwrap();
    assert!(view.held_bytes > 0 && view.held_bytes < 200_000);
    assert_eq!(view.used_bytes, view.held_bytes);
    assert_eq!(view.status, TransferStatus::Active);
    assert!(!rig.root().join("big.bin").exists());

    let mut events = Vec::new();
    for message in &messages[1..] {
        events.extend(rig.data(1, message));
    }
    assert_eq!(
        phases(&events),
        vec![BodyPhase::Completed {
            length_bytes: 200_000
        }]
    );
    assert!(events.contains(&FilesEvent::Performed {
        grant: GRANT,
        stream: stream(1),
        request: id(9)
    }));
    assert_eq!(fs::read(rig.root().join("big.bin")).unwrap(), body);
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(rig.ledger.releases().len(), 1);
    assert_eq!(rig.ledger.releases()[0].1, 200_000);
    let progress: Vec<ProgressPhase> = rig
        .progress
        .events()
        .into_iter()
        .map(|event| event.phase)
        .collect();
    assert_eq!(progress.first(), Some(&ProgressPhase::Started));
    assert_eq!(progress.last(), Some(&ProgressPhase::Completed));
    let chunks = progress
        .iter()
        .filter(|phase| matches!(phase, ProgressPhase::ChunkDelivered { .. }))
        .count();
    assert_eq!(chunks, messages.len());
    assert!(rig.files.body(GRANT, id(9)).is_none());
    assert_eq!(outcome(&rig.drain(), 1), json!({"kind": "created"}));

    // A write replaces the file only once its new content is verified too.
    let replacement = pattern(150_000, 9);
    let events = rig.call(
        3,
        10,
        GuestOperation::Write {
            name: name("big.bin"),
            content: replacement.clone(),
        },
    );
    assert_eq!(
        phases(&events),
        vec![
            BodyPhase::Opened {
                length_bytes: 150_000
            },
            BodyPhase::Completed {
                length_bytes: 150_000
            }
        ]
    );
    assert_eq!(fs::read(rig.root().join("big.bin")).unwrap(), replacement);
    assert_eq!(outcome(&rig.drain(), 3), json!({"kind": "written"}));
    assert_eq!(rig.files.counters().bodies_completed, 2);
}

#[test]
fn a_large_body_whose_bytes_do_not_match_is_refused_and_never_written() {
    let mut rig = Rig::new();
    let declared = pattern(150_000, 1);
    let sent = pattern(150_000, 2);
    rig.open(1, content_entry(&declared), FileMode::Write);
    let events = rig.request(1, 3, create("big.bin", &sent));
    let mismatch = BodyPhase::Mismatched {
        declared: ContentKey::of(&declared),
        received: ContentKey::of(&sent),
    };
    assert_eq!(
        phases(&events),
        vec![
            BodyPhase::Opened {
                length_bytes: 150_000
            },
            mismatch
        ]
    );
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::ContentMismatch {
            declared: ContentKey::of(&declared),
            received: ContentKey::of(&sent),
        }]
    );
    let messages = rig.drain();
    assert_eq!(cancel_of(&messages, 1), Some(CancelCause::Failed));
    assert!(!rig.root().join("big.bin").exists());
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(
        rig.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Stopped {
            reason: StopReason::Cancelled
        })
    );
    let dispatcher = rig.files.dispatcher(GRANT).unwrap();
    assert_eq!(dispatcher.in_flight(), 0);
    assert_eq!(dispatcher.incomplete().count(), 0);
}

#[test]
fn a_grant_for_another_instance_boot_grant_object_or_budget_is_refused() {
    let cases = [
        (
            Issue::Source(guest_route(other_vm(), boot(), GRANT)),
            FilesRefusal::NotBound {
                field: BindingField::Source,
            },
        ),
        (
            Issue::Source(guest_route(vm(), other_boot(), GRANT)),
            FilesRefusal::NotBound {
                field: BindingField::Source,
            },
        ),
        (
            Issue::Source(guest_route(vm(), boot(), GrantHandle(42))),
            FilesRefusal::NotBound {
                field: BindingField::Source,
            },
        ),
        (
            Issue::Object(ContentKey::of(b"another object")),
            FilesRefusal::NotBound {
                field: BindingField::Scope,
            },
        ),
        (
            Issue::Budget(1_000),
            FilesRefusal::NotBound {
                field: BindingField::Budget,
            },
        ),
        (
            Issue::OtherKey,
            FilesRefusal::Transfer(TransferRefusal::Tampered),
        ),
        (
            Issue::Refuse(AuthorityRefusal::NotPermitted),
            FilesRefusal::Authority(AuthorityRefusal::NotPermitted),
        ),
        (
            Issue::Refuse(AuthorityRefusal::Unavailable),
            FilesRefusal::Authority(AuthorityRefusal::Unavailable),
        ),
    ];
    for (issue, expected) in cases {
        let mut rig = Rig::new();
        rig.issuer.set(issue);
        let events = rig.call(1, 1, create("big.bin", &pattern(100_000, 3)));
        assert_eq!(refusals(&events), vec![expected.clone()]);
        let messages = rig.drain();
        assert_eq!(cancel_of(&messages, 1), Some(expected.cancel_cause()));
        // Nothing was reserved or kept, and nothing was written.
        assert!(rig.ledger.requests().is_empty(), "{expected}");
        assert_eq!(rig.files.dispatcher(GRANT).unwrap().incomplete().count(), 0);
        assert!(!rig.root().join("big.bin").exists());
    }
}

#[test]
fn an_envelope_issued_for_another_body_is_refused() {
    let mut rig = Rig::new();
    let body = pattern(100_000, 4);
    let events = rig.call(1, 1, create("one.bin", &body));
    assert!(phases(&events).contains(&BodyPhase::Completed {
        length_bytes: 100_000
    }));
    rig.issuer.set(Issue::Replay);
    let events = rig.call(3, 2, create("two.bin", &body));
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::NotBound {
            field: BindingField::Operation
        }]
    );
    assert!(!rig.root().join("two.bin").exists());
    assert_eq!(rig.ledger.requests().len(), 1);
}

#[test]
fn the_guest_can_cancel_a_body_and_its_reservation_is_released() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 5);
    let messages = Rig::messages(5, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.data(1, &messages[1]);
    assert_eq!(rig.ledger.held_bytes(), 200_000);
    let events = rig.cancel(1, CancelCause::Requested);
    assert_eq!(phases(&events), vec![BodyPhase::Cancelled]);
    assert_eq!(
        events.last(),
        Some(&FilesEvent::GuestCancelled {
            grant: GRANT,
            stream: stream(1),
            cause: CancelCause::Requested
        })
    );
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(
        rig.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Stopped {
            reason: StopReason::Cancelled
        })
    );
    let dispatcher = rig.files.dispatcher(GRANT).unwrap();
    assert_eq!(dispatcher.incomplete().count(), 0);
    assert_eq!(dispatcher.buffered_bytes(), 0);
    assert!(rig.files.body(GRANT, id(5)).is_none());
    assert!(!rig.root().join("big.bin").exists());
    assert_eq!(rig.files.streams(), 0);
}

#[test]
fn a_revocation_stops_a_body_by_its_bounds_even_while_no_part_moves() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 6);
    let messages = Rig::messages(2, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.data(1, &messages[1]);
    let current = rig.authority.revoke(&parent()).unwrap();
    assert_eq!(current, revoked_epoch());
    let revoked = StopReason::AuthorityNotCurrent {
        granted: EPOCH,
        current: Some(current),
    };
    let events = rig.files.tick();
    assert_eq!(
        phases(&events),
        vec![BodyPhase::Stopped {
            reason: revoked.clone()
        }]
    );
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::Transfer(TransferRefusal::Stopped {
            reason: revoked
        })]
    );
    rig.pump();
    let sent = rig.drain();
    assert_eq!(cancel_of(&sent, 1), Some(CancelCause::Revoked));
    assert_eq!(rig.ledger.held_bytes(), 0);
    // A part the guest had in flight is refused by the link as one of a cancelled stream.
    assert!(rig.data(1, &messages[2]).is_empty());
    assert!(matches!(
        rig.other_events.last(),
        Some(LinkEvent::Refused(_))
    ));
    assert!(!rig.root().join("big.bin").exists());
}

#[test]
fn an_expired_grant_stops_its_body_as_timed_out() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 7);
    let messages = Rig::messages(3, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.clock.advance(2 * HOUR);
    let events = rig.data(1, &messages[1]);
    let expired = StopReason::Expired {
        expires_at: at(HOUR),
    };
    assert_eq!(
        phases(&events),
        vec![BodyPhase::Stopped {
            reason: expired.clone()
        }]
    );
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::Transfer(TransferRefusal::Stopped {
            reason: expired
        })]
    );
    assert_eq!(cancel_of(&rig.drain(), 1), Some(CancelCause::TimedOut));
    assert_eq!(rig.ledger.held_bytes(), 0);
}

#[test]
fn an_interrupted_body_resumes_on_a_new_link_of_the_same_boot_within_its_budget() {
    let mut rig = Rig::new();
    let body = pattern(260_000, 8);
    let messages = Rig::messages(11, create("big.bin", &body));
    assert!(messages.len() >= 4);
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.data(1, &messages[1]);
    let held = rig.files.body(GRANT, id(11)).unwrap().held_bytes;
    let events = rig.lose_link();
    assert_eq!(
        phases(&events),
        vec![BodyPhase::Interrupted { held_bytes: held }]
    );
    assert_eq!(events.last(), Some(&FilesEvent::LinkLost));
    let view = rig.files.body(GRANT, id(11)).unwrap();
    assert_eq!(view.status, TransferStatus::Interrupted);
    assert_eq!(view.stream, None);
    assert_eq!(rig.files.streams(), 0);
    // The reservation is kept while the body waits.
    assert_eq!(rig.ledger.held_bytes(), 260_000);

    assert!(rig.reconnect(16 << 20).is_empty());
    // The guest sends the whole request again on a stream declaring the same content.
    let mut events = rig.open(1, content_entry(&body), FileMode::Write);
    for message in &messages {
        events.extend(rig.data(1, message));
    }
    assert_eq!(
        phases(&events),
        vec![
            BodyPhase::Resumed {
                attempt: 2,
                held_bytes: held
            },
            BodyPhase::Completed {
                length_bytes: 260_000
            }
        ]
    );
    assert_eq!(rig.files.counters().resent_parts_dropped, 2);
    assert_eq!(rig.files.counters().bodies_resumed, 1);
    assert_eq!(fs::read(rig.root().join("big.bin")).unwrap(), body);
    // Nothing was reserved or charged twice.
    assert_eq!(rig.ledger.requests().len(), 1);
    assert_eq!(rig.ledger.releases().len(), 1);
    assert_eq!(rig.ledger.releases()[0].1, 260_000);
    let progress: Vec<ProgressPhase> = rig
        .progress
        .events()
        .into_iter()
        .map(|event| event.phase)
        .collect();
    assert!(progress
        .iter()
        .any(|phase| matches!(phase, ProgressPhase::Interrupted { .. })));
    assert!(progress.contains(&ProgressPhase::Resumed));
    assert_eq!(progress.last(), Some(&ProgressPhase::Completed));
    assert_eq!(outcome(&rig.drain(), 1), json!({"kind": "created"}));
}

#[test]
fn an_interrupted_body_never_resumes_from_another_boot_or_declaration() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 9);
    let messages = Rig::messages(2, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.lose_link();
    let mut rebooted = HostLink::new(
        binding(vm(), other_boot()),
        LinkLimits::default(),
        Arc::clone(&rig.clock),
    )
    .unwrap();
    let open = LinkEvent::Request(LinkRequest::OpenFile {
        stream: stream(1),
        grant: GRANT,
        entry: content_entry(&body),
        mode: FileMode::Write,
    });
    assert!(matches!(
        rig.files.handle(&mut rebooted, open),
        Err(LinkMismatch::OtherBoot { .. })
    ));
    assert_eq!(
        rig.files.body(GRANT, id(2)).unwrap().status,
        TransferStatus::Interrupted
    );

    // On a new link of the right boot, a stream declaring other content does not resume
    // it: the request id is still the body's, so the dispatcher refuses the message.
    rig.reconnect(16 << 20);
    rig.open(1, content_entry(b"other content"), FileMode::Write);
    let events = rig.data(1, &messages[0]);
    assert!(matches!(
        &events[..],
        [FilesEvent::ProtocolRefused {
            refusal: ProtocolRefusal::DuplicateRequestId,
            ..
        }]
    ));
    assert_eq!(rig.files.counters().bodies_resumed, 0);

    // The host drops the interrupted body; its reservation and buffer go back.
    let events = rig.files.cancel_interrupted(GRANT, id(2));
    assert_eq!(phases(&events), vec![BodyPhase::Cancelled]);
    assert!(rig.files.body(GRANT, id(2)).is_none());
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(rig.files.dispatcher(GRANT).unwrap().incomplete().count(), 0);
}

#[test]
fn a_new_link_is_noticed_by_its_sequence_or_its_stream_ids() {
    // By its sequence: the new link's first file event comes at a lower guest sequence.
    let mut rig = Rig::new();
    let body = pattern(200_000, 10);
    let messages = Rig::messages(4, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    let events = rig.reconnect(16 << 20);
    assert!(matches!(
        &phases(&events)[..],
        [BodyPhase::Interrupted { .. }]
    ));
    assert!(events.contains(&FilesEvent::LinkLost));

    // By its stream ids: the guest reopens a stream id the old link already used.
    let mut rig = Rig::new();
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    assert!(rig.reconnect(0).is_empty());
    for nonce in 0..8 {
        rig.send(LinkMessage::Ping { nonce });
    }
    let events = rig.open(1, content_entry(&body), FileMode::Write);
    assert!(matches!(
        &phases(&events)[..],
        [BodyPhase::Interrupted { .. }]
    ));
    assert!(events.contains(&FilesEvent::LinkLost));
    assert!(events.contains(&FilesEvent::Opened {
        grant: GRANT,
        stream: stream(1)
    }));
}

#[test]
fn answers_wait_for_credit_and_guest_messages_wait_for_answers() {
    let mut rig = Rig::with(Setup {
        limits: FilesLimits {
            max_pending_bytes: 100_000,
        },
        credit: 0,
    });
    let file = pattern(300_000, 11);
    fs::write(rig.root().join("big.bin"), &file).unwrap();
    rig.open(1, entry("read"), FileMode::Read);
    rig.open(3, entry("list"), FileMode::Read);
    let opens = rig.drain();
    assert!(opened(&opens, 1) && opened(&opens, 3));

    let events = rig.request(
        1,
        1,
        GuestOperation::Read {
            name: name("big.bin"),
            max_bytes: 400_000,
        },
    );
    assert_eq!(events.len(), 1);
    // Without credit nothing of the answer goes out.
    assert!(data_on(&rig.drain(), 1).is_empty());
    assert!(rig.files.pending_bytes() > 300_000);

    // Past the bound, a guest message waits unprocessed and keeps its bytes in the window.
    let listing = Rig::messages(2, list());
    assert!(rig.data(3, &listing[0]).is_empty());
    assert_eq!(rig.files.deferred(), 1);
    assert_eq!(
        rig.link.channel(Channel::File).buffered_bytes,
        listing[0].len() as u64
    );

    // Credit lets the answer out in order; once it fits the bound the message is taken.
    rig.credit(150_000);
    let mut sent = rig.drain();
    assert_eq!(data_on(&sent, 1).len(), 2);
    assert_eq!(rig.files.deferred(), 1);
    let events = rig.credit(1 << 20);
    assert!(events.contains(&FilesEvent::Performed {
        grant: GRANT,
        stream: stream(3),
        request: id(2)
    }));
    assert_eq!(rig.files.deferred(), 0);
    sent.extend(rig.drain());
    assert_eq!(content(&sent, 1), file);
    assert_eq!(listed_names(&sent, 3), vec!["big.bin"]);
    assert_eq!(rig.link.channel(Channel::File).buffered_bytes, 0);
    assert_eq!(rig.files.pending_bytes(), 0);
    assert_eq!(rig.files.counters().deferred, 1);
}

#[test]
fn a_part_on_another_stream_is_refused_and_the_body_continues() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 12);
    let messages = Rig::messages(4, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.open(3, content_entry(&body), FileMode::Write);
    let events = rig.data(3, &messages[1]);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::NoRequest { claimed: id(4) }]
    );
    let mut events = Vec::new();
    for message in &messages[1..] {
        events.extend(rig.data(1, message));
    }
    assert!(phases(&events).contains(&BodyPhase::Completed {
        length_bytes: 200_000
    }));
    assert_eq!(fs::read(rig.root().join("big.bin")).unwrap(), body);
    let sent = rig.drain();
    assert_eq!(cancel_of(&sent, 3), Some(CancelCause::Failed));
    assert_eq!(outcome(&sent, 1), json!({"kind": "created"}));
}

#[test]
fn a_stream_carries_one_request_and_nothing_after_its_answer() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 13);
    let messages = Rig::messages(5, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    let second = Rig::messages(6, GuestOperation::Delete { name: name("x") });
    let events = rig.data(1, &second[0]);
    assert_eq!(refusals(&events), vec![FilesRefusal::SecondRequest]);
    assert_eq!(phases(&events), vec![BodyPhase::Cancelled]);

    rig.open(3, content_entry(&body), FileMode::Write);
    rig.data(3, &messages[0]);
    let foreign = Rig::messages(77, create("big.bin", &body));
    let events = rig.data(3, &foreign[1]);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::OtherRequest {
            expected: id(5),
            claimed: id(77)
        }]
    );

    rig.call(5, 8, list());
    let events = rig.data(5, &Rig::messages(9, list())[0]);
    assert_eq!(refusals(&events), vec![FilesRefusal::AfterAnswer]);
    let sent = rig.drain();
    assert_eq!(cancel_of(&sent, 1), Some(CancelCause::Failed));
    assert_eq!(cancel_of(&sent, 3), Some(CancelCause::Failed));
    assert_eq!(cancel_of(&sent, 5), Some(CancelCause::Failed));
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert!(!rig.root().join("big.bin").exists());
}

#[test]
fn ending_a_stream_before_its_body_is_whole_cancels_the_body() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 14);
    let messages = Rig::messages(3, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    let held = rig.files.body(GRANT, id(3)).unwrap().held_bytes;
    let events = rig.end(1);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::BodyEndedEarly {
            held_bytes: held,
            declared_bytes: 200_000
        }]
    );
    assert_eq!(phases(&events), vec![BodyPhase::Cancelled]);
    assert_eq!(cancel_of(&rig.drain(), 1), Some(CancelCause::Failed));
    assert_eq!(rig.ledger.held_bytes(), 0);
}

#[test]
fn removing_a_grant_cancels_its_streams_and_bodies_and_hands_back_its_dispatcher() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 15);
    let messages = Rig::messages(1, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.open(3, entry("list"), FileMode::Read);
    let removed = rig.files.remove_grant(GRANT).unwrap();
    assert_eq!(removed.dispatcher.scope(), scope());
    assert_eq!(phases(&removed.events), vec![BodyPhase::Cancelled]);
    for stream_id in [1, 3] {
        assert!(removed.events.contains(&FilesEvent::HostCancelled {
            grant: GRANT,
            stream: stream(stream_id),
            cause: CancelCause::Revoked
        }));
    }
    rig.pump();
    let sent = rig.drain();
    assert_eq!(cancel_of(&sent, 1), Some(CancelCause::Revoked));
    assert_eq!(cancel_of(&sent, 3), Some(CancelCause::Revoked));
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(rig.files.grants().count(), 0);
    assert!(rig.files.remove_grant(GRANT).is_none());
    let events = rig.open(5, entry("list"), FileMode::Read);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::UnknownGrant { grant: GRANT }]
    );
}

#[test]
fn the_host_can_cancel_a_stream() {
    let mut rig = Rig::new();
    rig.open(1, entry("list"), FileMode::Read);
    let events = rig.files.cancel(stream(1));
    assert_eq!(
        events,
        vec![FilesEvent::HostCancelled {
            grant: GRANT,
            stream: stream(1),
            cause: CancelCause::Requested
        }]
    );
    assert!(rig.files.cancel(stream(1)).is_empty());
    // A message the guest sent before the cancel went out finds no stream; its bytes still
    // go back into the window.
    let events = rig.data(1, &Rig::messages(1, list())[0]);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::UnknownStream { stream: stream(1) }]
    );
    rig.pump();
    assert_eq!(cancel_of(&rig.drain(), 1), Some(CancelCause::Requested));
    assert_eq!(rig.files.streams(), 0);
    assert_eq!(rig.files.counters().host_cancels, 1);
    assert_eq!(rig.link.channel(Channel::File).buffered_bytes, 0);

    // The guest cancels a stream that carries nothing yet.
    rig.open(3, entry("list"), FileMode::Read);
    let events = rig.cancel(3, CancelCause::Requested);
    assert_eq!(
        events,
        vec![FilesEvent::GuestCancelled {
            grant: GRANT,
            stream: stream(3),
            cause: CancelCause::Requested
        }]
    );
    assert_eq!(rig.files.streams(), 0);
}

#[test]
fn a_closed_file_channel_or_a_timed_out_open_ends_what_it_held() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 18);
    let messages = Rig::messages(1, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    let closed = LinkEvent::ChannelClosed {
        channel: Channel::File,
        cause: ChannelCloseCause::WindowExceeded {
            remaining_bytes: 0,
            needed_bytes: 1,
        },
    };
    assert!(Files::is_file_event(&closed));
    let events = rig.files.handle(&mut rig.link, closed).unwrap();
    assert!(matches!(
        &phases(&events)[..],
        [BodyPhase::Interrupted { .. }]
    ));
    assert_eq!(events.last(), Some(&FilesEvent::LinkLost));
    assert_eq!(rig.files.streams(), 0);
    assert_eq!(
        rig.files.body(GRANT, id(1)).unwrap().status,
        TransferStatus::Interrupted
    );

    // The link dropped a stream it held half-opened; the adapter forgets it too.
    rig.open(3, entry("list"), FileMode::Read);
    let timed_out = LinkEvent::StreamTimedOut {
        channel: Channel::File,
        stream: stream(3),
        cancel_sent: true,
    };
    let events = rig.files.handle(&mut rig.link, timed_out).unwrap();
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::OpenTimedOut { stream: stream(3) }]
    );
    assert_eq!(rig.files.streams(), 0);
}

#[test]
fn a_body_resumes_from_the_parts_the_guest_sends_again_in_order() {
    let mut rig = Rig::new();
    let body = pattern(260_000, 19);
    let messages = Rig::messages(12, create("big.bin", &body));
    assert_eq!(messages.len(), 4);
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.data(1, &messages[1]);
    let held = rig.files.body(GRANT, id(12)).unwrap().held_bytes;
    rig.lose_link();
    rig.reconnect(16 << 20);
    // The guest resumes from part 1, which the host holds already, without part 0.
    let mut events = rig.open(1, content_entry(&body), FileMode::Write);
    for message in &messages[1..] {
        events.extend(rig.data(1, message));
    }
    assert_eq!(
        phases(&events),
        vec![
            BodyPhase::Resumed {
                attempt: 2,
                held_bytes: held
            },
            BodyPhase::Completed {
                length_bytes: 260_000
            }
        ]
    );
    assert_eq!(rig.files.counters().resent_parts_dropped, 1);
    assert_eq!(fs::read(rig.root().join("big.bin")).unwrap(), body);
    assert_eq!(rig.ledger.releases()[0].1, 260_000);

    // Parts sent again must rise: going back on a resuming stream ends the body.
    let mut rig = Rig::new();
    rig.open(1, content_entry(&body), FileMode::Write);
    for message in &messages[..3] {
        rig.data(1, message);
    }
    rig.lose_link();
    rig.reconnect(16 << 20);
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[2]);
    let events = rig.data(1, &messages[1]);
    assert_eq!(
        refusals(&events),
        vec![FilesRefusal::PartNotIncreasing { part: 1, last: 2 }]
    );
    assert_eq!(phases(&events), vec![BodyPhase::Cancelled]);
    assert_eq!(cancel_of(&rig.drain(), 1), Some(CancelCause::Failed));
    assert_eq!(rig.ledger.held_bytes(), 0);
}

#[test]
fn an_interrupted_body_stops_on_revocation_while_it_waits() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 20);
    let messages = Rig::messages(3, create("big.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.data(1, &messages[0]);
    rig.lose_link();
    let current = rig.authority.revoke(&parent()).unwrap();
    let events = rig.files.tick();
    assert_eq!(
        phases(&events),
        vec![BodyPhase::Stopped {
            reason: StopReason::AuthorityNotCurrent {
                granted: EPOCH,
                current: Some(current)
            }
        }]
    );
    // No stream carried it, so nothing is cancelled on the link.
    assert!(refusals(&events).is_empty());
    assert!(rig.files.body(GRANT, id(3)).is_none());
    assert_eq!(rig.ledger.held_bytes(), 0);
    assert_eq!(rig.files.dispatcher(GRANT).unwrap().incomplete().count(), 0);
}

#[test]
fn two_bodies_of_the_same_content_move_side_by_side() {
    let mut rig = Rig::new();
    let body = pattern(200_000, 21);
    let first = Rig::messages(1, create("a.bin", &body));
    let second = Rig::messages(2, create("b.bin", &body));
    rig.open(1, content_entry(&body), FileMode::Write);
    rig.open(3, content_entry(&body), FileMode::Write);
    let mut events = Vec::new();
    for (one, two) in first.iter().zip(&second) {
        events.extend(rig.data(1, one));
        events.extend(rig.data(3, two));
    }
    let completed = phases(&events)
        .into_iter()
        .filter(|phase| matches!(phase, BodyPhase::Completed { .. }))
        .count();
    assert_eq!(completed, 2);
    assert_eq!(fs::read(rig.root().join("a.bin")).unwrap(), body);
    assert_eq!(fs::read(rig.root().join("b.bin")).unwrap(), body);
    let operations: Vec<_> = rig
        .issuer
        .requests()
        .into_iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(operations.len(), 2);
    assert_ne!(operations[0], operations[1]);
    let releases = rig.ledger.releases();
    assert_eq!(releases.len(), 2);
    assert!(releases.iter().all(|(_, used)| *used == 200_000));
}

#[test]
fn a_body_the_dispatcher_refuses_asks_for_no_grant() {
    let mut rig = Rig::new();
    rig.open(1, content_entry(b"abc"), FileMode::Write);
    let header = json!({"version": 1, "request_id": 1, "part": 0,
        "request": {"operation": "create", "name": "x.bin", "length": 9 << 20}});
    let mut message = serde_json::to_vec(&header).unwrap();
    message.push(b'\n');
    message.extend_from_slice(b"abc");
    let events = rig.data(1, &message);
    assert!(matches!(
        &events[..],
        [FilesEvent::ProtocolRefused {
            refusal: ProtocolRefusal::ContentTooLarge { .. },
            ..
        }]
    ));
    assert!(rig.issuer.requests().is_empty());
    assert!(rig.ledger.requests().is_empty());
    let sent = rig.drain();
    assert_eq!(outcome(&sent, 1)["kind"], "protocol_refused");
    assert!(ended(&sent, 1));
}

#[test]
fn channel_bounds_follow_the_link() {
    assert_eq!(room(), 65_469);
    assert_eq!(
        channel_limits(&LinkLimits::default()).max_message_bytes,
        65_469
    );
    let mut rig = Rig::new();
    let other = rig.dir.path().join("other");
    fs::create_dir(&other).unwrap();
    // The file protocol's own default message bound does not fit one data frame.
    let refused = rig
        .files
        .add_grant(
            GrantHandle(42),
            dispatcher(&other, &rig.clock, scope(), ChannelLimits::default()),
        )
        .unwrap_err();
    assert_eq!(
        refused.error,
        GrantError::MessageBound {
            bound_bytes: 65_472,
            room_bytes: 65_469
        }
    );
    let refused = rig.files.add_grant(GRANT, *refused.dispatcher).unwrap_err();
    assert_eq!(refused.error, GrantError::Duplicate { grant: GRANT });

    let issuer = Arc::new(Issuer::new());
    let setup = |link: LinkLimits, limits: FilesLimits| {
        let authority = Arc::new(crate::foundation::transfer::fakes::FakeAuthority::default());
        let ledger = Arc::new(crate::foundation::transfer::fakes::FakeByteLedger::new(1));
        let progress = Arc::new(crate::foundation::transfer::fakes::FakeProgress::default());
        let transfers = transfers(&rig.clock, &authority, &ledger, &progress, &issuer);
        Files::new(identity(), link, transfers, limits).unwrap_err()
    };
    let mut small = LinkLimits::default();
    small.file.max_message_bytes = 16_000;
    assert_eq!(
        setup(small, FilesLimits::default()),
        SetupError::MessageRoom {
            room_bytes: 15_997,
            minimum: 16_385
        }
    );
    assert_eq!(
        setup(
            LinkLimits::default(),
            FilesLimits {
                max_pending_bytes: 0
            }
        ),
        SetupError::ZeroPending
    );
    let broken = LinkLimits {
        max_refusals: 0,
        ..LinkLimits::default()
    };
    assert!(matches!(
        setup(broken, FilesLimits::default()),
        SetupError::Link(_)
    ));
    // The adapter's bound is strict on input.
    let json = serde_json::to_value(FilesLimits::default()).unwrap();
    assert_eq!(json, json!({"max_pending_bytes": 8 << 20}));
    assert!(serde_json::from_value::<FilesLimits>(
        json!({"max_pending_bytes": 1, "unbounded": true})
    )
    .is_err());
}

#[test]
fn declarations_round_trip_through_their_entries() {
    for kind in OperationKind::ALL {
        if kind.carries_content() {
            assert!(Declaration::parse(&entry(kind.name()), FileMode::Write).is_err());
            continue;
        }
        let declaration = Declaration::Operation { kind };
        let text = declaration.entry().unwrap();
        assert_eq!(text.as_str(), kind.name());
        assert_eq!(Declaration::parse(&text, kind.mode()), Ok(declaration));
    }
    let key = ContentKey::of(b"content");
    let declaration = Declaration::Content { content: key };
    let text = declaration.entry().unwrap();
    assert_eq!(
        text.as_str(),
        format!("{CONTENT_ENTRY_PREFIX}{}", key.digest().to_hex())
    );
    assert_eq!(Declaration::parse(&text, FileMode::Write), Ok(declaration));
}

#[test]
fn refusals_say_why_plainly_and_map_to_link_causes() {
    let revoked = StopReason::AuthorityNotCurrent {
        granted: EPOCH,
        current: Some(revoked_epoch()),
    };
    let stopped = |reason| FilesRefusal::Transfer(TransferRefusal::Stopped { reason });
    assert_eq!(stopped(revoked).cancel_cause(), CancelCause::Revoked);
    assert_eq!(
        stopped(StopReason::Expired {
            expires_at: at(HOUR)
        })
        .cancel_cause(),
        CancelCause::TimedOut
    );
    assert_eq!(
        stopped(StopReason::ReservationWithdrawn).cancel_cause(),
        CancelCause::Revoked
    );
    let budget = FilesRefusal::Transfer(TransferRefusal::ReservationRefused {
        refusal: ByteBudgetRefusal {
            requested_bytes: 10,
            available_bytes: 0,
            retry_can_progress: true,
        },
    });
    assert_eq!(budget.cancel_cause(), CancelCause::QuotaExceeded);
    assert_eq!(
        FilesRefusal::WindowSpent.cancel_cause(),
        CancelCause::QuotaExceeded
    );
    assert_eq!(
        FilesRefusal::Authority(AuthorityRefusal::NotPermitted).cancel_cause(),
        CancelCause::Failed
    );
    let key = ContentKey::of(b"k");
    let refusals = [
        FilesRefusal::WrongChannel {
            channel: Channel::Terminal,
        },
        FilesRefusal::NotFileEvent,
        FilesRefusal::UnexpectedAnswer { stream: stream(2) },
        FilesRefusal::UnknownGrant { grant: STRANGER },
        FilesRefusal::Declaration(DeclarationRefusal::UnknownEntry {
            entry: entry("hello"),
        }),
        FilesRefusal::UnknownStream { stream: stream(3) },
        FilesRefusal::OpenTimedOut { stream: stream(5) },
        FilesRefusal::AfterAnswer,
        FilesRefusal::SecondRequest,
        FilesRefusal::OtherRequest {
            expected: id(1),
            claimed: id(2),
        },
        FilesRefusal::NoRequest { claimed: id(3) },
        FilesRefusal::PartNotIncreasing { part: 2, last: 4 },
        FilesRefusal::BodyEndedEarly {
            held_bytes: 1,
            declared_bytes: 2,
        },
        FilesRefusal::ContentMismatch {
            declared: key,
            received: key,
        },
        FilesRefusal::BodyLength {
            declared: 1,
            seen: 2,
        },
        FilesRefusal::Authority(AuthorityRefusal::Unavailable),
        FilesRefusal::NotBound {
            field: BindingField::StopBounds,
        },
        budget,
        FilesRefusal::WindowSpent,
        FilesRefusal::Disagreement,
    ];
    let mut texts: Vec<String> = refusals.iter().map(ToString::to_string).collect();
    texts.push(
        LinkMismatch::OtherBoot {
            expected: boot(),
            bound: other_boot(),
        }
        .to_string(),
    );
    texts.push(SetupError::ZeroPending.to_string());
    texts.push(GrantError::ScopeMismatch.to_string());
    for text in texts {
        assert!(!text.is_empty());
        assert!(!text.to_lowercase().contains("secure"), "{text}");
    }
}

#[test]
fn guest_ends_and_body_operations_are_bound_to_instance_boot_grant_and_body() {
    let routes = [
        guest_route(vm(), boot(), GRANT),
        guest_route(other_vm(), boot(), GRANT),
        guest_route(vm(), other_boot(), GRANT),
        guest_route(vm(), boot(), STRANGER),
    ];
    for (index, route) in routes.iter().enumerate() {
        assert!(matches!(route, Endpoint::NamedRoute { .. }));
        assert!(routes[index + 1..].iter().all(|other| other != route));
    }
    assert_eq!(identity().guest_end(GRANT), routes[0]);
    assert_eq!(
        identity().host_end(),
        Endpoint::Execution {
            execution: parent()
        }
    );
    let channel = identity().operation;
    let first = body_operation(&channel, GRANT, 1).unwrap();
    assert_eq!(first, body_operation(&channel, GRANT, 1).unwrap());
    assert!(first.as_str().starts_with("op-"));
    assert_ne!(first, body_operation(&channel, GRANT, 2).unwrap());
    assert_ne!(first, body_operation(&channel, STRANGER, 1).unwrap());
    let other_channel = crate::foundation::ids::OperationId::new("op-another-channel").unwrap();
    assert_ne!(first, body_operation(&other_channel, GRANT, 1).unwrap());
}
