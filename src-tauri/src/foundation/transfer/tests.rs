//! Transfer flows on fake ports driven by a manual clock (CORE-05, S3.7, INT-02, INT-08).

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

use super::fakes::*;
use super::*;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, ExecutionId, OperationId, TenantId,
};

const EPOCH_5: AuthorizationEpoch = AuthorizationEpoch::new(5);

fn weights() -> ContentKey {
    object("weights")
}

/// A pull of "weights" from the enrolled peer "donor" into the host catalog (GPU-W09).
fn peer_fields() -> EnvelopeFields {
    EnvelopeFields {
        operation: operation("op-peer"),
        direction: Direction::Peer,
        source: peer("donor"),
        credential: None,
        ..download_fields()
    }
}

/// The download grant re-issued from epoch 5, then changed by `change`.
fn reissued(change: impl FnOnce(&mut EnvelopeFields)) -> EnvelopeFields {
    let mut fields = download_fields();
    fields.epoch = EPOCH_5;
    change(&mut fields);
    fields
}

/// One widening re-issue and the violation it must be refused with.
fn case(
    fields: EnvelopeFields,
    check: fn(&RetryViolation) -> bool,
) -> (EnvelopeFields, fn(&RetryViolation) -> bool) {
    (fields, check)
}

fn open(world: &World, fields: EnvelopeFields) -> TransferSession {
    let connection = connection_for(&fields);
    world.gate.open(&world.seal(fields), &connection).unwrap()
}

/// Admits and delivers `range` of `object`; then the catalog verifies it.
fn move_verified(
    world: &World,
    session: &mut TransferSession,
    object: &ContentKey,
    range: ByteRange,
) {
    let permit = session.admit(object, range).unwrap();
    session.deliver(permit).unwrap();
    world.verify(session.envelope().fields(), object, range);
}

fn stop_record(session: &TransferSession) -> StopRecord {
    match session.status() {
        TransferStatus::Stopped(record) => record.clone(),
        other => panic!("expected a stopped transfer, found {other:?}"),
    }
}

/// Brief: a retry after revocation is refused, and the bounds persist (INT-08).
#[test]
fn a_retry_after_revocation_is_refused_and_the_bounds_persist() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    let mut session = world.gate.open(&sealed, &download_connection()).unwrap();
    let granted = session.envelope().clone();
    move_verified(&world, &mut session, &weights(), range(0, 40));
    let lost = session.admit(&weights(), range(40, 70)).unwrap();
    session.interrupt().unwrap();
    assert_eq!(session.used_bytes(), 70);

    assert_eq!(world.authority.revoke(&parent()), Some(EPOCH_5));
    assert_eq!(
        session.retry(&download_connection()).unwrap_err(),
        TransferRefusal::Stopped {
            reason: StopReason::AuthorityNotCurrent {
                granted: EPOCH,
                current: Some(EPOCH_5)
            }
        }
    );
    assert!(stop_record(&session).reason.is_revocation());
    assert!(matches!(
        session.retry(&download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    assert!(matches!(
        session.deliver(lost),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert!(matches!(
        session.admit(&weights(), range(40, 50)),
        Err(TransferRefusal::NotActive { .. })
    ));

    // The bounds persist: the same grant, and the first attempt's bytes still count.
    assert_eq!(session.envelope(), &granted);
    assert_eq!(session.used_bytes(), 70);
    assert_eq!(session.remaining_budget_bytes(), 80);
    assert_eq!(session.reservation(), None);
    assert_eq!(world.ledger.held_bytes(), 0);
    // Replaying the sealed envelope does not start over either.
    assert_eq!(
        world
            .gate
            .open(&sealed, &download_connection())
            .unwrap_err(),
        TransferRefusal::AlreadyOpened {
            operation: operation("op-download")
        }
    );
}

/// INT-08: a grant re-issued from the newer epoch continues the transfer only within the
/// original object, range, recipient, credential, expiry and byte bounds.
#[test]
fn a_reissued_grant_after_revocation_cannot_widen_anything() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    move_verified(&world, &mut session, &weights(), range(0, 40));
    world.authority.revoke(&parent());
    assert!(matches!(session.poll(), TransferStatus::Stopped(_)));

    let cases = vec![
        case(
            reissued(|f| {
                f.scope = TransferScope::new([
                    (weights(), ObjectGrant::whole(100).unwrap()),
                    (object("adapter"), ObjectGrant::whole(10).unwrap()),
                ])
                .unwrap()
            }),
            |v| matches!(v, RetryViolation::WiderScope { .. }),
        ),
        case(reissued(|f| f.budget_bytes = 151), |v| {
            matches!(
                v,
                RetryViolation::LargerBudget {
                    granted_bytes: 150,
                    proposed_bytes: 151
                }
            )
        }),
        case(reissued(|f| f.expires_at = at(2 * HOUR)), |v| {
            matches!(v, RetryViolation::LaterExpiry { .. })
        }),
        case(
            reissued(|f| {
                f.recipient = Endpoint::Execution {
                    execution: parent(),
                }
            }),
            |v| matches!(v, RetryViolation::OtherRecipient { .. }),
        ),
        case(reissued(|f| f.source = route("mirror")), |v| {
            matches!(v, RetryViolation::OtherSource { .. })
        }),
        case(
            reissued(|f| f.credential = Some(credential("other-token"))),
            |v| matches!(v, RetryViolation::OtherCredential),
        ),
        case(reissued(|f| f.credential = None), |v| {
            matches!(v, RetryViolation::OtherCredential)
        }),
        case(reissued(|f| f.stop_bounds.max_in_flight_bytes = 41), |v| {
            matches!(v, RetryViolation::LooserStopBounds { .. })
        }),
        case(
            reissued(|f| f.stop_bounds.max_chunk_duration = 11 * SECOND),
            |v| matches!(v, RetryViolation::LooserStopBounds { .. }),
        ),
        case(
            reissued(|f| {
                f.direction = Direction::Peer;
                f.source = peer("donor");
                f.credential = None;
            }),
            |v| matches!(v, RetryViolation::OtherDirection),
        ),
        case(reissued(|f| f.operation = operation("op-other")), |v| {
            matches!(v, RetryViolation::OtherOperation)
        }),
        case(
            reissued(|f| f.tenant = TenantId::new("tenant-b").unwrap()),
            |v| matches!(v, RetryViolation::OtherTenant),
        ),
        case(
            reissued(|f| f.parent = ExecutionId::new("exe-other").unwrap()),
            |v| matches!(v, RetryViolation::OtherParent),
        ),
        case(reissued(|f| f.epoch = EPOCH), |v| {
            matches!(v, RetryViolation::EpochNotNewer { .. })
        }),
        case(reissued(|f| f.clock = OTHER_SESSION), |v| {
            matches!(v, RetryViolation::OtherClock)
        }),
    ];
    for (fields, check) in cases {
        let connection = connection_for(&fields);
        let refused = session
            .retry_with_grant(&world.seal(fields), &connection)
            .unwrap_err();
        let TransferRefusal::RetryWidens { violations } = &refused else {
            panic!("{refused:?}");
        };
        assert!(violations.iter().any(check), "{refused}");
        assert!(matches!(session.status(), TransferStatus::Stopped(_)));
    }
    let forged = TransferKey::from_bytes(&[8u8; 32])
        .unwrap()
        .seal(TransferEnvelope::new(reissued(|_| {})).unwrap());
    assert_eq!(
        session.retry_with_grant(&forged, &download_connection()),
        Err(TransferRefusal::Tampered)
    );
    assert_eq!(world.ledger.requests().len(), 1);

    // A grant from the new epoch continues nothing until the parent holds authority
    // under that epoch, as after a new launch.
    assert_eq!(
        session.retry_with_grant(&world.seal(reissued(|_| {})), &download_connection()),
        Err(TransferRefusal::Stopped {
            reason: StopReason::ParentWithoutAuthority { epoch: EPOCH_5 }
        })
    );
    assert_eq!(world.ledger.requests().len(), 1);
    world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));

    // The same bounds from the new epoch continue the transfer, reusing what is verified.
    session
        .retry_with_grant(&world.seal(reissued(|_| {})), &download_connection())
        .unwrap();
    assert_eq!(session.status(), &TransferStatus::Active);
    assert_eq!(session.attempt(), 2);
    assert_eq!(session.verified_bytes(), 40);
    assert_eq!(session.used_bytes(), 40);
    assert_eq!(
        session.reservation().map(|held| held.reserved_bytes),
        Some(110)
    );
    assert!(matches!(
        session.admit(&weights(), range(0, 40)),
        Err(TransferRefusal::AlreadyCovered { .. })
    ));
    move_verified(&world, &mut session, &weights(), range(40, 80));
    move_verified(&world, &mut session, &weights(), range(80, 100));
    session.finish().unwrap();
    assert_eq!(session.used_bytes(), 100);
    assert_eq!(
        world.ledger.releases(),
        [
            (
                ByteReservation {
                    token: 1,
                    reserved_bytes: 150
                },
                40
            ),
            (
                ByteReservation {
                    token: 2,
                    reserved_bytes: 110
                },
                60
            )
        ]
    );
    let events = world.progress.events();
    assert_eq!(events.first().map(|event| event.epoch), Some(EPOCH));
    assert_eq!(events.last().map(|event| event.epoch), Some(EPOCH_5));
}

/// INT-08: a narrower re-issued grant is accepted, and its narrower bounds are enforced.
#[test]
fn a_narrower_reissued_grant_is_accepted_and_enforced() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    move_verified(&world, &mut session, &weights(), range(0, 40));
    session.interrupt().unwrap();
    world.authority.revoke(&parent());
    let narrower = reissued(|f| {
        f.scope = TransferScope::single(
            weights(),
            ObjectGrant::ranges(100, RangeSet::single(range(0, 60))).unwrap(),
        );
        f.budget_bytes = 70;
        f.expires_at = at(HOUR / 2);
        f.stop_bounds.max_in_flight_bytes = 10;
    });
    world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
    session
        .retry_with_grant(&world.seal(narrower), &download_connection())
        .unwrap();
    assert_eq!(session.remaining_budget_bytes(), 30);
    assert!(matches!(
        session.admit(&weights(), range(60, 70)),
        Err(TransferRefusal::RangeOutOfScope { .. })
    ));
    assert!(matches!(
        session.admit(&weights(), range(40, 60)),
        Err(TransferRefusal::InFlightLimit { .. })
    ));
    move_verified(&world, &mut session, &weights(), range(40, 50));
    move_verified(&world, &mut session, &weights(), range(50, 60));
    session.finish().unwrap();
    assert_eq!(world.ledger.held_bytes(), 0);
}

/// Brief: expiry stops a transfer, including a chunk admitted just before it.
#[test]
fn expiry_stops_a_transfer() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    move_verified(&world, &mut session, &weights(), range(0, 20));
    world.advance(HOUR - 5 * SECOND);
    let permit = session.admit(&weights(), range(20, 40)).unwrap();
    assert_eq!(permit.deadline(), at(HOUR));
    world.advance(5 * SECOND);

    let expired = StopReason::Expired {
        expires_at: at(HOUR),
    };
    assert_eq!(
        session.deliver(permit).unwrap_err(),
        TransferRefusal::Stopped {
            reason: expired.clone()
        }
    );
    assert_eq!(
        stop_record(&session),
        StopRecord {
            reason: expired.clone(),
            at: at(HOUR),
            cancelled_in_flight_bytes: 20,
            settled_by: at(HOUR),
        }
    );
    assert!(matches!(
        session.admit(&weights(), range(40, 60)),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert!(matches!(
        session.retry(&download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    assert!(matches!(
        session.retry_with_grant(&world.seal(reissued(|_| {})), &download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    assert_eq!(world.ledger.held_bytes(), 0);
    assert_eq!(
        world.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Stopped {
            reason: expired.clone()
        })
    );

    let mut late = download_fields();
    late.operation = operation("op-late");
    assert_eq!(
        world
            .gate
            .open(&world.seal(late), &download_connection())
            .unwrap_err(),
        TransferRefusal::Stopped { reason: expired }
    );
}

/// INT-02: a transfer never outlives the parent's own authority, and a later renewal of
/// the parent does not revive it.
#[test]
fn a_transfer_never_outlives_its_parents_authority() {
    let world = World::new();
    world.authority.grant(&parent(), EPOCH, at(HOUR / 2));
    let mut session = open(&world, download_fields());
    world.advance(HOUR / 2 - SECOND);
    let permit = session.admit(&weights(), range(0, 20)).unwrap();
    assert_eq!(permit.deadline(), at(HOUR / 2));
    world.advance(SECOND);
    assert_eq!(
        session.poll(),
        &TransferStatus::Stopped(StopRecord {
            reason: StopReason::AuthorityExpired {
                expires_at: at(HOUR / 2)
            },
            at: at(HOUR / 2),
            cancelled_in_flight_bytes: 20,
            settled_by: at(HOUR / 2),
        })
    );
    assert!(matches!(
        session.deliver(permit),
        Err(TransferRefusal::NotActive { .. })
    ));
    world.authority.grant(&parent(), EPOCH, at(HOUR));
    assert!(matches!(session.poll(), TransferStatus::Stopped(_)));
    assert!(matches!(
        session.retry(&download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
}

/// Brief: the byte budget is enforced, across attempts.
#[test]
fn the_byte_budget_is_enforced() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    assert_eq!(
        world.ledger.requests(),
        [ByteReservationRequest {
            tenant: tenant(),
            parent: parent(),
            operation: operation("op-download"),
            direction: Direction::Download,
            requested_bytes: 150,
            retry_number: 0,
        }]
    );
    let first = session.admit(&weights(), range(0, 40)).unwrap();
    session.deliver(first).unwrap();
    let _lost = session.admit(&weights(), range(40, 80)).unwrap();
    session.interrupt().unwrap();
    assert_eq!(session.used_bytes(), 80);

    // Nothing was verified, so the retry moves those bytes again, and they count again,
    // once the lost chunk is past its deadline and no longer counts as in flight.
    session.retry(&download_connection()).unwrap();
    world.advance(10 * SECOND);
    assert_eq!(session.remaining_budget_bytes(), 70);
    let again = session.admit(&weights(), range(0, 40)).unwrap();
    session.deliver(again).unwrap();
    assert_eq!(
        session.admit(&weights(), range(40, 80)).unwrap_err(),
        TransferRefusal::BudgetExhausted {
            budget_bytes: 150,
            used_bytes: 120,
            requested_bytes: 40
        }
    );
    let last = session.admit(&weights(), range(40, 70)).unwrap();
    session.deliver(last).unwrap();
    assert_eq!(session.remaining_budget_bytes(), 0);
    assert!(matches!(
        session.admit(&weights(), range(70, 71)),
        Err(TransferRefusal::BudgetExhausted { .. })
    ));
    assert_eq!(session.used_bytes(), 150);
    assert_eq!(world.ledger.held_bytes(), 150);
    session.cancel();
    assert_eq!(world.ledger.held_bytes(), 0);
    assert_eq!(world.ledger.releases()[0].1, 150);
}

#[test]
fn a_reservation_the_ledger_cannot_make_is_refused_before_any_byte_moves() {
    let world = World::with_ledger(100);
    assert_eq!(
        world
            .gate
            .open(&world.seal(download_fields()), &download_connection())
            .unwrap_err(),
        TransferRefusal::ReservationRefused {
            refusal: ByteBudgetRefusal {
                requested_bytes: 150,
                available_bytes: 100,
                retry_can_progress: false
            }
        }
    );
    assert_eq!(world.ledger.held_bytes(), 0);
    assert!(world.progress.events().is_empty());
    let mut fits = download_fields();
    fits.budget_bytes = 100;
    let session = world
        .gate
        .open(&world.seal(fits), &download_connection())
        .unwrap();
    assert_eq!(world.ledger.held_bytes(), 100);
    drop(session);
}

/// Brief: a range outside the scope is refused, and verified data outside the grant
/// never widens it (S3.3).
#[test]
fn a_range_outside_scope_is_refused() {
    let world = World::new();
    let mut fields = download_fields();
    fields.scope = TransferScope::new([
        (
            weights(),
            ObjectGrant::ranges(100, RangeSet::from_ranges([range(0, 30), range(60, 100)]))
                .unwrap(),
        ),
        (object("tokenizer"), ObjectGrant::whole(10).unwrap()),
    ])
    .unwrap();
    let mut session = open(&world, fields.clone());
    assert_eq!(
        session
            .admit(&object("other-model"), range(0, 10))
            .unwrap_err(),
        TransferRefusal::ObjectOutOfScope {
            object: object("other-model")
        }
    );
    for outside in [
        range(30, 60),
        range(20, 40),
        range(95, 101),
        range(100, 110),
    ] {
        assert_eq!(
            session.admit(&weights(), outside).unwrap_err(),
            TransferRefusal::RangeOutOfScope {
                object: weights(),
                range: outside
            }
        );
    }
    assert!(matches!(
        session.admit(&object("tokenizer"), range(5, 11)),
        Err(TransferRefusal::RangeOutOfScope { .. })
    ));
    assert_eq!(session.used_bytes(), 0);

    world.verify(&fields, &weights(), range(0, 100));
    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    assert_eq!(session.verified_bytes(), 70);
    assert!(matches!(
        session.admit(&weights(), range(40, 50)),
        Err(TransferRefusal::RangeOutOfScope { .. })
    ));
    assert_eq!(
        session.missing(),
        BTreeMap::from([(object("tokenizer"), RangeSet::single(range(0, 10)))])
    );
}

/// Brief: a recipient mismatch is refused, as are other sources and credentials, at
/// the start and on every retry (INT-08).
#[test]
fn a_recipient_mismatch_is_refused() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    let mut wrong_recipient = download_connection();
    wrong_recipient.recipient = Endpoint::Execution {
        execution: parent(),
    };
    assert_eq!(
        world.gate.open(&sealed, &wrong_recipient).unwrap_err(),
        TransferRefusal::RecipientMismatch {
            granted: Endpoint::HostCatalog,
            connected: Endpoint::Execution {
                execution: parent()
            },
        }
    );
    let mut wrong_source = download_connection();
    wrong_source.source = route("mirror");
    assert_eq!(
        world.gate.open(&sealed, &wrong_source).unwrap_err(),
        TransferRefusal::SourceMismatch {
            granted: route("model-hub"),
            connected: route("mirror"),
        }
    );
    for credential in [Some(credential("other-token")), None] {
        let mut wrong_credential = download_connection();
        wrong_credential.credential = credential;
        assert_eq!(
            world.gate.open(&sealed, &wrong_credential).unwrap_err(),
            TransferRefusal::CredentialMismatch
        );
    }
    assert!(world.ledger.requests().is_empty());

    // A refused open does not use up the grant, and a retry is checked the same way.
    let mut session = world.gate.open(&sealed, &download_connection()).unwrap();
    session.interrupt().unwrap();
    assert!(matches!(
        session.retry(&wrong_recipient),
        Err(TransferRefusal::RecipientMismatch { .. })
    ));
    assert_eq!(session.status(), &TransferStatus::Interrupted);
    session.retry(&download_connection()).unwrap();

    let upload = upload_fields();
    let mut to_attacker = connection_for(&upload);
    to_attacker.recipient = route("attacker");
    assert_eq!(
        world
            .gate
            .open(&world.seal(upload), &to_attacker)
            .unwrap_err(),
        TransferRefusal::RecipientMismatch {
            granted: route("partner-registry"),
            connected: route("attacker"),
        }
    );
}

/// Brief: the general release budget is untouched by a model download (S3.7, VM-D12).
#[test]
fn the_general_release_budget_is_untouched_by_a_model_download() {
    let world = World::new();
    let mut release = GeneralReleaseBudget::vm_d12_default();
    release.charge(MIB).unwrap();
    let before = release.clone();

    let model = object("llama-70b");
    let model_bytes = 64 * GIB;
    let mut fields = download_fields();
    fields.scope = TransferScope::single(model, ObjectGrant::whole(model_bytes).unwrap());
    fields.budget_bytes = model_bytes;
    fields.stop_bounds = StopBounds {
        max_in_flight_bytes: GIB,
        max_chunk_duration: 60 * SECOND,
    };
    assert!(fields.budget_bytes > VM_D12_GENERAL_RELEASE_BUDGET_BYTES);
    let mut session = open(&world, fields);
    for index in 0..64 {
        move_verified(
            &world,
            &mut session,
            &model,
            range(index * GIB, (index + 1) * GIB),
        );
    }
    session.finish().unwrap();
    assert_eq!(session.used_bytes(), model_bytes);

    assert_eq!(release, before);
    assert_eq!(release.limit_bytes(), 8 * MIB);
    assert_eq!(
        release.charge(7 * MIB + 1),
        Err(ReleaseBudgetExceeded {
            limit_bytes: 8 * MIB,
            released_bytes: MIB,
            requested_bytes: 7 * MIB + 1,
        })
    );
    let requests = world.ledger.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].direction, Direction::Download);
    assert_eq!(requests[0].requested_bytes, model_bytes);
    assert_eq!(world.ledger.releases().len(), 1);
    assert_eq!(world.ledger.releases()[0].1, model_bytes);
}

/// S3.7: a private-weight upload has its own explicit object, direction, recipient and
/// byte budget, moves only its scoped bytes, and leaves the general release budget alone.
#[test]
fn a_private_weight_upload_carries_its_own_budget() {
    let world = World::new();
    let release = GeneralReleaseBudget::vm_d12_default();
    let private = object("private-weights");
    let mut session = open(&world, upload_fields());
    assert_eq!(
        session.admit(&weights(), range(0, 10)).unwrap_err(),
        TransferRefusal::ObjectOutOfScope { object: weights() }
    );
    for index in 0..8 {
        move_verified(
            &world,
            &mut session,
            &private,
            range(index * 256 * MIB, (index + 1) * 256 * MIB),
        );
    }
    session.finish().unwrap();
    assert_eq!(release, GeneralReleaseBudget::vm_d12_default());
    let request = &world.ledger.requests()[0];
    assert_eq!(request.direction, Direction::Upload);
    assert_eq!(request.requested_bytes, 2 * GIB);
}

/// S3.7: bulk-transfer authorization never becomes arbitrary outbound authority.
#[test]
fn bulk_transfer_authority_never_becomes_outbound_authority() {
    let mut outward = download_fields();
    outward.recipient = route("attacker");
    assert!(matches!(
        TransferEnvelope::new(outward),
        Err(EnvelopeError::EndpointsNotAllowed {
            direction: Direction::Download,
            ..
        })
    ));
    let mut to_peer = upload_fields();
    to_peer.recipient = peer("someone");
    assert!(matches!(
        TransferEnvelope::new(to_peer),
        Err(EnvelopeError::EndpointsNotAllowed { .. })
    ));
    let mut relay = peer_fields();
    relay.recipient = route("attacker");
    assert!(matches!(
        TransferEnvelope::new(relay),
        Err(EnvelopeError::EndpointsNotAllowed { .. })
    ));
    let mut neighbour = upload_fields();
    neighbour.source = Endpoint::Execution {
        execution: ExecutionId::new("exe-neighbour").unwrap(),
    };
    assert!(matches!(
        TransferEnvelope::new(neighbour),
        Err(EnvelopeError::ExecutionNotParent { .. })
    ));
}

/// GPU-W09 peer transfers are bound to the enrolled peer host and carry no credential.
#[test]
fn a_peer_transfer_is_bound_to_its_peer_host() {
    let world = World::new();
    let fields = peer_fields();
    let sealed = world.seal(fields.clone());
    let mut impostor = connection_for(&fields);
    impostor.source = peer("impostor");
    assert_eq!(
        world.gate.open(&sealed, &impostor).unwrap_err(),
        TransferRefusal::SourceMismatch {
            granted: peer("donor"),
            connected: peer("impostor"),
        }
    );
    let mut session = world.gate.open(&sealed, &connection_for(&fields)).unwrap();
    for start in [0, 40, 80] {
        move_verified(
            &world,
            &mut session,
            &weights(),
            range(start, (start + 40).min(100)),
        );
    }
    session.finish().unwrap();
    let mut credentialed = fields;
    credentialed.credential = Some(credential("token"));
    assert!(matches!(
        TransferEnvelope::new(credentialed),
        Err(EnvelopeError::CredentialWithoutRoute { .. })
    ));
}

/// Brief: a tampered envelope is rejected, whatever was changed, and nothing is
/// reserved or reported for it.
#[test]
fn a_tampered_envelope_is_rejected() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    let json = serde_json::to_value(&sealed).unwrap();
    let edits: Vec<Vec<(&str, Value)>> = vec![
        vec![("/envelope/operation", json!("op-other"))],
        vec![("/envelope/tenant", json!("tenant-b"))],
        vec![("/envelope/parent", json!("exe-other"))],
        vec![("/envelope/epoch", json!(5))],
        vec![(
            "/envelope/source",
            serde_json::to_value(route("mirror")).unwrap(),
        )],
        vec![(
            "/envelope/recipient",
            json!({"kind": "execution", "execution": "exe-parent"}),
        )],
        vec![("/envelope/credential", Value::Null)],
        vec![("/envelope/budget_bytes", json!(1_000_000_000_000u64))],
        vec![(
            "/envelope/stop_bounds/max_in_flight_bytes",
            json!(1u64 << 40),
        )],
        vec![(
            "/envelope/stop_bounds/max_chunk_duration_nanos",
            json!(u64::MAX),
        )],
        vec![("/envelope/expires_at", json!(u64::MAX))],
        vec![(
            "/envelope/clock",
            serde_json::to_value(OTHER_SESSION).unwrap(),
        )],
        vec![("/envelope/scope/0/ranges/0/end_bytes", json!(99))],
        vec![
            ("/envelope/scope/0/size_bytes", json!(1000)),
            ("/envelope/scope/0/ranges/0/end_bytes", json!(1000)),
        ],
        vec![
            ("/envelope/direction", json!("upload")),
            (
                "/envelope/source",
                serde_json::to_value(Endpoint::HostCatalog).unwrap(),
            ),
            (
                "/envelope/recipient",
                serde_json::to_value(route("attacker")).unwrap(),
            ),
        ],
    ];
    for edit in &edits {
        let mut changed = json.clone();
        for (pointer, value) in edit {
            *changed.pointer_mut(pointer).unwrap() = value.clone();
        }
        let read: SealedEnvelope = serde_json::from_value(changed)
            .unwrap_or_else(|error| panic!("{edit:?} no longer parses: {error}"));
        assert_eq!(
            world.gate.verify(&read),
            Err(TransferRefusal::Tampered),
            "{edit:?}"
        );
        assert_eq!(
            world.gate.open(&read, &download_connection()).unwrap_err(),
            TransferRefusal::Tampered,
            "{edit:?}"
        );
    }

    let tag = hex::decode(json["tag"].as_str().unwrap()).unwrap();
    for bit in 0..tag.len() * 8 {
        let mut flipped = tag.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        let mut changed = json.clone();
        changed["tag"] = json!(hex::encode(&flipped));
        let read: SealedEnvelope = serde_json::from_value(changed).unwrap();
        assert_eq!(world.gate.verify(&read), Err(TransferRefusal::Tampered));
    }

    let mut spliced = json.clone();
    spliced["tag"] = serde_json::to_value(world.seal(upload_fields())).unwrap()["tag"].clone();
    let spliced: SealedEnvelope = serde_json::from_value(spliced).unwrap();
    assert_eq!(world.gate.verify(&spliced), Err(TransferRefusal::Tampered));

    let foreign = TransferKey::from_bytes(&[8u8; 32])
        .unwrap()
        .seal(TransferEnvelope::new(download_fields()).unwrap());
    assert_eq!(
        world
            .gate
            .open(&foreign, &download_connection())
            .unwrap_err(),
        TransferRefusal::Tampered
    );

    assert!(world.ledger.requests().is_empty());
    assert!(world.progress.events().is_empty());
    assert!(world.gate.open(&sealed, &download_connection()).is_ok());
}

/// Brief: a URL-shaped destination cannot be constructed (S2 CORE-05: no generic
/// privileged URL proxy; INT-08: no generic URL authority appears).
#[test]
fn a_url_shaped_destination_cannot_be_constructed() {
    for text in [
        "https://huggingface.co/meta-llama/Llama-3-70B",
        "http://169.254.169.254/latest/meta-data/",
        "HTTPS://EVIL.EXAMPLE",
        "file:///etc/passwd",
        "s3://bucket/weights.safetensors",
        "ftp://mirror.example/x",
        "//evil.example/upload",
        "evil.example:443",
        "localhost:8080",
        "user@evil.example",
        "huggingface.co/meta-llama",
        "\\\\server\\share",
        "javascript:alert(1)",
        "data:text/plain,secret",
        "route://evil.example",
        "execution://exe-parent",
        "peer:https://evil.example",
    ] {
        assert_eq!(
            Endpoint::parse(text),
            Err(EndpointError::UrlNotAccepted),
            "{text}"
        );
    }
    let digest = "0".repeat(64);
    for refused in [
        r#""https://evil.example/x""#.to_owned(),
        r#"{"kind":"url","url":"https://evil.example/x"}"#.to_owned(),
        r#"{"kind":"named_route","route":"https://evil.example/x"}"#.to_owned(),
        r#"{"kind":"peer_host","host":"https://evil.example"}"#.to_owned(),
        r#"{"kind":"execution","execution":"https://evil.example/x"}"#.to_owned(),
        format!(r#"{{"kind":"named_route","route":"{digest}","url":"https://evil.example"}}"#),
        r#"{"kind":"host_catalog","proxy":"https://evil.example"}"#.to_owned(),
    ] {
        assert!(
            serde_json::from_str::<Endpoint>(&refused).is_err(),
            "{refused}"
        );
    }

    let world = World::new();
    let mut json = serde_json::to_value(world.seal(upload_fields())).unwrap();
    json["envelope"]["recipient"] = json!({"kind": "url", "url": "https://evil.example/upload"});
    assert!(serde_json::from_value::<SealedEnvelope>(json).is_err());

    let message = Endpoint::parse("https://user:secret-token@evil.example/x")
        .unwrap_err()
        .to_string();
    assert!(
        !message.contains("secret-token") && !message.contains("evil"),
        "{message}"
    );
}

/// INT-02: revoked while weights stream, new work is denied, in-flight chunks do not
/// count, and the transfer stops within its declared bounds.
#[test]
fn revocation_stops_in_flight_work_within_the_declared_bounds() {
    let world = World::new();
    let fields = download_fields();
    let bounds = fields.stop_bounds;
    let mut session = open(&world, fields);
    let first = session.admit(&weights(), range(0, 20)).unwrap();
    world.advance(2 * SECOND);
    let second = session.admit(&weights(), range(20, 40)).unwrap();
    assert_eq!(
        session.admit(&weights(), range(40, 41)).unwrap_err(),
        TransferRefusal::InFlightLimit {
            max_in_flight_bytes: 40,
            in_flight_bytes: 40,
            requested_bytes: 1
        }
    );
    world.advance(SECOND);
    world.authority.revoke(&parent());

    let refused = session.deliver(first).unwrap_err();
    assert!(
        matches!(&refused, TransferRefusal::Stopped { reason } if reason.is_revocation()),
        "{refused:?}"
    );
    assert!(matches!(
        session.deliver(second),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert!(matches!(
        session.admit(&weights(), range(40, 60)),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert_eq!(session.delivered_bytes(), 0);

    let record = stop_record(&session);
    assert_eq!(record.at, at(3 * SECOND));
    assert_eq!(record.cancelled_in_flight_bytes, 40);
    assert!(record.cancelled_in_flight_bytes <= bounds.max_in_flight_bytes);
    assert_eq!(record.settled_by, at(12 * SECOND));
    assert!(record.settled_by <= record.at.saturating_add(bounds.max_chunk_duration));

    assert_eq!(world.ledger.held_bytes(), 0);
    assert_eq!(
        world.ledger.releases(),
        [(
            ByteReservation {
                token: 1,
                reserved_bytes: 150
            },
            40
        )]
    );
    assert_eq!(session.envelope().fields().epoch, EPOCH);
    assert_eq!(
        world.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Stopped {
            reason: StopReason::AuthorityNotCurrent {
                granted: EPOCH,
                current: Some(EPOCH_5)
            }
        })
    );
}

/// INT-02: a revocation is acted on even while no chunk moves.
#[test]
fn revocation_is_seen_without_chunk_activity() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    let _permit = session.admit(&weights(), range(0, 40)).unwrap();
    world.authority.revoke(&parent());
    let calls = world.authority.calls();
    assert!(matches!(
        session.poll(),
        TransferStatus::Stopped(record) if record.reason.is_revocation()
    ));
    assert_eq!(world.authority.calls(), calls + 1);
    assert_eq!(world.ledger.held_bytes(), 0);
    session.poll();
    assert_eq!(world.authority.calls(), calls + 1);
}

/// INT-08: a retry reuses the extents the catalog verified, moves only the rest, and the
/// budget counts each byte the times it moved.
#[test]
fn retries_reuse_verified_extents() {
    let world = World::new();
    let fields = download_fields();
    let mut session = open(&world, fields.clone());
    move_verified(&world, &mut session, &weights(), range(0, 40));
    let unverified = session.admit(&weights(), range(40, 80)).unwrap();
    session.deliver(unverified).unwrap();
    session.interrupt().unwrap();
    assert_eq!(session.used_bytes(), 80);

    world.verify(&fields, &weights(), range(40, 60));
    session.retry(&download_connection()).unwrap();
    assert_eq!(session.attempt(), 2);
    assert_eq!(session.verified_bytes(), 60);
    assert_eq!(session.delivered_bytes(), 0);
    assert_eq!(
        session.missing(),
        BTreeMap::from([(weights(), RangeSet::single(range(60, 100)))])
    );
    for verified in [range(0, 40), range(10, 20), range(55, 65)] {
        assert_eq!(
            session.admit(&weights(), verified).unwrap_err(),
            TransferRefusal::AlreadyCovered {
                object: weights(),
                range: verified
            }
        );
    }
    move_verified(&world, &mut session, &weights(), range(60, 100));
    session.finish().unwrap();
    assert_eq!(session.used_bytes(), 120);
    let resumed = world
        .progress
        .events()
        .into_iter()
        .find(|event| event.phase == ProgressPhase::Resumed)
        .unwrap();
    assert_eq!(
        (resumed.attempt, resumed.verified_bytes, resumed.used_bytes),
        (2, 60, 80)
    );
}

/// S3.3: another tenant's verified copy of the same object is not reused.
#[test]
fn another_tenants_verified_copy_is_not_reused() {
    let world = World::new();
    world.extents.mark_verified(
        &TenantId::new("tenant-b").unwrap(),
        &Endpoint::HostCatalog,
        &weights(),
        range(0, 100),
    );
    let session = open(&world, download_fields());
    assert_eq!(session.verified_bytes(), 0);
    assert_eq!(
        session.missing(),
        BTreeMap::from([(weights(), RangeSet::single(range(0, 100)))])
    );
}

/// A replayed envelope neither restarts nor re-budgets a transfer (INT-08).
#[test]
fn a_replayed_envelope_is_refused() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    let replay = || {
        world
            .gate
            .open(&sealed, &download_connection())
            .unwrap_err()
    };
    let mut session = world.gate.open(&sealed, &download_connection()).unwrap();
    let already = TransferRefusal::AlreadyOpened {
        operation: operation("op-download"),
    };
    assert_eq!(replay(), already);
    for start in [0, 40, 80] {
        move_verified(
            &world,
            &mut session,
            &weights(),
            range(start, (start + 40).min(100)),
        );
    }
    session.finish().unwrap();
    assert_eq!(replay(), already);
    assert_eq!(
        world
            .gate
            .open(&world.seal(reissued(|_| {})), &download_connection())
            .unwrap_err(),
        already
    );
    assert_eq!(world.ledger.requests().len(), 1);

    world.clock.advance_to(at(HOUR));
    assert!(matches!(
        replay(),
        TransferRefusal::Stopped {
            reason: StopReason::Expired { .. }
        }
    ));
    let mut fresh = download_fields();
    fresh.operation = operation("op-fresh");
    fresh.expires_at = at(2 * HOUR);
    let _fresh = open(&world, fresh);
    assert!(format!("{:?}", world.gate).contains("opened: 1"));
}

/// Cancellation is final.
#[test]
fn cancellation_is_final() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    let mut session = world.gate.open(&sealed, &download_connection()).unwrap();
    let permit = session.admit(&weights(), range(0, 40)).unwrap();
    world.advance(SECOND);
    let cancelled = TransferStatus::Stopped(StopRecord {
        reason: StopReason::Cancelled,
        at: at(SECOND),
        cancelled_in_flight_bytes: 40,
        settled_by: at(10 * SECOND),
    });
    assert_eq!(session.cancel(), &cancelled);
    assert!(matches!(
        session.deliver(permit),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert!(matches!(
        session.retry(&download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    world.authority.revoke(&parent());
    assert!(matches!(
        session.retry_with_grant(&world.seal(reissued(|_| {})), &download_connection()),
        Err(TransferRefusal::NotRetryable { .. })
    ));
    assert!(matches!(
        session.finish(),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert_eq!(session.cancel(), &cancelled);
    assert_eq!(world.ledger.held_bytes(), 0);
    assert!(matches!(
        world.gate.open(&sealed, &download_connection()),
        Err(TransferRefusal::AlreadyOpened { .. })
    ));
}

/// INT-02 declared bounds: a chunk delivered after its deadline does not count.
#[test]
fn a_late_chunk_is_refused() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    let on_time = session.admit(&weights(), range(0, 40)).unwrap();
    assert_eq!(on_time.deadline(), at(10 * SECOND));
    world.advance(10 * SECOND);
    session.deliver(on_time).unwrap();
    let late = session.admit(&weights(), range(40, 80)).unwrap();
    world.advance(10 * SECOND + Duration::from_nanos(1));
    assert_eq!(
        session.deliver(late).unwrap_err(),
        TransferRefusal::ChunkLate {
            deadline: at(20 * SECOND),
            delivered_at: at(20 * SECOND + Duration::from_nanos(1)),
        }
    );
    assert_eq!(session.status(), &TransferStatus::Active);
    assert_eq!(session.delivered_bytes(), 40);
    assert_eq!(session.used_bytes(), 80);
    assert_eq!(
        session.missing(),
        BTreeMap::from([(weights(), RangeSet::single(range(40, 100)))])
    );
    assert!(session.admit(&weights(), range(40, 80)).is_ok());
}

#[test]
fn finishing_needs_every_granted_range_verified() {
    let world = World::new();
    let fields = download_fields();
    let mut session = open(&world, fields.clone());
    let first = session.admit(&weights(), range(0, 40)).unwrap();
    assert_eq!(
        session.finish().unwrap_err(),
        TransferRefusal::ChunksInFlight {
            in_flight_bytes: 40
        }
    );
    session.deliver(first).unwrap();
    for (start, end) in [(40, 80), (80, 100)] {
        let permit = session.admit(&weights(), range(start, end)).unwrap();
        session.deliver(permit).unwrap();
    }
    world.verify(&fields, &weights(), range(0, 80));
    assert_eq!(
        session.finish().unwrap_err(),
        TransferRefusal::Incomplete { missing_bytes: 20 }
    );
    assert_eq!(session.status(), &TransferStatus::Active);
    world.verify(&fields, &weights(), range(80, 100));
    session.finish().unwrap();
    assert_eq!(session.status(), &TransferStatus::Completed);
    assert_eq!(
        world.ledger.releases(),
        [(
            ByteReservation {
                token: 1,
                reserved_bytes: 150
            },
            100
        )]
    );
    assert_eq!(
        world.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Completed)
    );
    assert!(matches!(
        session.finish(),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert_eq!(session.cancel(), &TransferStatus::Completed);
}

#[test]
fn a_dropped_session_returns_its_reservation() {
    let world = World::new();
    let sealed = world.seal(download_fields());
    {
        let mut session = world.gate.open(&sealed, &download_connection()).unwrap();
        let _permit = session.admit(&weights(), range(0, 40)).unwrap();
        assert_eq!(world.ledger.held_bytes(), 150);
    }
    assert_eq!(world.ledger.held_bytes(), 0);
    assert_eq!(world.ledger.releases()[0].1, 40);
    assert_eq!(
        world.progress.last().map(|event| event.phase),
        Some(ProgressPhase::Stopped {
            reason: StopReason::Abandoned
        })
    );
    assert!(matches!(
        world.gate.open(&sealed, &download_connection()),
        Err(TransferRefusal::AlreadyOpened { .. })
    ));
}

#[test]
fn a_permit_from_another_session_is_refused() {
    let world = World::new();
    let mut first = open(&world, download_fields());
    let mut second_fields = download_fields();
    second_fields.operation = operation("op-second");
    let mut second = open(&world, second_fields);
    let permit = first.admit(&weights(), range(0, 40)).unwrap();
    let _own = second.admit(&weights(), range(0, 40)).unwrap();
    assert_eq!(
        second.deliver(permit).unwrap_err(),
        TransferRefusal::UnknownChunk
    );
    assert_eq!(second.delivered_bytes(), 0);
}

/// CORE-06: one monotonic sequence per transfer across attempts, with no credential or
/// endpoint in any event.
#[test]
fn progress_is_one_monotonic_sequence_across_attempts() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    move_verified(&world, &mut session, &weights(), range(0, 40));
    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    move_verified(&world, &mut session, &weights(), range(40, 80));
    move_verified(&world, &mut session, &weights(), range(80, 100));
    session.finish().unwrap();

    let events = world.progress.events();
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    assert_eq!(sequences, (1..=events.len() as u64).collect::<Vec<_>>());
    let phases: Vec<&str> = events
        .iter()
        .map(|event| match event.phase {
            ProgressPhase::Started => "started",
            ProgressPhase::Resumed => "resumed",
            ProgressPhase::ChunkDelivered { .. } => "chunk",
            ProgressPhase::Interrupted { .. } => "interrupted",
            ProgressPhase::Stopped { .. } => "stopped",
            ProgressPhase::Completed => "completed",
        })
        .collect();
    assert_eq!(
        phases,
        [
            "started",
            "chunk",
            "interrupted",
            "resumed",
            "chunk",
            "chunk",
            "completed"
        ]
    );
    let attempts: Vec<u32> = events.iter().map(|event| event.attempt).collect();
    assert_eq!(attempts, [1, 1, 1, 2, 2, 2, 2]);
    assert!(events
        .iter()
        .all(|event| event.operation == operation("op-download")));
    let completed = events.last().unwrap();
    assert_eq!(
        (
            completed.scope_bytes,
            completed.verified_bytes,
            completed.used_bytes,
            completed.budget_bytes
        ),
        (100, 100, 100, 150)
    );
    let text = serde_json::to_string(&events).unwrap();
    for secret in [
        credential("hub-token").digest().to_hex(),
        match route("model-hub") {
            Endpoint::NamedRoute { route } => route.to_hex(),
            _ => unreachable!(),
        },
    ] {
        assert!(!text.contains(&secret));
    }
}

#[test]
fn a_parent_that_is_not_running_stops_the_transfer() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    world.authority.end(&parent());
    let not_running = StopReason::AuthorityNotCurrent {
        granted: EPOCH,
        current: None,
    };
    assert!(matches!(
        session.poll(),
        TransferStatus::Stopped(record) if record.reason == not_running
    ));
    assert!(!not_running.is_revocation());
    assert!(not_running.to_string().contains("not running"));
    let mut other = download_fields();
    other.operation = operation("op-other");
    assert_eq!(
        world
            .gate
            .open(&world.seal(other), &download_connection())
            .unwrap_err(),
        TransferRefusal::Stopped {
            reason: not_running
        }
    );
}

/// S3.1: an envelope naming an epoch the parent has not reached is not current either.
#[test]
fn an_epoch_the_parent_has_not_reached_is_refused() {
    let world = World::new();
    let mut fields = download_fields();
    fields.epoch = AuthorizationEpoch::new(7);
    let reason = StopReason::AuthorityNotCurrent {
        granted: AuthorizationEpoch::new(7),
        current: Some(EPOCH),
    };
    assert!(!reason.is_revocation());
    assert_eq!(
        world
            .gate
            .open(&world.seal(fields), &download_connection())
            .unwrap_err(),
        TransferRefusal::Stopped { reason }
    );
    assert!(world.ledger.requests().is_empty());
}

#[test]
fn refusals_explain_themselves() {
    let refusal = TransferRefusal::RetryWidens {
        violations: vec![
            RetryViolation::LargerBudget {
                granted_bytes: 150,
                proposed_bytes: 151,
            },
            RetryViolation::OtherRecipient {
                granted: Endpoint::HostCatalog,
                proposed: route("attacker"),
            },
        ],
    };
    let text = refusal.to_string();
    assert!(text.contains("from 150 to 151"), "{text}");
    assert!(text.contains("recipient from catalog to route:"), "{text}");
    let revoked = StopReason::AuthorityNotCurrent {
        granted: EPOCH,
        current: Some(EPOCH_5),
    };
    assert!(revoked.to_string().contains("revoked"));
    assert!(TransferRefusal::Stopped { reason: revoked }
        .to_string()
        .contains("epoch 4 to epoch 5"));
}

/// The engine holds gates and sessions in async tasks, so both move between threads.
#[test]
fn gates_and_sessions_are_send_and_sync() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<TransferGate>();
    send_and_sync::<TransferSession>();
    send_and_sync::<SealedEnvelope>();
}

/// CORE-01 clock sessions: an envelope stamped before a restart is not honoured after
/// it, although its expiry looks later than the new clock's time.
#[test]
fn an_envelope_from_another_clock_session_is_refused() {
    let world = World::new();
    let mut before_restart = download_fields();
    before_restart.clock = OTHER_SESSION;
    assert!(before_restart.expires_at > world.clock.now());
    assert_eq!(
        world
            .gate
            .open(&world.seal(before_restart), &download_connection())
            .unwrap_err(),
        TransferRefusal::Stopped {
            reason: StopReason::EnvelopeOnOtherClock
        }
    );
    assert!(world.ledger.requests().is_empty());
}

/// The parent's authority reported on another clock session cannot be checked, so the
/// transfer stops instead of comparing times from different clocks.
#[test]
fn a_parent_authority_on_another_clock_session_stops_the_transfer() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    world.authority.set(
        &parent(),
        ParentAuthority {
            epoch: EPOCH,
            clock: OTHER_SESSION,
            expires_at: at(24 * HOUR),
        },
    );
    assert!(matches!(
        session.poll(),
        TransferStatus::Stopped(record) if record.reason == StopReason::AuthorityOnOtherClock
    ));
    assert_eq!(world.ledger.held_bytes(), 0);
}

/// CORE-03: each chunk is charged to the reservation before its bytes move, counting
/// only bytes used under that reservation.
#[test]
fn each_admitted_chunk_is_charged_before_it_moves() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    let token = session.reservation().unwrap().token;
    move_verified(&world, &mut session, &weights(), range(0, 40));
    let _lost = session.admit(&weights(), range(40, 70)).unwrap();
    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    world.advance(10 * SECOND);
    move_verified(&world, &mut session, &weights(), range(40, 80));
    assert_eq!(
        world.ledger.charges(),
        [(token, 40), (token, 70), (token, 110)]
    );
    assert_eq!(session.used_bytes(), 110);
}

/// INT-02: a reservation withdrawn under the transfer, as on revocation, stops it at
/// the next chunk, before any of that chunk's bytes move.
#[test]
fn a_withdrawn_reservation_stops_the_transfer() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    let reservation = session.reservation().unwrap();
    let in_flight = session.admit(&weights(), range(0, 20)).unwrap();
    world.ledger.withdraw(reservation.token);
    assert_eq!(
        session.admit(&weights(), range(20, 40)).unwrap_err(),
        TransferRefusal::Stopped {
            reason: StopReason::ReservationWithdrawn
        }
    );
    assert_eq!(session.used_bytes(), 20);
    assert_eq!(stop_record(&session).cancelled_in_flight_bytes, 20);
    assert!(matches!(
        session.deliver(in_flight),
        Err(TransferRefusal::NotActive { .. })
    ));
    assert_eq!(world.ledger.releases(), [(reservation, 20)]);
    assert!(!StopReason::ReservationWithdrawn.is_revocation());
}

/// CORE-03, INT-02: a release names when the last chunk that may still be moving is
/// past its deadline, including chunks an interrupted attempt dropped, so the ledger
/// never counts their bytes as free too early.
#[test]
fn a_release_waits_for_chunks_that_may_still_move() {
    let world = World::new();
    let mut finished = open(&world, download_fields());
    for (start, end) in [(0, 40), (40, 80), (80, 100)] {
        move_verified(&world, &mut finished, &weights(), range(start, end));
    }
    world.advance(SECOND);
    finished.finish().unwrap();

    let mut fields = download_fields();
    fields.operation = operation("op-interrupted");
    fields.scope = TransferScope::single(object("adapter"), ObjectGrant::whole(100).unwrap());
    let mut session = open(&world, fields);
    let _dropped = session.admit(&object("adapter"), range(0, 20)).unwrap();
    world.advance(2 * SECOND);
    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    world.advance(SECOND);
    let _moving = session.admit(&object("adapter"), range(20, 40)).unwrap();
    world.advance(SECOND);
    session.cancel();
    let record = stop_record(&session);
    assert_eq!(record.cancelled_in_flight_bytes, 40);
    assert_eq!(record.settled_by, at(14 * SECOND));
    assert_eq!(world.ledger.settle_times(), [at(SECOND), at(14 * SECOND)]);

    let mut idle = download_fields();
    idle.operation = operation("op-idle");
    idle.scope = TransferScope::single(object("idle"), ObjectGrant::whole(100).unwrap());
    let mut session = open(&world, idle);
    let _dropped = session.admit(&object("idle"), range(0, 40)).unwrap();
    session.interrupt().unwrap();
    world.advance(30 * SECOND);
    session.cancel();
    assert_eq!(stop_record(&session).settled_by, at(35 * SECOND));
}

/// CORE-06, GPU part §3.10: a progress event names each object it changes, with its
/// granted, completed and verified bytes, and where the bytes come from by kind only.
#[test]
fn progress_names_each_object_it_changes() {
    let world = World::new();
    let mut fields = download_fields();
    fields.scope = TransferScope::new([
        (weights(), ObjectGrant::whole(100).unwrap()),
        (object("tokenizer"), ObjectGrant::whole(10).unwrap()),
    ])
    .unwrap();
    let mut session = open(&world, fields.clone());
    let progress = |weights_bytes: (u64, u64), tokenizer_bytes: (u64, u64)| {
        let mut objects = vec![
            ObjectProgress {
                object: weights(),
                granted_bytes: 100,
                completed_bytes: weights_bytes.0,
                verified_bytes: weights_bytes.1,
            },
            ObjectProgress {
                object: object("tokenizer"),
                granted_bytes: 10,
                completed_bytes: tokenizer_bytes.0,
                verified_bytes: tokenizer_bytes.1,
            },
        ];
        objects.sort_by_key(|progress| progress.object);
        objects
    };
    let started = world.progress.last().unwrap();
    assert_eq!(started.origin, ByteOrigin::Remote);
    assert_eq!(started.objects, progress((0, 0), (0, 0)));

    move_verified(&world, &mut session, &object("tokenizer"), range(0, 10));
    let chunk = world.progress.last().unwrap();
    assert_eq!(
        chunk.objects,
        [ObjectProgress {
            object: object("tokenizer"),
            granted_bytes: 10,
            completed_bytes: 10,
            verified_bytes: 0,
        }]
    );

    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    let resumed = world.progress.last().unwrap();
    assert_eq!(resumed.phase, ProgressPhase::Resumed);
    assert_eq!(resumed.objects, progress((0, 0), (10, 10)));
    assert_eq!(ByteOrigin::of(&peer("donor")), ByteOrigin::Peer);
    assert_eq!(ByteOrigin::of(&Endpoint::HostCatalog), ByteOrigin::Local);
}

/// Review R1-b, finding 2 (INT-02 declared bounds): chunks an interrupted attempt dropped
/// may still be moving until their deadline, so they count toward the in-flight bound. A
/// retry cannot open a second full window over them, and a stop counts them.
#[test]
fn chunks_dropped_by_an_interrupt_count_toward_the_in_flight_bound() {
    let world = World::new();
    let mut session = open(&world, download_fields());
    let _dropped = session.admit(&weights(), range(0, 40)).unwrap();
    session.interrupt().unwrap();
    session.retry(&download_connection()).unwrap();
    assert_eq!(
        session.admit(&weights(), range(40, 80)).unwrap_err(),
        TransferRefusal::InFlightLimit {
            max_in_flight_bytes: 40,
            in_flight_bytes: 40,
            requested_bytes: 40
        }
    );
    world.advance(10 * SECOND);
    let second = session.admit(&weights(), range(40, 80)).unwrap();
    session.deliver(second).unwrap();

    let mut fields = download_fields();
    fields.operation = operation("op-unsettled");
    fields.scope = TransferScope::single(object("adapter"), ObjectGrant::whole(100).unwrap());
    let mut unsettled = open(&world, fields);
    let _dropped = unsettled.admit(&object("adapter"), range(0, 40)).unwrap();
    unsettled.interrupt().unwrap();
    unsettled.retry(&download_connection()).unwrap();
    world.advance(SECOND);
    world.authority.revoke(&parent());
    unsettled.poll();
    let record = stop_record(&unsettled);
    assert_eq!(record.cancelled_in_flight_bytes, 40);
    assert_eq!(record.settled_by, at(20 * SECOND));
}

/// Review R1-b, finding 3 (INT-08): replay protection is shared by every gate made from
/// the same key, so a second gate cannot reopen an envelope with a second full budget.
#[test]
fn a_second_gate_with_the_same_key_cannot_reopen_an_envelope() {
    let world = World::new();
    let second_gate = TransferGate::new(
        world.key.clone(),
        TransferPorts {
            clock: world.clock.clone(),
            clock_session: SESSION,
            authority: world.authority.clone(),
            budget: world.ledger.clone(),
            extents: world.extents.clone(),
            progress: world.progress.clone(),
        },
    );
    let sealed = world.seal(download_fields());
    let mut first = world.gate.open(&sealed, &download_connection()).unwrap();
    assert_eq!(
        second_gate
            .open(&sealed, &download_connection())
            .unwrap_err(),
        TransferRefusal::AlreadyOpened {
            operation: operation("op-download")
        }
    );
    for (start, end) in [(0, 40), (40, 80), (80, 100)] {
        move_verified(&world, &mut first, &weights(), range(start, end));
    }
    first.finish().unwrap();
    assert_eq!(first.used_bytes(), 100);
    assert!(matches!(
        second_gate.open(&sealed, &download_connection()),
        Err(TransferRefusal::AlreadyOpened { .. })
    ));
    assert_eq!(world.ledger.requests().len(), 1);
}

/// Review R1-b, finding 1 (the T14 follow-up decision), at the session: a continuation
/// under a re-issued grant after a stop reports progress as a new operation derived from
/// the stopped one and the new epoch, and every event of it names the stopped one. The
/// envelope, and so the budget and the replay record, keep the original operation. A
/// continuation of an interrupted transfer emitted no terminal phase and keeps its own.
#[test]
fn a_continuation_after_a_stop_is_a_new_operation_linked_to_the_stopped_one() {
    let world = World::new();
    let mut stopped = open(&world, download_fields());
    let mut other = download_fields();
    other.operation = operation("op-interrupted");
    other.scope = TransferScope::single(object("adapter"), ObjectGrant::whole(100).unwrap());
    let mut interrupted = open(&world, other.clone());
    move_verified(&world, &mut stopped, &weights(), range(0, 40));
    interrupted.interrupt().unwrap();
    world.authority.revoke(&parent());
    assert!(matches!(stopped.poll(), TransferStatus::Stopped(_)));
    let stop = world.progress.last().unwrap();
    assert_eq!(
        (stop.operation, stop.continues),
        (operation("op-download"), None)
    );
    world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));

    stopped
        .retry_with_grant(&world.seal(reissued(|_| {})), &download_connection())
        .unwrap();
    let expected = OperationId::new(format!(
        "op-{}",
        digest(CONTINUATION_DOMAIN, &[b"op-download", &5u64.to_be_bytes()]).to_hex()
    ))
    .unwrap();
    assert_eq!(
        continuation_operation(&operation("op-download"), EPOCH_5),
        Ok(expected.clone())
    );
    assert_eq!(stopped.progress_operation(), &expected);
    let resumed = world.progress.last().unwrap();
    assert_eq!(resumed.phase, ProgressPhase::Resumed);
    assert_eq!(resumed.operation, expected);
    assert_eq!(resumed.continues, Some(operation("op-download")));
    move_verified(&world, &mut stopped, &weights(), range(40, 80));
    let chunk = world.progress.last().unwrap();
    assert_eq!(
        (chunk.operation, chunk.continues),
        (expected, Some(operation("op-download")))
    );
    assert_eq!(
        stopped.envelope().fields().operation,
        operation("op-download")
    );

    let mut reissued_other = other;
    reissued_other.epoch = EPOCH_5;
    let connection = connection_for(&reissued_other);
    interrupted
        .retry_with_grant(&world.seal(reissued_other), &connection)
        .unwrap();
    assert_eq!(
        interrupted.progress_operation(),
        &operation("op-interrupted")
    );
    let resumed = world.progress.last().unwrap();
    assert_eq!(
        (resumed.operation, resumed.continues),
        (operation("op-interrupted"), None)
    );
}
