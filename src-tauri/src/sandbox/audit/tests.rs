//! The scenarios the task names, on fakes driven by a manual clock: concurrent writers
//! through one authority (VM-P22), a second authority refused, disk full and truncation
//! under the declared policy, the revocation lane under an audit flood, redaction of
//! fixture secrets with its stated coverage (VM-P12), rotation with linkage, the anchored
//! head against a rewrite, guest facts never written as host facts, claims without
//! evidence refused, stale evidence invalidating a claim, no score anywhere, and an
//! incident reconstructed over a fixture (VM-W42, VM-W44, VM-W52).

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::anchor::{AnchorRefusal, AnchorVerdict, CUSTODY_STATEMENT};
use super::correlation::{
    Approval, ApprovalDecision, ApprovalId, Approver, ArtifactLink, ArtifactRole, AuditPointer,
    CorrelationBounds, CorrelationError, CorrelationIndex, GuestReportKind, HostFactPointer,
    IncidentScope, NotHostObserved, Observation, ObservationSummary, OperationLink, RequestId,
    TelemetrySource, TimelineEvent, ToolName, ToolRequest,
};
use super::fakes::{
    context, execution, journal_id, manual_clock, operation, producer, stream_config, FakeAnchor,
    FakeSegmentStorage, FakeSpool, FileSegmentStorage, FIXTURE_SECRETS,
};
use super::ledger::{
    AssumptionId, AssumptionKind, AssuranceLedger, Citation, Claim, ClaimId, ClaimStatus,
    ClaimSupport, ExplicitGap, GapReason, Invalidation, LedgerError, ProbeCitation, ProfileId,
    Property, RiskId, RiskKind, TestCitation, TestId,
};
use super::segment::{
    verify_segments, Damage, ResumeFinding, SegmentError, SegmentOpening, TruncationWitness,
};
use super::stream::{
    Anchoring, AuditEvent, AuditStream, StreamAuthority, StreamConfig, StreamDirectory,
    StreamError, StreamRefusal, SECRET_SCAN_COVERAGE,
};
use crate::foundation::events::{
    AuditEntry, AuditFailurePolicy, AuditHealth, AuditRefusal, ChainError, Durability, EventHub,
    EventSequence, EvidenceLink, Field, FieldClass, GrantRevocation, HostFact, HubConfig,
    JournalHead, LossReason, MetricsConfig, Phase, ProducerIncarnation, ProgressConfig,
    RedactedValue, RedactionPolicy, Revocation, RevocationAdmission, RevocationConfig,
    RevocationReason, StoreRefusal,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HypervisorKind, HypervisorSubject, Observation as Probe,
    ProbeRegistry, SourceClass, Staleness, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, ExecutionCategory, GrantId, ManualClock,
    MonotonicTime,
};
use crate::foundation::report::RunSubstrate;

type Stream = AuditStream<FakeSegmentStorage, FakeSpool, FakeAnchor, Arc<ManualClock>>;
type FileStream = AuditStream<FileSegmentStorage, FakeSpool, FakeAnchor, Arc<ManualClock>>;

fn genesis(name: &str) -> JournalHead {
    JournalHead::genesis(journal_id(name), producer(&format!("{name}.audit")))
}

fn fact(step: u64) -> AuditEvent {
    AuditEvent::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    }
}

fn revocation(name: &str, epoch: u64) -> Revocation {
    Revocation {
        execution: execution(name),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    }
}

fn open(
    directory: &mut StreamDirectory,
    name: &str,
    storage: &FakeSegmentStorage,
    spool: &FakeSpool,
    anchor: &FakeAnchor,
    config: StreamConfig,
) -> (Stream, StreamAuthority) {
    AuditStream::open(
        directory,
        journal_id(name),
        producer(&format!("{name}.audit")),
        storage.clone(),
        spool.clone(),
        anchor.clone(),
        manual_clock(),
        config,
    )
    .unwrap()
}

fn resume(
    directory: &mut StreamDirectory,
    name: &str,
    storage: &FakeSegmentStorage,
    spool: &FakeSpool,
    anchor: &FakeAnchor,
    config: StreamConfig,
) -> Result<(Stream, StreamAuthority, super::stream::StreamResume), StreamError> {
    AuditStream::resume(
        directory,
        journal_id(name),
        producer(&format!("{name}.audit")),
        storage.clone(),
        spool.clone(),
        anchor.clone(),
        manual_clock(),
        config,
    )
}

fn stored_sequences(storage: &FakeSegmentStorage) -> Vec<u64> {
    storage
        .all_records()
        .iter()
        .map(|record| record.sequence().get())
        .collect()
}

fn with_anchoring(config: StreamConfig) -> StreamConfig {
    StreamConfig {
        anchoring: Anchoring::OnRotation,
        ..config
    }
}

/// VM-P22 "concurrent events"; VM-W42 "concurrent writers": four threads append through
/// the one authority, and the chain holds every record once, in sequence order.
#[test]
fn concurrent_writers_through_one_authority_keep_order() {
    let storage = FakeSegmentStorage::new(1_000);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let opened = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(8, 1, 7),
    );
    let shared = Arc::new(Mutex::new(opened));
    let writers: Vec<_> = (0..4u64)
        .map(|writer| {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut receipts = Vec::new();
                for step in 0..25u64 {
                    let mut guard = shared.lock().unwrap();
                    let (stream, authority) = &mut *guard;
                    let receipt = stream
                        .record(
                            authority,
                            context(&format!("op-{writer}"), Phase::Running),
                            fact(writer * 100 + step),
                        )
                        .unwrap();
                    assert_eq!(receipt.durability, Durability::Durable);
                    receipts.push(receipt.sequence.get());
                }
                receipts
            })
        })
        .collect();
    let mut all = Vec::new();
    for writer in writers {
        let receipts = writer.join().unwrap();
        // Each writer saw its own records in rising order.
        assert!(receipts.windows(2).all(|pair| pair[0] < pair[1]));
        all.extend(receipts);
    }
    all.sort_unstable();
    assert_eq!(all, (1..=100).collect::<Vec<u64>>());
    assert_eq!(stored_sequences(&storage), (1..=100).collect::<Vec<u64>>());
    let chain = verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert_eq!(chain.records, 100);
    assert_eq!(chain.segments, 15);
    assert!(chain.damage.is_empty());
    let guard = shared.lock().unwrap();
    assert_eq!(chain.head, guard.0.durable_head());
    assert_eq!(guard.0.totals().segments.out_of_order, 0);
}

/// VM-W42 "one append authority per stream": a second open or resume of a live stream
/// is refused, and an authority of another stream appends nothing.
#[test]
fn a_second_append_authority_on_a_stream_is_refused() {
    let storage = FakeSegmentStorage::new(100);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let (mut engine, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 10),
    );
    let _ = engine
        .record(&mut authority, context("op-1", Phase::Running), fact(1))
        .unwrap();
    let second = AuditStream::open(
        &mut directory,
        journal_id("engine"),
        producer("engine.audit"),
        FakeSegmentStorage::new(100),
        FakeSpool::new(),
        FakeAnchor::new(),
        manual_clock(),
        stream_config(4, 1, 10),
    );
    assert!(matches!(
        second.err(),
        Some(StreamError::AuthorityLive { stream }) if stream == journal_id("engine")
    ));
    assert!(matches!(
        resume(
            &mut directory,
            "engine",
            &storage,
            &spool,
            &anchor,
            stream_config(4, 1, 10)
        )
        .err(),
        Some(StreamError::AuthorityLive { .. })
    ));
    // Another stream's authority cannot append here, and its own stream is unaffected.
    let (mut warden, mut warden_authority) = open(
        &mut directory,
        "warden",
        &FakeSegmentStorage::new(100),
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 10),
    );
    assert_eq!(
        engine.record(
            &mut warden_authority,
            context("op-1", Phase::Running),
            fact(2)
        ),
        Err(StreamRefusal::WrongStream {
            authority: journal_id("warden"),
            stream: journal_id("engine")
        })
    );
    let _ = warden
        .record(
            &mut warden_authority,
            context("op-1", Phase::Running),
            fact(1),
        )
        .unwrap();
    assert_eq!(stored_sequences(&storage), [1]);
    // The authority alone keeps the stream live; dropping both ends the registration.
    drop(engine);
    assert!(directory.is_live(&journal_id("engine")));
    assert!(matches!(
        resume(
            &mut directory,
            "engine",
            &storage,
            &spool,
            &anchor,
            stream_config(4, 1, 10)
        )
        .err(),
        Some(StreamError::AuthorityLive { .. })
    ));
    drop(authority);
    assert!(!directory.is_live(&journal_id("engine")));
    let (resumed, mut resumed_authority, report) = resume(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 10),
    )
    .unwrap();
    assert_eq!(
        report.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    let mut resumed = resumed;
    let receipt = resumed
        .record(
            &mut resumed_authority,
            context("op-2", Phase::Running),
            fact(3),
        )
        .unwrap();
    assert_eq!(receipt.sequence.get(), 2);
    assert!(matches!(
        directory_error_text(&StreamError::AuthorityLive {
            stream: journal_id("engine")
        })
        .as_str(),
        "stream engine already has a live append authority; only dropping it ends that registration"
    ));
}

fn directory_error_text(error: &StreamError) -> String {
    error.to_string()
}

/// §8.2 line 2445: audit failure has a defined policy. With `SpoolHighImpact` a full disk
/// spools records in order and admits high-impact operations on spooled records until
/// the spool is full, then fails closed; with `DenyHighImpact` it denies them at once.
/// Nothing is dropped silently, and recovery stores everything in order.
#[test]
fn disk_full_is_handled_by_the_declared_policy() {
    let storage = FakeSegmentStorage::new(2);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(3, 1, 10),
    );
    for step in 1..=2 {
        let receipt = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
        assert_eq!(receipt.durability, Durability::Durable);
    }
    // Storage is full: the next record waits in the spool, with a receipt.
    let spooled = stream
        .record(&mut authority, context("op-1", Phase::Running), fact(3))
        .unwrap();
    assert_eq!(
        spooled.durability,
        Durability::Spooled { spooled_records: 1 }
    );
    assert_eq!(
        stream.health(),
        AuditHealth::Spooling {
            store: StoreRefusal::Full,
            spooled_records: 1
        }
    );
    // A high-impact operation may go ahead on a spooled record under this policy.
    let permit = stream
        .admit_high_impact(
            &mut authority,
            context("op-2", Phase::Requested),
            vec![Field::metadata("action", "release-artifact")],
        )
        .unwrap();
    assert_eq!(
        permit.durability,
        Durability::Spooled { spooled_records: 2 }
    );
    // The ordinary room of the spool (3 minus the reserve of 1) is used up: fail closed.
    let refused = stream.record(&mut authority, context("op-1", Phase::Running), fact(5));
    assert_eq!(
        refused,
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed {
            store: StoreRefusal::Full,
            spool: None,
            spooled_records: 2,
            kept: None
        }))
    );
    assert_eq!(
        stream.health(),
        AuditHealth::FailClosed {
            store: StoreRefusal::Full,
            spooled_records: 2
        }
    );
    // The revocation reserve still takes a revocation record; the next one is refused
    // visibly.
    let revoked = stream
        .record_revocation(
            &mut authority,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 2),
        )
        .unwrap();
    assert_eq!(
        revoked.durability,
        Durability::Spooled { spooled_records: 3 }
    );
    assert!(matches!(
        stream.record_revocation(
            &mut authority,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 3)
        ),
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed { .. }))
    ));
    // Storage recovers: the spool drains in order, the chain verifies.
    storage.set_capacity(100);
    let flushed = stream.flush();
    assert_eq!((flushed.written, flushed.remaining), (3, 0));
    assert_eq!(stored_sequences(&storage), [1, 2, 3, 4, 5]);
    assert_eq!(stream.health(), AuditHealth::Durable);
    verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    let totals = stream.totals();
    assert_eq!(
        (
            totals.audit.refused,
            totals.audit.spooled,
            totals.audit.flushed
        ),
        (2, 3, 3)
    );

    // The deny policy admits nothing on a spooled record.
    let storage = FakeSegmentStorage::new(1);
    let mut config = stream_config(3, 1, 10);
    config.audit.failure_policy = AuditFailurePolicy::DenyHighImpact;
    let (mut deny, mut deny_authority) = open(
        &mut directory,
        "deny",
        &storage,
        &FakeSpool::new(),
        &FakeAnchor::new(),
        config,
    );
    let _ = deny
        .record(
            &mut deny_authority,
            context("op-1", Phase::Running),
            fact(1),
        )
        .unwrap();
    assert_eq!(
        deny.admit_high_impact(
            &mut deny_authority,
            context("op-2", Phase::Requested),
            vec![]
        ),
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed {
            store: StoreRefusal::Full,
            spool: None,
            spooled_records: 0,
            kept: Some(EventSequence::new(2).unwrap())
        }))
    );
    assert!(matches!(
        deny.health(),
        AuditHealth::FailClosed {
            store: StoreRefusal::Full,
            ..
        }
    ));
}

/// VM-W42 "restart/truncation tested": a stop before the seal is found and recorded in
/// the next header; records cut from a sealed segment are found, the chain continues from
/// the sealed head, and the lost sequences are recorded in the chain; a rewritten record
/// or a missing segment refuses to resume.
#[test]
fn restart_and_truncation_are_detected_and_recorded() {
    let storage = FakeSegmentStorage::new(100);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 3),
    );
    for step in 1..=7 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    // The process stops without closing: segment 2 holds record 7 and has no seal.
    drop(stream);
    drop(authority);
    let (stream, mut authority, resumed) = resume(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 3),
    )
    .unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    assert_eq!(resumed.loss_record, None);
    assert_eq!(resumed.report.lost, None);
    assert_eq!(resumed.report.anchor, AnchorVerdict::NotAnchored);
    let header = stream.current_segment();
    assert_eq!(header.index(), 3);
    assert_eq!(
        header.opening(),
        SegmentOpening::Resume {
            finding: ResumeFinding::Unsealed { records_found: 1 }
        }
    );
    assert_eq!(header.opened_from().last.map(EventSequence::get), Some(7));
    let mut stream = stream;
    let receipt = stream
        .record(&mut authority, context("op-1", Phase::Running), fact(8))
        .unwrap();
    assert_eq!(receipt.sequence.get(), 8);
    // A clean close seals the last segment.
    let closed = stream.close().unwrap();
    assert_eq!(closed.seal.records(), 1);
    assert_eq!(closed.seal.head().last.map(EventSequence::get), Some(8));
    assert!(closed.anchor.is_none());
    drop(authority);
    let chain = verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert_eq!(
        chain.damage,
        [Damage::Unsealed {
            segment: 2,
            records_found: 1
        }]
    );
    assert!(chain.last_sealed);

    // Record 8 is cut from the sealed segment after the fact.
    storage.truncate_tail(1);
    let (stream, truncated_authority, resumed) = resume(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 3),
    )
    .unwrap();
    let at = |value: u64| EventSequence::new(value).unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Truncated {
            intact_through: Some(at(7)),
            continued_from: at(8),
            witness: TruncationWitness::Seal
        }
    );
    assert_eq!(
        resumed
            .report
            .lost
            .map(|range| (range.first(), range.last())),
        Some((at(8), at(8)))
    );
    // The chain continues from the sealed head, and the loss is the first new record.
    let loss = resumed.loss_record.unwrap();
    assert_eq!(loss.sequence.get(), 9);
    let records = storage.all_records();
    let last = records.last().unwrap();
    assert_eq!(last.sequence().get(), 9);
    match last.event().payload() {
        AuditEntry::EventsLost { lost } => {
            assert_eq!((lost.range.first(), lost.range.last()), (at(8), at(8)));
            assert_eq!(lost.reason, LossReason::ProducerRestarted);
            assert_eq!(lost.key.producer, producer("engine.audit"));
            assert_eq!(lost.key.incarnation, ProducerIncarnation::FIRST);
        }
        other => panic!("expected an events-lost record, found {other:?}"),
    }
    assert_eq!(stream.current_segment().index(), 4);
    let chain = verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert!(chain.damage.contains(&Damage::TailTruncated {
        segment: 3,
        intact_through: Some(at(7)),
        continued_from: at(8),
        witness: TruncationWitness::Seal
    }));
    assert_eq!(chain.head.last, Some(at(9)));
    drop((stream, truncated_authority));

    // A record edited in storage is a rewrite: refused, never continued.
    let intact = storage.snapshot();
    let mut edited = intact.clone();
    let mut json = serde_json::to_value(&edited[1].records[0]).unwrap();
    json["event"]["payload"]["fields"]["fields"][0]["value"]["value"] = serde_json::json!(99);
    edited[1].records[0] = serde_json::from_value(json).unwrap();
    storage.replace(edited);
    assert_eq!(
        resume(
            &mut directory,
            "engine",
            &storage,
            &spool,
            &anchor,
            stream_config(4, 1, 3)
        )
        .err(),
        Some(StreamError::Segment(SegmentError::Chain {
            segment: 1,
            error: ChainError::DigestMismatch { sequence: at(4) }
        }))
    );
    // A missing segment is found by the header chain.
    let mut gapped = intact.clone();
    gapped.remove(1);
    storage.replace(gapped);
    assert_eq!(
        resume(
            &mut directory,
            "engine",
            &storage,
            &spool,
            &anchor,
            stream_config(4, 1, 3)
        )
        .err(),
        Some(StreamError::Segment(SegmentError::MissingSegment {
            expected: 1,
            found: 2
        }))
    );
    // A seal removed from a middle segment is found too.
    let mut unsealed = intact;
    unsealed[1].seal = None;
    storage.replace(unsealed);
    assert_eq!(
        resume(
            &mut directory,
            "engine",
            &storage,
            &spool,
            &anchor,
            stream_config(4, 1, 3)
        )
        .err(),
        Some(StreamError::Segment(SegmentError::MissingSeal {
            segment: 1
        }))
    );
}

/// §8.2 line 2445 "never block the revocation channel"; CORE-06 row "metrics floods
/// cannot suppress revocation or corrupt audit ordering": with audit storage full, the
/// spool full and guest reports rate-limited, the event plane's revocation lane still
/// takes and delivers revocations, and the audit stream's own refusals stay visible.
#[test]
fn the_revocation_lane_is_never_blocked_by_an_audit_flood() {
    let clock = manual_clock();
    let mut hub = EventHub::new(
        Arc::clone(&clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 4,
                sample_above_events: 4,
                keep_one_in: NonZeroU32::MIN,
                retention: Duration::from_secs(60),
                max_series: 2,
            },
            progress: ProgressConfig {
                max_tracked: 2,
                terminal_retention: Duration::from_secs(60),
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::FIRST,
        },
    )
    .unwrap();
    let mut issuer = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    let storage = FakeSegmentStorage::new(1);
    let spool = FakeSpool::new();
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &FakeAnchor::new(),
        stream_config(2, 1, 10),
    );
    // The flood: one durable record, one spooled, then refusals, plus guest reports past
    // their emission limit.
    let mut refusals = 0;
    for step in 1..=20 {
        if stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .is_err()
        {
            refusals += 1;
        }
    }
    assert_eq!(refusals, 18);
    let mut rate_limited = 0;
    for _ in 0..20 {
        let outcome = stream.record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::GuestReport {
                fields: vec![Field::untrusted("stdout", "flood")],
            },
        );
        if matches!(
            outcome,
            Err(StreamRefusal::Audit(AuditRefusal::RateLimited { .. }))
        ) {
            rate_limited += 1;
        }
    }
    assert!(rate_limited >= 16, "{rate_limited}");
    assert!(matches!(
        stream.health(),
        AuditHealth::FailClosed {
            store: StoreRefusal::Full,
            ..
        }
    ));
    // The lane takes the revocation at once and delivers it first.
    assert_eq!(
        hub.emit_revocation(
            &mut issuer,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 2)
        ),
        Ok(RevocationAdmission::Queued)
    );
    let batch = hub.drain_revocations();
    assert_eq!(batch.notices.len(), 1);
    assert_eq!(batch.notices[0].payload().epoch, AuthorizationEpoch::new(2));
    // The durable copy uses the reserve; the next one is refused visibly, and the lane
    // still takes a later revocation.
    let copy = stream
        .record_revocation(
            &mut authority,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 2),
        )
        .unwrap();
    assert_eq!(copy.durability, Durability::Spooled { spooled_records: 2 });
    assert!(matches!(
        stream.record_revocation(
            &mut authority,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 3)
        ),
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed { .. }))
    ));
    assert_eq!(
        hub.emit_revocation(
            &mut issuer,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 3)
        ),
        Ok(RevocationAdmission::Queued)
    );
    assert_eq!(hub.drain_revocations().notices.len(), 1);
    // Audit ordering survived the flood.
    storage.set_capacity(100);
    stream.flush();
    assert_eq!(stored_sequences(&storage), [1, 2, 3]);
    verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert!(stream.totals().audit.refused >= 19);
    assert!(stream.totals().audit.suppressed_guest_observations >= 16);
}

/// VM-P12 "credential boundary" with its stated limited coverage; §8.2 line 2445: no
/// credentials, authorization headers, raw prompts or hidden reasoning are logged, and
/// attacker-controlled fields are bounded in size, number and rate.
#[test]
fn redaction_removes_fixture_secrets_from_every_field_and_bounds_hostile_fields() {
    assert!(SECRET_SCAN_COVERAGE.contains("do not scan"));
    let storage = FakeSegmentStorage::new(100);
    let spool = FakeSpool::new();
    let mut directory = StreamDirectory::new();
    let mut config = stream_config(4, 1, 100);
    // The policy that keeps untrusted text exercises the scanner; the metadata-only
    // policy withholds it entirely.
    config.audit.redaction = RedactionPolicy::metadata_only().keeping_untrusted_text();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &FakeAnchor::new(),
        config,
    );
    let planted = vec![
        Field::new("password", FieldClass::Credential, FIXTURE_SECRETS[0]),
        Field::new(
            "authorization",
            FieldClass::AuthorizationHeader,
            format!("Bearer {}", FIXTURE_SECRETS[2]),
        ),
        Field::new("prompt", FieldClass::Prompt, FIXTURE_SECRETS[4]),
        Field::new("reasoning", FieldClass::ModelReasoning, FIXTURE_SECRETS[5]),
        Field::new("path", FieldClass::PrivatePath, FIXTURE_SECRETS[6]),
        Field::metadata(
            "note",
            format!(
                "token {} and password={} at {}",
                FIXTURE_SECRETS[1], FIXTURE_SECRETS[0], FIXTURE_SECRETS[7]
            ),
        ),
        Field::untrusted(
            "stdout",
            format!(
                "key {} Authorization: Bearer {}",
                FIXTURE_SECRETS[3], FIXTURE_SECRETS[2]
            ),
        ),
        Field::metadata("tool", "release-file"),
    ];
    let _ = stream
        .record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::HostFact {
                fact: HostFact::AuthorizationDecision,
                fields: planted.clone(),
            },
        )
        .unwrap();
    let _ = stream
        .record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::GuestReport { fields: planted },
        )
        .unwrap();
    // Hostile fields: a long text is cut, surplus fields are counted, and the rate is
    // bounded.
    let long = "the guest printed this line ".repeat(400);
    let mut many: Vec<Field> = vec![Field::untrusted("long", long.clone())];
    const NAMES: [&str; 40] = [
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13",
        "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24", "f25", "f26",
        "f27", "f28", "f29", "f30", "f31", "f32", "f33", "f34", "f35", "f36", "f37", "f38", "f39",
    ];
    many.extend(NAMES.iter().map(|name| Field::untrusted(name, 1u64)));
    let hostile = stream
        .record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::GuestReport { fields: many },
        )
        .unwrap();
    assert_eq!(hostile.sequence.get(), 3);
    let records = storage.all_records();
    let AuditEntry::GuestObservation { fields } = records[2].event().payload() else {
        panic!("expected a guest observation");
    };
    let RedactedValue::Text { text, full_bytes } = fields.get("long").unwrap() else {
        panic!("expected kept text");
    };
    assert_eq!(text.len(), RedactionPolicy::DEFAULT_MAX_TEXT_BYTES);
    assert!(*full_bytes > 10_000, "{full_bytes}");
    assert_eq!(fields.fields().len(), RedactionPolicy::DEFAULT_MAX_FIELDS);
    assert_eq!(fields.omitted_fields(), 9);
    let mut rate_limited = 0;
    for _ in 0..8 {
        if matches!(
            stream.record(
                &mut authority,
                context("op-1", Phase::Running),
                AuditEvent::GuestReport {
                    fields: vec![Field::untrusted("stdout", "x")]
                }
            ),
            Err(StreamRefusal::Audit(AuditRefusal::RateLimited { .. }))
        ) {
            rate_limited += 1;
        }
    }
    assert!(rate_limited >= 6, "{rate_limited}");
    // The host fact kept its classes' markers only.
    let AuditEntry::HostFact { fields, .. } = records[0].event().payload() else {
        panic!("expected a host fact");
    };
    for (name, class) in [
        ("password", FieldClass::Credential),
        ("authorization", FieldClass::AuthorizationHeader),
        ("prompt", FieldClass::Prompt),
        ("reasoning", FieldClass::ModelReasoning),
        ("path", FieldClass::PrivatePath),
    ] {
        assert_eq!(fields.get(name), Some(&RedactedValue::Removed { class }));
    }
    assert_eq!(
        fields.get("note").map(|value| match value {
            RedactedValue::Text { text, .. } => text.as_str(),
            _ => "",
        }),
        Some("token [redacted] and password=[redacted] at [redacted-path]")
    );
    // The scan, within its stated coverage: stored segments, the spool and a
    // reconstruction built from the records.
    let mut index = CorrelationIndex::new(bounds()).unwrap();
    index
        .add_request(ToolRequest {
            request: RequestId::new("req-1").unwrap(),
            execution: execution("exe-1"),
            tool: ToolName::new("release-file").unwrap(),
            arguments: digest(
                "yougori/test/arguments/v1",
                &[FIXTURE_SECRETS[4].as_bytes()],
            ),
            requested_at: MonotonicTime::from_nanos(1),
            generations: Default::default(),
        })
        .unwrap();
    index
        .add_operation(OperationLink {
            operation: operation("op-1"),
            request: RequestId::new("req-1").unwrap(),
            approval: None,
            execution: execution("exe-1"),
            started_at: MonotonicTime::from_nanos(2),
        })
        .unwrap();
    let reconstruction = index.reconstruct(
        &IncidentScope::Execution {
            execution: execution("exe-1"),
        },
        &records,
    );
    assert_eq!(reconstruction.audit_records, 3);
    let scanned = [
        serde_json::to_string(&storage.snapshot()).unwrap(),
        serde_json::to_string(&spool.snapshot()).unwrap(),
        serde_json::to_string(&reconstruction).unwrap(),
    ];
    for text in &scanned {
        for secret in FIXTURE_SECRETS {
            assert!(!text.contains(secret), "{secret} leaked");
        }
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("alice"));
    }
    // The metadata-only policy withholds untrusted text altogether.
    let storage = FakeSegmentStorage::new(100);
    let (mut strict, mut strict_authority) = open(
        &mut directory,
        "strict",
        &storage,
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 100),
    );
    let _ = strict
        .record(
            &mut strict_authority,
            context("op-1", Phase::Running),
            AuditEvent::GuestReport {
                fields: vec![Field::metadata("claimed", FIXTURE_SECRETS[4])],
            },
        )
        .unwrap();
    let AuditEntry::GuestObservation { fields } =
        storage.all_records()[0].event().payload().clone()
    else {
        panic!("expected a guest observation");
    };
    assert_eq!(
        fields.get("claimed"),
        Some(&RedactedValue::Withheld { bytes: 28 })
    );
}

fn bounds() -> CorrelationBounds {
    CorrelationBounds {
        max_requests: 8,
        max_approvals: 8,
        max_operations: 8,
        max_artifacts: 8,
        max_observations: 8,
    }
}

/// VM-W42 "rotation": segments link by header digest and sealed head, verification walks
/// them as one chain, and a rotation on request seals the current segment.
#[test]
fn rotation_keeps_linkage_across_segments() {
    let storage = FakeSegmentStorage::new(100);
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 3),
    );
    for step in 1..=10 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    let segments = storage.snapshot();
    assert_eq!(segments.len(), 4);
    assert_eq!(
        segments
            .iter()
            .map(|segment| segment.records.len())
            .collect::<Vec<_>>(),
        [3, 3, 3, 1]
    );
    for (index, pair) in segments.windows(2).enumerate() {
        let (previous, next) = (&pair[0], &pair[1]);
        let seal = previous.seal.as_ref().unwrap();
        assert_eq!(seal.index(), index as u64);
        assert_eq!(next.header.opened_from(), seal.head());
        assert_eq!(
            next.header.previous_header(),
            Some(previous.header.digest())
        );
        assert_eq!(next.header.opening(), SegmentOpening::Rotation);
        assert_eq!(next.records[0].previous(), seal.head().digest);
    }
    let chain = verify_segments(&genesis("engine"), &segments).unwrap();
    assert_eq!((chain.segments, chain.records), (4, 10));
    assert_eq!(chain.head, stream.durable_head());
    assert!(!chain.last_sealed);
    assert_eq!(stream.totals().segments.rotations, 3);
    // A rotation on request seals the open segment; an empty one is not rotated.
    let seal = stream.rotate().unwrap().unwrap();
    assert_eq!(seal.records(), 1);
    assert_eq!(stream.rotate().unwrap(), None);
    assert_eq!(stream.current_segment().index(), 4);
    assert_eq!(stream.state().segment, 4);
    // A header whose content changed no longer matches its digest.
    let mut forged = storage.snapshot();
    let mut json = serde_json::to_value(&forged[2].header).unwrap();
    json["index"] = serde_json::json!(2);
    json["opening"] = serde_json::json!({"reason": "genesis"});
    forged[2].header = serde_json::from_value(json).unwrap();
    assert_eq!(
        verify_segments(&genesis("engine"), &forged),
        Err(SegmentError::HeaderDigest { segment: 2 })
    );
    // Another stream's genesis does not verify these segments.
    assert_eq!(
        verify_segments(&genesis("warden"), &storage.snapshot()),
        Err(SegmentError::WrongStream { segment: 0 })
    );
}

/// §8.2 line 2447: the anchored head makes a rewrite or a cut detectable; VM-W42
/// "delayed anchor tested": an unreachable anchor delays nothing.
#[test]
fn the_anchored_head_detects_a_rewrite_and_a_delayed_anchor_blocks_nothing() {
    let storage = FakeSegmentStorage::new(100);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let config = with_anchoring(stream_config(4, 1, 2));
    let (mut stream, mut authority) =
        open(&mut directory, "engine", &storage, &spool, &anchor, config);
    for step in 1..=5 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    // Two rotations happened, each followed by a publication of the durable head.
    assert_eq!(stream.totals().anchor_publications, 2);
    assert_eq!(
        anchor.held(&journal_id("engine")).unwrap().sequence().get(),
        5
    );
    assert_eq!(stream.state().anchor_lag_records, 0);
    // The anchor becomes unreachable: appends go on, the head stays pending.
    anchor.refuse(Some(AnchorRefusal::Unreachable));
    for step in 6..=8 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    assert_eq!(stream.totals().anchor_refusals, 1);
    assert_eq!(
        stream
            .anchor_state()
            .pending()
            .unwrap()
            .last
            .map(EventSequence::get),
        Some(7)
    );
    assert_eq!(stream.state().anchor_lag_records, 3);
    assert_eq!(stream.anchor_now(), Err(AnchorRefusal::Unreachable));
    // It recovers: the close publishes the final head.
    anchor.refuse(None);
    let closed = stream.close().unwrap();
    assert_eq!(closed.anchor.unwrap().unwrap().sequence().get(), 8);
    drop(authority);
    let intact = storage.snapshot();

    // A rewrite: a forger produces a self-consistent chain under the same name.
    let mut forger_directory = StreamDirectory::new();
    let forged_storage = FakeSegmentStorage::new(100);
    let (mut forger, mut forger_authority) = open(
        &mut forger_directory,
        "engine",
        &forged_storage,
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 2),
    );
    for step in 1..=8 {
        let _ = forger
            .record(
                &mut forger_authority,
                context("op-9", Phase::Running),
                fact(step + 100),
            )
            .unwrap();
    }
    forger.close().unwrap();
    drop(forger_authority);
    verify_segments(&genesis("engine"), &forged_storage.snapshot()).unwrap();
    storage.replace(forged_storage.snapshot());
    assert_eq!(
        resume(&mut directory, "engine", &storage, &spool, &anchor, config).err(),
        Some(StreamError::Segment(SegmentError::Rewritten {
            anchored: EventSequence::new(8).unwrap()
        }))
    );
    assert_eq!(
        super::anchor::compare_with_anchor(
            &journal_id("engine"),
            &forged_storage.snapshot(),
            anchor.held(&journal_id("engine")).as_ref()
        ),
        AnchorVerdict::Rewritten {
            anchored: EventSequence::new(8).unwrap()
        }
    );

    // A cut after the anchor: the last segment is gone entirely, so no seal shows it,
    // and the anchor does.
    let mut cut = intact.clone();
    cut.pop();
    storage.replace(cut);
    let (stream, cut_authority, resumed) =
        resume(&mut directory, "engine", &storage, &spool, &anchor, config).unwrap();
    let at = |value: u64| EventSequence::new(value).unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Truncated {
            intact_through: Some(at(6)),
            continued_from: at(8),
            witness: TruncationWitness::Anchor
        }
    );
    assert_eq!(
        resumed.report.anchor,
        AnchorVerdict::Truncated {
            anchored: at(8),
            stored_through: Some(at(6))
        }
    );
    assert_eq!(resumed.loss_record.unwrap().sequence, at(9));
    let chain = verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert!(chain.damage.contains(&Damage::TailTruncated {
        segment: 2,
        intact_through: Some(at(6)),
        continued_from: at(8),
        witness: TruncationWitness::Anchor
    }));
    assert_eq!(chain.head.last, Some(at(9)));
    drop((stream, cut_authority));

    // An unreachable anchor at resume is reported, not hidden, and resume goes on.
    storage.replace(intact);
    anchor.refuse(Some(AnchorRefusal::Unreachable));
    let (stream, _authority, resumed) =
        resume(&mut directory, "engine", &storage, &spool, &anchor, config).unwrap();
    assert_eq!(resumed.anchor_refusal, Some(AnchorRefusal::Unreachable));
    assert_eq!(resumed.report.anchor, AnchorVerdict::NotAnchored);
    assert_eq!(resumed.report.finding, ResumeFinding::Sealed);
    assert_eq!(stream.totals().anchor_refusals, 1);
    // Heads only move forward at the anchor.
    anchor.refuse(None);
    let earlier = super::anchor::AnchoredHead::new(
        JournalHead {
            last: Some(at(2)),
            ..genesis("engine")
        },
        0,
        MonotonicTime::ZERO,
    )
    .unwrap();
    let mut held = anchor.clone();
    assert_eq!(
        super::anchor::HeadAnchor::publish(&mut held, &earlier),
        Err(AnchorRefusal::Regressed {
            held: at(8),
            offered: at(2)
        })
    );
}

/// §8.2 line 2443 and VM-W44 "guest-reported events marked as such": a guest report is
/// written and labelled as one, whatever its fields claim, and cannot be pointed to or
/// indexed as a host-observed fact.
#[test]
fn a_guest_fact_cannot_be_stored_as_host_observed() {
    let storage = FakeSegmentStorage::new(100);
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 10),
    );
    let guest = AuditEvent::GuestReport {
        fields: vec![Field::metadata("uname", "Linux trusted-host 6.1")],
    };
    assert_eq!(guest.source(), SourceClass::GuestReport);
    let _ = stream
        .record(&mut authority, context("op-1", Phase::Running), guest)
        .unwrap();
    let _ = stream
        .record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::HostFact {
                fact: HostFact::LaunchFact,
                fields: vec![Field::metadata("uname", "Linux trusted-host 6.1")],
            },
        )
        .unwrap();
    let records = storage.all_records();
    assert_eq!(
        records[0].event().provenance().source(),
        SourceClass::GuestReport
    );
    assert!(matches!(
        records[0].event().payload(),
        AuditEntry::GuestObservation { .. }
    ));
    let AuditEntry::GuestObservation { fields } = records[0].event().payload() else {
        panic!("expected a guest observation");
    };
    assert_eq!(
        fields.get("uname"),
        Some(&RedactedValue::Withheld { bytes: 22 })
    );
    assert_eq!(
        HostFactPointer::of(&records[0]),
        Err(NotHostObserved {
            source: SourceClass::GuestReport,
            entry: "guest observation"
        })
    );
    assert_eq!(
        TelemetrySource::of_record(&records[0]),
        TelemetrySource::GuestReport {
            kind: GuestReportKind::AuditObservation
        }
    );
    let host = HostFactPointer::of(&records[1]).unwrap();
    assert_eq!(host.fact(), HostFact::LaunchFact);
    assert_eq!(host.pointer(), &AuditPointer::of(&records[1]));
    assert_eq!(
        TelemetrySource::of_record(&records[1]),
        TelemetrySource::HostObservation
    );
    // Hypervisor host syscalls are host-observed and never the guest's syscalls.
    let syscalls =
        Observation::hypervisor_host_syscalls(operation("op-1"), MonotonicTime::ZERO, 40);
    assert!(syscalls.source.is_host_observation());
    assert!(!syscalls.source.describes_guest_syscalls());
    assert!(syscalls.source.label().contains("not the guest's syscalls"));
    let report = Observation::guest_report(
        GuestReportKind::SyscallReport,
        operation("op-1"),
        MonotonicTime::ZERO,
        ObservationSummary::Syscalls { calls: 3 },
    );
    assert!(!report.source.is_host_observation());
    assert!(report.source.describes_guest_syscalls());
    assert!(report.source.label().contains("untrusted"));
}

fn hypervisor() -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: digest("yougori/test/machine/v1", &[b"workstation"]),
        hypervisor: HypervisorKind::Kvm,
    })
}

fn fingerprint(value: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("firewall", value)]).unwrap()
}

fn ledger_with_basics(configuration: ConfigurationFingerprint) -> AssuranceLedger {
    let mut ledger = AssuranceLedger::new(configuration);
    ledger
        .add_assumption(
            AssumptionId::new("host-admin").unwrap(),
            AssumptionKind::HostAdministratorTrusted,
        )
        .unwrap();
    ledger
        .add_risk(
            RiskId::new("unknown-escape").unwrap(),
            RiskKind::UnknownEscape,
        )
        .unwrap();
    ledger
}

fn assumptions() -> BTreeSet<AssumptionId> {
    BTreeSet::from([AssumptionId::new("host-admin").unwrap()])
}

fn risks() -> BTreeSet<RiskId> {
    BTreeSet::from([RiskId::new("unknown-escape").unwrap()])
}

fn claim(
    id: &str,
    configuration: ConfigurationFingerprint,
    support: ClaimSupport,
) -> Result<Claim, LedgerError> {
    Claim::new(
        ClaimId::new(id).unwrap(),
        Property::HypervisorConfinement,
        ExecutionCategory::VmSandbox,
        ProfileId::new("local-containment").unwrap(),
        configuration,
        assumptions(),
        risks(),
        support,
    )
}

/// VM-W52 "every release claim has evidence or an explicit gap"; VM-P50: a claim with
/// evidence support and no citation, a fake-substrate test, or a guest-only observation
/// for a host-only capability is refused; a gap is stated, never hidden.
#[test]
fn a_claim_without_evidence_is_refused() {
    let configuration = fingerprint("1");
    assert!(matches!(
        claim(
            "c1",
            configuration,
            ClaimSupport::Evidence { citations: vec![] }
        ),
        Err(LedgerError::NoEvidence { .. })
    ));
    let fake = TestCitation {
        test: TestId::new("vm-p04-run-7").unwrap(),
        record: digest("yougori/test/record/v1", &[b"r"]),
        configuration,
        substrate: RunSubstrate::FakeTimeControlled,
    };
    assert!(matches!(
        claim(
            "c2",
            configuration,
            ClaimSupport::Evidence {
                citations: vec![Citation::Test(fake)]
            }
        ),
        Err(LedgerError::FakeSubstrateIsNotEvidence { .. })
    ));
    // A guest report cannot be cited for hypervisor availability, a host-only capability.
    let guest_link = EvidenceLink {
        capability: Capability::HypervisorAvailable,
        subject: hypervisor().identity(),
        configuration,
        source: SourceClass::GuestReport,
        clock: crate::foundation::evidence::ClockSession::generate(),
        observed_at: MonotonicTime::ZERO,
    };
    assert!(matches!(
        claim(
            "c3",
            configuration,
            ClaimSupport::Evidence {
                citations: vec![Citation::Probe(ProbeCitation {
                    link: guest_link,
                    subject: hypervisor(),
                    max_age: Duration::from_secs(60),
                })]
            }
        ),
        Err(LedgerError::SourceTooWeak {
            capability: Capability::HypervisorAvailable,
            ..
        })
    ));
    // A link that names another subject than the citation is refused.
    let mismatched = EvidenceLink {
        source: SourceClass::HostProbe,
        subject: digest("yougori/test/other/v1", &[b"x"]),
        ..guest_link
    };
    assert!(matches!(
        claim(
            "c4",
            configuration,
            ClaimSupport::Evidence {
                citations: vec![Citation::Probe(ProbeCitation {
                    link: mismatched,
                    subject: hypervisor(),
                    max_age: Duration::from_secs(60),
                })]
            }
        ),
        Err(LedgerError::CitationSubjectMismatch { .. })
    ));
    // Assumptions and residual risks are not optional.
    assert!(matches!(
        Claim::new(
            ClaimId::new("c5").unwrap(),
            Property::Audit,
            ExecutionCategory::VmSandbox,
            ProfileId::new("local-containment").unwrap(),
            configuration,
            BTreeSet::new(),
            risks(),
            ClaimSupport::Gap {
                gap: ExplicitGap {
                    reason: GapReason::NotTested
                }
            },
        ),
        Err(LedgerError::NoAssumptions { .. })
    ));
    assert!(matches!(
        Claim::new(
            ClaimId::new("c5").unwrap(),
            Property::Audit,
            ExecutionCategory::VmSandbox,
            ProfileId::new("local-containment").unwrap(),
            configuration,
            assumptions(),
            BTreeSet::new(),
            ClaimSupport::Gap {
                gap: ExplicitGap {
                    reason: GapReason::NotTested
                }
            },
        ),
        Err(LedgerError::NoResidualRisks { .. })
    ));
    // A gap is a status of its own, and the ledger knows every assumption and risk.
    let mut ledger = ledger_with_basics(configuration);
    let registry = ProbeRegistry::new(manual_clock());
    let gap = claim(
        "gap",
        configuration,
        ClaimSupport::Gap {
            gap: ExplicitGap {
                reason: GapReason::HardwareUnavailable,
            },
        },
    )
    .unwrap();
    ledger.add_claim(gap).unwrap();
    assert_eq!(
        ledger
            .status(&ClaimId::new("gap").unwrap(), &registry)
            .unwrap(),
        ClaimStatus::Gap {
            reason: GapReason::HardwareUnavailable
        }
    );
    let unknown = Claim::new(
        ClaimId::new("c6").unwrap(),
        Property::Audit,
        ExecutionCategory::VmSandbox,
        ProfileId::new("local-containment").unwrap(),
        configuration,
        BTreeSet::from([AssumptionId::new("nobody").unwrap()]),
        risks(),
        ClaimSupport::Gap {
            gap: ExplicitGap {
                reason: GapReason::NotTested,
            },
        },
    )
    .unwrap();
    assert!(matches!(
        ledger.add_claim(unknown),
        Err(LedgerError::UnknownAssumption { .. })
    ));
    assert!(matches!(
        ledger.status(&ClaimId::new("none").unwrap(), &registry),
        Err(LedgerError::UnknownClaim { .. })
    ));
}

/// VM-W52 "stale evidence invalidates the affected claim"; §8.1 line 2439 "re-evaluate
/// relevant evidence after ... changes": a claim cited on fresh host evidence is
/// supported until the evidence ages out, is superseded, or the configuration changes.
#[test]
fn stale_evidence_invalidates_a_claim() {
    let clock = manual_clock();
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::hypervisor_availability());
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let configuration = fingerprint("1");
    probe.respond(
        &hypervisor(),
        Probe::supported(
            configuration,
            Duration::from_secs(60),
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Kvm,
            },
        ),
    );
    let link = EvidenceLink::of(
        registry
            .refresh(Capability::HypervisorAvailable, &hypervisor())
            .unwrap(),
    );
    let observed_at = link.observed_at;
    let mut ledger = ledger_with_basics(configuration);
    let cite = |id: &str, configuration| {
        claim(
            id,
            configuration,
            ClaimSupport::Evidence {
                citations: vec![Citation::Probe(ProbeCitation {
                    link,
                    subject: hypervisor(),
                    max_age: Duration::from_secs(60),
                })],
            },
        )
        .unwrap()
    };
    ledger
        .add_claim(cite("confinement", configuration))
        .unwrap();
    let id = ClaimId::new("confinement").unwrap();
    assert_eq!(
        ledger.status(&id, &registry).unwrap(),
        ClaimStatus::Supported {
            citations: 1,
            fresh_until: Some(observed_at.saturating_add(Duration::from_secs(60)))
        }
    );
    // The evidence ages out.
    clock.advance(Duration::from_secs(61));
    assert!(matches!(
        ledger.status(&id, &registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::Stale {
                capability: Capability::HypervisorAvailable,
                staleness: Staleness::TooOld { .. }
            }
        }
    ));
    // A fresh observation replaces it, but the claim cited the old one.
    registry
        .refresh(Capability::HypervisorAvailable, &hypervisor())
        .unwrap();
    assert!(matches!(
        ledger.status(&id, &registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::Superseded { .. }
        }
    ));
    // The configuration changes: the claim is invalidated at once.
    assert_eq!(ledger.set_configuration(fingerprint("2")), 1);
    assert!(matches!(
        ledger.status(&id, &registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::ClaimConfigurationChanged { .. }
        }
    ));
    // A claim made under the new configuration still cites evidence observed under the
    // old one, which the live evidence refuses.
    let latest = EvidenceLink::of(
        registry
            .latest(Capability::HypervisorAvailable, &hypervisor())
            .unwrap(),
    );
    let recited = claim(
        "recited",
        fingerprint("2"),
        ClaimSupport::Evidence {
            citations: vec![Citation::Probe(ProbeCitation {
                link: latest,
                subject: hypervisor(),
                max_age: Duration::from_secs(60),
            })],
        },
    )
    .unwrap();
    ledger.add_claim(recited).unwrap();
    assert!(matches!(
        ledger
            .status(&ClaimId::new("recited").unwrap(), &registry)
            .unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::EvidenceConfigurationChanged { .. }
        }
    ));
    // A test cited under another configuration is invalidated the same way.
    let tested = claim(
        "tested",
        fingerprint("2"),
        ClaimSupport::Evidence {
            citations: vec![Citation::Test(TestCitation {
                test: TestId::new("vm-p04-run-8").unwrap(),
                record: digest("yougori/test/record/v1", &[b"r"]),
                configuration: fingerprint("1"),
                substrate: RunSubstrate::AuthorizedDisposable {
                    authorization: crate::foundation::report::Label::new("disposable-host")
                        .unwrap(),
                },
            })],
        },
    )
    .unwrap();
    ledger.add_claim(tested).unwrap();
    assert!(matches!(
        ledger
            .status(&ClaimId::new("tested").unwrap(), &registry)
            .unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::TestConfigurationChanged { .. }
        }
    ));
    let summary = ledger.summary(&registry);
    assert_eq!(
        (
            summary.claims,
            summary.supported,
            summary.gaps,
            summary.invalidated
        ),
        (3, 0, 0, 3)
    );
}

/// VM-W52 "no wall multipliers or generic secure badge", "no aggregate probability
/// fabricated from surface counts": the summary counts and nothing else, and no status
/// text carries a badge.
#[test]
fn no_score_exists() {
    let configuration = fingerprint("1");
    let mut ledger = ledger_with_basics(configuration);
    let registry = ProbeRegistry::new(manual_clock());
    for (id, reason) in [
        ("egress", GapReason::NotTested),
        ("dns", GapReason::BlindSpot),
        ("guest", GapReason::GuestOnlyObservation),
    ] {
        ledger
            .add_claim(
                claim(
                    id,
                    configuration,
                    ClaimSupport::Gap {
                        gap: ExplicitGap { reason },
                    },
                )
                .unwrap(),
            )
            .unwrap();
    }
    let summary = ledger.summary(&registry);
    let json = serde_json::to_value(&summary).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["claims", "entries", "gaps", "invalidated", "supported"]
    );
    let texts = [summary.to_string(), json.to_string()];
    for text in &texts {
        let lowered = text.to_ascii_lowercase();
        for forbidden in ["%", "score", "secure", "probability", "rating", "grade"] {
            assert!(!lowered.contains(forbidden), "{forbidden} in {text}");
        }
    }
    assert!(summary
        .to_string()
        .starts_with("3 claims: 0 supported, 3 with an explicit gap, 0 invalidated"));
    for status in [
        ClaimStatus::Supported {
            citations: 2,
            fresh_until: Some(MonotonicTime::from_nanos(5)),
        },
        ClaimStatus::Gap {
            reason: GapReason::EvidencePending,
        },
        ClaimStatus::Invalidated {
            reason: Invalidation::ClaimConfigurationChanged {
                claimed_under: fingerprint("1"),
                current: fingerprint("2"),
            },
        },
    ] {
        assert!(!status.to_string().to_ascii_lowercase().contains("secure"));
    }
    for text in [CUSTODY_STATEMENT, SECRET_SCAN_COVERAGE] {
        assert!(!text.to_ascii_lowercase().contains("secure"));
    }
    assert_eq!(Property::DefaultEgressDenial.to_string(), "VM-P06");
}

/// VM-W44 "useful incident reconstruction with minimal content retention": a request,
/// its approval, the operation, its artifact, the audit records and the observations
/// become one labelled timeline; the arguments survive only as a digest.
#[test]
fn an_incident_is_reconstructed_over_a_fixture() {
    let storage = FakeSegmentStorage::new(100);
    let mut directory = StreamDirectory::new();
    let clock = manual_clock();
    let (mut stream, mut authority) = AuditStream::open(
        &mut directory,
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        FakeSpool::new(),
        FakeAnchor::new(),
        Arc::clone(&clock),
        stream_config(4, 1, 10),
    )
    .unwrap();
    let tick = |clock: &ManualClock| {
        clock.advance(Duration::from_millis(10));
        clock.now()
    };
    let requested_at = tick(&clock);
    let decided_at = tick(&clock);
    let decision = stream
        .record(
            &mut authority,
            context("op-release", Phase::Requested),
            AuditEvent::HostFact {
                fact: HostFact::AuthorizationDecision,
                fields: vec![
                    Field::metadata("decision", "approved"),
                    Field::metadata("tool", "release-file"),
                ],
            },
        )
        .unwrap();
    let started_at = tick(&clock);
    let _ = stream
        .record(
            &mut authority,
            context("op-release", Phase::Running),
            AuditEvent::HostFact {
                fact: HostFact::LaunchFact,
                fields: vec![Field::metadata("boot_generation", 3u64)],
            },
        )
        .unwrap();
    let observed_at = tick(&clock);
    let _ = stream
        .record(
            &mut authority,
            context("op-release", Phase::Running),
            AuditEvent::GuestReport {
                fields: vec![Field::untrusted("stdout", "released 1 file to the user")],
            },
        )
        .unwrap();
    // An unrelated operation of another execution stays out of the incident.
    let _ = stream
        .record(
            &mut authority,
            context("op-other", Phase::Running),
            AuditEvent::HostFact {
                fact: HostFact::Lease,
                fields: vec![Field::metadata("note", "unrelated user work")],
            },
        )
        .unwrap();
    let revoked_at = tick(&clock);
    let _ = stream
        .record_revocation(
            &mut authority,
            context("op-release", Phase::Revoked),
            revocation("exe-1", 2),
        )
        .unwrap();
    let records = storage.all_records();

    let mut index = CorrelationIndex::new(bounds()).unwrap();
    let request = RequestId::new("req-1").unwrap();
    let approval = ApprovalId::new("apr-1").unwrap();
    let secret_arguments = b"{\"path\":\"/home/alice/.ssh/id_ed25519\"}";
    index
        .add_request(ToolRequest {
            request: request.clone(),
            execution: execution("exe-1"),
            tool: ToolName::new("release-file").unwrap(),
            arguments: digest("yougori/test/arguments/v1", &[secret_arguments]),
            requested_at,
            generations: Default::default(),
        })
        .unwrap();
    index
        .add_approval(Approval {
            approval: approval.clone(),
            request: request.clone(),
            decision: ApprovalDecision::Approved,
            decided_by: Approver::User,
            epoch: AuthorizationEpoch::new(1),
            decided_at,
            audit: Some(AuditPointer {
                stream: journal_id("engine"),
                sequence: decision.sequence,
                digest: decision.digest,
            }),
        })
        .unwrap();
    index
        .add_operation(OperationLink {
            operation: operation("op-release"),
            request: request.clone(),
            approval: Some(approval.clone()),
            execution: execution("exe-1"),
            started_at,
        })
        .unwrap();
    let artifact = ContentKey::of(b"released bytes");
    index
        .add_artifact(ArtifactLink {
            artifact,
            operation: operation("op-release"),
            role: ArtifactRole::Released,
            bytes: 14,
            at: observed_at,
        })
        .unwrap();
    index
        .add_observation(Observation::host(
            operation("op-release"),
            revoked_at,
            ObservationSummary::ExitCode { code: 0 },
        ))
        .unwrap();
    index
        .add_observation(Observation::guest_report(
            GuestReportKind::Stdout,
            operation("op-release"),
            observed_at,
            ObservationSummary::Bytes { bytes: 29 },
        ))
        .unwrap();
    index
        .add_observation(Observation::hypervisor_host_syscalls(
            operation("op-release"),
            observed_at,
            120,
        ))
        .unwrap();
    // Links must name indexed records, and an approval decides exactly its request.
    assert!(matches!(
        index.add_artifact(ArtifactLink {
            artifact,
            operation: operation("op-unknown"),
            role: ArtifactRole::Consumed,
            bytes: 1,
            at: observed_at,
        }),
        Err(CorrelationError::UnknownOperation { .. })
    ));
    index
        .add_request(ToolRequest {
            request: RequestId::new("req-2").unwrap(),
            execution: execution("exe-2"),
            tool: ToolName::new("read-file").unwrap(),
            arguments: digest("yougori/test/arguments/v1", &[b"x"]),
            requested_at,
            generations: Default::default(),
        })
        .unwrap();
    assert!(matches!(
        index.add_operation(OperationLink {
            operation: operation("op-other"),
            request: RequestId::new("req-2").unwrap(),
            approval: Some(approval.clone()),
            execution: execution("exe-2"),
            started_at,
        }),
        Err(CorrelationError::ApprovalForAnotherRequest { .. })
    ));

    let reconstruction = index.reconstruct(
        &IncidentScope::Execution {
            execution: execution("exe-1"),
        },
        &records,
    );
    assert_eq!(reconstruction.requests.len(), 1);
    assert_eq!(reconstruction.approvals.len(), 1);
    assert_eq!(reconstruction.operations.len(), 1);
    assert_eq!(reconstruction.artifacts.len(), 1);
    assert_eq!(reconstruction.audit_records, 4);
    assert_eq!(reconstruction.guest_reports, 2);
    // Only the two metadata texts of the decision are retained as text.
    assert_eq!(
        reconstruction.retained_text_bytes,
        "approved".len() as u64 + "release-file".len() as u64
    );
    let kinds: Vec<&str> = reconstruction
        .timeline
        .iter()
        .map(|entry| match &entry.event {
            TimelineEvent::Requested { .. } => "requested",
            TimelineEvent::Decided { .. } => "decided",
            TimelineEvent::Started { .. } => "started",
            TimelineEvent::Audited { .. } => "audited",
            TimelineEvent::Artifact { .. } => "artifact",
            TimelineEvent::Observed { .. } => "observed",
            TimelineEvent::Revoked { .. } => "revoked",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "requested",
            "decided",
            "audited",
            "started",
            "audited",
            "audited",
            "artifact",
            "observed",
            "observed",
            "revoked",
            "observed"
        ]
    );
    assert!(reconstruction
        .timeline
        .windows(2)
        .all(|pair| pair[0].at <= pair[1].at));
    assert_eq!(reconstruction.guest_reported().count(), 2);
    let sources: BTreeSet<&str> = reconstruction
        .timeline
        .iter()
        .map(|entry| entry.source.label())
        .collect();
    assert!(sources.contains("hypervisor host syscalls (host-observed; not the guest's syscalls)"));
    let json = serde_json::to_string(&reconstruction).unwrap();
    assert!(!json.contains("id_ed25519"));
    assert!(!json.contains("alice"));
    assert!(!json.contains("unrelated user work"));
    assert!(json.contains(&digest("yougori/test/arguments/v1", &[secret_arguments]).to_hex()));
    // Narrower scopes.
    let by_operation = index.reconstruct(
        &IncidentScope::Operation {
            operation: operation("op-release"),
        },
        &records,
    );
    assert_eq!(by_operation.audit_records, 4);
    assert_eq!(by_operation.requests.len(), 1);
    let by_request = index.reconstruct(&IncidentScope::Request { request }, &records);
    assert_eq!(by_request.operations.len(), 1);
    let unknown = index.reconstruct(
        &IncidentScope::Operation {
            operation: operation("op-other"),
        },
        &records,
    );
    assert_eq!(unknown.audit_records, 1);
    assert!(unknown.requests.is_empty());
    // The record types have no place for content: an extra field is refused.
    let mut json = serde_json::to_value(&reconstruction.requests[0]).unwrap();
    json["prompt"] = serde_json::json!("summarise my medical history");
    assert!(serde_json::from_value::<ToolRequest>(json).is_err());
    assert!(ToolName::new("release file").is_err());
    // Bounds hold without dropping anything.
    let mut tiny = CorrelationIndex::new(CorrelationBounds {
        max_requests: 1,
        ..bounds()
    })
    .unwrap();
    tiny.add_request(reconstruction.requests[0].clone())
        .unwrap();
    assert_eq!(
        tiny.add_request(ToolRequest {
            request: RequestId::new("req-9").unwrap(),
            ..reconstruction.requests[0].clone()
        }),
        Err(CorrelationError::Bound {
            what: "requests",
            limit: 1
        })
    );
}

/// The storage port on files in a temporary directory: a stream closes, resumes from the
/// files, continues its sequence, and a file truncated after sealing is found.
#[test]
fn file_storage_round_trips_and_shows_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let open_file =
        |directory: &mut StreamDirectory| -> Result<(FileStream, StreamAuthority), StreamError> {
            AuditStream::open(
                directory,
                journal_id("engine"),
                producer("engine.audit"),
                FileSegmentStorage::new(dir.path()),
                spool.clone(),
                anchor.clone(),
                manual_clock(),
                stream_config(4, 1, 3),
            )
        };
    let resume_file = |directory: &mut StreamDirectory| {
        AuditStream::resume(
            directory,
            journal_id("engine"),
            producer("engine.audit"),
            FileSegmentStorage::new(dir.path()),
            spool.clone(),
            anchor.clone(),
            manual_clock(),
            stream_config(4, 1, 3),
        )
    };
    let (mut stream, mut authority) = open_file(&mut directory).unwrap();
    for step in 1..=7 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    stream.close().unwrap();
    drop(authority);
    // Opening again on files that hold segments is refused; resuming continues.
    assert!(matches!(
        open_file(&mut directory).err(),
        Some(StreamError::Segment(SegmentError::NotEmpty))
    ));
    let (mut stream, mut authority, resumed) = resume_file(&mut directory).unwrap();
    assert_eq!(resumed.report.finding, ResumeFinding::Sealed);
    assert_eq!(
        (resumed.report.chain.segments, resumed.report.chain.records),
        (3, 7)
    );
    let receipt = stream
        .record(&mut authority, context("op-1", Phase::Running), fact(8))
        .unwrap();
    assert_eq!(receipt.sequence.get(), 8);
    assert_eq!(stream.current_segment().index(), 3);
    stream.close().unwrap();
    drop(authority);
    // Segment 3 (record 8) loses its record after sealing.
    FileSegmentStorage::new(dir.path()).truncate_tail(3, 1);
    let (stream, _authority, resumed) = resume_file(&mut directory).unwrap();
    assert!(matches!(
        resumed.report.finding,
        ResumeFinding::Truncated {
            witness: TruncationWitness::Seal,
            ..
        }
    ));
    assert_eq!(resumed.report.chain.damage.len(), 1);
    drop(stream);
    let files = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(files, 5);
}

/// An unclear storage refusal (a write that landed after its deadline) never duplicates a
/// record, even across a restart that offers the spooled copy again, and rotation on a
/// refused seal or header is retried, never skipped.
#[test]
fn unclear_refusals_never_duplicate_or_skip() {
    let storage = FakeSegmentStorage::new(100);
    let spool = FakeSpool::new();
    let anchor = FakeAnchor::new();
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 2),
    );
    storage.store_but_report_slow_once();
    let first = stream
        .record(&mut authority, context("op-1", Phase::Running), fact(1))
        .unwrap();
    assert!(matches!(first.durability, Durability::Spooled { .. }));
    assert_eq!(stored_sequences(&storage), [1]);
    assert_eq!(spool.snapshot().len(), 1);
    // The process stops before the spool drains; storage already holds the record.
    drop((stream, authority));
    let (mut stream, mut authority, resumed) = resume(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &anchor,
        stream_config(4, 1, 2),
    )
    .unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    // Resume offered the spooled copy again; storage took it as a duplicate, once.
    assert!(spool.snapshot().is_empty());
    assert_eq!(stream.totals().segments.duplicates, 1);
    assert_eq!(stored_sequences(&storage), [1]);
    for step in 2..=3 {
        let receipt = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
        assert_eq!(receipt.sequence.get(), step);
    }
    assert_eq!(stored_sequences(&storage), [1, 2, 3]);
    // The seal is refused: the record waits, and the next attempt rotates.
    storage.refuse_seals(Some(StoreRefusal::Slow));
    let fourth = stream
        .record(&mut authority, context("op-1", Phase::Running), fact(4))
        .unwrap();
    assert!(matches!(fourth.durability, Durability::Spooled { .. }));
    assert_eq!(stored_sequences(&storage), [1, 2, 3]);
    storage.refuse_seals(None);
    storage.refuse_begins(Some(StoreRefusal::Failed));
    assert_eq!(stream.flush().written, 0);
    assert!(storage.snapshot()[1].seal.is_some());
    storage.refuse_begins(None);
    assert_eq!(stream.flush().written, 1);
    assert_eq!(stored_sequences(&storage), [1, 2, 3, 4]);
    assert_eq!(storage.snapshot().len(), 3);
    let chain = verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    assert_eq!(
        chain.damage,
        [Damage::Unsealed {
            segment: 0,
            records_found: 1
        }]
    );
    assert_eq!(stream.totals().segments.rotations, 1);
    // Linkage to another stream's head is a record of this chain.
    let (warden, _warden_authority) = open(
        &mut directory,
        "warden",
        &FakeSegmentStorage::new(10),
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 1, 2),
    );
    let linked = stream
        .record(
            &mut authority,
            context("op-1", Phase::Running),
            AuditEvent::Linkage(warden.head()),
        )
        .unwrap();
    assert_eq!(linked.sequence.get(), 5);
    assert!(matches!(
        storage.all_records()[4].event().payload(),
        AuditEntry::Linkage { head } if *head == warden.head()
    ));
}

/// §6.3 step 1 (line 2308) and §8.2 line 2445 "never block the revocation channel": the
/// revocation of one grant is a typed record on the revocation reserve, exactly as a
/// revocation is. With storage full and the ordinary part of the spool used, an ordinary
/// record is refused while a grant revocation and a revocation still take the reserve;
/// once the reserve is used, the next one is refused visibly. Storage takes them in order
/// when it recovers, and a reconstruction for the execution finds its grant revocation
/// under any operation.
#[test]
fn a_grant_revocation_takes_the_revocation_reserve_as_a_revocation_does() {
    let storage = FakeSegmentStorage::new(1);
    let spool = FakeSpool::new();
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = open(
        &mut directory,
        "engine",
        &storage,
        &spool,
        &FakeAnchor::new(),
        stream_config(4, 2, 10),
    );
    for step in 1..=3 {
        let _ = stream
            .record(&mut authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
    }
    assert!(matches!(
        stream.record(&mut authority, context("op-1", Phase::Running), fact(4)),
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed { .. }))
    ));
    assert!(matches!(stream.health(), AuditHealth::FailClosed { .. }));

    let grant = GrantRevocation {
        execution: execution("exe-1"),
        grant: GrantId::from_digest(digest("yougori/test/grant/v1", &[b"route-a"])),
        epoch: AuthorizationEpoch::FIRST,
        reason: RevocationReason::SecurityEvent,
    };
    let receipt = stream
        .record_grant_revocation(
            &mut authority,
            context("op-grant", Phase::Revoked),
            grant.clone(),
        )
        .unwrap();
    assert_eq!(receipt.sequence.get(), 4);
    assert_eq!(
        receipt.durability,
        Durability::Spooled { spooled_records: 3 }
    );
    let whole = stream
        .record_revocation(
            &mut authority,
            context("op-2", Phase::Revoked),
            revocation("exe-2", 2),
        )
        .unwrap();
    assert_eq!(whole.durability, Durability::Spooled { spooled_records: 4 });
    assert!(matches!(
        stream.record_grant_revocation(
            &mut authority,
            context("op-grant", Phase::Revoked),
            grant.clone()
        ),
        Err(StreamRefusal::Audit(AuditRefusal::FailClosed { .. }))
    ));
    // Another stream's authority records nothing here.
    let (_warden, mut warden_authority) = open(
        &mut directory,
        "warden",
        &FakeSegmentStorage::new(10),
        &FakeSpool::new(),
        &FakeAnchor::new(),
        stream_config(4, 2, 10),
    );
    assert_eq!(
        stream.record_grant_revocation(
            &mut warden_authority,
            context("op-grant", Phase::Revoked),
            grant.clone()
        ),
        Err(StreamRefusal::WrongStream {
            authority: journal_id("warden"),
            stream: journal_id("engine")
        })
    );

    storage.set_capacity(100);
    assert_eq!(stream.flush().written, 4);
    assert_eq!(stored_sequences(&storage), [1, 2, 3, 4, 5]);
    verify_segments(&genesis("engine"), &storage.snapshot()).unwrap();
    let records = storage.all_records();
    assert!(matches!(
        records[3].event().payload(),
        AuditEntry::GrantRevocation { revocation } if *revocation == grant
    ));
    assert_eq!(records[3].event().phase(), Phase::Revoked);
    assert_eq!(
        TelemetrySource::of_record(&records[3]),
        TelemetrySource::HostObservation
    );
    assert!(matches!(
        records[4].event().payload(),
        AuditEntry::Revocation { .. }
    ));

    let index = CorrelationIndex::new(bounds()).unwrap();
    let of_exe_1 = index.reconstruct(
        &IncidentScope::Execution {
            execution: execution("exe-1"),
        },
        &records,
    );
    assert_eq!(of_exe_1.audit_records, 1);
    assert!(matches!(
        of_exe_1.timeline.as_slice(),
        [entry] if matches!(
            &entry.event,
            TimelineEvent::Audited { entry: AuditEntry::GrantRevocation { revocation }, .. }
                if *revocation == grant
        )
    ));
    let of_exe_2 = index.reconstruct(
        &IncidentScope::Execution {
            execution: execution("exe-2"),
        },
        &records,
    );
    assert_eq!(of_exe_2.audit_records, 1);
    assert!(matches!(
        of_exe_2.timeline.as_slice(),
        [entry] if matches!(entry.event, TimelineEvent::Revoked { .. })
    ));
}
