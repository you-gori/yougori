//! The sink on the spooled durable stream (§8.2 lines 2441–2450, line 2445 "use a bounded
//! local spool; never block the revocation channel"; VM-W42 at line 2665 "restart/truncation,
//! disk full ... tested"; VM-W43 at line 2666 "audit overload cannot block emergency
//! revocation"; VM-W44 at line 2667): the records its log refused survive a restart and
//! drain into the log in order; ordinary records fail closed while revocations use the
//! reserve, and a restart leaves exactly the reserve that was left before it; an explicit
//! release is reported, a failed one included.
//!
//! No test fills a real disk. A log whose segment bound lies below the line of every record
//! the sink writes, though above its segment headers and seals, refuses each record as a
//! full disk would, as `StoreRefusal::Failed` where a full disk gives `Full`; opening the
//! stream again under a larger bound is the disk with room again. The identifiers are long
//! so that every record line stays well above that bound and every header line well below
//! it. Every file lives in a temporary directory the test owns.

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use super::audit_sink::{AuditSink, ReleaseFailure, SinkRefusal, SinkRelease, SinkTotals};
use super::fakes::{at, execution, named, operation, stream_config_reserving, TestClock};
use crate::foundation::coordination::network_grant_id;
use crate::foundation::events::{
    AuditEntry, AuditHealth, AuditReceipt, AuditRecord, AuditRefusal, Durability, EventContext,
    EventSequence, GrantRevocation, JournalHead, JournalId, LogConfig, LogError, LogMarker,
    OwnerError, Phase, ProducerId, RedactedValue, Revocation, RevocationReason, SequenceRange,
    StoreRefusal, Takeover,
};
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, ManualClock, SandboxBootGeneration};
use crate::sandbox::audit::{
    verify_segments, DurableError, DurableSegments, FileSpool, NoAnchor, ResumeFinding,
    SegmentError, SegmentStorage as _, SpoolRoom, SpooledOpening, StoredSegment, StreamDirectory,
    StreamError, StreamRefusal, StreamRelease,
};
use crate::sandbox::lifecycle::{GrantRevocationCause, LifecycleReceipt, RevocationCause};

type Spooled = AuditSink<DurableSegments, FileSpool, NoAnchor, TestClock>;

/// The receipt's sequence and durability, or the refusal.
type Outcome = Result<(u64, Durability), SinkRefusal>;

/// A segment bound below every record line the sink writes here and above every header
/// and seal line.
const REFUSING: u64 = 640;
/// A segment bound that takes every line.
const TAKING: u64 = 1 << 16;
const EXECUTION: &str = "exe-task-spooled-0123456789-0123456789";
const OPERATION: &str = "op-task-spooled-0123456789-0123456789-0123456789";

fn journal() -> JournalId {
    JournalId::new("supervisor").unwrap()
}

fn owner() -> ProducerId {
    ProducerId::new("supervisor.audit").unwrap()
}

fn genesis() -> JournalHead {
    JournalHead::genesis(journal(), owner())
}

fn clock() -> TestClock {
    Arc::new(ManualClock::new(at(1)))
}

fn log(segment_bytes: u64) -> LogConfig {
    LogConfig {
        max_entries: 10_000,
        max_bytes: 1 << 26,
        segment_entries: 64,
        segment_bytes,
    }
}

/// The sink on the stream `supervisor` with a spool of four records, two of them the
/// revocation reserve, and a log of segments of at most `segment_bytes`.
fn open(
    directory: &mut StreamDirectory,
    clock: &TestClock,
    segment_bytes: u64,
) -> Result<(Spooled, SpooledOpening), StreamError> {
    AuditSink::open_durable_spooled(
        directory,
        journal(),
        owner(),
        NoAnchor,
        Arc::clone(clock),
        stream_config_reserving(4, 2),
        log(segment_bytes),
    )
}

fn exe() -> ExecutionId {
    execution(EXECUTION)
}

fn context(phase: Phase) -> EventContext {
    EventContext::new(operation(OPERATION), phase)
}

fn launched() -> LifecycleReceipt {
    LifecycleReceipt::Launched {
        execution: exe(),
        boot: SandboxBootGeneration::FIRST,
        context: context(Phase::Booting),
    }
}

fn first_command(step: u64) -> LifecycleReceipt {
    LifecycleReceipt::FirstCommand {
        execution: exe(),
        boot: SandboxBootGeneration::FIRST,
        elapsed: Duration::from_secs(step),
    }
}

fn revocation(epoch: u64) -> Revocation {
    Revocation {
        execution: exe(),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    }
}

fn revoked(epoch: u64) -> LifecycleReceipt {
    LifecycleReceipt::Revoked {
        revocation: revocation(epoch),
        cause: RevocationCause::Violation,
        context: context(Phase::Revoked),
    }
}

fn grant_revocation() -> GrantRevocation {
    GrantRevocation {
        execution: exe(),
        grant: network_grant_id(&NetworkGrant::NamedRoute {
            route: named("yougori/test/route/v1", "a"),
        }),
        epoch: AuthorizationEpoch::FIRST,
        reason: RevocationReason::SecurityEvent,
    }
}

fn grant_revoked() -> LifecycleReceipt {
    LifecycleReceipt::GrantRevoked {
        revocation: grant_revocation(),
        cause: GrantRevocationCause::Violation,
        cancelled: Vec::new(),
        context: context(Phase::Revoked),
    }
}

fn stopped() -> LifecycleReceipt {
    LifecycleReceipt::Stopped {
        execution: exe(),
        context: context(Phase::Releasing),
    }
}

fn outcome(result: Result<AuditReceipt, SinkRefusal>) -> Outcome {
    result.map(|receipt| (receipt.sequence.get(), receipt.durability))
}

fn record_all(sink: &mut Spooled, receipts: &[LifecycleReceipt]) -> Vec<Outcome> {
    receipts
        .iter()
        .map(|receipt| outcome(sink.record_receipt(receipt)))
        .collect()
}

fn spooled(records: usize) -> Durability {
    Durability::Spooled {
        spooled_records: records,
    }
}

/// The refusal of a record the spool has no room for while the log refuses.
fn fail_closed(spooled_records: usize) -> Outcome {
    Err(SinkRefusal::Stream(StreamRefusal::Audit(
        AuditRefusal::FailClosed {
            store: StoreRefusal::Failed,
            spool: None,
            spooled_records,
            kept: None,
        },
    )))
}

fn range(first: u64, last: u64) -> Option<SequenceRange> {
    SequenceRange::new(EventSequence::new(first)?, EventSequence::new(last)?)
}

fn stored(sink: &Spooled) -> Vec<StoredSegment> {
    sink.stream()
        .with_storage(|storage| storage.segments().unwrap())
}

fn records(segments: &[StoredSegment]) -> Vec<AuditRecord> {
    segments
        .iter()
        .flat_map(|segment| segment.records.iter().cloned())
        .collect()
}

/// Each record's sequence and what it records: the event of a host fact, or the kind of a
/// revocation.
fn labels(segments: &[StoredSegment]) -> Vec<(u64, String)> {
    records(segments)
        .iter()
        .map(|record| {
            let label = match record.event().payload() {
                AuditEntry::HostFact { fields, .. } => match fields.get("event") {
                    Some(RedactedValue::Text { text, .. }) => text.clone(),
                    other => format!("{other:?}"),
                },
                AuditEntry::Revocation { .. } => "revocation".to_owned(),
                AuditEntry::GrantRevocation { .. } => "grant_revocation".to_owned(),
                other => format!("{other:?}"),
            };
            (record.sequence().get(), label)
        })
        .collect()
}

fn labelled(expected: &[(u64, &str)]) -> Vec<(u64, String)> {
    expected
        .iter()
        .map(|(sequence, label)| (*sequence, (*label).to_owned()))
        .collect()
}

fn empty_room() -> SpoolRoom {
    SpoolRoom {
        spooled_records: 0,
        bound: 4,
        reserve: 2,
        ordinary: 2,
        revocation: 4,
    }
}

/// VM-W42 "restart ... disk full ... tested" and §8.2 line 2445: while the log refuses,
/// a launch, a first command and a revocation wait in the spool on file. The sink is
/// released cleanly with the three still spooled, and once it opens again on a log that
/// takes them they drain into it in order, before the next record, under the operation
/// they were recorded with, and the chain verifies from genesis.
#[test]
fn a_sink_that_restarts_with_spooled_records_drains_them_in_order() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let clock = clock();
    let (mut sink, opening) = open(&mut directory, &clock, REFUSING).unwrap();
    assert!(opening.durable.log.created && opening.durable.resume.is_none());
    assert_eq!(opening.spool.held, None);
    assert_eq!(sink.stream().spool_room(), empty_room());
    assert_eq!(
        record_all(&mut sink, &[launched(), first_command(1), revoked(2)]),
        [
            Ok((1, spooled(1))),
            Ok((2, spooled(2))),
            Ok((3, spooled(3))),
        ]
    );
    assert!(matches!(
        sink.stream()
            .with_storage(|storage| storage.last_error().cloned()),
        Some(LogError::TooLarge {
            limit: REFUSING,
            ..
        })
    ));
    let released = sink.release();
    assert!(released.is_clean(), "{:?}", released.failures());
    assert_eq!(released.spooled_records(), Some(3));
    assert_eq!(released.totals.records, 3);
    assert!(!directory.is_live(&journal()));

    let (mut sink, opening) = open(&mut directory, &clock, TAKING).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert_eq!(opening.spool.held, range(1, 3));
    assert_eq!(opening.spool.torn_tail, None);
    assert_eq!(sink.stream().state().spooled_records, 0);
    assert_eq!(sink.stream().health(), AuditHealth::Durable);
    assert_eq!(sink.stream().spool_room(), empty_room());
    assert_eq!(
        outcome(sink.record_receipt(&stopped())),
        Ok((4, Durability::Durable))
    );
    let segments = stored(&sink);
    verify_segments(&genesis(), &segments).unwrap();
    assert_eq!(
        labels(&segments),
        labelled(&[
            (1, "launched"),
            (2, "first_command"),
            (3, "revocation"),
            (4, "vm_stopped"),
        ])
    );
    assert!(records(&segments)
        .iter()
        .all(|record| record.event().operation() == &operation(OPERATION)));
    assert!(sink.release().is_clean());
}

/// §8.2 line 2445 "never block the revocation channel" and VM-W43 "audit overload cannot
/// block emergency revocation", across a restart: with the log refusing, ordinary records
/// take the spool's ordinary room and then fail closed, and a revocation takes the reserve.
/// After a restart the spool holds the same records, its room is what it was, an ordinary
/// record still fails closed, and a grant revocation takes exactly the one slot of the
/// reserve that was left; the next revocation is refused visibly. Once the log takes
/// records again, all four reach it in order as their typed records.
#[test]
fn a_refusing_store_fails_ordinary_records_closed_while_revocations_use_the_reserve_across_a_restart(
) {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let clock = clock();
    let (mut sink, _) = open(&mut directory, &clock, REFUSING).unwrap();
    assert_eq!(
        record_all(
            &mut sink,
            &[launched(), first_command(1), first_command(2), revoked(2)]
        ),
        [
            Ok((1, spooled(1))),
            Ok((2, spooled(2))),
            fail_closed(2),
            Ok((3, spooled(3))),
        ]
    );
    let before = sink.stream().spool_room();
    assert_eq!(
        before,
        SpoolRoom {
            spooled_records: 3,
            bound: 4,
            reserve: 2,
            ordinary: 0,
            revocation: 1,
        }
    );
    assert_eq!(before.reserve_left(), 1);
    assert_eq!(
        sink.totals(),
        SinkTotals {
            records: 3,
            refused: 1,
            uncorrelated: 0,
        }
    );
    let released = sink.release();
    assert!(released.is_clean(), "{:?}", released.failures());
    assert_eq!(released.spooled_records(), Some(3));

    // The process starts again; the log still refuses.
    let (mut sink, opening) = open(&mut directory, &clock, REFUSING).unwrap();
    assert_eq!(opening.spool.held, range(1, 3));
    assert_eq!(sink.stream().spool_room(), before);
    assert_eq!(
        sink.stream().health(),
        AuditHealth::FailClosed {
            store: StoreRefusal::Failed,
            spooled_records: 3,
        }
    );
    assert_eq!(
        record_all(&mut sink, &[first_command(3), grant_revoked(), revoked(3)]),
        [fail_closed(3), Ok((4, spooled(4))), fail_closed(4)]
    );
    assert_eq!(sink.stream().spool_room().reserve_left(), 0);
    assert_eq!(
        sink.totals(),
        SinkTotals {
            records: 1,
            refused: 2,
            uncorrelated: 1,
        }
    );
    assert!(sink.release().is_clean());

    let (sink, opening) = open(&mut directory, &clock, TAKING).unwrap();
    assert_eq!(opening.spool.held, range(1, 4));
    assert_eq!(sink.stream().spool_room(), empty_room());
    let segments = stored(&sink);
    verify_segments(&genesis(), &segments).unwrap();
    assert_eq!(
        labels(&segments),
        labelled(&[
            (1, "launched"),
            (2, "first_command"),
            (3, "revocation"),
            (4, "grant_revocation"),
        ])
    );
    let records = records(&segments);
    assert!(matches!(
        records[2].event().payload(),
        AuditEntry::Revocation { revocation: recorded } if *recorded == revocation(2)
    ));
    assert!(matches!(
        records[3].event().payload(),
        AuditEntry::GrantRevocation { revocation } if *revocation == grant_revocation()
    ));
    assert!(sink.release().is_clean());
}

/// VM-W42 "restart ... tested" and the tracker's "release on drop cannot report a failed
/// release record": an explicit release reports that the seal and the owner record were
/// written, with nothing left in the spool and the sink's totals, and the next owner finds
/// a clean release and a sealed segment. Dropping the sink instead still releases the log,
/// as the fallback.
#[test]
fn an_explicit_release_is_reported_and_the_next_owner_finds_it_released() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let clock = clock();
    let (mut sink, _) = open(&mut directory, &clock, TAKING).unwrap();
    assert_eq!(
        record_all(&mut sink, &[launched(), first_command(1)]),
        [Ok((1, Durability::Durable)), Ok((2, Durability::Durable))]
    );
    let released = sink.release();
    assert!(released.is_clean());
    assert!(released.failures().is_empty());
    assert_eq!(released.spooled_records(), Some(0));
    assert_eq!(
        released
            .stream
            .close
            .as_ref()
            .map(|close| close.seal.head().last)
            .ok(),
        Some(EventSequence::new(2))
    );
    assert_eq!(released.stream.release, Ok(()));
    assert_eq!(released.totals.records, 2);
    assert!(!directory.is_live(&journal()));

    let (sink, opening) = open(&mut directory, &clock, TAKING).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert!(opening.durable.log.markers.is_empty());
    assert_eq!(
        opening.durable.resume.unwrap().report.finding,
        ResumeFinding::Sealed
    );
    assert_eq!(sink.stream().head().last, EventSequence::new(2));

    // Dropping instead of releasing still leaves a released owner record.
    drop(sink);
    let (_sink, opening) = open(&mut directory, &clock, TAKING).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert!(opening.durable.log.markers.is_empty());
}

/// The tracker's "release on drop cannot report a failed release record": when the owner
/// record cannot be written, the release reports it as a typed failure and is not clean,
/// although the seal was written and the lock given up; the next owner then finds the
/// stale owner the failure announced, and the chain continues after the last record.
#[test]
fn a_failed_release_is_reported_and_the_next_owner_finds_a_stale_owner() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let clock = clock();
    let (mut sink, _) = open(&mut directory, &clock, TAKING).unwrap();
    assert_eq!(
        record_all(&mut sink, &[launched(), first_command(1)]),
        [Ok((1, Durability::Durable)), Ok((2, Durability::Durable))]
    );
    // The owner record is written through a temporary file; a directory in its place makes
    // that write fail.
    let obstacle = directory.stream_path(&journal()).unwrap().join("owner.tmp");
    fs::create_dir(&obstacle).unwrap();
    let released = sink.release();
    assert!(!released.is_clean());
    let failures = released.failures();
    assert!(
        matches!(
            failures.as_slice(),
            [ReleaseFailure::OwnerRecord(DurableError::Log(
                LogError::Owner(OwnerError::Io {
                    action: "write",
                    ..
                })
            ))]
        ),
        "{failures:?}"
    );
    assert!(failures[0].to_string().starts_with(
        "the audit stream's owner record could not record its release: could not write"
    ));
    assert_eq!(
        released
            .stream
            .close
            .as_ref()
            .map(|close| close.seal.head().last)
            .ok(),
        Some(EventSequence::new(2))
    );
    assert!(!directory.is_live(&journal()));
    fs::remove_dir(&obstacle).unwrap();

    let (mut sink, opening) = open(&mut directory, &clock, TAKING).unwrap();
    assert!(opening.durable.log.takeover.is_stale());
    assert!(matches!(
        opening.durable.log.markers.as_slice(),
        [(_, LogMarker::StaleOwner { owner: stale, .. })] if *stale == owner()
    ));
    assert_eq!(
        opening.durable.resume.unwrap().report.finding,
        ResumeFinding::Sealed
    );
    assert_eq!(
        outcome(sink.record_receipt(&stopped())),
        Ok((3, Durability::Durable))
    );
    verify_segments(&genesis(), &stored(&sink)).unwrap();
    assert!(sink.release().is_clean());
}

/// Both parts of a release can fail; they are reported in the order the release went,
/// each with its own sober text, and a release whose seal failed has no flush report.
#[test]
fn release_failures_are_reported_in_order_and_describe_themselves() {
    let seal = StreamError::Segment(SegmentError::Storage(StoreRefusal::Full));
    let release = SinkRelease {
        stream: StreamRelease {
            close: Err(seal.clone()),
            release: Err(DurableError::StillShared),
        },
        totals: SinkTotals::default(),
    };
    assert!(!release.is_clean());
    assert_eq!(release.spooled_records(), None);
    let failures = release.failures();
    assert_eq!(
        failures,
        [
            ReleaseFailure::Seal(seal.clone()),
            ReleaseFailure::OwnerRecord(DurableError::StillShared),
        ]
    );
    assert_eq!(
        failures[0].to_string(),
        format!("the audit stream could not be sealed: {seal}")
    );
    assert_eq!(
        failures[1].to_string(),
        format!(
            "the audit stream's owner record could not record its release: {}",
            DurableError::StillShared
        )
    );
}
