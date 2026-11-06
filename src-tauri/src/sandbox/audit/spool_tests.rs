//! The spool on file and the explicit release (§8.2 at lines 2441–2450, line 2445 "a
//! bounded local spool; never block the revocation channel"; VM-W42 at line 2665 "bounded
//! queues" and "restart/truncation, disk full ... tested"; VM-W43 at line 2666 "audit
//! overload cannot block emergency revocation"; S06): the revocation reserve kept exactly
//! as an in-memory spool keeps it, spooled records across a restart, a torn tail and
//! damage in the spool, and a release whose failure is reported. Every file lives in a
//! temporary directory the test owns.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use super::durable::{DurableError, DurableSegments};
use super::fakes::{
    context, execution, journal_id, manual_clock, producer, stream_config, FakeAnchor,
    FakeSegmentStorage, FakeSpool,
};
use super::segment::{verify_segments, ResumeFinding, SegmentStorage, StoredSegment};
use super::spool::{FileSpool, SpoolError, SpoolOpening, SpoolProblem, SpooledOpening, SPOOL_FILE};
use super::stream::{
    AuditEvent, AuditStream, SpoolRoom, StreamAuthority, StreamDirectory, StreamError,
    StreamRefusal,
};
use crate::foundation::events::{
    AuditEntry, AuditHealth, AuditReceipt, AuditRefusal, AuditSpool, Durability, EventSequence,
    Field, GrantRevocation, HostFact, JournalHead, LogConfig, LogError, LogMarker, OwnerError,
    Phase, Revocation, RevocationReason, SequenceRange, StoreRefusal, Takeover,
};
use crate::foundation::ids::{digest, AuthorizationEpoch, GrantId, ManualClock};

type Stream<P> = AuditStream<FakeSegmentStorage, P, FakeAnchor, Arc<ManualClock>>;
type Spooled = AuditStream<DurableSegments, FileSpool, FakeAnchor, Arc<ManualClock>>;

/// What one step of a test returned: the receipt's sequence and durability, or the
/// refusal.
type Outcome = Result<(u64, Durability), StreamRefusal>;

fn genesis() -> JournalHead {
    JournalHead::genesis(journal_id("engine"), producer("engine.audit"))
}

fn fact(step: u64) -> AuditEvent {
    AuditEvent::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    }
}

/// A fact whose line is longer than the two KiB a small log takes.
fn large_fact() -> AuditEvent {
    const NAMES: [&str; 12] = [
        "f00", "f01", "f02", "f03", "f04", "f05", "f06", "f07", "f08", "f09", "f10", "f11",
    ];
    AuditEvent::HostFact {
        fact: HostFact::Lease,
        fields: NAMES
            .iter()
            .map(|name| Field::metadata(name, "x".repeat(250)))
            .collect(),
    }
}

fn revocation(epoch: u64) -> Revocation {
    Revocation {
        execution: execution("exe-2"),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    }
}

fn grant() -> GrantRevocation {
    GrantRevocation {
        execution: execution("exe-1"),
        grant: GrantId::from_digest(digest("yougori/test/grant/v1", &[b"route-a"])),
        epoch: AuthorizationEpoch::FIRST,
        reason: RevocationReason::SecurityEvent,
    }
}

fn outcome(result: Result<AuditReceipt, StreamRefusal>) -> Outcome {
    result.map(|receipt| (receipt.sequence.get(), receipt.durability))
}

fn spooled(records: usize) -> Durability {
    Durability::Spooled {
        spooled_records: records,
    }
}

fn fail_closed(store: StoreRefusal, spooled_records: usize) -> Outcome {
    Err(StreamRefusal::Audit(AuditRefusal::FailClosed {
        store,
        spool: None,
        spooled_records,
        kept: None,
    }))
}

fn range(first: u64, last: u64) -> Option<SequenceRange> {
    SequenceRange::new(EventSequence::new(first)?, EventSequence::new(last)?)
}

fn sequences(segments: &[StoredSegment]) -> Vec<u64> {
    segments
        .iter()
        .flat_map(|segment| segment.records.iter())
        .map(|record| record.sequence().get())
        .collect()
}

/// A stream on `storage` and `spool` with a spool of four records and a reserve of two.
fn open_on<P: AuditSpool>(storage: &FakeSegmentStorage, spool: P) -> (Stream<P>, StreamAuthority) {
    AuditStream::open(
        &mut StreamDirectory::new(),
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        spool,
        FakeAnchor::new(),
        manual_clock(),
        stream_config(4, 2, 10),
    )
    .unwrap()
}

/// Storage that holds one record, a spool of four with a reserve of two: four facts, a
/// grant revocation and two revocations.
fn overload<P: AuditSpool>(
    stream: &mut Stream<P>,
    authority: &mut StreamAuthority,
) -> Vec<Outcome> {
    let mut outcomes: Vec<Outcome> = (1..=4)
        .map(|step| outcome(stream.record(authority, context("op-1", Phase::Running), fact(step))))
        .collect();
    outcomes.push(outcome(stream.record_grant_revocation(
        authority,
        context("op-grant", Phase::Revoked),
        grant(),
    )));
    for epoch in [2, 3] {
        outcomes.push(outcome(stream.record_revocation(
            authority,
            context("op-2", Phase::Revoked),
            revocation(epoch),
        )));
    }
    outcomes
}

/// §8.2 line 2445 "never block the revocation channel"; VM-W43 "audit overload cannot
/// block emergency revocation": with storage full, the spool on file takes ordinary
/// records up to its ordinary room, then fails closed, while a grant revocation and a
/// revocation still take the reserve, step for step as the in-memory spool does. After a
/// restart the spooled records are all there, in order, the bound still holds, and storage
/// takes them in order when it recovers; the emptied spool leaves an empty file.
#[test]
fn a_file_spool_keeps_the_reserve_as_an_in_memory_spool_does_and_survives_a_restart() {
    let config = stream_config(4, 2, 10);
    let (mut memory, mut memory_authority) = open_on(&FakeSegmentStorage::new(1), FakeSpool::new());
    let in_memory = overload(&mut memory, &mut memory_authority);

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("spool");
    let storage = FakeSegmentStorage::new(1);
    let (spool, opening) = FileSpool::open(&path, &journal_id("engine"), &config.audit).unwrap();
    assert_eq!(opening.held, None);
    let (mut stream, mut authority) = open_on(&storage, spool);
    let on_file = overload(&mut stream, &mut authority);
    assert_eq!(on_file, in_memory);
    assert_eq!(
        on_file,
        [
            Ok((1, Durability::Durable)),
            Ok((2, spooled(1))),
            Ok((3, spooled(2))),
            fail_closed(StoreRefusal::Full, 2),
            Ok((4, spooled(3))),
            Ok((5, spooled(4))),
            fail_closed(StoreRefusal::Full, 4),
        ]
    );
    // The process stops; the spool's file is all that holds records 2 to 5.
    drop((stream, authority));

    let (spool, opening) = FileSpool::open(&path, &journal_id("engine"), &config.audit).unwrap();
    assert_eq!(opening.held, range(2, 5));
    let (mut stream, mut authority, resumed) = AuditStream::resume(
        &mut StreamDirectory::new(),
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        spool,
        FakeAnchor::new(),
        manual_clock(),
        config,
    )
    .unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    assert_eq!(stream.head().last, EventSequence::new(5));
    assert_eq!(stream.state().spooled_records, 4);
    assert_eq!(
        stream.health(),
        AuditHealth::FailClosed {
            store: StoreRefusal::Full,
            spooled_records: 4
        }
    );
    assert_eq!(
        outcome(stream.record_revocation(
            &mut authority,
            context("op-2", Phase::Revoked),
            revocation(3)
        )),
        fail_closed(StoreRefusal::Full, 4)
    );

    storage.set_capacity(100);
    let flushed = stream.flush();
    assert_eq!((flushed.written, flushed.remaining), (4, 0));
    let segments = storage.snapshot();
    assert_eq!(sequences(&segments), [1, 2, 3, 4, 5]);
    verify_segments(&genesis(), &segments).unwrap();
    assert!(matches!(
        segments[1].records[2].event().payload(),
        AuditEntry::GrantRevocation { revocation } if *revocation == grant()
    ));
    assert_eq!(
        outcome(stream.record(&mut authority, context("op-1", Phase::Running), fact(6))),
        Ok((6, Durability::Durable))
    );
    assert_eq!(fs::read(path.join(SPOOL_FILE)).unwrap(), b"");
}

/// Room for these tests' lines, each at most `segment_bytes`.
fn log(segment_bytes: u64) -> LogConfig {
    LogConfig {
        max_entries: 1_000,
        max_bytes: 1 << 24,
        segment_entries: 8,
        segment_bytes,
    }
}

fn open_spooled(
    directory: &mut StreamDirectory,
    segment_bytes: u64,
) -> Result<(Spooled, StreamAuthority, SpooledOpening), StreamError> {
    AuditStream::open_durable_spooled(
        directory,
        journal_id("engine"),
        producer("engine.audit"),
        FakeAnchor::new(),
        manual_clock(),
        stream_config(3, 1, 3),
        log(segment_bytes),
    )
}

fn stored(stream: &Spooled) -> Vec<StoredSegment> {
    stream.with_storage(|storage| storage.segments().unwrap())
}

fn spool_file(directory: &StreamDirectory) -> std::path::PathBuf {
    directory
        .spool_path(&journal_id("engine"))
        .unwrap()
        .join(SPOOL_FILE)
}

fn line_count(path: &Path) -> usize {
    fs::read(path)
        .unwrap()
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

/// A durable stream whose log takes lines of at most two KiB: two facts reach it, a large
/// one is refused and waits in the spool with the facts after it, and the rest fail closed
/// but for a revocation on the reserve.
fn spool_behind_a_large_record(
    stream: &mut Spooled,
    authority: &mut StreamAuthority,
) -> Vec<Outcome> {
    let mut outcomes: Vec<Outcome> = Vec::new();
    for event in [fact(1), fact(2), large_fact(), fact(4), fact(5)] {
        outcomes.push(outcome(stream.record(
            authority,
            context("op-1", Phase::Running),
            event,
        )));
    }
    outcomes.push(outcome(stream.record_revocation(
        authority,
        context("op-2", Phase::Revoked),
        revocation(2),
    )));
    outcomes.push(outcome(stream.record_grant_revocation(
        authority,
        context("op-grant", Phase::Revoked),
        grant(),
    )));
    outcomes
}

/// VM-W42 "restart ... disk full ... tested"; S06 "a file-backed `AuditSpool`": a durable
/// stream keeps the records its log refused in the spool on file in its own directory.
/// They survive two restarts, the first of which finds a torn last line in the spool,
/// quarantines it and reports it, and they reach the log in order, before any new record,
/// once the log takes them.
#[test]
fn a_durable_stream_keeps_its_spool_across_restarts_and_reports_a_torn_tail() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    assert_eq!(
        directory.spool_path(&journal_id("engine")),
        Some(root.path().join("audit-engine").join("spool"))
    );
    assert_eq!(
        StreamDirectory::new().spool_path(&journal_id("engine")),
        None
    );
    let (mut stream, mut authority, opening) = open_spooled(&mut directory, 2_048).unwrap();
    assert!(opening.durable.log.created && opening.durable.resume.is_none());
    assert_eq!(
        opening.spool,
        SpoolOpening {
            held: None,
            torn_tail: None,
            interrupted_rewrite: false
        }
    );
    assert_eq!(
        spool_behind_a_large_record(&mut stream, &mut authority),
        [
            Ok((1, Durability::Durable)),
            Ok((2, Durability::Durable)),
            Ok((3, spooled(1))),
            Ok((4, spooled(2))),
            fail_closed(StoreRefusal::Failed, 2),
            Ok((5, spooled(3))),
            fail_closed(StoreRefusal::Failed, 3),
        ]
    );
    assert!(matches!(
        stream.with_storage(|storage| storage.last_error().cloned()),
        Some(LogError::TooLarge { limit: 2_048, .. })
    ));
    let released = stream.release();
    let closed = released.close.unwrap();
    assert_eq!(
        (
            closed.flush.written,
            closed.flush.remaining,
            closed.flush.refusal
        ),
        (0, 3, Some(StoreRefusal::Failed))
    );
    assert_eq!(closed.seal.head().last, EventSequence::new(2));
    assert_eq!(released.release, Ok(()));
    drop(authority);

    // A write to the spool stopped half way.
    let path = spool_file(&directory);
    assert_eq!(line_count(&path), 3);
    let whole = fs::read(&path).unwrap();
    let torn = b"0123456789abcdef {\"line\":\"spooled\",\"rec";
    let mut bytes = whole.clone();
    bytes.extend_from_slice(torn);
    fs::write(&path, bytes).unwrap();

    // The log still refuses the large record: everything stays spooled.
    let (stream, authority, opening) = open_spooled(&mut directory, 2_048).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert_eq!(opening.spool.held, range(3, 5));
    let tail = opening.spool.torn_tail.unwrap();
    assert_eq!(tail.bytes, torn.len() as u64);
    assert_eq!(
        fs::read(path.parent().unwrap().join(&tail.quarantine)).unwrap(),
        torn
    );
    assert_eq!(fs::read(&path).unwrap(), whole);
    assert_eq!(stream.head().last, EventSequence::new(5));
    assert_eq!(stream.state().spooled_records, 3);
    assert_eq!(stream.release().release, Ok(()));
    drop(authority);

    // A log that takes the large record: the spool drains into it first, in order.
    let (mut stream, mut authority, opening) = open_spooled(&mut directory, 1 << 16).unwrap();
    assert_eq!(opening.spool.held, range(3, 5));
    assert_eq!(opening.spool.torn_tail, None);
    assert_eq!(
        opening.durable.resume.unwrap().report.finding,
        ResumeFinding::Sealed
    );
    assert_eq!(stream.state().spooled_records, 0);
    assert_eq!(stream.health(), AuditHealth::Durable);
    assert_eq!(
        outcome(stream.record(&mut authority, context("op-1", Phase::Running), fact(6))),
        Ok((6, Durability::Durable))
    );
    let segments = stored(&stream);
    assert_eq!(sequences(&segments), [1, 2, 3, 4, 5, 6]);
    verify_segments(&genesis(), &segments).unwrap();
    let large = segments
        .iter()
        .flat_map(|segment| segment.records.iter())
        .find(|record| record.sequence().get() == 3)
        .unwrap();
    assert!(matches!(
        large.event().payload(),
        AuditEntry::HostFact { fields, .. } if fields.fields().len() == 12
    ));
    assert_eq!(fs::read(&path).unwrap(), b"");
}

/// A spool damaged anywhere but its last line refuses the stream, every time, until the
/// file is put right; each refused open releases the log again, so nothing is held.
#[test]
fn a_damaged_spool_refuses_the_stream() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let (mut stream, mut authority, _) = open_spooled(&mut directory, 2_048).unwrap();
    let _ = spool_behind_a_large_record(&mut stream, &mut authority);
    assert_eq!(stream.release().release, Ok(()));
    drop(authority);
    let path = spool_file(&directory);
    let whole = fs::read(&path).unwrap();
    let mut bytes = whole.clone();
    bytes[70] ^= 0x01;
    fs::write(&path, &bytes).unwrap();

    for _ in 0..2 {
        let refused = open_spooled(&mut directory, 2_048).err().unwrap();
        assert_eq!(
            refused,
            StreamError::Spool(SpoolError::Damaged {
                line: 1,
                problem: SpoolProblem::Checksum
            })
        );
        assert!(refused
            .to_string()
            .starts_with("line 1 of the audit spool is damaged"));
        assert!(!directory.is_live(&journal_id("engine")));
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);

    fs::write(&path, &whole).unwrap();
    let (stream, _authority, opening) = open_spooled(&mut directory, 2_048).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert_eq!(opening.spool.held, range(3, 5));
    assert_eq!(stream.head().last, EventSequence::new(5));
}

/// §8.2 line 2445 and VM-W43: the reserve is exact across a restart. The room the spool
/// on file leaves ordinary records and revocations is the same after the stream opens again
/// under the same configuration, and a revocation takes exactly the slot of the reserve left
/// before the restart. A spool written under a larger bound does not open under a smaller
/// one, where its records would take the reserve; nothing is changed, and it opens again
/// under a bound of at least what it holds.
#[test]
fn the_spool_room_is_the_same_after_a_restart_and_a_spool_over_its_bound_does_not_open() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let open = |directory: &mut StreamDirectory, spool_records: usize| {
        AuditStream::open_durable_spooled(
            directory,
            journal_id("engine"),
            producer("engine.audit"),
            FakeAnchor::new(),
            manual_clock(),
            stream_config(spool_records, 1, 3),
            log(2_048),
        )
    };
    let (mut stream, mut authority, _) = open(&mut directory, 3).unwrap();
    assert_eq!(
        stream.spool_room(),
        SpoolRoom {
            spooled_records: 0,
            bound: 3,
            reserve: 1,
            ordinary: 2,
            revocation: 3
        }
    );
    let outcomes: Vec<Outcome> = [fact(1), fact(2), large_fact(), fact(4), fact(5)]
        .into_iter()
        .map(|event| outcome(stream.record(&mut authority, context("op-1", Phase::Running), event)))
        .collect();
    assert_eq!(
        outcomes,
        [
            Ok((1, Durability::Durable)),
            Ok((2, Durability::Durable)),
            Ok((3, spooled(1))),
            Ok((4, spooled(2))),
            fail_closed(StoreRefusal::Failed, 2),
        ]
    );
    let before = stream.spool_room();
    assert_eq!(
        before,
        SpoolRoom {
            spooled_records: 2,
            bound: 3,
            reserve: 1,
            ordinary: 0,
            revocation: 1
        }
    );
    assert_eq!(before.reserve_left(), 1);
    assert_eq!(stream.release().release, Ok(()));
    drop(authority);

    let (mut stream, mut authority, opening) = open(&mut directory, 3).unwrap();
    assert_eq!(opening.spool.held, range(3, 4));
    assert_eq!(stream.spool_room(), before);
    assert_eq!(
        outcome(stream.record(&mut authority, context("op-1", Phase::Running), fact(6))),
        fail_closed(StoreRefusal::Failed, 2)
    );
    assert_eq!(
        outcome(stream.record_revocation(
            &mut authority,
            context("op-2", Phase::Revoked),
            revocation(2)
        )),
        Ok((5, spooled(3)))
    );
    assert_eq!(
        outcome(stream.record_grant_revocation(
            &mut authority,
            context("op-grant", Phase::Revoked),
            grant()
        )),
        fail_closed(StoreRefusal::Failed, 3)
    );
    assert_eq!(stream.spool_room().reserve_left(), 0);
    assert_eq!(stream.release().release, Ok(()));
    drop(authority);

    let spool = fs::read(spool_file(&directory)).unwrap();
    for _ in 0..2 {
        let refused = open(&mut directory, 2).err().unwrap();
        assert_eq!(
            refused,
            StreamError::Spool(SpoolError::OverBound { held: 3, bound: 2 })
        );
        assert_eq!(
            refused.to_string(),
            "the audit spool holds 3 records, more than its bound of 2; it opens under a bound \
             of at least 3"
        );
        assert!(!directory.is_live(&journal_id("engine")));
    }
    assert_eq!(fs::read(spool_file(&directory)).unwrap(), spool);

    let (stream, _authority, opening) = open(&mut directory, 4).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert_eq!(opening.spool.held, range(3, 5));
    assert_eq!(
        stream.spool_room(),
        SpoolRoom {
            spooled_records: 3,
            bound: 4,
            reserve: 1,
            ordinary: 0,
            revocation: 1
        }
    );
}

/// The tracker's open item "release on drop cannot report a failed release record": an
/// explicit release reports that the owner record could not be written, and the next
/// owner then finds the stale owner it announced; a release that worked is found as one,
/// and dropping the stream still releases it as the fallback.
#[test]
fn an_explicit_release_reports_a_release_record_it_could_not_write() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let (mut stream, mut authority, _) = open_spooled(&mut directory, 1 << 16).unwrap();
    for step in 1..=2 {
        assert_eq!(
            outcome(stream.record(&mut authority, context("op-1", Phase::Running), fact(step))),
            Ok((step, Durability::Durable))
        );
    }
    // The owner record is written through a temporary file; a directory in its place makes
    // that write fail.
    let obstacle = directory
        .stream_path(&journal_id("engine"))
        .unwrap()
        .join("owner.tmp");
    fs::create_dir(&obstacle).unwrap();
    let released = stream.release();
    assert_eq!(
        released.close.unwrap().seal.head().last,
        EventSequence::new(2)
    );
    let failure = released.release.unwrap_err();
    assert!(
        matches!(
            &failure,
            DurableError::Log(LogError::Owner(OwnerError::Io {
                action: "write",
                ..
            }))
        ),
        "{failure:?}"
    );
    assert!(failure.to_string().starts_with("could not write"));
    drop(authority);
    fs::remove_dir(&obstacle).unwrap();

    let (stream, authority, opening) = open_spooled(&mut directory, 1 << 16).unwrap();
    assert!(opening.durable.log.takeover.is_stale());
    assert!(matches!(
        opening.durable.log.markers.as_slice(),
        [(_, LogMarker::StaleOwner { owner, .. })] if *owner == producer("engine.audit")
    ));
    assert_eq!(
        opening.durable.resume.unwrap().report.finding,
        ResumeFinding::Sealed
    );
    assert_eq!(stream.head().last, EventSequence::new(2));
    assert_eq!(stream.release().release, Ok(()));
    drop(authority);

    let (stream, authority, opening) = open_spooled(&mut directory, 1 << 16).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert!(opening.durable.log.markers.is_empty());
    // Dropping instead of releasing still leaves a released owner record.
    drop((stream, authority));
    let (_stream, _authority, opening) = open_spooled(&mut directory, 1 << 16).unwrap();
    assert!(matches!(
        opening.durable.log.takeover,
        Takeover::Released { .. }
    ));
    assert_eq!(
        DurableError::StillShared.store_refusal(),
        StoreRefusal::Failed
    );
}
