//! The file-backed audit spool (S06; VM part §8.2; VM-W42; VM-CP-22): bounded, crash-safe,
//! one owner, its records replayed into durable storage in order after a restart, and a
//! full or damaged spool reported, never dropped silently.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use super::fakes::{context, execution, journal_id, manual_clock, producer, FakeAuditStore};
use super::*;
use crate::foundation::ids::AuthorizationEpoch;

fn spool_config(max_records: usize, max_bytes: u64) -> SpoolConfig {
    SpoolConfig {
        max_records,
        max_bytes,
    }
}

fn audit_config(spool_records: usize, revocation_reserve_records: usize) -> AuditConfig {
    AuditConfig {
        spool_records,
        revocation_reserve_records,
        failure_policy: AuditFailurePolicy::SpoolHighImpact,
        guest_observations: EmissionLimit::new(10, Duration::from_secs(1)).unwrap(),
        redaction: RedactionPolicy::metadata_only(),
    }
}

fn open_spool(
    directory: &Path,
    config: SpoolConfig,
) -> Result<(FileAuditSpool, SpoolOpened), SpoolError> {
    FileAuditSpool::open(directory, producer("engine.audit.spool"), config)
}

fn genesis() -> JournalHead {
    JournalHead::genesis(journal_id("engine"), producer("engine.audit"))
}

fn lease(step: u64) -> AuditDraft {
    AuditDraft::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    }
}

/// `count` chained records of the journal `engine`, as storage that takes every one holds
/// them.
fn chain(count: u64) -> Vec<AuditRecord> {
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(usize::MAX),
        FakeAuditSpoolless,
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=count {
        let receipt = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
        assert_eq!(receipt.durability, Durability::Durable);
    }
    journal.store().records().to_vec()
}

/// A spool that is never used: storage takes every record.
struct FakeAuditSpoolless;

impl AuditSpool for FakeAuditSpoolless {
    fn push(&mut self, _: &AuditRecord) -> Result<(), StoreRefusal> {
        Err(StoreRefusal::Failed)
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(None)
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        Ok(())
    }

    fn len(&self) -> usize {
        0
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(Vec::new())
    }
}

/// The spool's record files, by name, in order.
fn record_files(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("spooled-"))
        .collect();
    names.sort();
    names
}

fn file_of(directory: &Path, sequence: u64) -> PathBuf {
    directory.join(format!("spooled-{sequence:020}.json"))
}

#[test]
fn records_survive_a_restart_in_order_and_leave_durably() {
    let directory = tempfile::tempdir().unwrap();
    let records = chain(4);
    let (mut spool, opened) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    assert_eq!(opened.takeover, Takeover::Fresh);
    assert_eq!(opened.records, 0);
    for record in &records[..3] {
        spool.push(record).unwrap();
    }
    assert_eq!(spool.len(), 3);
    assert_eq!(record_files(directory.path()).len(), 3);
    // One owner: a second spool on the directory is refused at once.
    assert!(matches!(
        open_spool(directory.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Owner(OwnerError::HeldInProcess { .. }))
    ));
    spool.crash();

    // After a crash every acknowledged record is back, oldest first.
    let (mut spool, opened) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    assert!(opened.takeover.is_stale());
    assert_eq!(opened.records, 3);
    assert_eq!(spool.records().unwrap(), records[..3].to_vec());
    assert_eq!(spool.front().unwrap(), Some(records[0].clone()));
    spool.pop_front().unwrap();
    assert_eq!(record_files(directory.path()).len(), 2);
    spool.push(&records[3]).unwrap();
    spool.close().unwrap();

    let (spool, opened) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    assert!(matches!(opened.takeover, Takeover::Released { .. }));
    assert_eq!(spool.records().unwrap(), records[1..].to_vec());
    assert_eq!(spool.totals(), SpoolTotals::default());
}

#[test]
fn a_full_spool_refuses_and_drops_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let records = chain(4);
    let (mut spool, _) = open_spool(directory.path(), spool_config(2, 1 << 20)).unwrap();
    spool.push(&records[0]).unwrap();
    spool.push(&records[1]).unwrap();
    assert_eq!(spool.push(&records[2]), Err(StoreRefusal::Full));
    assert_eq!(spool.totals().refused_full, 1);
    assert_eq!(spool.records().unwrap(), records[..2].to_vec());
    assert_eq!(record_files(directory.path()).len(), 2);
    drop(spool);

    // Bytes bound too: one record fits, the next does not.
    let bytes = tempfile::tempdir().unwrap();
    let one = serde_json::to_vec(&records[0]).unwrap().len();
    let (mut spool, _) = open_spool(
        bytes.path(),
        spool_config(8, u64::try_from(one + one / 2).unwrap()),
    )
    .unwrap();
    spool.push(&records[0]).unwrap();
    assert_eq!(spool.push(&records[1]), Err(StoreRefusal::Full));
    assert_eq!(spool.bytes(), u64::try_from(one).unwrap());

    // Reopened with smaller bounds, what it holds stays and the excess is reported.
    drop(spool);
    let (spool, opened) = open_spool(directory.path(), spool_config(1, 1 << 20)).unwrap();
    assert!(opened.over_bounds);
    assert_eq!(spool.len(), 2);
}

#[test]
fn a_record_that_does_not_continue_the_last_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let records = chain(3);
    let other = {
        let (mut journal, mut authority) = AuditJournal::open(
            journal_id("warden"),
            producer("warden.audit"),
            FakeAuditStore::new(usize::MAX),
            FakeAuditSpoolless,
            manual_clock(),
            audit_config(4, 1),
        )
        .unwrap();
        let receipt = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(1))
            .unwrap();
        assert_eq!(receipt.sequence.get(), 1);
        journal.store().records()[0].clone()
    };
    let (mut spool, _) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    spool.push(&records[0]).unwrap();
    // Skipped, repeated and foreign records would break the chain and the files' order.
    assert_eq!(spool.push(&records[2]), Err(StoreRefusal::Failed));
    assert_eq!(spool.push(&records[0]), Err(StoreRefusal::Failed));
    assert_eq!(spool.push(&other), Err(StoreRefusal::Failed));
    assert_eq!(spool.totals().refused_out_of_order, 3);
    spool.push(&records[1]).unwrap();
    assert_eq!(spool.len(), 2);
}

#[test]
fn an_interrupted_push_leaves_nothing_and_is_removed_on_open() {
    let directory = tempfile::tempdir().unwrap();
    let records = chain(2);
    let (mut spool, _) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    spool.push(&records[0]).unwrap();
    spool.crash();
    // A crash in the middle of writing the next record leaves only its temporary file.
    let encoded = serde_json::to_vec(&records[1]).unwrap();
    fs::write(
        directory.path().join(format!("spooled-{:020}.tmp", 2)),
        &encoded[..encoded.len() / 2],
    )
    .unwrap();
    let (spool, opened) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
    assert_eq!(opened.interrupted, 1);
    assert_eq!(spool.records().unwrap(), records[..1].to_vec());
    assert_eq!(
        record_files(directory.path()),
        [format!("spooled-{:020}.json", 1)]
    );
}

#[test]
fn a_damaged_spool_is_reported_and_kept_as_it_was() {
    let records = chain(3);
    let filled = || {
        let directory = tempfile::tempdir().unwrap();
        let (mut spool, _) = open_spool(directory.path(), spool_config(8, 1 << 20)).unwrap();
        for record in &records {
            spool.push(record).unwrap();
        }
        spool.close().unwrap();
        directory
    };

    // A record that does not read.
    let garbled = filled();
    fs::write(file_of(garbled.path(), 2), b"{\"journal\":").unwrap();
    assert!(matches!(
        open_spool(garbled.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Damaged(SpoolDamage::Unreadable { file, .. }))
            if file == format!("spooled-{:020}.json", 2)
    ));
    // The files stay for someone to look at, and the refusal left no owner behind.
    assert_eq!(record_files(garbled.path()).len(), 3);
    assert!(matches!(
        open_spool(garbled.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Damaged(_))
    ));

    // A record under another sequence's name.
    let misnamed = filled();
    fs::remove_file(file_of(misnamed.path(), 3)).unwrap();
    fs::rename(file_of(misnamed.path(), 2), file_of(misnamed.path(), 3)).unwrap();
    assert!(matches!(
        open_spool(misnamed.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Damaged(SpoolDamage::Misnamed { record, .. })) if record.get() == 2
    ));

    // A record missing from the middle.
    let missing = filled();
    fs::remove_file(file_of(missing.path(), 2)).unwrap();
    assert!(matches!(
        open_spool(missing.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Damaged(SpoolDamage::Chain(
            ChainError::OutOfOrder { .. }
        )))
    ));

    // A record rewritten so that it still reads.
    let rewritten = filled();
    let path = file_of(rewritten.path(), 3);
    let text = fs::read_to_string(&path).unwrap();
    let edited = text.replacen("\"operation\":\"op-1\"", "\"operation\":\"op-9\"", 1);
    assert_ne!(edited, text);
    fs::write(&path, edited).unwrap();
    assert!(matches!(
        open_spool(rewritten.path(), spool_config(8, 1 << 20)),
        Err(SpoolError::Damaged(SpoolDamage::Chain(
            ChainError::DigestMismatch { .. }
        )))
    ));
}

/// Durable storage that is unavailable while its switch says so, as a full or detached
/// audit volume is: it refuses as slow and stores nothing.
struct Switched {
    log: DurableLog<AuditRecord>,
    unavailable: Rc<Cell<bool>>,
}

impl AuditStore for Switched {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.unavailable.get() {
            return Err(StoreRefusal::Slow);
        }
        AuditStore::append(&mut self.log, record)
    }
}

fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 1_000,
        max_bytes: 1 << 24,
        segment_entries: 3,
        segment_bytes: 1 << 20,
    }
}

fn open_log(directory: &Path) -> DurableLog<AuditRecord> {
    DurableLog::open(
        directory,
        DurableStreamId::new("engine.audit").unwrap(),
        producer("engine.audit"),
        log_config(),
    )
    .unwrap()
    .0
}

fn stored(log: &DurableLog<AuditRecord>) -> Vec<AuditRecord> {
    log.read(&log.start(), usize::MAX)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(record),
                ..
            } => Some(record),
            _ => None,
        })
        .collect()
}

#[test]
fn spooled_records_replay_into_the_durable_store_in_order_after_a_crash() {
    let root = tempfile::tempdir().unwrap();
    let store_directory = root.path().join("store");
    let spool_directory = root.path().join("spool");
    let unavailable = Rc::new(Cell::new(false));
    let store = Switched {
        log: open_log(&store_directory),
        unavailable: Rc::clone(&unavailable),
    };
    let (spool, _) = open_spool(&spool_directory, spool_config(4, 1 << 20)).unwrap();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        store,
        spool,
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=2 {
        let receipt = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
        assert_eq!(receipt.durability, Durability::Durable);
    }
    // The audit volume goes away: records wait in the file spool, in order.
    unavailable.set(true);
    for step in 3..=5 {
        let receipt = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
        assert!(matches!(receipt.durability, Durability::Spooled { .. }));
    }
    // The ordinary room is full; a revocation still has the reserve.
    let refused = journal
        .append(&mut authority, context("op-1", Phase::Running), lease(6))
        .unwrap_err();
    assert!(matches!(
        refused,
        AuditRefusal::FailClosed {
            spool: None,
            spooled_records: 3,
            ..
        }
    ));
    let revoked = journal
        .append(
            &mut authority,
            context("op-revoke", Phase::Revoked),
            AuditDraft::Revocation(Revocation {
                execution: execution("exe-1"),
                epoch: AuthorizationEpoch::new(2),
                reason: RevocationReason::SecurityEvent,
            }),
        )
        .unwrap();
    assert!(matches!(
        revoked.durability,
        Durability::Spooled { spooled_records: 4 }
    ));
    let head = journal.head();
    assert_eq!(head.last.map(EventSequence::get), Some(6));
    // The process stops; the spool's files are what is left of those records.
    drop(journal);
    assert_eq!(record_files(&spool_directory).len(), 4);

    // After the restart the volume is back. The journal resumes from the stored chain and
    // the spool; resuming replays the spool into the store, in order, and empties it.
    let log = open_log(&store_directory);
    let stored_head = verify_chain(&genesis(), &stored(&log)).unwrap();
    assert_eq!(stored_head.last.map(EventSequence::get), Some(2));
    let (spool, opened) = open_spool(&spool_directory, spool_config(4, 1 << 20)).unwrap();
    assert_eq!(opened.records, 4);
    let store = Switched {
        log,
        unavailable: Rc::new(Cell::new(false)),
    };
    let (mut journal, mut authority) = AuditJournal::resume(
        stored_head,
        store,
        spool,
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    assert_eq!(journal.head(), head);
    assert_eq!(journal.spooled(), 0);
    assert_eq!(journal.health(), AuditHealth::Durable);
    assert!(record_files(&spool_directory).is_empty());
    let receipt = journal
        .append(&mut authority, context("op-2", Phase::Running), lease(7))
        .unwrap();
    assert_eq!(receipt.sequence.get(), 7);
    let records = stored(&journal.store().log);
    assert_eq!(
        records
            .iter()
            .map(|record| record.sequence().get())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(verify_chain(&genesis(), &records).unwrap(), journal.head());
}

#[test]
fn a_full_file_spool_fails_the_journal_closed_visibly() {
    let root = tempfile::tempdir().unwrap();
    let unavailable = Rc::new(Cell::new(true));
    let store = Switched {
        log: open_log(&root.path().join("store")),
        unavailable: Rc::clone(&unavailable),
    };
    // The spool's own bound is tighter than the journal's.
    let (spool, _) = open_spool(&root.path().join("spool"), spool_config(1, 1 << 20)).unwrap();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        store,
        spool,
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    let receipt = journal
        .append(&mut authority, context("op-1", Phase::Running), lease(1))
        .unwrap();
    assert!(matches!(
        receipt.durability,
        Durability::Spooled { spooled_records: 1 }
    ));
    let refused = journal
        .append(&mut authority, context("op-1", Phase::Running), lease(2))
        .unwrap_err();
    assert!(matches!(
        refused,
        AuditRefusal::FailClosed {
            spool: Some(StoreRefusal::Full),
            spooled_records: 1,
            kept: None,
            ..
        }
    ));
    assert_eq!(journal.totals().spool_refusals, 1);
    // Nothing was dropped to make room. Once storage is back, everything accepted is
    // stored in order.
    unavailable.set(false);
    let report = journal.flush();
    assert_eq!(report.written, 1);
    assert_eq!(report.remaining, 0);
    let records = stored(&journal.store().log);
    assert_eq!(verify_chain(&genesis(), &records).unwrap(), journal.head());
}
