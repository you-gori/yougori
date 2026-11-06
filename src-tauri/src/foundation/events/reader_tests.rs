//! Readers of a durable stream that do not own it (S06 "readers in other processes";
//! VM-CP-22): the owner and the reader on separate handles in one process, in threads, and
//! the reader in another process that re-runs this test executable. The reader reads up to
//! the synced mark, with explicit gaps, never appends, tolerates appends and retention
//! while it reads, and refuses torn or unverifiable data.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::durable::list;
use super::fakes::{context, journal_id, manual_clock, producer, FakeAuditSpool};
use super::*;

type Log = DurableLog<u64>;
type Reader = DurableReader<u64>;

/// Set in the environment of the child process: the stream's directory and the last
/// sequence to wait for.
const CHILD_DIRECTORY: &str = "YOUGORI_TEST_DURABLE_READER_DIRECTORY";
const CHILD_TARGET: &str = "YOUGORI_TEST_DURABLE_READER_TARGET";
const CHILD_PREFIX: &str = "durable-reader-child:";

fn stream_id() -> DurableStreamId {
    DurableStreamId::new("engine.events").unwrap()
}

fn config(segment_entries: u64, max_entries: u64) -> LogConfig {
    LogConfig {
        max_entries,
        max_bytes: 1 << 24,
        segment_entries,
        segment_bytes: 1 << 16,
    }
}

fn open_owner(directory: &Path, config: LogConfig) -> (Log, OpenReport) {
    DurableLog::open(directory, stream_id(), producer("engine"), config).unwrap()
}

fn open_reader(directory: &Path) -> Reader {
    DurableReader::open(directory, stream_id()).unwrap()
}

fn sequence(value: u64) -> EventSequence {
    EventSequence::new(value).unwrap()
}

fn range(first: u64, last: u64) -> SequenceRange {
    SequenceRange::new(sequence(first), sequence(last)).unwrap()
}

/// Appends the records `values`, each its own value.
fn append(log: &mut Log, values: std::ops::RangeInclusive<u64>) {
    for value in values {
        log.append(value).unwrap();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Record(u64, u64),
    Marker(u64, &'static str),
    Gap(SequenceRange, GapReason),
}

fn seen(items: Vec<ReadItem<u64>>) -> Vec<Seen> {
    items
        .into_iter()
        .map(|item| match item {
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(value),
                ..
            } => Seen::Record(sequence.get(), value),
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Marker(marker),
                ..
            } => Seen::Marker(
                sequence.get(),
                match marker {
                    LogMarker::StaleOwner { .. } => "stale_owner",
                    LogMarker::TornTail { .. } => "torn_tail",
                    LogMarker::Truncated { .. } => "truncated",
                    LogMarker::OwnerRecordLost { .. } => "owner_record_lost",
                },
            ),
            ReadItem::Gap { missing, reason } => Seen::Gap(missing, reason),
        })
        .collect()
}

fn records(values: std::ops::RangeInclusive<u64>) -> Vec<Seen> {
    values.map(|value| Seen::Record(value, value)).collect()
}

/// Everything after `cursor`, as one batch.
fn read_all(reader: &mut Reader, cursor: &LogCursor) -> (Vec<Seen>, ReadBatch<u64>) {
    let batch = reader.read(cursor, usize::MAX).unwrap();
    (seen(batch.items.clone()), batch)
}

fn read_from_start(reader: &mut Reader) -> (Vec<Seen>, ReadBatch<u64>) {
    let start = reader.start();
    read_all(reader, &start)
}

/// Every file of the directory and its bytes; the owner's lock file, which holds none and
/// which Windows bars from reading while it is locked, by its length.
fn snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let bytes = if name == "owner.lock" {
                entry.metadata().unwrap().len().to_le_bytes().to_vec()
            } else {
                fs::read(entry.path()).unwrap()
            };
            (name, bytes)
        })
        .collect()
}

fn segment_files(directory: &Path) -> Vec<PathBuf> {
    list(directory)
        .unwrap()
        .segments
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

fn last_segment(directory: &Path) -> PathBuf {
    segment_files(directory).pop().unwrap()
}

/// Flips one bit in the middle of line `line` (from 1) of the file at `path`.
fn flip_line(path: &Path, line: usize) {
    let mut bytes = fs::read(path).unwrap();
    let ends: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .map(|(position, _)| position)
        .collect();
    let start = if line == 1 { 0 } else { ends[line - 2] + 1 };
    bytes[(start + ends[line - 1]) / 2] ^= 0x01;
    fs::write(path, &bytes).unwrap();
}

#[test]
fn a_reader_follows_the_owner_up_to_the_mark_and_writes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(4, 1_000));
    append(&mut log, 1..=5);
    let before = snapshot(directory.path());
    let mut reader = open_reader(directory.path());
    assert_eq!(reader.stream(), log.stream());
    assert_eq!(reader.high_water(), log.last());
    let (items, batch) = read_from_start(&mut reader);
    assert_eq!(items, records(1..=5));
    assert!(batch.caught_up);
    assert_eq!(batch.cursor, log.end());
    assert_eq!(reader.unsettled(), None);
    // Reading never changed a byte of the stream, nor added or removed a file.
    assert_eq!(snapshot(directory.path()), before);

    // The owner keeps appending; the reader resumes from its cursor, a batch at a time.
    append(&mut log, 6..=9);
    let batch = reader.read(&batch.cursor, 3).unwrap();
    assert!(!batch.caught_up);
    assert_eq!(seen(batch.items), records(6..=8));
    let (items, batch) = read_all(&mut reader, &batch.cursor);
    assert_eq!(items, records(9..=9));
    assert!(batch.caught_up);
    // Reading again from the end returns nothing and stays caught up.
    let (items, again) = read_all(&mut reader, &batch.cursor);
    assert!(items.is_empty());
    assert!(again.caught_up);
    // The owner's own read and the reader's agree.
    assert_eq!(
        seen(log.read(&log.start(), usize::MAX).unwrap().items),
        read_from_start(&mut reader).0
    );
    assert!(reader.totals().lines_verified >= 9);
    log.close().unwrap();
}

#[test]
fn a_line_past_the_mark_is_never_read() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(10, 1_000));
    append(&mut log, 1..=3);
    let mark = fs::read(directory.path().join("high-water.bin")).unwrap();
    // A whole line written, its mark not yet synced: as a crash between the two leaves it.
    append(&mut log, 4..=4);
    log.crash();
    fs::write(directory.path().join("high-water.bin"), &mark).unwrap();
    // And half of the next line, as a crash in the middle of writing it leaves it.
    let mut file = OpenOptions::new()
        .append(true)
        .open(last_segment(directory.path()))
        .unwrap();
    file.write_all(b"0123456789abcdef").unwrap();
    drop(file);

    let mut reader = open_reader(directory.path());
    assert_eq!(reader.high_water(), Some(sequence(3)));
    let (items, batch) = read_from_start(&mut reader);
    assert_eq!(items, records(1..=3));
    assert!(batch.caught_up);

    // The next owner keeps the whole line, quarantines the half one and burns its
    // sequence; the reader then reads all of it in order.
    let (log, _) = open_owner(directory.path(), config(10, 1_000));
    let (items, batch) = read_all(&mut reader, &batch.cursor);
    assert_eq!(
        items,
        [
            Seen::Record(4, 4),
            Seen::Gap(range(5, 5), GapReason::Truncated),
            Seen::Marker(6, "truncated"),
            Seen::Marker(7, "stale_owner"),
            Seen::Marker(8, "torn_tail"),
        ]
    );
    assert!(batch.caught_up);
    assert_eq!(reader.high_water(), log.last());
}

#[test]
fn a_torn_or_rewritten_line_up_to_the_mark_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(10, 1_000));
    append(&mut log, 1..=4);
    let mut reader = open_reader(directory.path());
    let (_, batch) = read_from_start(&mut reader);
    log.crash();

    // An acknowledged line rewritten in the middle of the stream: damage.
    let segment = last_segment(directory.path());
    let pristine = fs::read(&segment).unwrap();
    flip_line(&segment, 2);
    let refused = reader.read(&reader.start(), usize::MAX).unwrap_err();
    assert!(matches!(
        refused,
        LogError::Damaged(LogDamage::Line {
            line: 2,
            problem: LineProblem::Checksum,
            ..
        })
    ));
    assert!(matches!(
        DurableReader::<u64>::open(directory.path(), stream_id()),
        Err(LogError::Damaged(LogDamage::Line { line: 2, .. }))
    ));

    // The last acknowledged line torn: refused as well, never read past or skipped.
    fs::write(&segment, &pristine).unwrap();
    flip_line(&segment, 4);
    assert!(matches!(
        reader.read(&batch.cursor, usize::MAX),
        Err(LogError::Damaged(LogDamage::Line {
            line: 4,
            problem: LineProblem::Checksum,
            ..
        }))
    ));
    assert!(reader.totals().retries > 0);

    // Once the owner has quarantined it and recorded the loss, the reader goes on.
    let (_log, _) = open_owner(directory.path(), config(10, 1_000));
    let (items, batch) = read_from_start(&mut reader);
    assert_eq!(
        items,
        [
            Seen::Record(1, 1),
            Seen::Record(2, 2),
            Seen::Record(3, 3),
            Seen::Gap(range(4, 5), GapReason::Truncated),
            Seen::Marker(6, "truncated"),
            Seen::Marker(7, "stale_owner"),
            Seen::Marker(8, "torn_tail"),
        ]
    );
    assert!(batch.caught_up);
}

#[test]
fn entries_lost_from_the_end_stay_unsettled_until_the_owner_records_them() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(2, 1_000));
    append(&mut log, 1..=6);
    log.crash();
    // A crash, then the last segment lost: its sequences were acknowledged.
    fs::remove_file(last_segment(directory.path())).unwrap();

    let mut reader = open_reader(directory.path());
    let (items, batch) = read_from_start(&mut reader);
    assert_eq!(items, records(1..=4));
    // Not given up as a gap: no line and no marker settles them yet.
    assert!(!batch.caught_up);
    assert_eq!(reader.unsettled(), Some(range(5, 6)));
    assert_eq!(reader.high_water(), Some(sequence(6)));

    let (_log, report) = open_owner(directory.path(), config(2, 1_000));
    assert_eq!(report.markers.len(), 2);
    let (items, batch) = read_all(&mut reader, &batch.cursor);
    assert_eq!(
        items,
        [
            Seen::Gap(range(5, 6), GapReason::Truncated),
            Seen::Marker(7, "truncated"),
            Seen::Marker(8, "stale_owner"),
        ]
    );
    assert!(batch.caught_up);
    assert_eq!(reader.unsettled(), None);
}

/// Cuts the file at `path` back to its first `lines` lines.
fn keep_lines(path: &Path, lines: usize) {
    let bytes = fs::read(path).unwrap();
    let end = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(lines - 1)
        .map(|(position, _)| position + 1)
        .unwrap();
    fs::write(path, &bytes[..end]).unwrap();
}

#[test]
fn lines_cut_back_under_a_reader_after_a_crash_are_never_reused_or_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(4, 1_000));
    append(&mut log, 1..=6);
    let mut reader = open_reader(directory.path());
    let (items, batch) = read_from_start(&mut reader);
    assert_eq!(items, records(1..=6));
    log.crash();
    // The disk lost the last acknowledged line after the reader had read it.
    keep_lines(&last_segment(directory.path()), 1);

    let (items, after_loss) = read_all(&mut reader, &batch.cursor);
    assert!(items.is_empty());
    assert_eq!(reader.unsettled(), Some(range(6, 6)));
    assert!(reader.totals().rescans > 0);
    let (items, _) = read_from_start(&mut reader);
    assert_eq!(items, records(1..=5));

    // The next owner records the loss; the reader goes on from where it was.
    let (mut log, _) = open_owner(directory.path(), config(4, 1_000));
    append(&mut log, 9..=9);
    let (items, end) = read_all(&mut reader, &after_loss.cursor);
    assert_eq!(
        items,
        [
            Seen::Marker(7, "truncated"),
            Seen::Marker(8, "stale_owner"),
            Seen::Record(9, 9),
        ]
    );
    assert!(end.caught_up);
    let (items, _) = read_from_start(&mut reader);
    assert_eq!(items[5], Seen::Gap(range(6, 6), GapReason::Truncated));
}

#[test]
fn retention_dropping_segments_under_a_reader_is_read_as_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(2, 4));
    append(&mut log, 1..=4);
    let mut reader = open_reader(directory.path());
    let batch = reader.read(&reader.start(), 2).unwrap();
    assert_eq!(seen(batch.items), records(1..=2));
    // The owner appends on, and retention drops the segments the reader was in.
    append(&mut log, 5..=8);
    assert_eq!(log.retention().low_water, Some(sequence(4)));
    let (items, end) = read_all(&mut reader, &batch.cursor);
    assert_eq!(
        items,
        [
            Seen::Gap(range(3, 4), GapReason::Retention),
            Seen::Record(5, 5),
            Seen::Record(6, 6),
            Seen::Record(7, 7),
            Seen::Record(8, 8),
        ]
    );
    assert!(end.caught_up);
    let (items, _) = read_from_start(&mut reader);
    assert_eq!(items[0], Seen::Gap(range(1, 4), GapReason::Retention));
    // The owner's view and the reader's agree.
    assert_eq!(
        seen(log.read(&log.start(), usize::MAX).unwrap().items),
        items
    );
    append(&mut log, 9..=10);
    let (items, _) = read_all(&mut reader, &end.cursor);
    assert_eq!(items, records(9..=10));
}

#[test]
fn cursors_and_streams_that_are_not_this_one_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(4, 1_000));
    append(&mut log, 1..=3);
    let mut reader = open_reader(directory.path());

    let other = tempfile::tempdir().unwrap();
    let (other_log, _) = open_owner(other.path(), config(4, 1_000));
    assert!(matches!(
        reader.read(&other_log.start(), 10),
        Err(LogError::Cursor(CursorError::WrongStream { .. }))
    ));
    let future = LogCursor {
        stream: reader.stream().clone(),
        after: Some(sequence(4)),
    };
    assert!(matches!(
        reader.read(&future, 10),
        Err(LogError::Cursor(CursorError::Future { last: Some(last), .. })) if last.get() == 3
    ));
    // No stream, and another stream, are refused at open.
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        DurableReader::<u64>::open(empty.path(), stream_id()),
        Err(LogError::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        })
    ));
    assert!(matches!(
        DurableReader::<u64>::open(
            directory.path(),
            DurableStreamId::new("warden.events").unwrap()
        ),
        Err(LogError::Damaged(LogDamage::OtherStream { .. }))
    ));

    // The stream deleted and created again is another instance: the reader stops.
    log.close().unwrap();
    for entry in fs::read_dir(directory.path()).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let (mut recreated, _) = open_owner(directory.path(), config(4, 1_000));
    append(&mut recreated, 1..=1);
    assert!(matches!(
        reader.read(&reader.start(), 10),
        Err(LogError::Damaged(LogDamage::OtherStream { .. }))
    ));
}

#[test]
fn a_reader_of_an_audit_stream_verifies_the_chain_it_reads() {
    let directory = tempfile::tempdir().unwrap();
    let audit_stream = DurableStreamId::new("engine.audit").unwrap();
    let (log, _) = DurableLog::<AuditRecord>::open(
        directory.path(),
        audit_stream.clone(),
        producer("engine.audit"),
        config(3, 1_000),
    )
    .unwrap();
    let config = AuditConfig {
        spool_records: 4,
        revocation_reserve_records: 1,
        failure_policy: AuditFailurePolicy::SpoolHighImpact,
        guest_observations: EmissionLimit::new(10, Duration::from_secs(1)).unwrap(),
        redaction: RedactionPolicy::metadata_only(),
    };
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        log,
        FakeAuditSpool::new(),
        manual_clock(),
        config,
    )
    .unwrap();
    for step in 1..=7u64 {
        let receipt = journal
            .append(
                &mut authority,
                context("op-1", Phase::Running),
                AuditDraft::HostFact {
                    fact: HostFact::Lease,
                    fields: vec![Field::metadata("step", step)],
                },
            )
            .unwrap();
        assert_eq!(receipt.durability, Durability::Durable);
    }
    let mut reader = DurableReader::<AuditRecord>::open(directory.path(), audit_stream).unwrap();
    let batch = reader.read(&reader.start(), usize::MAX).unwrap();
    let records: Vec<AuditRecord> = batch
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(record),
                ..
            } => Some(record),
            _ => None,
        })
        .collect();
    let genesis = JournalHead::genesis(journal_id("engine"), producer("engine.audit"));
    assert_eq!(verify_chain(&genesis, &records).unwrap(), journal.head());
    let correlation = reader
        .correlate(&crate::foundation::ids::OperationId::new("op-1").unwrap())
        .unwrap();
    assert_eq!(correlation.records.len(), 7);
}

/// Checks one reader's view of a stream whose record values equal their sequences and that
/// has no markers: every item in order, every entry its own value, every gap retention's.
/// Returns the last sequence reached.
fn check_items(items: &[ReadItem<u64>], mut reached: u64) -> Result<u64, String> {
    for item in items {
        match item {
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(value),
                ..
            } if sequence.get() == reached + 1 && *value == sequence.get() => {
                reached = sequence.get();
            }
            ReadItem::Gap {
                missing,
                reason: GapReason::Retention,
            } if missing.first().get() == reached + 1 => reached = missing.last().get(),
            other => return Err(format!("after {reached}: {other:?}")),
        }
    }
    Ok(reached)
}

/// Reads until the stream reached `target`, or the deadline passed.
fn follow(reader: &mut Reader, target: u64, deadline: Instant) -> Result<u64, String> {
    let mut cursor = reader.start();
    let mut reached = 0;
    while reached < target {
        if Instant::now() > deadline {
            return Err(format!("reached {reached} of {target} before the deadline"));
        }
        let batch = reader
            .read(&cursor, 64)
            .map_err(|error| format!("after {reached}: {error}"))?;
        reached = check_items(&batch.items, reached)?;
        cursor = batch.cursor;
        if batch.items.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(reached)
}

#[test]
fn an_owner_and_a_reader_on_separate_handles_run_at_once() {
    let directory = tempfile::tempdir().unwrap();
    // Small segments and tight retention: segments go while the reader reads them.
    let (mut log, _) = open_owner(directory.path(), config(5, 20));
    append(&mut log, 1..=1);
    let path = directory.path().to_path_buf();
    let reader = std::thread::spawn(move || {
        let mut reader = open_reader(&path);
        let reached = follow(&mut reader, 300, Instant::now() + Duration::from_secs(120));
        (reached, reader.totals())
    });
    append(&mut log, 2..=300);
    let (reached, totals) = reader.join().unwrap();
    assert_eq!(reached, Ok(300));
    assert!(totals.refreshes > 1);
    assert!(log.retention().dropped_entries >= 280);
}

/// The child half of [`a_reader_in_another_process_follows_the_owner`]: a no-op unless that
/// test started this executable to run it.
#[test]
fn durable_reader_child_process() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let target: u64 = std::env::var(CHILD_TARGET).unwrap().parse().unwrap();
    let mut reader = open_reader(Path::new(&directory));
    println!("{CHILD_PREFIX} started");
    let reached = follow(
        &mut reader,
        target,
        Instant::now() + Duration::from_secs(120),
    );
    match reached {
        Ok(reached) => println!(
            "{CHILD_PREFIX} reached {reached} after {} refreshes",
            reader.totals().refreshes
        ),
        Err(error) => println!("{CHILD_PREFIX} failed {error}"),
    }
}

#[test]
fn a_reader_in_another_process_follows_the_owner() {
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_owner(directory.path(), config(8, 32));
    append(&mut log, 1..=10);
    // This test executable again, running only the child test: another process.
    let child_test = module_path!()
        .split_once("::")
        .map(|(_, path)| format!("{path}::durable_reader_child_process"))
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            child_test.as_str(),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIRECTORY, directory.path())
        .env(CHILD_TARGET, "400")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The child's lines, wherever the test harness's own output put them on a line.
    let mut lines = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(Result::unwrap)
        .filter_map(|line| line.find(CHILD_PREFIX).map(|at| line[at..].to_owned()));
    assert_eq!(lines.next(), Some(format!("{CHILD_PREFIX} started")));
    // The owner appends, and retention drops segments, while the other process reads.
    append(&mut log, 11..=400);
    let reported: Vec<String> = lines.collect();
    assert!(child.wait().unwrap().success());
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert!(
        reported[0].starts_with(&format!("{CHILD_PREFIX} reached 400 ")),
        "{}",
        reported[0]
    );
    assert!(log.retention().dropped_entries > 300);
    log.close().unwrap();
}
