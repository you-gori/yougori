//! Audit streams on CORE-06 durable logs (S06; VM-W42 "one append authority per stream"
//! and "restart/truncation ... tested" at line 2665): one owner in this process and across
//! processes, a sequence and a chain that continue after a restart and a stale owner, a
//! torn tail quarantined and reported, lines lost from the end refused, retention reported
//! with the chain verified from what it left, lines out of place refused, and a stored line
//! with a number for a tag or a repeated key refused. Every log lives in a temporary
//! directory the test owns.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::anchor::AnchorVerdict;
use super::durable::{DurableError, DurableOpening, DurableSegments, LayoutProblem, SegmentLine};
use super::fakes::{
    context, journal_id, manual_clock, producer, stream_config, FakeAnchor, FakeSegmentStorage,
    FakeSpool,
};
use super::segment::{
    verify_retained_segments, verify_segments, Damage, ResumeFinding, SegmentError, SegmentStorage,
    StoredSegment,
};
use super::stream::{
    Anchoring, AuditEvent, AuditStream, StreamAuthority, StreamConfig, StreamDirectory, StreamError,
};
use super::strict_tests::{sample_segments, segment_lines, shown, variant_names, Document};
use crate::foundation::events::{
    AuditRecord, Durability, DurableLog, DurableStreamId, EventSequence, Field, GapReason,
    HostFact, JournalHead, LineProblem, LogConfig, LogDamage, LogEntry, LogError, LogMarker,
    OwnerError, Phase, ReadItem, Takeover,
};
use crate::foundation::ids::ManualClock;

type Durable = AuditStream<DurableSegments, FakeSpool, FakeAnchor, Arc<ManualClock>>;

fn genesis() -> JournalHead {
    JournalHead::genesis(journal_id("engine"), producer("engine.audit"))
}

fn fact(step: u64) -> AuditEvent {
    AuditEvent::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    }
}

/// Room for every line these tests write, in log segments of eight lines.
fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 1_000,
        max_bytes: 1 << 24,
        segment_entries: 8,
        segment_bytes: 1 << 16,
    }
}

fn open_with(
    directory: &mut StreamDirectory,
    anchor: &FakeAnchor,
    config: StreamConfig,
    log: LogConfig,
) -> Result<(Durable, StreamAuthority, DurableOpening), StreamError> {
    AuditStream::open_durable(
        directory,
        journal_id("engine"),
        producer("engine.audit"),
        FakeSpool::new(),
        anchor.clone(),
        manual_clock(),
        config,
        log,
    )
}

fn open(
    directory: &mut StreamDirectory,
) -> Result<(Durable, StreamAuthority, DurableOpening), StreamError> {
    open_with(
        directory,
        &FakeAnchor::new(),
        stream_config(4, 1, 3),
        log_config(),
    )
}

fn record_facts(
    stream: &mut Durable,
    authority: &mut StreamAuthority,
    steps: std::ops::RangeInclusive<u64>,
) {
    for step in steps {
        let receipt = stream
            .record(authority, context("op-1", Phase::Running), fact(step))
            .unwrap();
        assert_eq!(receipt.sequence.get(), step);
        assert_eq!(receipt.durability, Durability::Durable);
    }
}

fn stored(stream: &Durable) -> Vec<StoredSegment> {
    stream.with_storage(|storage| storage.segments().unwrap())
}

fn records(segments: &[StoredSegment]) -> Vec<u64> {
    segments
        .iter()
        .flat_map(|segment| segment.records.iter())
        .map(|record| record.sequence().get())
        .collect()
}

fn stream_path(directory: &StreamDirectory) -> PathBuf {
    directory.stream_path(&journal_id("engine")).unwrap()
}

/// The log's last segment file.
fn last_log_segment(path: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|file| {
            file.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("segment-") && name.ends_with(".jsonl"))
        })
        .collect();
    files.sort();
    files.pop().unwrap()
}

/// Makes the owner record say its owner never released the stream, as after a crash.
fn mark_stale(path: &Path) {
    let file = path.join("owner.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    record["released"] = serde_json::json!(false);
    fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
}

/// VM-W42 "one append authority per stream"; S06 "a clear append owner": the directory
/// refuses a second authority, another directory in this process meets the log's owner,
/// and another process holding the stream's lock is refused and named; nothing waits.
#[test]
fn a_durable_stream_has_one_owner_in_this_process_and_across_processes() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    assert_eq!(directory.root(), Some(root.path()));
    let (mut stream, mut authority, opening) = open(&mut directory).unwrap();
    assert_eq!(opening.log.takeover, Takeover::Fresh);
    assert!(opening.log.created && opening.log.markers.is_empty());
    assert!(opening.gaps.is_empty() && opening.resume.is_none());
    record_facts(&mut stream, &mut authority, 1..=2);

    assert!(matches!(
        open(&mut directory).err(),
        Some(StreamError::AuthorityLive { stream }) if stream == journal_id("engine")
    ));
    let mut other = StreamDirectory::durable(root.path());
    assert!(matches!(
        open(&mut other).err(),
        Some(StreamError::Durable(DurableError::Log(LogError::Owner(
            OwnerError::HeldInProcess { .. }
        ))))
    ));
    assert_eq!(
        open(&mut StreamDirectory::new()).err(),
        Some(StreamError::Durable(DurableError::NoRoot))
    );
    let closed = stream.close().unwrap();
    assert_eq!(closed.seal.head().last, EventSequence::new(2));
    drop(authority);

    // Another process holds the stream: its lock is taken through a handle of its own.
    let foreign = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(stream_path(&directory).join("owner.lock"))
        .unwrap();
    foreign.try_lock().unwrap();
    let refused = open(&mut directory).err().unwrap();
    assert!(
        matches!(
            &refused,
            StreamError::Durable(DurableError::Log(LogError::Owner(OwnerError::HeldElsewhere {
                holder: Some(holder),
                ..
            }))) if holder.owner == producer("engine.audit") && holder.released
        ),
        "{refused:?}"
    );
    assert!(refused
        .to_string()
        .starts_with("engine.audit owns the stream"));
    assert!(!directory.is_live(&journal_id("engine")));
    drop(foreign);
    let (stream, _authority, opening) = open(&mut directory).unwrap();
    assert!(matches!(opening.log.takeover, Takeover::Released { .. }));
    assert_eq!(stream.head().last, EventSequence::new(2));
}

/// VM-W42 "restart ... tested"; S06 "a sequence that continues after restart": after a
/// clean close the chain resumes where it ended; after an owner that never released the
/// stream, the log records the stale owner and the chain resumes after the last record,
/// with every line read back verifying as one chain from genesis.
#[test]
fn a_restart_continues_the_sequence_and_a_stale_owner_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let (mut stream, mut authority, _) = open(&mut directory).unwrap();
    record_facts(&mut stream, &mut authority, 1..=5);
    stream.close().unwrap();
    drop(authority);

    let (mut stream, mut authority, opening) = open(&mut directory).unwrap();
    assert!(matches!(opening.log.takeover, Takeover::Released { .. }));
    assert!(opening.log.markers.is_empty() && opening.gaps.is_empty());
    let resumed = opening.resume.unwrap();
    assert_eq!(resumed.report.finding, ResumeFinding::Sealed);
    assert_eq!(
        (resumed.report.chain.segments, resumed.report.chain.records),
        (2, 5)
    );
    assert_eq!(resumed.report.chain.retained_from, None);
    assert_eq!(resumed.loss_record, None);
    assert_eq!(stream.current_segment().index(), 2);
    record_facts(&mut stream, &mut authority, 6..=6);
    // Nine lines before the restart, the new header and record 6 after it.
    assert_eq!(
        stream.with_storage(|storage| storage.log().last()),
        EventSequence::new(11)
    );

    // The process stops without releasing the stream.
    drop((stream, authority));
    mark_stale(&stream_path(&directory));
    let (stream, _authority, opening) = open(&mut directory).unwrap();
    assert!(opening.log.takeover.is_stale());
    assert!(matches!(
        opening.log.markers.as_slice(),
        [(sequence, LogMarker::StaleOwner { owner, .. })]
            if sequence.get() == 12 && *owner == producer("engine.audit")
    ));
    let resumed = opening.resume.unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    assert_eq!(resumed.loss_record, None);
    assert_eq!(stream.head().last, EventSequence::new(6));
    let segments = stored(&stream);
    assert_eq!(records(&segments), [1, 2, 3, 4, 5, 6]);
    let chain = verify_segments(&genesis(), &segments).unwrap();
    assert_eq!(
        chain.damage,
        [Damage::Unsealed {
            segment: 2,
            records_found: 1
        }]
    );
    assert_eq!(chain.segments, 4);
    // The marker is the log's own: a reader meets it in order, outside every segment.
    let markers = stream.with_storage(|storage| {
        storage
            .log()
            .read(&storage.log().start(), usize::MAX)
            .unwrap()
            .items
            .into_iter()
            .filter(|item| {
                matches!(
                    item,
                    ReadItem::Entry {
                        entry: LogEntry::Marker(_),
                        ..
                    }
                )
            })
            .count()
    });
    assert_eq!(markers, 1);
}

/// S06 "torn tails quarantined": an append cut off half way leaves half a line at the end
/// of the log. The next open moves it to a quarantine file, records it and the sequence it
/// burned, and reports both; nothing the log acknowledged was lost, so the chain resumes
/// after the last whole line without recording a loss.
#[test]
fn a_torn_tail_is_quarantined_and_reported_and_the_chain_resumes_after_it() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let (mut stream, mut authority, _) = open(&mut directory).unwrap();
    record_facts(&mut stream, &mut authority, 1..=4);
    drop((stream, authority));
    let path = stream_path(&directory);
    let torn = b"0123456789abcdef {\"sequence\":8,\"own";
    let mut bytes = fs::read(last_log_segment(&path)).unwrap();
    bytes.extend_from_slice(torn);
    fs::write(last_log_segment(&path), bytes).unwrap();

    let (mut stream, mut authority, opening) = open(&mut directory).unwrap();
    let [(_, LogMarker::Truncated { missing }), (_, LogMarker::TornTail { bytes, quarantine })] =
        opening.log.markers.as_slice()
    else {
        panic!("{:?}", opening.log.markers);
    };
    assert_eq!((missing.first().get(), missing.count()), (8, 1));
    assert_eq!(*bytes, torn.len() as u64);
    assert_eq!(fs::read(path.join(quarantine)).unwrap(), torn);
    assert_eq!(opening.gaps, [(*missing, GapReason::Truncated)]);
    let resumed = opening.resume.unwrap();
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 1 }
    );
    assert_eq!(resumed.report.lost, None);
    assert_eq!(resumed.loss_record, None);
    record_facts(&mut stream, &mut authority, 5..=5);
    assert_eq!(records(&stored(&stream)), [1, 2, 3, 4, 5]);
    verify_segments(&genesis(), &stored(&stream)).unwrap();
}

/// VM-CP-22 "a truncated file ... detected": when lines the log acknowledged are cut from
/// its end, no record can be shown to continue the chain. The stream does not open, says
/// which log sequences are gone, and stays refused; nothing is appended after the cut.
#[test]
fn lines_lost_from_the_end_of_the_log_refuse_to_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let (mut stream, mut authority, _) = open(&mut directory).unwrap();
    record_facts(&mut stream, &mut authority, 1..=4);
    stream.close().unwrap();
    drop(authority);
    // Eight lines in one log segment; the last two (record 4 and the seal) are cut.
    let segment = last_log_segment(&stream_path(&directory));
    let bytes = fs::read(&segment).unwrap();
    let ends: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .map(|(at, _)| at + 1)
        .collect();
    assert_eq!(ends.len(), 8);
    fs::write(&segment, &bytes[..ends[5]]).unwrap();

    for _ in 0..2 {
        let refused = open(&mut directory).err().unwrap();
        let StreamError::Durable(DurableError::TailLost { truncated }) = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(truncated.len(), 1);
        assert_eq!(
            (truncated[0].first().get(), truncated[0].last().get()),
            (7, 8)
        );
        assert!(refused
            .to_string()
            .contains("log sequences 7 to 8 are gone"));
        assert!(!directory.is_live(&journal_id("engine")));
    }
}

/// S06 "bounded retention ... typed gaps": the log drops its oldest segments under a small
/// bound. The gap is in the opening and in every read; the chain is verified from the first
/// segment whose header retention left, which strict verification from genesis refuses;
/// the sequence continues. An anchored head that retention dropped is reported as dropped,
/// and one it kept is compared as before.
#[test]
fn retention_is_reported_and_the_chain_resumes_from_what_it_kept() {
    let small = LogConfig {
        max_entries: 14,
        max_bytes: 1 << 20,
        segment_entries: 4,
        segment_bytes: 1 << 14,
    };
    let anchored = |config: StreamConfig| StreamConfig {
        anchoring: Anchoring::OnRotation,
        ..config
    };
    let config = anchored(stream_config(4, 1, 2));
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let early = FakeAnchor::new();
    let late = FakeAnchor::new();
    // Bounds that could drop the header being written are refused before the log opens.
    assert_eq!(
        open_with(
            &mut directory,
            &early,
            config,
            LogConfig {
                max_entries: 13,
                ..small
            }
        )
        .err(),
        Some(StreamError::Durable(DurableError::RetentionTooSmall {
            setting: "max_entries",
            needed: 14,
            configured: 13
        }))
    );
    assert!(!stream_path(&directory).exists());

    let (mut stream, mut authority, _) = open_with(&mut directory, &early, config, small).unwrap();
    record_facts(&mut stream, &mut authority, 1..=3);
    stream.close().unwrap();
    drop(authority);
    assert_eq!(
        early.held(&journal_id("engine")).unwrap().sequence().get(),
        3
    );
    let (mut stream, mut authority, opening) =
        open_with(&mut directory, &late, config, small).unwrap();
    assert_eq!(
        opening.resume.unwrap().report.anchor,
        AnchorVerdict::NotAnchored
    );
    record_facts(&mut stream, &mut authority, 4..=30);
    stream.close().unwrap();
    drop(authority);

    // Against the early anchor: its head was dropped, and nothing is left to compare.
    let (stream, authority, opening) = open_with(&mut directory, &early, config, small).unwrap();
    let Some((first_gap, GapReason::Retention)) = opening.gaps.first().copied() else {
        panic!("{:?}", opening.gaps);
    };
    assert_eq!(first_gap.first(), EventSequence::FIRST);
    let resumed = opening.resume.unwrap();
    assert_eq!(
        resumed.report.anchor,
        AnchorVerdict::Dropped {
            anchored: EventSequence::new(3).unwrap()
        }
    );
    assert!(resumed.report.anchor.allows_resume());
    assert_eq!(resumed.report.finding, ResumeFinding::Sealed);
    let start = resumed.report.chain.retained_from.clone().unwrap();
    assert!(start.segment > 0);
    assert_eq!(start.retention.dropped_entries, first_gap.count());
    assert_eq!(start.after.journal, genesis().journal);
    // What the log holds now, after the header resuming wrote: whole segments from the
    // first header retention left, their records one run up to the last.
    let segments = stored(&stream);
    let first = segments[0].header.index();
    assert!(first >= start.segment);
    let after = segments[0].header.opened_from().last.unwrap().get();
    assert_eq!(records(&segments), (after + 1..=30).collect::<Vec<u64>>());
    // Retention is accepted only where storage declares it.
    assert_eq!(
        verify_segments(&genesis(), &segments).err(),
        Some(SegmentError::MissingSegment {
            expected: 0,
            found: first
        })
    );
    let retention = stream.with_storage(|storage| storage.retention().unwrap());
    assert!(retention.is_some());
    let chain = verify_retained_segments(&genesis(), retention, &segments).unwrap();
    assert_eq!(chain.retained_from.map(|start| start.segment), Some(first));
    assert_eq!(chain.head.last, EventSequence::new(30));
    drop((stream, authority));

    // Against the late anchor, which holds a head retention kept.
    let (mut stream, mut authority, opening) =
        open_with(&mut directory, &late, config, small).unwrap();
    let resumed = opening.resume.unwrap();
    assert_eq!(
        resumed.report.anchor,
        AnchorVerdict::Reaches {
            anchored: EventSequence::new(30).unwrap()
        }
    );
    assert_eq!(
        resumed.report.finding,
        ResumeFinding::Unsealed { records_found: 0 }
    );
    record_facts(&mut stream, &mut authority, 31..=31);
    let segments = stored(&stream);
    let retention = stream.with_storage(|storage| storage.retention().unwrap());
    let chain = verify_retained_segments(&genesis(), retention, &segments).unwrap();
    assert_eq!(chain.head.last, EventSequence::new(31));
}

/// Lines that do not form segments are damage, not something to guess around: a record
/// before any header, and a record after its segment's seal, are refused at open.
#[test]
fn lines_out_of_place_are_refused() {
    // Records of one chain, made on in-memory storage.
    let storage = FakeSegmentStorage::new(100);
    let mut fake = StreamDirectory::new();
    let (mut source, mut source_authority) = AuditStream::open(
        &mut fake,
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        FakeSpool::new(),
        FakeAnchor::new(),
        manual_clock(),
        stream_config(4, 1, 1),
    )
    .unwrap();
    for step in 1..=2 {
        let _ = source
            .record(
                &mut source_authority,
                context("op-1", Phase::Running),
                fact(step),
            )
            .unwrap();
    }
    let segments = storage.snapshot();
    let record: AuditRecord = segments[0].records[0].clone();
    let raw = |path: &Path, lines: Vec<SegmentLine>| {
        let (mut log, _) = DurableLog::open(
            path,
            DurableStreamId::new("engine").unwrap(),
            producer("engine.audit"),
            log_config(),
        )
        .unwrap();
        for line in lines {
            log.append(line).unwrap();
        }
        log.close().unwrap();
    };

    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    raw(
        &stream_path(&directory),
        vec![SegmentLine::Record {
            record: Box::new(record.clone()),
        }],
    );
    assert_eq!(
        open(&mut directory).err(),
        Some(StreamError::Durable(DurableError::Layout {
            sequence: EventSequence::FIRST,
            problem: LayoutProblem::BeforeHeader
        }))
    );

    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    raw(
        &stream_path(&directory),
        vec![
            SegmentLine::Header {
                header: segments[0].header.clone(),
            },
            SegmentLine::Record {
                record: Box::new(record.clone()),
            },
            SegmentLine::Seal {
                seal: segments[0].seal.clone().unwrap(),
            },
            SegmentLine::Record {
                record: Box::new(record),
            },
        ],
    );
    assert_eq!(
        open(&mut directory).err(),
        Some(StreamError::Durable(DurableError::Layout {
            sequence: EventSequence::new(4).unwrap(),
            problem: LayoutProblem::AfterSeal
        }))
    );
    // A line reads back as written, and an unknown field next to it is refused.
    let line = SegmentLine::Header {
        header: segments[1].header.clone(),
    };
    let mut json = serde_json::to_value(&line).unwrap();
    assert_eq!(json["line"], "header");
    assert_eq!(
        serde_json::from_value::<SegmentLine>(json.clone()).unwrap(),
        line
    );
    json["note"] = serde_json::json!("x");
    assert!(serde_json::from_value::<SegmentLine>(json).is_err());
}

/// `foundation::strict_serde` (the S06 item "Strict tags of read-back tagged enums" of
/// docs/combined-plan-leftover-tasks.md): a line the log keeps whose tag, or the tag of an
/// enum nested in it, is a number, or that writes a key twice, does not decode, and the
/// stream does not open: the log is damaged at that line. serde would read a number for a
/// tag nested in a line, such as a header's opening, as the variant with that index. The
/// same lines as written open.
#[test]
fn a_stored_line_with_a_number_tag_or_a_repeated_key_is_refused() {
    let lines: Vec<serde_json::Value> = segment_lines(&sample_segments())
        .iter()
        .map(|line| serde_json::to_value(line).unwrap())
        .collect();
    // Writes each document as one entry of the stream's log and opens the stream.
    let open_lines = |root: &Path, documents: Vec<Document>| {
        let mut directory = StreamDirectory::durable(root);
        let (mut log, _) = DurableLog::<Document>::open(
            &stream_path(&directory),
            DurableStreamId::new("engine").unwrap(),
            producer("engine.audit"),
            log_config(),
        )
        .unwrap();
        for document in documents {
            log.append(document).unwrap();
        }
        log.close().unwrap();
        open(&mut directory).map(|(stream, _, _)| records(&stored(&stream)))
    };
    let as_written = || lines.iter().cloned().map(Document::new).collect::<Vec<_>>();
    let root = tempfile::tempdir().unwrap();
    assert_eq!(open_lines(root.path(), as_written()), Ok(vec![1, 2, 3, 4]));

    // Each place a variant name is written, once: swapped for its index, and its key
    // written twice.
    let mut checked: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        for name in variant_names::<SegmentLine>(line) {
            let path = shown(&name.path);
            if checked.contains(&path) {
                continue;
            }
            let mut cases = vec![Document::new(name.swapped(line))];
            if let Some((object, key)) = name.key() {
                cases.push(Document::repeating(line.clone(), object, key));
            }
            for tampered in cases {
                let mut documents = as_written();
                documents[index] = tampered;
                let root = tempfile::tempdir().unwrap();
                let refused = open_lines(root.path(), documents).err();
                let sequence = u64::try_from(index).unwrap() + 1;
                assert!(
                    matches!(
                        &refused,
                        Some(StreamError::Durable(DurableError::Log(LogError::Damaged(
                            LogDamage::Line {
                                segment,
                                line: at,
                                problem: LineProblem::Encoding,
                            }
                        )))) if segment.get() + at - 1 == sequence
                    ),
                    "line {sequence}, `{path}`: {refused:?}"
                );
            }
            checked.push(path);
        }
    }
    for path in [
        "line",
        "header.opening.reason",
        "header.opening.finding.kind",
    ] {
        assert!(
            checked.iter().any(|found| found == path),
            "{path}: {checked:?}"
        );
    }
}
