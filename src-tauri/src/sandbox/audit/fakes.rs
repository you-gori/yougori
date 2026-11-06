//! Test doubles: in-memory segment storage whose conditions a test controls, segment
//! storage on files in a temporary directory, a spool and an anchor that outlive their
//! stream, and small constructors. Nothing here touches the host beyond a temporary
//! directory a test owns.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::anchor::{AnchorRefusal, AnchoredHead, HeadAnchor};
use super::segment::{SegmentConfig, SegmentHeader, SegmentSeal, SegmentStorage, StoredSegment};
use super::stream::{Anchoring, StreamConfig};
use crate::foundation::events::{
    AuditConfig, AuditFailurePolicy, AuditRecord, AuditSpool, EmissionLimit, EventContext,
    EventSequence, JournalId, Phase, ProducerId, RedactionPolicy, StoreRefusal,
};
use crate::foundation::ids::{ExecutionId, ManualClock, MonotonicTime, OperationId};

/// Secrets the redaction tests plant and then look for (VM-P12). Each has the shape the
/// redaction policy or a field class is meant to catch.
pub const FIXTURE_SECRETS: &[&str] = &[
    "hunter2-password",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJhbGciOiJIUzI1NiJ9.fixture-bearer",
    "sk-fixture1234567890abcdefghijklmnop",
    "summarise my medical history",
    "the user seems to be lying",
    "C:\\Users\\alice\\secret-model",
    "/home/alice/.ssh/id_ed25519",
];

pub fn journal_id(name: &str) -> JournalId {
    JournalId::new(name).unwrap()
}

pub fn producer(name: &str) -> ProducerId {
    ProducerId::new(name).unwrap()
}

pub fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn context(operation_name: &str, phase: Phase) -> EventContext {
    EventContext::new(operation(operation_name), phase)
}

/// A manual clock standing at one second.
pub fn manual_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)))
}

/// A stream configuration: spooling high-impact operations, four guest observations per
/// second, metadata-only redaction, no anchoring.
pub fn stream_config(
    spool_records: usize,
    revocation_reserve_records: usize,
    max_records_per_segment: u64,
) -> StreamConfig {
    StreamConfig {
        audit: AuditConfig {
            spool_records,
            revocation_reserve_records,
            failure_policy: AuditFailurePolicy::SpoolHighImpact,
            guest_observations: EmissionLimit::new(4, Duration::from_secs(1)).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
        segment: SegmentConfig {
            max_records_per_segment,
        },
        anchoring: Anchoring::Off,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Default)]
struct StorageState {
    segments: Vec<StoredSegment>,
    capacity_records: usize,
    store_but_report_slow: bool,
    refuse_seals: Option<StoreRefusal>,
    refuse_begins: Option<StoreRefusal>,
}

impl StorageState {
    fn records(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.records.len())
            .sum()
    }
}

/// In-memory segment storage that can be full, report an unclear refusal, or refuse seals
/// and headers, and
/// whose content a test can cut or replace as damage or tampering on disk would. Clones
/// share one content, so a test can drop a stream and resume from the same storage.
#[derive(Clone, Debug, Default)]
pub struct FakeSegmentStorage {
    shared: Arc<Mutex<StorageState>>,
}

impl FakeSegmentStorage {
    pub fn new(capacity_records: usize) -> Self {
        let storage = Self::default();
        storage.set_capacity(capacity_records);
        storage
    }

    pub fn set_capacity(&self, capacity_records: usize) {
        lock(&self.shared).capacity_records = capacity_records;
    }

    /// The next append stores its record but reports slow, like a write that completed
    /// after its deadline.
    pub fn store_but_report_slow_once(&self) {
        lock(&self.shared).store_but_report_slow = true;
    }

    pub fn refuse_seals(&self, refusal: Option<StoreRefusal>) {
        lock(&self.shared).refuse_seals = refusal;
    }

    pub fn refuse_begins(&self, refusal: Option<StoreRefusal>) {
        lock(&self.shared).refuse_begins = refusal;
    }

    pub fn snapshot(&self) -> Vec<StoredSegment> {
        lock(&self.shared).segments.clone()
    }

    /// Every stored record, in order.
    pub fn all_records(&self) -> Vec<AuditRecord> {
        lock(&self.shared)
            .segments
            .iter()
            .flat_map(|segment| segment.records.iter().cloned())
            .collect()
    }

    /// Replaces the content, as rewriting the files on disk would.
    pub fn replace(&self, segments: Vec<StoredSegment>) {
        lock(&self.shared).segments = segments;
    }

    /// Removes the last `records` records of the last segment and keeps its seal.
    pub fn truncate_tail(&self, records: usize) {
        if let Some(last) = lock(&self.shared).segments.last_mut() {
            let keep = last.records.len().saturating_sub(records);
            last.records.truncate(keep);
        }
    }
}

impl SegmentStorage for FakeSegmentStorage {
    fn begin_segment(&mut self, header: &SegmentHeader) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        if let Some(refusal) = state.refuse_begins {
            return Err(refusal);
        }
        if let Some(last) = state.segments.last() {
            if last.header == *header {
                return Ok(());
            }
        }
        state.segments.push(StoredSegment {
            header: header.clone(),
            records: Vec::new(),
            seal: None,
        });
        Ok(())
    }

    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        let stored = state.records();
        let capacity = state.capacity_records;
        let Some(last) = state.segments.last() else {
            return Err(StoreRefusal::Failed);
        };
        if last.seal.is_some() {
            return Err(StoreRefusal::Failed);
        }
        if state
            .segments
            .iter()
            .any(|segment| segment.records.iter().any(|known| known == record))
        {
            return Ok(());
        }
        if stored >= capacity {
            return Err(StoreRefusal::Full);
        }
        let report_slow = state.store_but_report_slow;
        state.store_but_report_slow = false;
        if let Some(last) = state.segments.last_mut() {
            last.records.push(record.clone());
        }
        if report_slow {
            return Err(StoreRefusal::Slow);
        }
        Ok(())
    }

    fn seal_segment(&mut self, seal: &SegmentSeal) -> Result<(), StoreRefusal> {
        let mut state = lock(&self.shared);
        if let Some(refusal) = state.refuse_seals {
            return Err(refusal);
        }
        let Some(last) = state.segments.last_mut() else {
            return Err(StoreRefusal::Failed);
        };
        match &last.seal {
            Some(existing) if existing == seal => Ok(()),
            Some(_) => Err(StoreRefusal::Failed),
            None => {
                last.seal = Some(seal.clone());
                Ok(())
            }
        }
    }

    fn segments(&self) -> Result<Vec<StoredSegment>, StoreRefusal> {
        Ok(self.snapshot())
    }

    fn record(&self, sequence: EventSequence) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(lock(&self.shared)
            .segments
            .iter()
            .flat_map(|segment| segment.records.iter())
            .find(|record| record.sequence() == sequence)
            .cloned())
    }
}

/// One line of a segment file. It reads through `foundation::strict_serde`, as the
/// durable log's lines do, so a tag that is not a string or a repeated key is refused.
#[derive(Serialize, Deserialize)]
#[serde(tag = "line", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub(super) enum Line {
    Header { header: SegmentHeader },
    Record { record: AuditRecord },
    Seal { seal: SegmentSeal },
}

crate::foundation::strict_serde::strict_tag!(Line, "line");

/// Segment storage on files in a directory the test owns: one file per segment, one JSON
/// line per header, record and seal.
#[derive(Clone, Debug)]
pub struct FileSegmentStorage {
    dir: PathBuf,
}

impl FileSegmentStorage {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, index: u64) -> PathBuf {
        self.dir.join(format!("segment-{index:06}.jsonl"))
    }

    fn files(&self) -> Result<Vec<PathBuf>, StoreRefusal> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)
            .map_err(|_| StoreRefusal::Failed)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect();
        files.sort();
        Ok(files)
    }

    fn read(path: &Path) -> Result<StoredSegment, StoreRefusal> {
        let text = fs::read_to_string(path).map_err(|_| StoreRefusal::Failed)?;
        let mut header = None;
        let mut records = Vec::new();
        let mut seal = None;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<Line>(line).map_err(|_| StoreRefusal::Failed)? {
                Line::Header { header: found } => header = Some(found),
                Line::Record { record } => records.push(record),
                Line::Seal { seal: found } => seal = Some(found),
            }
        }
        Ok(StoredSegment {
            header: header.ok_or(StoreRefusal::Failed)?,
            records,
            seal,
        })
    }

    fn write_line(path: &Path, line: &Line) -> Result<(), StoreRefusal> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| StoreRefusal::Failed)?;
        let mut text = serde_json::to_string(line).map_err(|_| StoreRefusal::Failed)?;
        text.push('\n');
        file.write_all(text.as_bytes())
            .map_err(|_| StoreRefusal::Failed)?;
        file.sync_all().map_err(|_| StoreRefusal::Failed)
    }

    fn last(&self) -> Result<Option<(PathBuf, StoredSegment)>, StoreRefusal> {
        match self.files()?.pop() {
            Some(path) => Ok(Some((path.clone(), Self::read(&path)?))),
            None => Ok(None),
        }
    }

    /// Rewrites segment `index` without its last `records` records, keeping its seal, as
    /// a truncated file would look.
    pub fn truncate_tail(&self, index: u64, records: usize) {
        let path = self.path(index);
        let segment = Self::read(&path).unwrap();
        let keep = segment.records.len().saturating_sub(records);
        let mut lines = vec![Line::Header {
            header: segment.header,
        }];
        lines.extend(
            segment
                .records
                .into_iter()
                .take(keep)
                .map(|record| Line::Record { record }),
        );
        if let Some(seal) = segment.seal {
            lines.push(Line::Seal { seal });
        }
        fs::remove_file(&path).unwrap();
        for line in &lines {
            Self::write_line(&path, line).unwrap();
        }
    }
}

impl SegmentStorage for FileSegmentStorage {
    fn begin_segment(&mut self, header: &SegmentHeader) -> Result<(), StoreRefusal> {
        let path = self.path(header.index());
        if path.exists() {
            return if Self::read(&path)?.header == *header {
                Ok(())
            } else {
                Err(StoreRefusal::Failed)
            };
        }
        Self::write_line(
            &path,
            &Line::Header {
                header: header.clone(),
            },
        )
    }

    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        let Some((path, last)) = self.last()? else {
            return Err(StoreRefusal::Failed);
        };
        if last.seal.is_some() {
            return Err(StoreRefusal::Failed);
        }
        if self.record(record.sequence())?.as_ref() == Some(record) {
            return Ok(());
        }
        Self::write_line(
            &path,
            &Line::Record {
                record: record.clone(),
            },
        )
    }

    fn seal_segment(&mut self, seal: &SegmentSeal) -> Result<(), StoreRefusal> {
        let Some((path, last)) = self.last()? else {
            return Err(StoreRefusal::Failed);
        };
        match &last.seal {
            Some(existing) if existing == seal => Ok(()),
            Some(_) => Err(StoreRefusal::Failed),
            None => Self::write_line(&path, &Line::Seal { seal: seal.clone() }),
        }
    }

    fn segments(&self) -> Result<Vec<StoredSegment>, StoreRefusal> {
        self.files()?.iter().map(|path| Self::read(path)).collect()
    }

    fn record(&self, sequence: EventSequence) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(self
            .segments()?
            .into_iter()
            .flat_map(|segment| segment.records)
            .find(|record| record.sequence() == sequence))
    }
}

#[derive(Debug, Default)]
struct SpoolState {
    records: VecDeque<AuditRecord>,
}

/// A spool standing in for durable local storage; clones share one content.
#[derive(Clone, Debug, Default)]
pub struct FakeSpool {
    shared: Arc<Mutex<SpoolState>>,
}

impl FakeSpool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<AuditRecord> {
        lock(&self.shared).records.iter().cloned().collect()
    }
}

impl AuditSpool for FakeSpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        lock(&self.shared).records.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        Ok(lock(&self.shared).records.front().cloned())
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        lock(&self.shared).records.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        lock(&self.shared).records.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        Ok(self.snapshot())
    }
}

#[derive(Debug, Default)]
struct AnchorStore {
    heads: BTreeMap<JournalId, AnchoredHead>,
    refuse: Option<AnchorRefusal>,
}

/// An anchor held elsewhere: it keeps one head per stream, refuses heads that go
/// backwards, and can be made unreachable. Clones share one content.
#[derive(Clone, Debug, Default)]
pub struct FakeAnchor {
    shared: Arc<Mutex<AnchorStore>>,
}

impl FakeAnchor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every publish and read refuses with `refusal` until set back to `None`.
    pub fn refuse(&self, refusal: Option<AnchorRefusal>) {
        lock(&self.shared).refuse = refusal;
    }

    pub fn held(&self, stream: &JournalId) -> Option<AnchoredHead> {
        lock(&self.shared).heads.get(stream).cloned()
    }
}

impl HeadAnchor for FakeAnchor {
    fn publish(&mut self, head: &AnchoredHead) -> Result<(), AnchorRefusal> {
        let mut state = lock(&self.shared);
        if let Some(refusal) = state.refuse {
            return Err(refusal);
        }
        if let Some(held) = state.heads.get(head.stream()) {
            if held.sequence() > head.sequence() {
                return Err(AnchorRefusal::Regressed {
                    held: held.sequence(),
                    offered: head.sequence(),
                });
            }
        }
        state.heads.insert(head.stream().clone(), head.clone());
        Ok(())
    }

    fn latest(&self, stream: &JournalId) -> Result<Option<AnchoredHead>, AnchorRefusal> {
        let state = lock(&self.shared);
        if let Some(refusal) = state.refuse {
            return Err(refusal);
        }
        Ok(state.heads.get(stream).cloned())
    }
}
