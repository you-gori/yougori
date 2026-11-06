//! Durable sightings: the earliest report of each finding, kept on a CORE-06 durable
//! stream (M18: "durable storage of sightings (S06 or the audit stream)"; line 2459:
//! "patch deadlines"; VM-W47, line 2670: "remediation window";
//! docs/combined-plan-leftover-tasks.md S06: "give each durable stream a clear append
//! owner").
//!
//! The remediation window runs from a finding's earliest report ([`Sightings`]). A
//! [`SightingsLog`] keeps the sightings on one [`DurableLog`] of its own, under the one
//! [`StreamOwner`](crate::foundation::events::StreamOwner) the log holds, so that a
//! restart neither forgets a sighting nor restarts a window:
//!
//! - [`SightingsLog::intake`] takes a scan in as [`intake`](super::intake::intake) does and
//!   appends every sighting the scan adds or moves earlier before the in-memory sightings
//!   change and before the record is returned. A refused intake appends nothing; an append
//!   that fails leaves the sightings as they were, and what did reach the stream is true
//!   either way, since a sighting only ever moves earlier.
//! - [`SightingsLog::open`] replays the whole stream: every sighting in it, the markers
//!   owners left ([`LogMarker`]), and the sequences it lost.
//! - Retention never drops a sighting that is not held elsewhere in the stream. Before an
//!   append would let the stream since the last complete restatement grow past half of
//!   what retention keeps (bounds less one segment), the log restates every sighting it
//!   holds ([`SightingRecord::RestatementBegins`] and [`SightingRecord::Restated`]);
//!   retention may then drop what came before. A restatement larger than that half is
//!   refused ([`SightingsError::NoRoom`]) before anything is written. Sizes are estimated
//!   from each record's encoding with a margin above the stored line's framing.
//! - Losses are explicit. A gap in the stream (a truncated tail, a removed segment, a
//!   retention drop after the bounds shrank) is a [`LostRange`]: a finding first reported
//!   there may have its window restart. A restatement carries the losses its owner knew
//!   of, so a later compaction never hides one.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::intake::{
    take_in, FindingKey, IntakeRefusal, ReachabilityStatements, ScanRecord, ScanRun, Sightings,
    MAX_SIGHTINGS,
};
use super::inventory::ConfigurationInventory;
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogEntry, LogError,
    LogMarker, OpenReport, ProducerId, ReadItem, SequenceRange,
};
use crate::sandbox::trust::{AdvisoryId, ComponentKind, ComponentVersion, TrustClock, UnixSeconds};

/// Most sightings in one record of the stream.
pub const MAX_SIGHTINGS_PER_RECORD: usize = 1_024;
/// Most losses a restatement carries; further ones join the last.
pub const MAX_LOSSES: usize = 64;
/// Bytes added to a record's encoding for its stored line: the line digest, the sequence,
/// the owner incarnation, the entry tag and the newline take less.
const LINE_MARGIN_BYTES: u64 = 192;
/// Items one read of the replay asks for; the replay reads until it is caught up.
const REPLAY_BATCH_ITEMS: usize = 1_024;

/// One finding's earliest report, as the stream keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sighting {
    pub advisory: AdvisoryId,
    pub component: ComponentKind,
    pub component_version: ComponentVersion,
    pub first_reported: UnixSeconds,
}

impl Sighting {
    fn of((advisory, component, component_version): &FindingKey, time: UnixSeconds) -> Self {
        Self {
            advisory: advisory.clone(),
            component: *component,
            component_version: component_version.clone(),
            first_reported: time,
        }
    }

    fn into_report(self) -> (FindingKey, UnixSeconds) {
        (
            (self.advisory, self.component, self.component_version),
            self.first_reported,
        )
    }
}

/// Sequences of the stream whose records are gone, and why: a sighting there is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LostRange {
    pub missing: SequenceRange,
    pub reason: GapReason,
}

/// One record of the sightings stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SightingRecord {
    /// Findings a scan reported first, or earlier than the stream held.
    Sighted { sightings: Vec<Sighting> },
    /// A restatement of every sighting held begins: `parts` [`SightingRecord::Restated`]
    /// records with `total` sightings in all follow, and `losses` are the losses its
    /// owner knew of. Once complete, everything before it is held in it.
    RestatementBegins {
        parts: u64,
        total: u64,
        losses: Vec<LostRange>,
    },
    /// Part `part`, counted from 1, of the restatement that began last.
    Restated { part: u64, sightings: Vec<Sighting> },
}

/// Why the sightings stream refused an open or an intake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SightingsError {
    /// The scan was refused; nothing was appended.
    Intake(IntakeRefusal),
    Log(LogError),
    /// The log's bounds leave no room to restate the sightings without retention
    /// dropping one no restatement holds. Nothing was appended.
    NoRoom {
        needed_entries: u64,
        needed_bytes: u64,
        budget_entries: u64,
        budget_bytes: u64,
    },
    /// Half of the bounds less one segment is zero: no restatement could ever fit.
    BoundsTooSmall,
    /// A record of the stream is outside what this module writes.
    BadRecord {
        sequence: EventSequence,
        detail: &'static str,
    },
    /// The stream holds more than [`MAX_SIGHTINGS`] findings.
    TooMany {
        max: usize,
    },
}

impl fmt::Display for SightingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Intake(refusal) => write!(f, "{refusal}"),
            Self::Log(error) => write!(f, "the sightings stream failed: {error}"),
            Self::NoRoom {
                needed_entries,
                needed_bytes,
                budget_entries,
                budget_bytes,
            } => write!(
                f,
                "restating the sightings takes {needed_entries} entries and about {needed_bytes} bytes; the log's bounds leave {budget_entries} entries and {budget_bytes} bytes"
            ),
            Self::BoundsTooSmall => f.write_str(
                "the log's bounds leave no room to restate the sightings; raise them",
            ),
            Self::BadRecord { sequence, detail } => {
                write!(f, "sightings record {sequence} is refused: {detail}")
            }
            Self::TooMany { max } => {
                write!(f, "the sightings stream holds more than {max} findings")
            }
        }
    }
}

impl std::error::Error for SightingsError {}

/// Entries and estimated bytes of a stretch of the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    entries: u64,
    bytes: u64,
}

impl Span {
    fn plus(self, other: Self) -> Self {
        Self {
            entries: self.entries.saturating_add(other.entries),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    fn within(self, limit: Self) -> bool {
        self.entries <= limit.entries && self.bytes <= limit.bytes
    }
}

/// The estimated stored size of one entry.
fn entry_bytes<P: Serialize>(entry: &LogEntry<P>) -> u64 {
    let encoded = serde_json::to_vec(entry).map_or(u64::MAX, |bytes| bytes.len() as u64);
    encoded.saturating_add(LINE_MARGIN_BYTES)
}

fn record_bytes(record: &SightingRecord) -> u64 {
    entry_bytes(&LogEntry::Record(record.clone()))
}

/// A restatement being read, not yet complete.
struct Pending {
    parts: u64,
    total: u64,
    next_part: u64,
    count: u64,
    losses: Vec<LostRange>,
    span: Span,
}

/// What a replay of the stream rebuilt.
#[derive(Default)]
struct Replayed {
    first_reported: BTreeMap<FindingKey, UnixSeconds>,
    losses: Vec<LostRange>,
    markers: Vec<(EventSequence, LogMarker)>,
    /// The stream from the start of the last complete restatement, or from its start.
    since: Span,
    pending: Option<Pending>,
}

impl Replayed {
    fn fold(&mut self, item: ReadItem<SightingRecord>) -> Result<(), SightingsError> {
        match item {
            ReadItem::Gap { missing, reason } => {
                self.pending = None;
                push_loss(&mut self.losses, LostRange { missing, reason });
            }
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Marker(marker),
                ..
            } => {
                self.pending = None;
                let size = entry_bytes::<SightingRecord>(&LogEntry::Marker(marker.clone()));
                self.since = self.since.plus(Span {
                    entries: 1,
                    bytes: size,
                });
                self.markers.push((sequence, marker));
            }
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(record),
                ..
            } => {
                let size = Span {
                    entries: 1,
                    bytes: record_bytes(&record),
                };
                self.since = self.since.plus(size);
                self.record(sequence, record, size)?;
            }
        }
        Ok(())
    }

    fn record(
        &mut self,
        sequence: EventSequence,
        record: SightingRecord,
        size: Span,
    ) -> Result<(), SightingsError> {
        let bad = |detail| SightingsError::BadRecord { sequence, detail };
        match record {
            SightingRecord::Sighted { sightings } => {
                self.pending = None;
                if sightings.len() > MAX_SIGHTINGS_PER_RECORD {
                    return Err(bad("it holds too many sightings"));
                }
                self.merge(sightings)?;
            }
            SightingRecord::RestatementBegins {
                parts,
                total,
                losses,
            } => {
                if losses.len() > MAX_LOSSES {
                    return Err(bad("it carries too many losses"));
                }
                if total > MAX_SIGHTINGS as u64 || parts > total || (parts == 0) != (total == 0) {
                    return Err(bad("its parts and total disagree"));
                }
                self.pending = Some(Pending {
                    parts,
                    total,
                    next_part: 1,
                    count: 0,
                    losses,
                    span: size,
                });
                self.complete();
            }
            SightingRecord::Restated { part, sightings } => {
                if sightings.len() > MAX_SIGHTINGS_PER_RECORD {
                    return Err(bad("it holds too many sightings"));
                }
                let count = sightings.len() as u64;
                self.merge(sightings)?;
                match self.pending.as_mut() {
                    Some(pending) if pending.next_part == part => {
                        pending.next_part = part.saturating_add(1);
                        pending.count = pending.count.saturating_add(count);
                        pending.span = pending.span.plus(size);
                        self.complete();
                    }
                    _ => self.pending = None,
                }
            }
        }
        Ok(())
    }

    /// Ends the pending restatement once its last part is read: complete when it held
    /// the sightings it announced, abandoned otherwise.
    fn complete(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.next_part <= pending.parts {
            self.pending = Some(pending);
            return;
        }
        if pending.count == pending.total {
            self.losses = pending.losses;
            self.since = pending.span;
        }
    }

    fn merge(&mut self, sightings: Vec<Sighting>) -> Result<(), SightingsError> {
        for sighting in sightings {
            let (key, time) = sighting.into_report();
            let entry = self.first_reported.entry(key).or_insert(time);
            *entry = (*entry).min(time);
        }
        if self.first_reported.len() > MAX_SIGHTINGS {
            return Err(SightingsError::TooMany { max: MAX_SIGHTINGS });
        }
        Ok(())
    }
}

/// Adds a loss; past [`MAX_LOSSES`] it joins the last, which then covers more sequences
/// than were lost, never fewer.
fn push_loss(losses: &mut Vec<LostRange>, loss: LostRange) {
    if losses.len() < MAX_LOSSES {
        losses.push(loss);
        return;
    }
    if let Some(last) = losses.last_mut() {
        if let Some(joined) = SequenceRange::new(last.missing.first(), loss.missing.last()) {
            last.missing = joined;
            last.reason = loss.reason;
        }
    }
}

/// The sightings of one stream, kept durably (CORE-06; S06). One owner at a time.
#[derive(Debug)]
pub struct SightingsLog {
    log: DurableLog<SightingRecord>,
    sightings: Sightings,
    losses: Vec<LostRange>,
    markers: Vec<(EventSequence, LogMarker)>,
    since: Span,
    budget: Span,
    segment_bytes: u64,
}

impl SightingsLog {
    /// Takes ownership of the sightings stream `stream` in `directory` for `owner`,
    /// creating it if the directory holds none, recovers it as [`DurableLog::open`] does,
    /// and replays it. Refuses while any owner holds the stream, bounds that leave no room
    /// for a restatement, and a stream with a record this module does not write.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        config: LogConfig,
    ) -> Result<(Self, OpenReport), SightingsError> {
        config
            .validate()
            .map_err(|error| SightingsError::Log(LogError::Config(error)))?;
        let budget = Span {
            entries: config.max_entries.saturating_sub(config.segment_entries) / 2,
            bytes: config.max_bytes.saturating_sub(config.segment_bytes) / 2,
        };
        if budget.entries == 0 || budget.bytes == 0 {
            return Err(SightingsError::BoundsTooSmall);
        }
        let (log, report) =
            DurableLog::open(directory, stream, owner, config).map_err(SightingsError::Log)?;
        let mut replayed = Replayed::default();
        let mut cursor = log.start();
        loop {
            let batch = log
                .read(&cursor, REPLAY_BATCH_ITEMS)
                .map_err(SightingsError::Log)?;
            let finished = batch.caught_up || batch.items.is_empty();
            for item in batch.items {
                replayed.fold(item)?;
            }
            cursor = batch.cursor;
            if finished {
                break;
            }
        }
        let mut sightings = Sightings::new();
        sightings.merge(replayed.first_reported);
        Ok((
            Self {
                log,
                sightings,
                losses: replayed.losses,
                markers: replayed.markers,
                since: replayed.since,
                budget,
                segment_bytes: config.segment_bytes,
            },
            report,
        ))
    }

    /// Takes in one scanner report as [`intake`](super::intake::intake) does, with the
    /// sightings this stream holds, and keeps the sightings it adds or moves earlier on the
    /// stream before they count and before the record is returned.
    pub fn intake(
        &mut self,
        inventory: &ConfigurationInventory,
        run: &ScanRun,
        report: &[u8],
        reachability: &ReachabilityStatements,
        clock: &TrustClock,
    ) -> Result<ScanRecord, SightingsError> {
        let (record, seen) = take_in(inventory, run, report, reachability, &self.sightings, clock)
            .map_err(SightingsError::Intake)?;
        let changes = self
            .sightings
            .changes(&seen)
            .map_err(SightingsError::Intake)?;
        if !changes.is_empty() {
            self.keep(&changes)?;
        }
        self.sightings.merge(changes);
        Ok(record)
    }

    /// The sightings held: every one the stream kept, and every one taken in since.
    pub fn sightings(&self) -> &Sightings {
        &self.sightings
    }

    /// Sequences whose sightings are unknown and that no restatement holds. A finding
    /// first reported only there may have its window restart; empty when the stream lost
    /// nothing.
    pub fn losses(&self) -> &[LostRange] {
        &self.losses
    }

    /// What owners found when they opened the stream, in order, as the replay read them.
    pub fn markers(&self) -> &[(EventSequence, LogMarker)] {
        &self.markers
    }

    /// The stream itself, for reads, cursors, retention and totals. Only
    /// [`SightingsLog::intake`] appends to it.
    pub fn log(&self) -> &DurableLog<SightingRecord> {
        &self.log
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), SightingsError> {
        self.log.close().map_err(SightingsError::Log)
    }

    /// Appends `changes`, restating everything held with them when appending alone would
    /// let the stream since the last restatement outgrow the budget.
    fn keep(&mut self, changes: &[(FindingKey, UnixSeconds)]) -> Result<(), SightingsError> {
        let sighted: Vec<Sighting> = changes
            .iter()
            .map(|(key, time)| Sighting::of(key, *time))
            .collect();
        let records = self.chunks(sighted, |sightings| SightingRecord::Sighted { sightings })?;
        let cost = span_of(&records);
        if self.since.plus(cost).within(self.budget) {
            return self.append(records, false);
        }
        let mut all: BTreeMap<FindingKey, UnixSeconds> = self
            .sightings
            .iter()
            .map(|(key, time)| (key.clone(), time))
            .collect();
        for (key, time) in changes {
            let entry = all.entry(key.clone()).or_insert(*time);
            *entry = (*entry).min(*time);
        }
        let total = all.len() as u64;
        let restated: Vec<Sighting> = all
            .iter()
            .map(|(key, time)| Sighting::of(key, *time))
            .collect();
        let mut part = 0_u64;
        let parts = self.chunks(restated, |sightings| {
            part = part.saturating_add(1);
            SightingRecord::Restated { part, sightings }
        })?;
        let mut restatement = vec![SightingRecord::RestatementBegins {
            parts: parts.len() as u64,
            total,
            losses: self.losses.clone(),
        }];
        restatement.extend(parts);
        let cost = span_of(&restatement);
        let fits_segment = restatement
            .iter()
            .all(|record| record_bytes(record) <= self.segment_bytes);
        // Within the budget, the stream since the last restatement plus this one stays
        // within what retention keeps, so nothing it is to hold can go before it is
        // complete. Only after the bounds were lowered can that stream exceed the budget;
        // the restatement is written all the same, since refusing would refuse every later
        // intake, and a stop before it completes shows in the replay as a loss.
        if !fits_segment || !cost.within(self.budget) {
            return Err(SightingsError::NoRoom {
                needed_entries: cost.entries,
                needed_bytes: cost.bytes,
                budget_entries: self.budget.entries,
                budget_bytes: self.budget.bytes,
            });
        }
        self.append(restatement, true)
    }

    /// Splits `sightings` into records of at most [`MAX_SIGHTINGS_PER_RECORD`] that each
    /// fit one segment.
    fn chunks(
        &self,
        sightings: Vec<Sighting>,
        mut wrap: impl FnMut(Vec<Sighting>) -> SightingRecord,
    ) -> Result<Vec<SightingRecord>, SightingsError> {
        // The record around no sighting, with the longest part number it could carry.
        let frame = record_bytes(&SightingRecord::Restated {
            part: u64::MAX,
            sightings: Vec::new(),
        });
        let mut records = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_bytes = frame;
        for sighting in sightings {
            let bytes = serde_json::to_vec(&sighting)
                .map_or(u64::MAX, |encoded| encoded.len() as u64)
                .saturating_add(1);
            if frame.saturating_add(bytes) > self.segment_bytes {
                return Err(SightingsError::BoundsTooSmall);
            }
            if chunk.len() == MAX_SIGHTINGS_PER_RECORD
                || chunk_bytes.saturating_add(bytes) > self.segment_bytes
            {
                records.push(wrap(std::mem::take(&mut chunk)));
                chunk_bytes = frame;
            }
            chunk_bytes = chunk_bytes.saturating_add(bytes);
            chunk.push(sighting);
        }
        if !chunk.is_empty() {
            records.push(wrap(chunk));
        }
        Ok(records)
    }

    /// Appends `records` in order. A restatement counts from its start once complete;
    /// until then, and after a failed append, what was appended counts after the last
    /// complete one.
    fn append(
        &mut self,
        records: Vec<SightingRecord>,
        restating: bool,
    ) -> Result<(), SightingsError> {
        let mut appended = Span::default();
        for record in records {
            let size = Span {
                entries: 1,
                bytes: record_bytes(&record),
            };
            if let Err(error) = self.log.append(record) {
                self.since = self.since.plus(appended);
                return Err(SightingsError::Log(error));
            }
            appended = appended.plus(size);
        }
        self.since = if restating {
            appended
        } else {
            self.since.plus(appended)
        };
        Ok(())
    }
}

fn span_of(records: &[SightingRecord]) -> Span {
    records.iter().fold(Span::default(), |span, record| {
        span.plus(Span {
            entries: 1,
            bytes: record_bytes(record),
        })
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::sandbox::trust::{
        BlockReason, CalendarAnchor, Disposition, Governance, GovernancePolicy, Severity,
    };
    use crate::sandbox::trust_scan::coverage::PackageListStatement;
    use crate::sandbox::trust_scan::intake::{ReportedAtBasis, TargetBinding};
    use crate::sandbox::trust_scan::inventory::tests::{configuration, runtime_inventory};
    use crate::sandbox::trust_scan::package::TargetName;
    use crate::sandbox::trust_scan::report::{ReportTarget, ScannerKind, ScannerVersion};

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_793_232_000;

    fn clock() -> TrustClock {
        let start = MonotonicTime::from_nanos(1_000);
        TrustClock::new(
            Arc::new(ManualClock::new(start)),
            CalendarAnchor {
                monotonic: start,
                unix_seconds: UnixSeconds::new(NOW),
            },
        )
        .unwrap()
    }

    fn inventory() -> ConfigurationInventory {
        ConfigurationInventory::new(configuration(), vec![runtime_inventory()]).unwrap()
    }

    fn stream() -> DurableStreamId {
        DurableStreamId::new("trust-scan.sightings").unwrap()
    }

    fn owner() -> ProducerId {
        ProducerId::new("trust-scan").unwrap()
    }

    fn config(max_entries: u64, segment_entries: u64) -> LogConfig {
        LogConfig {
            max_entries,
            max_bytes: 1 << 20,
            segment_entries,
            segment_bytes: 1 << 16,
        }
    }

    fn open(directory: &Path, config: LogConfig) -> SightingsLog {
        SightingsLog::open(directory, stream(), owner(), config)
            .unwrap()
            .0
    }

    fn run(scanned_at: u64) -> ScanRun {
        ScanRun {
            scanner: ScannerKind::Trivy,
            scanner_version: ScannerVersion::new("0.56.2").unwrap(),
            scanned_at: UnixSeconds::new(scanned_at),
            targets: vec![TargetBinding {
                target: ReportTarget::Named(TargetName::new("rt/Cargo.lock").unwrap()),
                components: BTreeMap::from([(
                    ComponentKind::Runtime,
                    ComponentVersion::new("rt-1.0.0").unwrap(),
                )]),
            }],
            package_lists: PackageListStatement::NotStated,
        }
    }

    /// A Trivy report of `ids` on the runtime's lockfile, without publication dates, so
    /// that only sightings start their windows.
    fn report(ids: &[String]) -> Vec<u8> {
        let vulnerabilities: Vec<_> = ids
            .iter()
            .map(|id| {
                json!({"VulnerabilityID": id, "PkgName": "fixture-codec", "InstalledVersion": "2.1.0",
                       "FixedVersion": "2.1.1", "Severity": "HIGH"})
            })
            .collect();
        json!({"SchemaVersion": 2, "Results": [{
            "Target": "rt/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo",
            "Vulnerabilities": vulnerabilities
        }]})
        .to_string()
        .into_bytes()
    }

    fn id(n: u64) -> String {
        format!("FIXTURE-2026-{n:04}")
    }

    fn take(
        log: &mut SightingsLog,
        ids: &[String],
        scanned_at: u64,
    ) -> Result<ScanRecord, SightingsError> {
        log.intake(
            &inventory(),
            &run(scanned_at),
            &report(ids),
            &ReachabilityStatements::none(),
            &clock(),
        )
    }

    fn first_reported(log: &SightingsLog, n: u64) -> Option<UnixSeconds> {
        log.sightings().first_reported(
            &AdvisoryId::new(id(n)).unwrap(),
            ComponentKind::Runtime,
            &ComponentVersion::new("rt-1.0.0").unwrap(),
        )
    }

    fn governance() -> Governance {
        Governance::new(GovernancePolicy {
            block_at: Severity::Medium,
            remediation_window_seconds: BTreeMap::from([
                (Severity::Low, 90 * DAY),
                (Severity::Medium, 30 * DAY),
                (Severity::High, 7 * DAY),
                (Severity::Critical, 2 * DAY),
            ]),
            max_exception_seconds: 60 * DAY,
        })
        .unwrap()
    }

    #[test]
    fn a_restart_neither_forgets_nor_restarts_a_window() {
        let directory = tempfile::tempdir().unwrap();
        let first_scan = NOW - 10 * DAY;
        let mut log = open(directory.path(), config(1_000, 100));
        let first = take(&mut log, &[id(1)], first_scan).unwrap();
        assert_eq!(
            first.findings[0].reported_at_basis,
            ReportedAtBasis::ThisScan
        );
        assert_eq!(log.log().last().map(EventSequence::get), Some(1));
        log.close().unwrap();

        let mut log = open(directory.path(), config(1_000, 100));
        assert_eq!(first_reported(&log, 1), Some(UnixSeconds::new(first_scan)));
        assert!(log.losses().is_empty() && log.markers().is_empty());
        let later = take(&mut log, &[id(1)], NOW - DAY).unwrap();
        assert_eq!(
            later.findings[0].reported_at_basis,
            ReportedAtBasis::EarlierScan
        );
        assert_eq!(
            later.findings[0].finding.reported_at,
            UnixSeconds::new(first_scan)
        );
        // Nothing new was sighted, so nothing was appended.
        assert_eq!(log.log().last().map(EventSequence::get), Some(1));
        let outcome = later
            .gate(&governance(), &configuration(), UnixSeconds::new(NOW))
            .unwrap();
        assert_eq!(
            outcome.dispositions[0].1,
            Disposition::Blocked {
                reason: BlockReason::PastDeadline {
                    deadline: UnixSeconds::new(first_scan + 7 * DAY)
                }
            }
        );
        // An earlier report than the one kept moves the sighting, durably.
        take(&mut log, &[id(1)], first_scan - DAY).unwrap();
        assert_eq!(log.log().last().map(EventSequence::get), Some(2));
        drop(log);

        let log = open(directory.path(), config(1_000, 100));
        assert_eq!(
            first_reported(&log, 1),
            Some(UnixSeconds::new(first_scan - DAY))
        );
        assert_eq!(log.sightings().len(), 1);
    }

    #[test]
    fn a_refused_intake_appends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), config(1_000, 100));
        assert!(matches!(
            log.intake(
                &inventory(),
                &run(NOW),
                b"{",
                &ReachabilityStatements::none(),
                &clock()
            ),
            Err(SightingsError::Intake(IntakeRefusal::Parse { .. }))
        ));
        assert!(matches!(
            take(&mut log, &[id(1)], NOW + 1),
            Err(SightingsError::Intake(
                IntakeRefusal::ScannedInFuture { .. }
            ))
        ));
        assert_eq!(log.log().last(), None);
        assert!(log.sightings().is_empty());
    }

    #[test]
    fn restatements_let_retention_drop_without_forgetting() {
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), config(24, 4));
        for n in 0..40 {
            take(&mut log, &[id(n)], NOW - (40 - n) * 3_600).unwrap();
        }
        assert!(log.log().retention().dropped_entries > 0);
        assert!(log.losses().is_empty());
        let mut cursor = log.log().start();
        let mut restatements = 0;
        loop {
            let batch = log.log().read(&cursor, 64).unwrap();
            for item in &batch.items {
                if let ReadItem::Entry {
                    entry: LogEntry::Record(SightingRecord::RestatementBegins { .. }),
                    ..
                } = item
                {
                    restatements += 1;
                }
            }
            cursor = batch.cursor;
            if batch.caught_up || batch.items.is_empty() {
                break;
            }
        }
        assert!(restatements > 0);
        log.close().unwrap();

        let log = open(directory.path(), config(24, 4));
        assert!(log.losses().is_empty(), "{:?}", log.losses());
        assert_eq!(log.sightings().len(), 40);
        for n in 0..40 {
            assert_eq!(
                first_reported(&log, n),
                Some(UnixSeconds::new(NOW - (40 - n) * 3_600))
            );
        }
    }

    #[test]
    fn a_restatement_that_cannot_fit_is_refused_before_anything_is_written() {
        let directory = tempfile::tempdir().unwrap();
        // Half of six entries less a segment of four leaves one entry: room for one
        // record, never for a restatement.
        let mut log = open(directory.path(), config(6, 4));
        take(&mut log, &[id(1)], NOW).unwrap();
        assert!(matches!(
            take(&mut log, &[id(2)], NOW),
            Err(SightingsError::NoRoom {
                needed_entries: 2,
                budget_entries: 1,
                ..
            })
        ));
        assert_eq!(log.log().last().map(EventSequence::get), Some(1));
        assert_eq!(log.sightings().len(), 1);
        drop(log);
        assert_eq!(
            SightingsLog::open(directory.path(), stream(), owner(), config(4, 4)).err(),
            Some(SightingsError::BoundsTooSmall)
        );
    }

    #[test]
    fn lost_sightings_are_reported_and_carried_by_restatements() {
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), config(24, 4));
        for n in 0..3 {
            take(&mut log, &[id(n)], NOW).unwrap();
        }
        log.close().unwrap();
        for entry in fs::read_dir(directory.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("segment-") {
                fs::remove_file(&path).unwrap();
            }
        }

        let mut log = open(directory.path(), config(24, 4));
        assert!(log.sightings().is_empty());
        assert_eq!(log.losses().len(), 1);
        let lost = log.losses()[0];
        assert_eq!(
            (lost.missing.first().get(), lost.missing.last().get()),
            (1, 3)
        );
        assert_eq!(lost.reason, GapReason::Truncated);
        assert!(matches!(log.markers()[0].1, LogMarker::Truncated { .. }));
        // Enough later sightings that the log restates them, and then retention drops the
        // gap itself: the loss stays named.
        for n in 10..60 {
            take(&mut log, &[id(n)], NOW).unwrap();
        }
        assert!(log.log().retention().dropped_entries > 0);
        log.close().unwrap();
        let log = open(directory.path(), config(24, 4));
        assert_eq!(log.sightings().len(), 50);
        assert_eq!(log.losses(), [lost]);
    }

    #[test]
    fn one_owner_at_a_time_and_records_are_read_strictly() {
        let directory = tempfile::tempdir().unwrap();
        let log = open(directory.path(), config(1_000, 100));
        assert!(matches!(
            SightingsLog::open(directory.path(), stream(), owner(), config(1_000, 100)),
            Err(SightingsError::Log(LogError::Owner(_)))
        ));
        log.close().unwrap();

        // A record this module never writes is refused at replay.
        let (mut raw, _) = DurableLog::<SightingRecord>::open(
            directory.path(),
            stream(),
            owner(),
            config(1_000, 100),
        )
        .unwrap();
        raw.append(SightingRecord::RestatementBegins {
            parts: 2,
            total: 1,
            losses: Vec::new(),
        })
        .unwrap();
        raw.close().unwrap();
        assert!(matches!(
            SightingsLog::open(directory.path(), stream(), owner(), config(1_000, 100)),
            Err(SightingsError::BadRecord { .. })
        ));

        let record = json!({"sighted": {"sightings": [{
            "advisory": "FIXTURE-2026-0001", "component": "runtime",
            "component_version": "rt-1.0.0", "first_reported": NOW
        }]}});
        assert!(serde_json::from_value::<SightingRecord>(record.clone()).is_ok());
        let mut extra = record;
        extra["sighted"]["sightings"][0]["trusted"] = json!(true);
        assert!(serde_json::from_value::<SightingRecord>(extra).is_err());
    }

    /// One step of a path into a JSON value.
    #[derive(Clone, Copy)]
    enum At {
        Key(&'static str),
        Index(usize),
    }

    /// A record written with the key `key` of the object at `object` twice, both times
    /// with its value, when it names one: a form `serde_json::Value` cannot hold.
    #[derive(Clone)]
    struct Document {
        value: serde_json::Value,
        repeated: Option<(Vec<At>, &'static str)>,
    }

    impl Serialize for Document {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let repeated = self
                .repeated
                .as_ref()
                .map(|(object, key)| (object.as_slice(), *key));
            Part {
                value: &self.value,
                repeated,
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Document {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self {
                value: serde_json::Value::deserialize(deserializer)?,
                repeated: None,
            })
        }
    }

    /// One part of a [`Document`] as it is written.
    struct Part<'a> {
        value: &'a serde_json::Value,
        repeated: Option<(&'a [At], &'a str)>,
    }

    impl Serialize for Part<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::{SerializeMap, SerializeSeq};
            use serde_json::Value;
            let Some((object, key)) = self.repeated else {
                return self.value.serialize(serializer);
            };
            match (self.value, object.split_first()) {
                (Value::Object(fields), None) => {
                    let mut map = serializer.serialize_map(None)?;
                    for (name, field) in fields {
                        map.serialize_entry(name, field)?;
                        if name == key {
                            map.serialize_entry(name, field)?;
                        }
                    }
                    map.end()
                }
                (Value::Object(fields), Some((At::Key(next), rest))) => {
                    let mut map = serializer.serialize_map(None)?;
                    for (name, field) in fields {
                        let repeated = (name == next).then_some((rest, key));
                        map.serialize_entry(
                            name,
                            &Part {
                                value: field,
                                repeated,
                            },
                        )?;
                    }
                    map.end()
                }
                (Value::Array(items), Some((At::Index(next), rest))) => {
                    let mut seq = serializer.serialize_seq(None)?;
                    for (index, item) in items.iter().enumerate() {
                        let repeated = (index == *next).then_some((rest, key));
                        seq.serialize_element(&Part {
                            value: item,
                            repeated,
                        })?;
                    }
                    seq.end()
                }
                _ => self.value.serialize(serializer),
            }
        }
    }

    /// `foundation::strict_serde` (the S06 item "Strict tags of read-back tagged enums" of
    /// docs/combined-plan-leftover-tasks.md): the records of the stream hold no internally
    /// or adjacently tagged enum, the one form serde reads a number for once it has
    /// buffered a record, so each line is read straight from JSON. A number for a record's
    /// variant, a component or a gap reason, and a key written twice, do not decode, and
    /// the stream does not open: the log is damaged at that line. The records as written
    /// replay.
    #[test]
    fn a_stored_record_with_a_number_for_a_variant_or_a_repeated_key_is_refused() {
        let sighted = json!({"sighted": {"sightings": [{
            "advisory": "FIXTURE-2026-0001", "component": "runtime",
            "component_version": "rt-1.0.0", "first_reported": NOW
        }]}});
        let lost = LostRange {
            missing: SequenceRange::new(EventSequence::FIRST, EventSequence::FIRST).unwrap(),
            reason: GapReason::Truncated,
        };
        let begins = json!({"restatement_begins": {
            "parts": 1, "total": 1, "losses": [serde_json::to_value(lost).unwrap()]
        }});
        for record in [&sighted, &begins] {
            assert!(serde_json::from_value::<SightingRecord>(record.clone()).is_ok());
        }
        let replay = |record: Document| {
            let directory = tempfile::tempdir().unwrap();
            let (mut raw, _) = DurableLog::<Document>::open(
                directory.path(),
                stream(),
                owner(),
                config(1_000, 100),
            )
            .unwrap();
            raw.append(record).unwrap();
            raw.close().unwrap();
            SightingsLog::open(directory.path(), stream(), owner(), config(1_000, 100))
                .map(|(log, _)| log.close().unwrap())
        };
        let plain = |value: serde_json::Value| Document {
            value,
            repeated: None,
        };
        let twice = |value: &serde_json::Value, object: &[At], key: &'static str| Document {
            value: value.clone(),
            repeated: Some((object.to_vec(), key)),
        };
        assert_eq!(replay(plain(sighted.clone())), Ok(()));

        let by_index = json!({ "0": sighted["sighted"].clone() });
        let mut cases = vec![("the variant by its index", plain(by_index))];
        let mut component = sighted.clone();
        component["sighted"]["sightings"][0]["component"] = json!(0);
        cases.push(("a component by its index", plain(component)));
        let mut reason = begins.clone();
        reason["restatement_begins"]["losses"][0]["reason"] = json!(0);
        cases.push(("a gap reason by its index", plain(reason)));
        cases.push(("the variant twice", twice(&sighted, &[], "sighted")));
        cases.push((
            "a sighting's field twice",
            twice(
                &sighted,
                &[At::Key("sighted"), At::Key("sightings"), At::Index(0)],
                "advisory",
            ),
        ));
        cases.push((
            "a restatement's field twice",
            twice(&begins, &[At::Key("restatement_begins")], "parts"),
        ));
        for (what, record) in cases {
            assert!(
                matches!(
                    replay(record),
                    Err(SightingsError::Log(LogError::Damaged(
                        crate::foundation::events::LogDamage::Line {
                            problem: crate::foundation::events::LineProblem::Encoding,
                            ..
                        }
                    )))
                ),
                "{what}"
            );
        }
    }
}
