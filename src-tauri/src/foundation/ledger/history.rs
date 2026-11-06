//! The owner of one host ledger's history: its closed reservation records and its events
//! (CORE-03, S2 line 40; cost attribution for BENCH-08, S7 line 128).
//!
//! A [`Ledger`] keeps every closed record and every event that happened without its
//! owner's call until someone takes them. When several clients share one host ledger, no
//! client may take them for itself, since another client's queued request may be waiting
//! for its grant. [`LedgerHistory`] is that someone: the one drainer per host ledger.
//!
//! - [`LedgerHistory::collect`] takes the ledger's closed records and events, so the
//!   ledger never accumulates them and no client has to stop admitting because they pile
//!   up. Each becomes a numbered [`HistoryEntry`]: the closed reservation records first,
//!   then the records of closed shared extents and of ended transition peaks, then the
//!   events, each kind in the order the ledger kept it.
//! - The ledger keeps extent and peak records in bounded lists of its own and counts what
//!   it drops from them. Records it dropped before the owner collected them become one
//!   [`HistoryItem::RecordsDropped`] entry and count as lost
//!   ([`HistoryTotals::lost_before_collect`]).
//! - A bounded window keeps the latest entries for cost attribution and diagnostics. The
//!   oldest leave first. An entry that leaves before any sink took it is counted as lost
//!   ([`HistoryTotals::lost_unexported`]); history is never dropped silently.
//! - [`LedgerHistory::export`] offers the entries no sink has taken, in sequence order, to
//!   a [`HistorySink`] such as the durable [`JsonLinesSink`] or the CORE-06
//!   [`HistoryJournal`](super::HistoryJournal). A sink takes a batch whole or refuses it; a
//!   refused batch stays for the next export.
//! - A queued request's outcome is kept for the client holding its ticket until that
//!   client takes it ([`LedgerHistory::take_outcome`]). Outcomes are bounded too: the
//!   oldest untaken outcome goes first, and taking it then says it was lost instead of
//!   still pending.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::admission::{Ledger, LedgerEvent};
use super::error::LedgerError;
use super::record::ReservationRecord;
use super::request::{QueueTicket, ReservationId};
use super::{PeakRecord, SharedExtentRecord};
use crate::foundation::ids::Clock;

/// How much history one owner keeps in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryLimits {
    max_entries: usize,
    max_outcomes: usize,
}

impl HistoryLimits {
    /// 4,096 entries in the window and 256 untaken ticket outcomes per host ledger.
    pub const DEFAULT: Self = Self {
        max_entries: 4_096,
        max_outcomes: 256,
    };

    /// `max_entries` entries in the window and `max_outcomes` untaken ticket outcomes;
    /// both must be at least one.
    pub fn new(max_entries: usize, max_outcomes: usize) -> Result<Self, HistoryError> {
        if max_entries == 0 {
            return Err(HistoryError::ZeroLimit {
                limit: "max_entries",
            });
        }
        if max_outcomes == 0 {
            return Err(HistoryError::ZeroLimit {
                limit: "max_outcomes",
            });
        }
        Ok(Self {
            max_entries,
            max_outcomes,
        })
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn max_outcomes(&self) -> usize {
        self.max_outcomes
    }
}

/// One piece of ledger history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryItem {
    /// A reservation the ledger closed, with its whole accounting record.
    Closed { record: Box<ReservationRecord> },
    /// A queued request was granted.
    QueueGranted {
        ticket: QueueTicket,
        reservation: ReservationId,
    },
    /// A queued request was refused, for the reason the ledger gave.
    QueueRefused { ticket: QueueTicket, reason: String },
    /// A granted reservation was reclaimed because its workload was never created.
    Reclaimed { reservation: ReservationId },
    /// A shared extent closed, with each holder's time and share of its cost (BENCH-08).
    ExtentClosed { record: Box<SharedExtentRecord> },
    /// A transition peak ended, and how.
    PeakEnded { record: Box<PeakRecord> },
    /// The ledger dropped this many records of closed shared extents and of ended
    /// transition peaks from its bounded lists before this owner collected them; they are
    /// lost.
    RecordsDropped {
        extent_records: u64,
        peak_records: u64,
    },
}

/// A numbered piece of ledger history. Sequences start at 1 and increase by one for each
/// entry one owner collects, so a reader of exported entries can tell a duplicate (a
/// sequence it has seen) from a gap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub sequence: u64,
    pub item: HistoryItem,
}

/// What became of a queued request, for the client holding its ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TicketOutcome {
    /// Not decided when last collected, already taken, or never queued in this ledger.
    Unknown,
    Granted {
        reservation: ReservationId,
    },
    Refused {
        error: LedgerError,
    },
    /// Decided, but dropped from the bounded outcomes before its holder took it.
    Lost,
}

/// Counts over the owner's whole life.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryTotals {
    /// Entries collected from the ledger.
    pub collected: u64,
    /// Entries a sink took.
    pub exported: u64,
    /// Entries that left the window after a sink took them.
    pub evicted: u64,
    /// Entries that left the window before any sink took them.
    pub lost_unexported: u64,
    /// Ticket outcomes dropped before their holder took them.
    pub outcomes_lost: u64,
    /// Extent and peak records the ledger dropped before they were collected.
    pub lost_before_collect: u64,
}

/// Where exported history goes, such as a durable journal.
pub trait HistorySink {
    /// Takes `entries`, in sequence order, all or nothing.
    fn accept(&mut self, entries: &[HistoryEntry]) -> Result<(), SinkError>;
}

/// Why a sink refused a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError {
    pub reason: String,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the ledger history sink refused a batch: {}",
            self.reason
        )
    }
}

impl std::error::Error for SinkError {}

/// A history setting or file that cannot work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryError {
    /// A bound that must be at least one is zero.
    ZeroLimit { limit: &'static str },
    /// The journal directory cannot be created or read.
    Directory { reason: String },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit { limit } => write!(f, "the ledger history {limit} must be at least 1"),
            Self::Directory { reason } => {
                write!(
                    f,
                    "the ledger history journal directory is unusable: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for HistoryError {}

/// The one drainer of a host ledger's closed records and events (see the module docs).
#[derive(Debug)]
pub struct LedgerHistory {
    limits: HistoryLimits,
    next_sequence: u64,
    window: VecDeque<HistoryEntry>,
    /// The highest sequence a sink took; 0 when none has.
    exported_through: u64,
    outcomes: BTreeMap<QueueTicket, TicketOutcome>,
    /// Decided tickets, oldest first, for evicting untaken outcomes.
    outcome_order: VecDeque<QueueTicket>,
    /// Tickets whose outcome was dropped untaken, bounded like the outcomes.
    lost_tickets: BTreeSet<QueueTicket>,
    /// The ledger's counts of dropped extent and peak records at the last collection.
    drops_seen: (u64, u64),
    totals: HistoryTotals,
}

impl LedgerHistory {
    pub fn new(limits: HistoryLimits) -> Self {
        Self {
            limits,
            next_sequence: 1,
            window: VecDeque::new(),
            exported_through: 0,
            outcomes: BTreeMap::new(),
            outcome_order: VecDeque::new(),
            lost_tickets: BTreeSet::new(),
            drops_seen: (0, 0),
            totals: HistoryTotals::default(),
        }
    }

    pub fn limits(&self) -> HistoryLimits {
        self.limits
    }

    /// Takes every closed record, every record of a closed shared extent or an ended
    /// transition peak, and every event `ledger` holds, so it keeps none, and returns how
    /// many entries were added. Call it under the same lock as the ledger's other users,
    /// after any call that may close a reservation, an extent or a peak, or queue a
    /// decision.
    pub fn collect<C: Clock>(&mut self, ledger: &mut Ledger<C>) -> usize {
        let records = ledger.take_closed_records();
        let dropped = self.dropped_since_last(ledger);
        let extents = ledger.take_extent_records();
        let peaks = ledger.take_peak_records();
        let events = ledger.drain_events();
        let added = records.len()
            + usize::from(dropped.is_some())
            + extents.len()
            + peaks.len()
            + events.len();
        for record in records {
            self.push(HistoryItem::Closed {
                record: Box::new(record),
            });
        }
        if let Some(item) = dropped {
            self.push(item);
        }
        for record in extents {
            self.push(HistoryItem::ExtentClosed {
                record: Box::new(record),
            });
        }
        for record in peaks {
            self.push(HistoryItem::PeakEnded {
                record: Box::new(record),
            });
        }
        for event in events {
            match event {
                LedgerEvent::QueueGranted {
                    ticket,
                    reservation,
                } => {
                    self.decide(ticket, TicketOutcome::Granted { reservation });
                    self.push(HistoryItem::QueueGranted {
                        ticket,
                        reservation,
                    });
                }
                LedgerEvent::QueueRefused { ticket, error } => {
                    let reason = error.to_string();
                    self.decide(ticket, TicketOutcome::Refused { error });
                    self.push(HistoryItem::QueueRefused { ticket, reason });
                }
                LedgerEvent::Reclaimed { reservation } => {
                    self.push(HistoryItem::Reclaimed { reservation });
                }
            }
        }
        added
    }

    /// The outcome of `ticket`, handed over once: a later call says
    /// [`TicketOutcome::Unknown`]. Collect first to see the latest decisions.
    pub fn take_outcome(&mut self, ticket: QueueTicket) -> TicketOutcome {
        if let Some(outcome) = self.outcomes.remove(&ticket) {
            self.outcome_order.retain(|decided| *decided != ticket);
            return outcome;
        }
        if self.lost_tickets.remove(&ticket) {
            return TicketOutcome::Lost;
        }
        TicketOutcome::Unknown
    }

    /// Offers the entries no sink has taken to `sink`, in sequence order, and returns how
    /// many it took. A refusal keeps them for the next export.
    pub fn export(&mut self, sink: &mut dyn HistorySink) -> Result<usize, SinkError> {
        let first = self
            .window
            .iter()
            .position(|entry| entry.sequence > self.exported_through);
        let Some(first) = first else {
            return Ok(0);
        };
        let pending: Vec<HistoryEntry> = self.window.iter().skip(first).cloned().collect();
        sink.accept(&pending)?;
        if let Some(last) = pending.last() {
            self.exported_through = last.sequence;
        }
        let taken = pending.len();
        self.totals.exported = self
            .totals
            .exported
            .saturating_add(u64::try_from(taken).unwrap_or(u64::MAX));
        Ok(taken)
    }

    /// The entries in the window, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &HistoryEntry> {
        self.window.iter()
    }

    /// The closed records in the window, oldest first, for cost attribution.
    pub fn records(&self) -> impl Iterator<Item = &ReservationRecord> {
        self.window.iter().filter_map(|entry| match &entry.item {
            HistoryItem::Closed { record } => Some(record.as_ref()),
            _ => None,
        })
    }

    /// The records of closed shared extents in the window, oldest first, with each
    /// holder's share of the cost.
    pub fn extent_records(&self) -> impl Iterator<Item = &SharedExtentRecord> {
        self.window.iter().filter_map(|entry| match &entry.item {
            HistoryItem::ExtentClosed { record } => Some(record.as_ref()),
            _ => None,
        })
    }

    /// The records of ended transition peaks in the window, oldest first.
    pub fn peak_records(&self) -> impl Iterator<Item = &PeakRecord> {
        self.window.iter().filter_map(|entry| match &entry.item {
            HistoryItem::PeakEnded { record } => Some(record.as_ref()),
            _ => None,
        })
    }

    /// How many entries in the window no sink has taken.
    pub fn pending_export(&self) -> usize {
        self.window
            .iter()
            .filter(|entry| entry.sequence > self.exported_through)
            .count()
    }

    /// The highest sequence a sink took; 0 when none has.
    pub fn exported_through(&self) -> u64 {
        self.exported_through
    }

    pub fn totals(&self) -> HistoryTotals {
        self.totals
    }

    /// The extent and peak records `ledger` dropped since the last collection, as one
    /// entry, counted as lost; `None` when it dropped none.
    fn dropped_since_last<C: Clock>(&mut self, ledger: &Ledger<C>) -> Option<HistoryItem> {
        let now = (
            ledger.extent_records_dropped(),
            ledger.peak_records_dropped(),
        );
        let extent_records = now.0.saturating_sub(self.drops_seen.0);
        let peak_records = now.1.saturating_sub(self.drops_seen.1);
        self.drops_seen = now;
        if extent_records == 0 && peak_records == 0 {
            return None;
        }
        self.totals.lost_before_collect = self
            .totals
            .lost_before_collect
            .saturating_add(extent_records)
            .saturating_add(peak_records);
        Some(HistoryItem::RecordsDropped {
            extent_records,
            peak_records,
        })
    }

    fn push(&mut self, item: HistoryItem) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.window.push_back(HistoryEntry { sequence, item });
        self.totals.collected = self.totals.collected.saturating_add(1);
        while self.window.len() > self.limits.max_entries {
            let Some(oldest) = self.window.pop_front() else {
                break;
            };
            if oldest.sequence > self.exported_through {
                self.totals.lost_unexported = self.totals.lost_unexported.saturating_add(1);
            } else {
                self.totals.evicted = self.totals.evicted.saturating_add(1);
            }
        }
    }

    fn decide(&mut self, ticket: QueueTicket, outcome: TicketOutcome) {
        self.lost_tickets.remove(&ticket);
        if self.outcomes.insert(ticket, outcome).is_none() {
            self.outcome_order.push_back(ticket);
        }
        while self.outcomes.len() > self.limits.max_outcomes {
            let Some(oldest) = self.outcome_order.pop_front() else {
                break;
            };
            if self.outcomes.remove(&oldest).is_some() {
                self.totals.outcomes_lost = self.totals.outcomes_lost.saturating_add(1);
                self.lost_tickets.insert(oldest);
            }
        }
        while self.lost_tickets.len() > self.limits.max_outcomes {
            let Some(oldest) = self.lost_tickets.iter().next().copied() else {
                break;
            };
            self.lost_tickets.remove(&oldest);
        }
    }
}

const JOURNAL_PREFIX: &str = "ledger-history-";
const JOURNAL_SUFFIX: &str = ".jsonl";

/// A durable journal of exported history: one JSON object per line in numbered files,
/// rotated by size and bounded in number.
///
/// A batch is serialized whole before anything is written, then appended and synced to
/// storage. If a write fails part-way, some of its lines may already be on disk and are
/// written again by the next export, so a reader treats a repeated sequence as a
/// duplicate. Rotation removes the oldest journal files beyond the bound; they hold
/// accounting history, never user data.
#[derive(Debug)]
pub struct JsonLinesSink {
    directory: PathBuf,
    max_file_bytes: u64,
    max_files: usize,
    index: u64,
}

impl JsonLinesSink {
    /// A journal in `directory`, created when missing, continuing after the highest
    /// numbered file already there.
    pub fn open(
        directory: impl Into<PathBuf>,
        max_file_bytes: u64,
        max_files: usize,
    ) -> Result<Self, HistoryError> {
        if max_file_bytes == 0 {
            return Err(HistoryError::ZeroLimit {
                limit: "max_file_bytes",
            });
        }
        if max_files == 0 {
            return Err(HistoryError::ZeroLimit { limit: "max_files" });
        }
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(|error| HistoryError::Directory {
            reason: error.kind().to_string(),
        })?;
        let index = journal_indices(&directory)?.last().copied().unwrap_or(1);
        Ok(Self {
            directory,
            max_file_bytes,
            max_files,
            index,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The journal files, oldest first.
    pub fn files(&self) -> Result<Vec<PathBuf>, HistoryError> {
        Ok(journal_indices(&self.directory)?
            .into_iter()
            .map(|index| self.path(index))
            .collect())
    }

    fn path(&self, index: u64) -> PathBuf {
        self.directory
            .join(format!("{JOURNAL_PREFIX}{index:06}{JOURNAL_SUFFIX}"))
    }

    fn open_current(&mut self) -> Result<File, SinkError> {
        let size = fs::metadata(self.path(self.index))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if size >= self.max_file_bytes {
            self.index = self.index.saturating_add(1);
            self.prune()?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(self.index))
            .map_err(|error| SinkError {
                reason: error.kind().to_string(),
            })
    }

    /// Removes the oldest files beyond the bound, never the current one.
    fn prune(&self) -> Result<(), SinkError> {
        let indices = journal_indices(&self.directory).map_err(|error| SinkError {
            reason: error.to_string(),
        })?;
        let keep_older = self.max_files.saturating_sub(1);
        let older: Vec<u64> = indices
            .into_iter()
            .filter(|index| *index < self.index)
            .collect();
        let excess = older.len().saturating_sub(keep_older);
        for index in older.into_iter().take(excess) {
            fs::remove_file(self.path(index)).map_err(|error| SinkError {
                reason: error.kind().to_string(),
            })?;
        }
        Ok(())
    }
}

impl HistorySink for JsonLinesSink {
    fn accept(&mut self, entries: &[HistoryEntry]) -> Result<(), SinkError> {
        let mut lines = Vec::new();
        for entry in entries {
            serde_json::to_writer(&mut lines, entry).map_err(|error| SinkError {
                reason: error.to_string(),
            })?;
            lines.push(b'\n');
        }
        let mut file = self.open_current()?;
        file.write_all(&lines)
            .and_then(|()| file.sync_data())
            .map_err(|error| SinkError {
                reason: error.kind().to_string(),
            })
    }
}

/// The numbers of the journal files in `directory`, ascending.
fn journal_indices(directory: &Path) -> Result<Vec<u64>, HistoryError> {
    let entries = fs::read_dir(directory).map_err(|error| HistoryError::Directory {
        reason: error.kind().to_string(),
    })?;
    let mut indices = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| HistoryError::Directory {
            reason: error.kind().to_string(),
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(number) = name
            .strip_prefix(JOURNAL_PREFIX)
            .and_then(|rest| rest.strip_suffix(JOURNAL_SUFFIX))
        else {
            continue;
        };
        if let Ok(index) = number.parse::<u64>() {
            indices.push(index);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{
        Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, LedgerConfig, Priority,
        Provenance, QueueLimits, Requester, ReservationRequest, ResourceKey,
    };
    use super::*;
    use crate::foundation::evidence::{HostSubject, SourceClass};
    use crate::foundation::ids::{
        digest, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
    };

    const GIB: u64 = 1 << 30;
    const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);

    fn ledger(clock: &ManualClock) -> Ledger<&ManualClock> {
        let config = LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(300),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        };
        let host = HostSubject {
            machine: digest("yougori/test/machine/v1", &[b"history"]),
        };
        let mut ledger = Ledger::new(clock, host, config);
        ledger
            .declare_capacity(
                RAM,
                CapacityDeclaration {
                    total: 8 * GIB,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger
            .set_tenant_budget(TenantId::new("alpha").unwrap(), RAM, u64::MAX)
            .unwrap();
        ledger
    }

    fn request(name: &str, bytes: u64) -> ReservationRequest {
        ReservationRequest::new(
            Provenance {
                requester: Requester::ModelPlacement,
                execution: ExecutionId::new(name).unwrap(),
                operation: OperationId::new(format!("op-{name}")).unwrap(),
                tenant: TenantId::new("alpha").unwrap(),
                purpose: CostPurpose::Compute,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().host_ram_bytes(bytes),
        )
    }

    fn granted(ledger: &mut Ledger<&ManualClock>, name: &str, bytes: u64) -> ReservationId {
        match ledger.reserve(request(name, bytes)) {
            Ok(Admission::Granted(reservation)) => reservation,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    fn queued(ledger: &mut Ledger<&ManualClock>, name: &str, bytes: u64) -> QueueTicket {
        match ledger.reserve(request(name, bytes).wait_up_to(Duration::from_secs(60))) {
            Ok(Admission::Queued { ticket, .. }) => ticket,
            other => panic!("expected a queue entry, got {other:?}"),
        }
    }

    fn limits(entries: usize, outcomes: usize) -> HistoryLimits {
        HistoryLimits::new(entries, outcomes).unwrap()
    }

    fn clock() -> ManualClock {
        ManualClock::new(MonotonicTime::from_nanos(1_000))
    }

    #[derive(Default)]
    struct Memory {
        taken: Vec<HistoryEntry>,
        refuse: bool,
    }

    impl HistorySink for Memory {
        fn accept(&mut self, entries: &[HistoryEntry]) -> Result<(), SinkError> {
            if self.refuse {
                return Err(SinkError {
                    reason: "full".into(),
                });
            }
            self.taken.extend_from_slice(entries);
            Ok(())
        }
    }

    #[test]
    fn zero_limits_are_refused() {
        assert_eq!(
            HistoryLimits::new(0, 1),
            Err(HistoryError::ZeroLimit {
                limit: "max_entries"
            })
        );
        assert_eq!(
            HistoryLimits::new(1, 0),
            Err(HistoryError::ZeroLimit {
                limit: "max_outcomes"
            })
        );
    }

    #[test]
    fn collecting_empties_the_ledger_and_numbers_the_entries() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(16, 4));
        let first = granted(&mut ledger, "exe-a", GIB);
        let second = granted(&mut ledger, "exe-b", GIB);
        ledger.cancel(first).unwrap();
        ledger.cancel(second).unwrap();
        assert_eq!(ledger.closed_records().len(), 2);

        assert_eq!(history.collect(&mut ledger), 2);
        assert!(ledger.closed_records().is_empty());
        let sequences: Vec<u64> = history.entries().map(|entry| entry.sequence).collect();
        assert_eq!(sequences, vec![1, 2]);
        let closed: Vec<ReservationId> = history.records().map(|record| record.id()).collect();
        assert_eq!(closed, vec![first, second]);
        assert_eq!(history.collect(&mut ledger), 0);
        assert_eq!(history.totals().collected, 2);
    }

    #[test]
    fn the_window_is_bounded_and_counts_what_no_sink_took() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(3, 4));
        for index in 0..5 {
            let reservation = granted(&mut ledger, &format!("exe-{index}"), GIB);
            ledger.cancel(reservation).unwrap();
        }
        history.collect(&mut ledger);
        assert_eq!(history.entries().count(), 3);
        assert_eq!(
            history.entries().next().map(|entry| entry.sequence),
            Some(3)
        );
        assert_eq!(history.totals().lost_unexported, 2);
        assert_eq!(history.totals().evicted, 0);

        let mut sink = Memory::default();
        assert_eq!(history.export(&mut sink), Ok(3));
        for index in 5..7 {
            let reservation = granted(&mut ledger, &format!("exe-{index}"), GIB);
            ledger.cancel(reservation).unwrap();
        }
        history.collect(&mut ledger);
        let totals = history.totals();
        assert_eq!((totals.evicted, totals.lost_unexported), (2, 2));
        assert_eq!(history.pending_export(), 2);
    }

    #[test]
    fn export_is_in_order_once_and_a_refusal_keeps_the_batch() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(16, 4));
        for index in 0..3 {
            let reservation = granted(&mut ledger, &format!("exe-{index}"), GIB);
            ledger.cancel(reservation).unwrap();
        }
        history.collect(&mut ledger);

        let mut refusing = Memory {
            refuse: true,
            ..Memory::default()
        };
        assert!(history.export(&mut refusing).is_err());
        assert_eq!(history.exported_through(), 0);
        assert_eq!(history.pending_export(), 3);

        let mut sink = Memory::default();
        assert_eq!(history.export(&mut sink), Ok(3));
        assert_eq!(history.export(&mut sink), Ok(0));
        let sequences: Vec<u64> = sink.taken.iter().map(|entry| entry.sequence).collect();
        assert_eq!(sequences, vec![1, 2, 3]);
        assert_eq!(history.exported_through(), 3);
        assert_eq!(history.totals().exported, 3);
    }

    #[test]
    fn a_ticket_outcome_waits_for_its_holder_and_is_handed_over_once() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(16, 4));
        let holder = granted(&mut ledger, "exe-holder", 8 * GIB);
        let ticket = queued(&mut ledger, "exe-waiting", 4 * GIB);
        assert_eq!(history.take_outcome(ticket), TicketOutcome::Unknown);

        ledger.cancel(holder).unwrap();
        history.collect(&mut ledger);
        let TicketOutcome::Granted { reservation } = history.take_outcome(ticket) else {
            panic!("the queued request was granted");
        };
        assert!(ledger.reservation(reservation).is_some());
        assert_eq!(history.take_outcome(ticket), TicketOutcome::Unknown);
        assert!(history.entries().any(|entry| matches!(
            entry.item,
            HistoryItem::QueueGranted { ticket: granted, .. } if granted == ticket
        )));
    }

    #[test]
    fn untaken_outcomes_are_bounded_and_report_their_loss() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(64, 1));
        let holder = granted(&mut ledger, "exe-holder", 8 * GIB);
        let first = queued(&mut ledger, "exe-first", 2 * GIB);
        let second = queued(&mut ledger, "exe-second", 2 * GIB);
        ledger.cancel(holder).unwrap();
        history.collect(&mut ledger);

        assert_eq!(history.take_outcome(first), TicketOutcome::Lost);
        assert!(matches!(
            history.take_outcome(second),
            TicketOutcome::Granted { .. }
        ));
        assert_eq!(history.take_outcome(first), TicketOutcome::Unknown);
        assert_eq!(history.totals().outcomes_lost, 1);
    }

    #[test]
    fn a_refused_wait_keeps_its_reason() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(16, 4));
        let _holder = granted(&mut ledger, "exe-holder", 8 * GIB);
        let ticket = queued(&mut ledger, "exe-waiting", 4 * GIB);
        clock.advance(Duration::from_secs(61));
        let releasing = granted_or_none(&mut ledger);
        assert!(releasing.is_none());
        history.collect(&mut ledger);
        assert!(matches!(
            history.take_outcome(ticket),
            TicketOutcome::Refused { .. }
        ));
        assert!(history.entries().any(|entry| matches!(
            &entry.item,
            HistoryItem::QueueRefused { ticket: refused, reason }
                if *refused == ticket && !reason.is_empty()
        )));
    }

    /// Another request, which serves the queue first; the full host refuses it.
    fn granted_or_none(ledger: &mut Ledger<&ManualClock>) -> Option<ReservationId> {
        match ledger.reserve(request("exe-probe", GIB)) {
            Ok(Admission::Granted(reservation)) => Some(reservation),
            _ => None,
        }
    }

    #[test]
    fn the_ledger_never_piles_up_when_the_owner_collects() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(256, 4));
        for index in 0..5_000 {
            let reservation = granted(&mut ledger, &format!("exe-{index}"), GIB);
            ledger.cancel(reservation).unwrap();
            history.collect(&mut ledger);
            assert!(ledger.closed_records().is_empty());
        }
        assert_eq!(history.entries().count(), 256);
        assert_eq!(history.totals().collected, 5_000);
        assert_eq!(history.totals().lost_unexported, 5_000 - 256);
    }

    #[test]
    fn the_journal_round_trips_rotates_and_continues_after_reopening() {
        let clock = clock();
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(limits(64, 4));
        let directory = tempfile::tempdir().unwrap();
        let mut sink = JsonLinesSink::open(directory.path().join("journal"), 1, 2).unwrap();
        for index in 0..3 {
            let reservation = granted(&mut ledger, &format!("exe-{index}"), GIB);
            ledger.cancel(reservation).unwrap();
            history.collect(&mut ledger);
            history.export(&mut sink).unwrap();
        }
        let files = sink.files().unwrap();
        assert_eq!(files.len(), 2, "rotation keeps at most two files");
        let last = fs::read_to_string(files.last().unwrap()).unwrap();
        let entry: HistoryEntry = serde_json::from_str(last.trim_end()).unwrap();
        assert_eq!(entry.sequence, 3);
        assert!(matches!(entry.item, HistoryItem::Closed { .. }));

        let reopened = JsonLinesSink::open(directory.path().join("journal"), 1, 2).unwrap();
        assert_eq!(reopened.files().unwrap(), files);

        let unknown = r#"{"sequence":4,"item":{"reclaimed":{"reservation":1}},"extra":true}"#;
        assert!(serde_json::from_str::<HistoryEntry>(unknown).is_err());
        assert_eq!(
            JsonLinesSink::open(directory.path().join("other"), 0, 1).err(),
            Some(HistoryError::ZeroLimit {
                limit: "max_file_bytes"
            })
        );
    }
}
