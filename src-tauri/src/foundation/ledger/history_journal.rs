//! A bounded durable destination for a host ledger's history (CORE-03 with CORE-06;
//! docs/combined-plan-leftover-tasks.md S03: "an owner for bounded retention/export of
//! ledger history and events" and "a bounded durable history export destination"; S06
//! durable streams).
//!
//! A [`LedgerHistory`] keeps a bounded window in memory and counts what leaves it
//! unexported. Where exported history goes beyond that window, and how much of it is kept,
//! is the owner's decision, so nothing is exported by default:
//! [`HistoryDestination::NotConfigured`] is an explicit state, and
//! [`HistoryExport::export`] then reports what waits in the window instead of writing
//! anywhere.
//!
//! The one destination is a [`HistoryJournal`]: the history on a CORE-06 [`DurableLog`]
//! under the log's one [`StreamOwner`](crate::foundation::events::StreamOwner), in a
//! directory, under a stream name and owner, and within bounds ([`LogConfig`]) the owner
//! chooses. It writes no file format of its own; the durable log provides it:
//!
//! - Crash-safe appends. Each record is one verified line, acknowledged only once it and
//!   the stream's high-water mark are synced; a refused append leaves nothing of the
//!   record. A torn tail a crash left is quarantined and marked in the stream when the
//!   journal is opened again, and no sequence is used twice.
//! - Size and rotation. Segments rotate by entries and bytes, and retention drops whole
//!   segments, oldest first, counting every entry and byte it dropped across restarts
//!   ([`DurableLog::retention`]); a reader meets each drop as an explicit gap.
//! - Loss accounting in the stream itself. History entries the journal will never hold
//!   are recorded as [`JournalRecord::Missing`] by the owner's numbering, with the reason:
//!   they left the owner's window before any export took them, another sink or an earlier
//!   opening of the journal took them, or the log can never hold them (larger than a
//!   segment, or not encodable). Records the ledger dropped before the owner collected
//!   them arrive as [`HistoryItem::RecordsDropped`](super::HistoryItem::RecordsDropped)
//!   entries.
//!
//! Each history owner numbers its entries from 1, and each opening of the journal is a new
//! owner incarnation of the stream, so a reader tells entries apart by the incarnation and
//! the number. One journal serves one history owner: a batch that goes back to or before
//! the last entry the journal took is refused unless it repeats that entry, as a retry
//! after a refused batch does, and the entries already durable are then not appended
//! twice.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::history::{HistoryEntry, HistorySink, LedgerHistory, SinkError};
use crate::foundation::events::{
    DurableLog, DurableStreamId, LogConfig, LogError, OpenReport, ProducerId,
};

/// Where a host ledger's exported history goes (see the module documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HistoryDestination {
    /// No destination is configured, the default: history stays in the owner's bounded
    /// window, and what leaves it unexported is counted as lost.
    #[default]
    NotConfigured,
    /// A [`HistoryJournal`] in `directory`: the stream `stream`, appended by `owner`
    /// alone, within `bounds`.
    Journal {
        directory: PathBuf,
        stream: DurableStreamId,
        owner: ProducerId,
        bounds: LogConfig,
    },
}

/// Why history entries are not in the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// They left the owner's bounded window before any sink took them: lost.
    NotExported,
    /// Another sink, or an earlier opening of this journal, took them.
    ExportedElsewhere,
    /// The log can never hold them: larger than a segment, or not encodable. Lost.
    Unstorable,
}

impl fmt::Display for MissingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotExported => "they left the history window before any export took them",
            Self::ExportedElsewhere => "another sink or an earlier journal took them",
            Self::Unstorable => "the journal can never hold them",
        })
    }
}

/// One record of the history journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalRecord {
    /// One history entry, numbered by its owner.
    Entry(HistoryEntry),
    /// The owner's entries `first` to `last` are not in the journal, for `reason`.
    Missing {
        first: u64,
        last: u64,
        reason: MissingReason,
    },
}

/// Counts of what a journal did since it was opened. What retention dropped is counted
/// across restarts by the log ([`DurableLog::retention`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalTotals {
    /// History entries appended.
    pub appended: u64,
    /// Entries offered again after a refused batch that were already durable; none was
    /// appended twice.
    pub repeated: u64,
    /// Entries recorded missing because they left the window before any sink took them.
    pub not_exported: u64,
    /// Entries recorded missing because another sink or an earlier journal took them.
    pub exported_elsewhere: u64,
    /// Entries recorded missing because the log can never hold them.
    pub unstorable: u64,
    /// Batches storage refused; their owner keeps them for the next export.
    pub refused_batches: u64,
}

/// A host ledger's history on a CORE-06 durable log (see the module documentation).
#[derive(Debug)]
pub struct HistoryJournal {
    log: DurableLog<JournalRecord>,
    /// The highest number of the owner's entries the journal accounts for, taken or
    /// recorded missing; 0 before any.
    through: u64,
    /// The last entry it took or recorded unstorable, to recognise a repeated batch.
    last: Option<HistoryEntry>,
    totals: JournalTotals,
}

impl HistoryJournal {
    /// Takes ownership of the stream `stream` in `directory` for `owner`, creating it when
    /// the directory holds none, and recovers it as [`DurableLog::open`] does. Refused
    /// while any owner, in this process or another, holds it.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        bounds: LogConfig,
    ) -> Result<(Self, OpenReport), LogError> {
        let (log, report) = DurableLog::open(directory, stream, owner, bounds)?;
        Ok((
            Self {
                log,
                through: 0,
                last: None,
                totals: JournalTotals::default(),
            },
            report,
        ))
    }

    /// Exports what `history` holds that no sink took, as [`LedgerHistory::export`] does,
    /// and returns how many entries the journal took. Entries an earlier export gave
    /// another sink, or an earlier opening of this journal, are first recorded missing
    /// here, so that every gap is explained. A refusal keeps the entries in the window.
    pub fn export(&mut self, history: &mut LedgerHistory) -> Result<usize, SinkError> {
        let elsewhere = history.exported_through();
        if elsewhere > self.through {
            let first = self.through.saturating_add(1);
            self.record_missing(first, elsewhere, MissingReason::ExportedElsewhere)?;
        }
        history.export(self)
    }

    /// The durable log, to read the journal or inspect its retention and totals.
    pub fn log(&self) -> &DurableLog<JournalRecord> {
        &self.log
    }

    /// The highest number of the owner's entries the journal accounts for; 0 before any.
    pub fn through(&self) -> u64 {
        self.through
    }

    pub fn totals(&self) -> JournalTotals {
        self.totals
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), LogError> {
        self.log.close()
    }

    /// The part of `entries` the journal has not accounted for. A batch that goes back to
    /// or before the last entry the journal took is accepted only when it repeats that
    /// entry, as a retry after a refused batch does.
    fn fresh<'a>(&self, entries: &'a [HistoryEntry]) -> Result<&'a [HistoryEntry], SinkError> {
        let repeated = entries
            .iter()
            .take_while(|entry| entry.sequence <= self.through)
            .count();
        if repeated == 0 {
            return Ok(entries);
        }
        let repeats_last = self.last.as_ref().is_some_and(|last| {
            last.sequence == self.through && entries.get(repeated.saturating_sub(1)) == Some(last)
        });
        if !repeats_last {
            return Err(SinkError {
                reason: format!(
                    "the batch goes back to entry {} although the journal accounts for entries \
                     through {}; one journal serves one history owner",
                    entries.first().map_or(0, |entry| entry.sequence),
                    self.through
                ),
            });
        }
        Ok(entries.get(repeated..).unwrap_or_default())
    }

    /// Records the owner's entries `first` to `last` missing for `reason`.
    fn record_missing(
        &mut self,
        first: u64,
        last: u64,
        reason: MissingReason,
    ) -> Result<(), SinkError> {
        let record = JournalRecord::Missing {
            first,
            last,
            reason,
        };
        if let Err(error) = self.log.append(record) {
            return Err(self.refused(&error));
        }
        let count = last.saturating_sub(first).saturating_add(1);
        let counter = match reason {
            MissingReason::NotExported => &mut self.totals.not_exported,
            MissingReason::ExportedElsewhere => &mut self.totals.exported_elsewhere,
            MissingReason::Unstorable => &mut self.totals.unstorable,
        };
        *counter = counter.saturating_add(count);
        self.through = self.through.max(last);
        Ok(())
    }

    fn refused(&mut self, error: &LogError) -> SinkError {
        self.totals.refused_batches = self.totals.refused_batches.saturating_add(1);
        SinkError {
            reason: error.to_string(),
        }
    }
}

impl HistorySink for HistoryJournal {
    /// Appends the entries it has not accounted for, in order, each durable before the
    /// next. A gap in the owner's numbering is recorded missing first: those entries left
    /// the window before any sink took them. An entry the log can never hold is recorded
    /// missing instead of appended. A storage refusal stops the batch; the entries already
    /// durable are skipped when the owner offers the batch again.
    fn accept(&mut self, entries: &[HistoryEntry]) -> Result<(), SinkError> {
        let ascending = entries
            .iter()
            .zip(entries.iter().skip(1))
            .all(|(earlier, later)| earlier.sequence < later.sequence);
        if !ascending {
            return Err(SinkError {
                reason: "the batch is not in sequence order".to_owned(),
            });
        }
        let fresh = self.fresh(entries)?;
        let repeated = entries.len().saturating_sub(fresh.len());
        self.totals.repeated = self
            .totals
            .repeated
            .saturating_add(u64::try_from(repeated).unwrap_or(u64::MAX));
        for entry in fresh {
            let expected = self.through.saturating_add(1);
            if entry.sequence > expected {
                self.record_missing(
                    expected,
                    entry.sequence.saturating_sub(1),
                    MissingReason::NotExported,
                )?;
            }
            match self.log.append(JournalRecord::Entry(entry.clone())) {
                Ok(_) => {
                    self.totals.appended = self.totals.appended.saturating_add(1);
                    self.through = entry.sequence;
                }
                Err(LogError::TooLarge { .. } | LogError::Encoding { .. }) => {
                    self.record_missing(entry.sequence, entry.sequence, MissingReason::Unstorable)?;
                }
                Err(error) => return Err(self.refused(&error)),
            }
            self.last = Some(entry.clone());
        }
        Ok(())
    }
}

/// The export of one history owner: explicit when no destination is configured.
#[derive(Debug, Default)]
pub enum HistoryExport {
    /// No destination is configured, the default: nothing is written anywhere.
    #[default]
    NotConfigured,
    /// History goes to this journal.
    Journal(Box<HistoryJournal>),
}

/// What one export did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportOutcome {
    /// No destination is configured. `pending` entries wait in the owner's window; any
    /// that leave it before a destination takes them are counted as lost.
    NotConfigured { pending: usize },
    /// The journal took `entries` entries.
    Exported { entries: usize },
}

impl HistoryExport {
    /// The export `destination` describes: nothing for [`HistoryDestination::NotConfigured`],
    /// and otherwise its journal, opened, with what opening it found.
    pub fn open(destination: &HistoryDestination) -> Result<(Self, Option<OpenReport>), LogError> {
        match destination {
            HistoryDestination::NotConfigured => Ok((Self::NotConfigured, None)),
            HistoryDestination::Journal {
                directory,
                stream,
                owner,
                bounds,
            } => {
                let (journal, report) =
                    HistoryJournal::open(directory, stream.clone(), owner.clone(), *bounds)?;
                Ok((Self::Journal(Box::new(journal)), Some(report)))
            }
        }
    }

    /// Whether a destination is configured.
    pub fn is_configured(&self) -> bool {
        matches!(self, Self::Journal(_))
    }

    /// The journal, when one is configured.
    pub fn journal(&self) -> Option<&HistoryJournal> {
        match self {
            Self::NotConfigured => None,
            Self::Journal(journal) => Some(journal),
        }
    }

    /// Exports what `history` holds that no sink took, or says that no destination is
    /// configured and how much waits. A refusal keeps the entries in the window.
    pub fn export(&mut self, history: &mut LedgerHistory) -> Result<ExportOutcome, SinkError> {
        match self {
            Self::NotConfigured => Ok(ExportOutcome::NotConfigured {
                pending: history.pending_export(),
            }),
            Self::Journal(journal) => journal
                .export(history)
                .map(|entries| ExportOutcome::Exported { entries }),
        }
    }

    /// Releases the journal's stream, if one is configured.
    pub fn close(self) -> Result<(), LogError> {
        match self {
            Self::NotConfigured => Ok(()),
            Self::Journal(journal) => (*journal).close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::Duration;

    use super::super::{
        Admission, Amounts, CapacityDeclaration, CostPurpose, HistoryItem, HistoryLimits,
        HostResource, Ledger, LedgerConfig, Priority, Provenance, QueueLimits, QueueTicket,
        Requester, ReservationId, ReservationRequest, ResourceKey,
    };
    use super::*;
    use crate::foundation::events::{GapReason, LogEntry, LogMarker, ReadItem, Takeover};
    use crate::foundation::evidence::{HostSubject, SourceClass};
    use crate::foundation::ids::{
        digest, ExecutionId, Incarnation, ManualClock, MonotonicTime, OperationId, TenantId,
    };

    const GIB: u64 = 1 << 30;
    const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);

    fn bounds(max_entries: u64, segment_entries: u64, segment_bytes: u64) -> LogConfig {
        LogConfig {
            max_entries,
            max_bytes: 1 << 24,
            segment_entries,
            segment_bytes,
        }
    }

    fn destination(directory: &Path, bounds: LogConfig) -> HistoryDestination {
        HistoryDestination::Journal {
            directory: directory.to_path_buf(),
            stream: DurableStreamId::new("ledger.history").unwrap(),
            owner: ProducerId::new("ledger.history").unwrap(),
            bounds,
        }
    }

    fn open(directory: &Path, bounds: LogConfig) -> (HistoryJournal, OpenReport) {
        HistoryJournal::open(
            directory,
            DurableStreamId::new("ledger.history").unwrap(),
            ProducerId::new("ledger.history").unwrap(),
            bounds,
        )
        .unwrap()
    }

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
            machine: digest("yougori/test/machine/v1", &[b"history-journal"]),
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

    /// Grants and cancels `count` reservations, so the ledger closes `count` records.
    fn close_reservations(ledger: &mut Ledger<&ManualClock>, from: usize, count: usize) {
        for index in from..from + count {
            let request = ReservationRequest::new(
                Provenance {
                    requester: Requester::ModelPlacement,
                    execution: ExecutionId::new(format!("exe-{index}")).unwrap(),
                    operation: OperationId::new(format!("op-{index}")).unwrap(),
                    tenant: TenantId::new("alpha").unwrap(),
                    purpose: CostPurpose::Compute,
                    retry_number: 0,
                },
                Priority::Foreground,
                Amounts::new().host_ram_bytes(GIB),
            );
            let Ok(Admission::Granted(reservation)) = ledger.reserve(request) else {
                panic!("expected a grant");
            };
            ledger.cancel(reservation).unwrap();
        }
    }

    fn reclaimed(sequence: u64) -> HistoryEntry {
        HistoryEntry {
            sequence,
            item: HistoryItem::Reclaimed {
                reservation: ReservationId::new(sequence),
            },
        }
    }

    /// Every item of the journal, read from its start.
    fn read_all(journal: &HistoryJournal) -> Vec<ReadItem<JournalRecord>> {
        let log = journal.log();
        let mut cursor = log.start();
        let mut items = Vec::new();
        loop {
            let batch = log.read(&cursor, 64).unwrap();
            items.extend(batch.items);
            cursor = batch.cursor;
            if batch.caught_up {
                return items;
            }
        }
    }

    /// The journal's own records, in order, without the owners that wrote them.
    fn records(journal: &HistoryJournal) -> Vec<JournalRecord> {
        read_all(journal)
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

    fn entry_numbers(journal: &HistoryJournal) -> Vec<u64> {
        records(journal)
            .into_iter()
            .filter_map(|record| match record {
                JournalRecord::Entry(entry) => Some(entry.sequence),
                JournalRecord::Missing { .. } => None,
            })
            .collect()
    }

    #[test]
    fn nothing_is_exported_until_an_owner_configures_a_destination() {
        assert_eq!(
            HistoryDestination::default(),
            HistoryDestination::NotConfigured
        );
        let (mut export, report) = HistoryExport::open(&HistoryDestination::default()).unwrap();
        assert!(report.is_none());
        assert!(!export.is_configured());
        assert!(export.journal().is_none());
        assert!(matches!(
            HistoryExport::default(),
            HistoryExport::NotConfigured
        ));

        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(HistoryLimits::new(2, 4).unwrap());
        close_reservations(&mut ledger, 0, 3);
        history.collect(&mut ledger);
        assert_eq!(
            export.export(&mut history),
            Ok(ExportOutcome::NotConfigured { pending: 2 })
        );
        assert_eq!(history.exported_through(), 0);
        assert_eq!(history.totals().lost_unexported, 1);
        assert_eq!(export.close(), Ok(()));
    }

    #[test]
    fn the_journal_keeps_history_durably_and_a_restart_continues_it() {
        let directory = tempfile::tempdir().unwrap();
        let place = directory.path().join("history");
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(HistoryLimits::new(64, 4).unwrap());
        let (mut export, report) =
            HistoryExport::open(&destination(&place, bounds(64, 8, 1 << 20))).unwrap();
        assert!(report.unwrap().created);
        assert!(export.is_configured());

        close_reservations(&mut ledger, 0, 3);
        history.collect(&mut ledger);
        assert_eq!(
            export.export(&mut history),
            Ok(ExportOutcome::Exported { entries: 3 })
        );
        assert_eq!(
            export.export(&mut history),
            Ok(ExportOutcome::Exported { entries: 0 })
        );
        assert_eq!(history.exported_through(), 3);
        let journal = export.journal().unwrap();
        assert_eq!(journal.totals().appended, 3);
        assert_eq!(journal.through(), 3);
        export.close().unwrap();

        // A restart: a new owner numbers from 1 again, under the next owner incarnation.
        let (mut reopened, report) = open(&place, bounds(64, 8, 1 << 20));
        assert!(matches!(report.takeover, Takeover::Released { .. }));
        assert!(report.markers.is_empty());
        let mut history = LedgerHistory::new(HistoryLimits::new(64, 4).unwrap());
        close_reservations(&mut ledger, 3, 2);
        history.collect(&mut ledger);
        assert_eq!(reopened.export(&mut history), Ok(2));

        let owners: Vec<(Incarnation, u64)> = read_all(&reopened)
            .into_iter()
            .filter_map(|item| match item {
                ReadItem::Entry {
                    owner,
                    entry: LogEntry::Record(JournalRecord::Entry(entry)),
                    ..
                } => Some((owner, entry.sequence)),
                _ => None,
            })
            .collect();
        let first = owners[0].0;
        let second = first.next().unwrap();
        assert_eq!(
            owners,
            vec![(first, 1), (first, 2), (first, 3), (second, 1), (second, 2)]
        );
        let closed = records(&reopened)
            .into_iter()
            .filter(|record| {
                matches!(
                    record,
                    JournalRecord::Entry(HistoryEntry {
                        item: HistoryItem::Closed { .. },
                        ..
                    })
                )
            })
            .count();
        assert_eq!(closed, 5);
    }

    #[test]
    fn entries_that_left_the_window_unexported_are_recorded_missing() {
        let directory = tempfile::tempdir().unwrap();
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(HistoryLimits::new(2, 4).unwrap());
        let (mut journal, _) = open(directory.path(), bounds(64, 8, 1 << 20));
        close_reservations(&mut ledger, 0, 5);
        history.collect(&mut ledger);
        assert_eq!(history.totals().lost_unexported, 3);

        assert_eq!(journal.export(&mut history), Ok(2));
        close_reservations(&mut ledger, 5, 1);
        history.collect(&mut ledger);
        assert_eq!(journal.export(&mut history), Ok(1));
        let missing: Vec<JournalRecord> = records(&journal)
            .into_iter()
            .filter(|record| matches!(record, JournalRecord::Missing { .. }))
            .collect();
        assert_eq!(
            missing,
            vec![JournalRecord::Missing {
                first: 1,
                last: 3,
                reason: MissingReason::NotExported
            }]
        );
        assert_eq!(entry_numbers(&journal), vec![4, 5, 6]);
        assert_eq!(journal.totals().not_exported, 3);
    }

    #[test]
    fn entries_another_sink_took_are_recorded_as_exported_elsewhere() {
        let directory = tempfile::tempdir().unwrap();
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let mut ledger = ledger(&clock);
        let mut history = LedgerHistory::new(HistoryLimits::new(16, 4).unwrap());
        close_reservations(&mut ledger, 0, 2);
        history.collect(&mut ledger);
        let mut other =
            super::super::JsonLinesSink::open(directory.path().join("other"), 1 << 20, 2).unwrap();
        assert_eq!(history.export(&mut other), Ok(2));

        let (mut journal, _) = open(&directory.path().join("journal"), bounds(64, 8, 1 << 20));
        close_reservations(&mut ledger, 2, 1);
        history.collect(&mut ledger);
        assert_eq!(journal.export(&mut history), Ok(1));
        assert_eq!(
            records(&journal).first(),
            Some(&JournalRecord::Missing {
                first: 1,
                last: 2,
                reason: MissingReason::ExportedElsewhere
            })
        );
        assert_eq!(entry_numbers(&journal), vec![3]);
        assert_eq!(journal.totals().exported_elsewhere, 2);
    }

    #[test]
    fn a_repeated_batch_appends_nothing_twice_and_another_owners_batch_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = open(directory.path(), bounds(64, 8, 1 << 20));
        journal.accept(&[reclaimed(1), reclaimed(2)]).unwrap();
        // A retry offers the batch again with what followed: only the new entry is appended.
        journal
            .accept(&[reclaimed(1), reclaimed(2), reclaimed(3)])
            .unwrap();
        assert_eq!(entry_numbers(&journal), vec![1, 2, 3]);
        assert_eq!(journal.totals().repeated, 2);
        assert_eq!(journal.totals().appended, 3);

        // Another owner's numbering starts again at 1, with other entries: refused.
        let other = HistoryEntry {
            sequence: 3,
            item: HistoryItem::Reclaimed {
                reservation: ReservationId::new(99),
            },
        };
        assert!(journal.accept(&[reclaimed(1)]).is_err());
        assert!(journal.accept(&[other, reclaimed(4)]).is_err());
        // A batch out of sequence order is refused before anything is written.
        assert!(journal.accept(&[reclaimed(5), reclaimed(4)]).is_err());
        assert_eq!(entry_numbers(&journal), vec![1, 2, 3]);
        // The refusals left the journal where it was: the next entries follow on.
        journal.accept(&[reclaimed(4)]).unwrap();
        assert_eq!(entry_numbers(&journal), vec![1, 2, 3, 4]);
        assert_eq!(journal.totals().refused_batches, 0);
    }

    #[test]
    fn an_entry_the_log_cannot_hold_is_recorded_missing_and_skipped() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = open(directory.path(), bounds(64, 8, 1_024));
        let huge = HistoryEntry {
            sequence: 2,
            item: HistoryItem::QueueRefused {
                ticket: QueueTicket::new(7),
                reason: "x".repeat(2_048),
            },
        };
        journal
            .accept(&[reclaimed(1), huge.clone(), reclaimed(3)])
            .unwrap();
        assert_eq!(
            records(&journal),
            vec![
                JournalRecord::Entry(reclaimed(1)),
                JournalRecord::Missing {
                    first: 2,
                    last: 2,
                    reason: MissingReason::Unstorable
                },
                JournalRecord::Entry(reclaimed(3)),
            ]
        );
        assert_eq!(journal.totals().unstorable, 1);
        // Offered again, the unstorable entry is recognised as accounted for.
        journal.accept(&[huge, reclaimed(3), reclaimed(4)]).unwrap();
        assert_eq!(entry_numbers(&journal), vec![1, 3, 4]);
    }

    #[test]
    fn retention_bounds_the_journal_and_counts_what_it_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = open(directory.path(), bounds(4, 2, 1 << 20));
        let entries: Vec<HistoryEntry> = (1..=9).map(reclaimed).collect();
        journal.accept(&entries).unwrap();
        let retention = journal.log().retention();
        assert!(retention.retained_entries <= 4);
        assert!(retention.dropped_entries >= 5);
        assert_eq!(retention.retained_entries + retention.dropped_entries, 9);
        let items = read_all(&journal);
        assert!(matches!(
            items.first(),
            Some(ReadItem::Gap {
                reason: GapReason::Retention,
                ..
            })
        ));
        assert_eq!(entry_numbers(&journal).last(), Some(&9));

        // The dropped counts persist across a restart.
        journal.close().unwrap();
        let (reopened, _) = open(directory.path(), bounds(4, 2, 1 << 20));
        assert_eq!(
            reopened.log().retention().dropped_entries,
            retention.dropped_entries
        );
    }

    #[test]
    fn a_torn_append_left_by_a_crash_is_quarantined_and_marked() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = open(directory.path(), bounds(64, 64, 1 << 20));
        journal.accept(&[reclaimed(1), reclaimed(2)]).unwrap();
        journal.close().unwrap();
        // A crash in the middle of an append leaves half a line.
        let segment = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("segment-"))
            })
            .max()
            .unwrap();
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(b"0123456789abcdef {\"sequence\":3,")
            .unwrap();
        drop(file);

        let (mut reopened, report) = open(directory.path(), bounds(64, 64, 1 << 20));
        assert!(report
            .markers
            .iter()
            .any(|(_, marker)| matches!(marker, LogMarker::TornTail { .. })));
        assert_eq!(entry_numbers(&reopened), vec![1, 2]);
        reopened.accept(&[reclaimed(1)]).unwrap();
        assert_eq!(entry_numbers(&reopened), vec![1, 2, 1]);
    }

    #[test]
    fn journal_records_read_back_strictly() {
        let record = JournalRecord::Missing {
            first: 1,
            last: 3,
            reason: MissingReason::NotExported,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            serde_json::from_str::<JournalRecord>(&json).unwrap(),
            record
        );
        let extra = r#"{"missing":{"first":1,"last":3,"reason":"not_exported","why":1}}"#;
        assert!(serde_json::from_str::<JournalRecord>(extra).is_err());
        let unknown = r#"{"missing":{"first":1,"last":3,"reason":"forgotten"}}"#;
        assert!(serde_json::from_str::<JournalRecord>(unknown).is_err());
        assert!(MissingReason::Unstorable.to_string().contains("never hold"));
    }
}
