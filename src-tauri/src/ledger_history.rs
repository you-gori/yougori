//! Where the engine's host ledger history goes, and its automation method `ledger_history`
//! (CORE-03 with CORE-06: docs/combined-gpu-memory-and-vm-sandbox-plan.md S2, lines 212
//! and 215; docs/combined-plan-leftover-tasks.md S03: "wiring `HistoryExport` into
//! `model_runner/optimizer/capacity.rs` with an owner-chosen directory and bounds").
//!
//! The engine's one host ledger (`model_runner/optimizer/capacity.rs`) has one history
//! owner, a [`LedgerHistory`] that keeps a bounded window in memory. Where its history goes
//! beyond that window, and how much of it is kept, is the owner's decision, so nothing is
//! exported by default. The owner names a directory of its own with the environment
//! variable [`HISTORY_DIR_SETTING`], an absolute path, created if missing. The journal there
//! keeps at most [`HISTORY_MAX_BYTES_SETTING`] bytes ([`DEFAULT_MAX_BYTES`] when unset) and
//! [`HISTORY_MAX_ENTRIES_SETTING`] entries ([`DEFAULT_MAX_ENTRIES`] when unset), in sixteen
//! segments that retention drops oldest first. The variables are read once, when the
//! engine first uses them. Without the directory the destination is
//! [`HistoryDestination::NotConfigured`]: the status says so and how to configure it, and
//! nothing is written. A value that cannot be used is reported the same way and writes
//! nothing either.
//!
//! Export takes two steps, so that no file I/O ever happens under the ledger lock:
//!
//! - Staging, in memory. After each collection, under the ledger and history locks, the
//!   capacity adapter calls [`HistoryExporter::stage`]: the history exports what no sink
//!   took to the exporter's staging list, bounded by [`MAX_STAGED`]. A batch that does not
//!   fit is refused and stays in the window, which counts what leaves it unexported as
//!   lost.
//! - The journal, on storage. [`HistoryExporter::flush`] then offers the staged entries to
//!   the [`HistoryJournal`] under the exporter's own journal lock, with neither the ledger
//!   nor the history locked, and drops them from staging once the journal accounts for
//!   them. The journal syncs every entry, records every entry it will never hold as
//!   missing, and skips what it already holds when a batch is offered again, so nothing is
//!   written twice. A refusal never reaches admission: it is reported and counted, and the
//!   entries wait for the next export.
//!
//! The journal takes the staged entries through its [`HistorySink`] side rather than
//! [`HistoryJournal::export`], which needs the history itself for as long as it writes and
//! so would hold the history lock, and with it the ledger lock, across file I/O.
//!
//! Lock order: the host accounting, then the ledger, then the history, then staging; and
//! separately the journal lock, then staging. Staging is a leaf held only for memory work.
//! The journal lock is the only one held across file I/O, nothing takes it while holding
//! another of these locks, and the exporter holds no handle to the ledger or the history,
//! so it can never wait for them while it writes. The schedule lock (below) is a leaf
//! too, held only to change a few counters.
//!
//! Scheduling (review finding R1, docs/manager-work-split/reviewer-findings.md): an
//! export request after an accounting operation ([`export_in_background`]) never takes
//! the journal lock and never adds a second worker. Under the engine's runtime at most one
//! blocking worker per exporter runs at a time; a request while one runs marks the
//! schedule pending and is coalesced into that worker, which, after each write, serves a
//! pending request before it exits, so entries staged as a worker finishes are written
//! by that worker and never wait for an unrelated later admission. A worker that ends
//! without running (a runtime shutting down) leaves the request pending for the next one.
//! A journal writer that stalls therefore holds one blocking thread, not a growing queue
//! of them, and admission keeps going; the stall shows in the status, which never waits
//! for the journal either: while an export writes, the status reports the last known
//! journal state and that an export is in progress. Without a runtime (tests and tools)
//! the request writes on the caller's thread and does wait for storage.
//!
//! The journal opens on the first export. When it cannot, the failure is reported and
//! opening is tried again on an export at least [`OPEN_RETRY`] later, or at once with the
//! method's `export` action. It opens at most once per engine run: an opening is one owner
//! incarnation of the stream, and the history's numbering belongs to one run, so a journal
//! that refuses every append (a log poisoned by an append it could not undo) waits for the
//! engine to restart. An engine that stops leaves the stream to the next run as a stale
//! owner, which that run records; every entry the journal acknowledged is already durable.
//!
//! `status` (the default) shows whether a destination is configured and how to configure
//! it, the journal's location, owner incarnation, totals, retention and through-number, the
//! window's counts as of the last collection, what waits in staging, and the last export
//! failure, without touching storage. `export` writes what waits now.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::foundation::events::{DurableStreamId, LogConfig, OpenReport, ProducerId, Takeover};
use crate::foundation::ledger::{
    HistoryDestination, HistoryEntry, HistoryExport, HistorySink, HistoryTotals, LedgerHistory,
    SinkError,
};

/// The environment variable naming the journal's directory.
pub(crate) const HISTORY_DIR_SETTING: &str = "YOUGORI_LEDGER_HISTORY_DIR";

/// The value of [`HISTORY_DIR_SETTING`] that keeps the history in memory only, overriding the
/// default journal under the engine's data folder.
pub(crate) const HISTORY_OFF: &str = "off";

/// The journal's default folder under the engine's data folder when the setting is unset.
pub(crate) const DEFAULT_FOLDER: &str = "ledger-history";

/// The engine's data folder, handed over at start-up ([`use_data_folder`]).
static DATA_FOLDER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Hands the history export the engine's data folder before its first use; only the first
/// call counts.
pub(crate) fn use_data_folder(app_directory: &Path) {
    let _ = DATA_FOLDER.set(app_directory.to_path_buf());
}

/// The environment variable giving the bytes the journal keeps at most.
pub(crate) const HISTORY_MAX_BYTES_SETTING: &str = "YOUGORI_LEDGER_HISTORY_MAX_BYTES";

/// The environment variable giving the entries the journal keeps at most.
pub(crate) const HISTORY_MAX_ENTRIES_SETTING: &str = "YOUGORI_LEDGER_HISTORY_MAX_ENTRIES";

/// 64 MiB of journal when [`HISTORY_MAX_BYTES_SETTING`] is unset.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// 1,048,576 journal entries when [`HISTORY_MAX_ENTRIES_SETTING`] is unset.
pub(crate) const DEFAULT_MAX_ENTRIES: u64 = 1_048_576;

/// The bytes the owner may give: 1 MiB to 1 TiB.
const MAX_BYTES_RANGE: (u64, u64) = (1024 * 1024, 1 << 40);

/// The entries the owner may give: 1,024 to 2^32.
const MAX_ENTRIES_RANGE: (u64, u64) = (1_024, 1 << 32);

/// Retention drops whole segments, so the journal keeps between fifteen and sixteen
/// sixteenths of its bounds.
const SEGMENTS: u64 = 16;

/// The journal's stream in its directory.
pub(crate) const STREAM: &str = "ledger.history";

/// The producer that appends to it: the engine's host ledger history.
pub(crate) const OWNER: &str = "engine.ledger.history";

/// Entries that may wait in staging for the journal: as many as the history's default
/// window holds.
pub(crate) const MAX_STAGED: usize = 4_096;

/// The least time between two attempts to open a journal that could not be opened.
pub(crate) const OPEN_RETRY: Duration = Duration::from_secs(60);

/// The destination as configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HistorySetting {
    /// No directory is configured, the default: nothing is written.
    NotConfigured,
    /// `setting` holds `value`, which cannot be used because of `problem`: nothing is
    /// written.
    Invalid {
        setting: &'static str,
        value: String,
        problem: String,
    },
    /// The journal in `directory`, within `bounds`.
    Journal {
        directory: PathBuf,
        bounds: LogConfig,
    },
}

impl HistorySetting {
    /// The setting from the values of [`HISTORY_DIR_SETTING`],
    /// [`HISTORY_MAX_BYTES_SETTING`] and [`HISTORY_MAX_ENTRIES_SETTING`]. An absent or empty
    /// directory is not configured; a relative one, or a bound that is not a whole number
    /// in its range, is invalid; an absent or empty bound takes its default. Nothing is
    /// read here.
    pub(crate) fn from_values(
        directory: Option<&OsStr>,
        max_bytes: Option<&OsStr>,
        max_entries: Option<&OsStr>,
    ) -> Self {
        let Some(value) = directory.filter(|value| !value.is_empty()) else {
            return Self::NotConfigured;
        };
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Self::Invalid {
                setting: HISTORY_DIR_SETTING,
                value: value.to_string_lossy().into_owned(),
                problem: "it is not an absolute path".to_owned(),
            };
        }
        let max_bytes = match bound(
            HISTORY_MAX_BYTES_SETTING,
            max_bytes,
            DEFAULT_MAX_BYTES,
            MAX_BYTES_RANGE,
        ) {
            Ok(bytes) => bytes,
            Err(invalid) => return invalid,
        };
        let max_entries = match bound(
            HISTORY_MAX_ENTRIES_SETTING,
            max_entries,
            DEFAULT_MAX_ENTRIES,
            MAX_ENTRIES_RANGE,
        ) {
            Ok(entries) => entries,
            Err(invalid) => return invalid,
        };
        Self::Journal {
            directory: path,
            bounds: journal_bounds(max_bytes, max_entries),
        }
    }

    /// The setting from this process's environment, with the default applied: an unset
    /// directory means the journal under the engine's data folder ([`use_data_folder`],
    /// [`DEFAULT_FOLDER`]) within the default bounds; the value [`HISTORY_OFF`] keeps the
    /// history in memory, by the owner's choice (S03 "the configured journal policy").
    pub(crate) fn from_environment() -> Self {
        Self::from_values_with_default(
            std::env::var_os(HISTORY_DIR_SETTING).as_deref(),
            std::env::var_os(HISTORY_MAX_BYTES_SETTING).as_deref(),
            std::env::var_os(HISTORY_MAX_ENTRIES_SETTING).as_deref(),
            DATA_FOLDER.get().map(PathBuf::as_path),
        )
    }

    /// [`Self::from_values`] with the default directory under `data_folder` when the
    /// setting is unset, and [`HISTORY_OFF`] meaning not configured.
    pub(crate) fn from_values_with_default(
        directory: Option<&OsStr>,
        max_bytes: Option<&OsStr>,
        max_entries: Option<&OsStr>,
        data_folder: Option<&Path>,
    ) -> Self {
        let explicit = directory.filter(|value| !value.is_empty());
        if explicit.is_some_and(|value| {
            value
                .to_string_lossy()
                .trim()
                .eq_ignore_ascii_case(HISTORY_OFF)
        }) {
            return Self::NotConfigured;
        }
        match (explicit, data_folder) {
            (None, Some(folder)) => {
                let default = folder.join(DEFAULT_FOLDER);
                Self::from_values(Some(default.as_os_str()), max_bytes, max_entries)
            }
            _ => Self::from_values(directory, max_bytes, max_entries),
        }
    }

    /// Whether a usable journal directory is configured.
    pub(crate) fn is_journal(&self) -> bool {
        matches!(self, Self::Journal { .. })
    }

    /// The destination this setting names: [`HistoryDestination::NotConfigured`] unless it
    /// names a usable directory.
    pub(crate) fn destination(&self) -> Result<HistoryDestination, String> {
        match self {
            Self::NotConfigured | Self::Invalid { .. } => Ok(HistoryDestination::NotConfigured),
            Self::Journal { directory, bounds } => Ok(HistoryDestination::Journal {
                directory: directory.clone(),
                stream: DurableStreamId::new(STREAM).map_err(|error| error.to_string())?,
                owner: ProducerId::new(OWNER).map_err(|error| error.to_string())?,
                bounds: *bounds,
            }),
        }
    }

    fn view(&self) -> Value {
        match self {
            Self::NotConfigured => json!({
                "state": "not_configured",
                "setting": HISTORY_DIR_SETTING,
                "remedy": format!(
                    "No ledger history destination is configured and none is built in, so \
                     the host ledger's history stays in its bounded in-memory window, what \
                     leaves it unexported is counted as lost, and nothing is written. Set \
                     {HISTORY_DIR_SETTING} to the absolute path of a directory of its own \
                     (created if missing) for a durable journal, optionally with \
                     {HISTORY_MAX_BYTES_SETTING} (default {DEFAULT_MAX_BYTES} bytes) and \
                     {HISTORY_MAX_ENTRIES_SETTING} (default {DEFAULT_MAX_ENTRIES} entries), \
                     and restart the engine."
                ),
            }),
            Self::Invalid {
                setting,
                value,
                problem,
            } => json!({
                "state": "invalid",
                "setting": setting,
                "value": value,
                "remedy": format!(
                    "{setting} is '{value}', but {problem}; nothing is written until it is \
                     fixed and the engine restarts."
                ),
            }),
            Self::Journal { directory, bounds } => json!({
                "state": "configured",
                "setting": HISTORY_DIR_SETTING,
                "directory": directory.display().to_string(),
                "stream": STREAM,
                "owner": OWNER,
                "bounds": {
                    "max_bytes": bounds.max_bytes,
                    "max_entries": bounds.max_entries,
                    "segment_bytes": bounds.segment_bytes,
                    "segment_entries": bounds.segment_entries,
                    "settings": [HISTORY_MAX_BYTES_SETTING, HISTORY_MAX_ENTRIES_SETTING],
                },
            }),
        }
    }
}

/// The bound configured as `value` under `setting`: `default` when absent or empty, and
/// otherwise a whole number within `range`.
fn bound(
    setting: &'static str,
    value: Option<&OsStr>,
    default: u64,
    (low, high): (u64, u64),
) -> Result<u64, HistorySetting> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let text = value.to_string_lossy();
    match text.trim().parse::<u64>() {
        Ok(number) if (low..=high).contains(&number) => Ok(number),
        _ => Err(HistorySetting::Invalid {
            setting,
            value: text.into_owned(),
            problem: format!("it must be a whole number from {low} to {high}"),
        }),
    }
}

/// The journal's bounds for `max_bytes` and `max_entries`: sixteen segments, each of 64 KiB
/// to 64 MiB (also the largest entry the journal holds) and 64 to 65,536 entries.
fn journal_bounds(max_bytes: u64, max_entries: u64) -> LogConfig {
    LogConfig {
        max_entries,
        max_bytes,
        segment_entries: (max_entries / SEGMENTS).clamp(64, 65_536),
        segment_bytes: (max_bytes / SEGMENTS).clamp(64 * 1024, 64 * 1024 * 1024),
    }
}

/// The history's window as of a collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct WindowCounts {
    /// Entries in the window.
    pub held: usize,
    pub max_entries: usize,
    /// Entries in the window no sink took.
    pub pending_export: usize,
    /// The highest sequence a sink took; 0 when none has.
    pub exported_through: u64,
    pub totals: HistoryTotals,
}

impl WindowCounts {
    fn of(history: &LedgerHistory) -> Self {
        Self {
            held: history.entries().count(),
            max_entries: history.limits().max_entries(),
            pending_export: history.pending_export(),
            exported_through: history.exported_through(),
            totals: history.totals(),
        }
    }
}

/// History taken from the window that the journal has not accounted for yet.
#[derive(Debug, Default)]
struct Staged {
    entries: VecDeque<HistoryEntry>,
    /// Batches refused because they did not fit; the window kept them.
    refused_batches: u64,
    /// Collections the exporter saw.
    collections: u64,
    /// The window as of the last of them.
    window: Option<WindowCounts>,
}

impl Staged {
    /// Drops the entries the journal accounts for, those numbered up to `through`, and
    /// returns how many.
    fn settle(&mut self, through: u64) -> usize {
        let mut settled = 0;
        while self
            .entries
            .front()
            .is_some_and(|entry| entry.sequence <= through)
        {
            self.entries.pop_front();
            settled += 1;
        }
        settled
    }
}

impl HistorySink for Staged {
    /// Takes the whole batch when it fits under [`MAX_STAGED`], in memory, and refuses it
    /// otherwise.
    fn accept(&mut self, entries: &[HistoryEntry]) -> Result<(), SinkError> {
        if self.entries.len().saturating_add(entries.len()) > MAX_STAGED {
            self.refused_batches = self.refused_batches.saturating_add(1);
            return Err(SinkError {
                reason: format!(
                    "{} entries already wait for the journal, and at most {MAX_STAGED} may",
                    self.entries.len()
                ),
            });
        }
        self.entries.extend(entries.iter().cloned());
        Ok(())
    }
}

/// What opening the journal found.
#[derive(Clone, Copy, Debug, Serialize)]
struct Opened {
    created: bool,
    /// How the previous owner left the stream: `fresh`, `released`, `stale` or `lost`.
    takeover: &'static str,
    markers: usize,
    leftover_segments: u64,
    torn_tail: bool,
}

impl Opened {
    fn of(report: &OpenReport) -> Self {
        Self {
            created: report.created,
            takeover: match report.takeover {
                Takeover::Fresh => "fresh",
                Takeover::Released { .. } => "released",
                Takeover::Stale { .. } => "stale",
                Takeover::Lost { .. } => "lost",
            },
            markers: report.markers.len(),
            leftover_segments: report.leftover_segments,
            torn_tail: report.torn_tail.is_some(),
        }
    }
}

/// An export that failed.
#[derive(Clone, Debug)]
struct Failure {
    reason: String,
    at: Instant,
    /// Entries waiting in staging then.
    waiting: usize,
}

/// The journal and what exporting to it did. Only its lock is held across file I/O.
#[derive(Debug, Default)]
pub(crate) struct JournalState {
    export: HistoryExport,
    opened: Option<Opened>,
    /// No attempt to open the journal before then.
    next_attempt: Option<Instant>,
    flushes: u64,
    /// Staged entries the journal accounted for.
    exported: u64,
    failures: u64,
    last_failure: Option<Failure>,
}

impl JournalState {
    fn fail(&mut self, reason: String, waiting: usize) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure = Some(Failure {
            reason,
            at: Instant::now(),
            waiting,
        });
    }
}

/// What one export did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum FlushOutcome {
    /// No usable destination is configured: nothing was written.
    NotConfigured,
    /// The journal is not open, for `reason`; the staged entries wait.
    NotOpen { reason: String },
    /// The journal accounted for `entries` staged entries.
    Exported { entries: usize },
    /// The journal accounted for `entries` staged entries and then refused the rest, which
    /// wait for the next export.
    Refused { entries: usize, reason: String },
}

/// The background export schedule of one exporter (module documentation, scheduling):
/// whether a worker runs, whether a request waits for it, and the counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Schedule {
    /// A background worker is running or about to.
    pub(crate) worker_active: bool,
    /// A request arrived that no write has served yet.
    pub(crate) pending: bool,
    /// Requests made under a runtime.
    pub(crate) requests: u64,
    /// Workers started for them.
    pub(crate) workers_started: u64,
    /// Requests served by a worker already running.
    pub(crate) coalesced: u64,
    /// Writes the workers made.
    pub(crate) worker_runs: u64,
}

impl Schedule {
    /// A request arrived: whether the caller must start a worker for it.
    fn request(&mut self) -> bool {
        self.requests = self.requests.saturating_add(1);
        self.pending = true;
        if self.worker_active {
            self.coalesced = self.coalesced.saturating_add(1);
            false
        } else {
            self.worker_active = true;
            self.workers_started = self.workers_started.saturating_add(1);
            true
        }
    }

    /// A worker is about to write: it takes the pending request.
    fn begin_run(&mut self) {
        self.pending = false;
        self.worker_runs = self.worker_runs.saturating_add(1);
    }

    /// A worker wrote: whether it must write again for a request that arrived meanwhile;
    /// otherwise it exits.
    fn end_run(&mut self) -> bool {
        if self.pending {
            true
        } else {
            self.worker_active = false;
            false
        }
    }

    /// The worker ended without writing again: a pending request waits for the next one.
    fn worker_gone(&mut self) {
        self.worker_active = false;
    }
}

/// The export of one host ledger's history (see the module documentation).
#[derive(Debug)]
pub(crate) struct HistoryExporter {
    setting: HistorySetting,
    staged: Mutex<Staged>,
    journal: Mutex<JournalState>,
    schedule: Mutex<Schedule>,
    /// The journal's view as of the last export, for a status read while an export
    /// holds the journal lock.
    last_journal_view: Mutex<Option<Value>>,
}

/// Marks the schedule's worker gone when dropped: a worker that panicked or was never
/// run by a stopping runtime does not leave the schedule believing a worker runs.
struct WorkerLease {
    exporter: Arc<HistoryExporter>,
    exited: bool,
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if !self.exited {
            lock(&self.exporter.schedule).worker_gone();
        }
    }
}

/// Reads through a poisoned lock: staging and the journal state change only in whole
/// steps, and the journal recovers its own storage.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn encoded(value: impl Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

impl HistoryExporter {
    /// The export `setting` describes. Nothing is opened until the first export.
    pub(crate) fn new(setting: HistorySetting) -> Self {
        Self {
            setting,
            staged: Mutex::new(Staged::default()),
            journal: Mutex::new(JournalState::default()),
            schedule: Mutex::new(Schedule::default()),
            last_journal_view: Mutex::new(None),
        }
    }

    /// The background schedule now.
    pub(crate) fn schedule(&self) -> Schedule {
        *lock(&self.schedule)
    }

    /// Runs as the one background worker: writes, and writes again while requests
    /// arrive meanwhile, then exits. `lease` marks the worker gone if this never runs.
    fn run_worker(&self, mut lease: WorkerLease) {
        loop {
            lock(&self.schedule).begin_run();
            self.flush();
            if !lock(&self.schedule).end_run() {
                lease.exited = true;
                return;
            }
        }
    }

    /// An export with no destination: nothing is ever written.
    pub(crate) fn not_configured() -> Self {
        Self::new(HistorySetting::NotConfigured)
    }

    /// Whether a usable journal directory is configured.
    pub(crate) fn is_configured(&self) -> bool {
        self.setting.is_journal()
    }

    /// Takes what `history` holds that no sink took into staging, in memory, when a
    /// journal is configured, and notes the window's counts. The capacity adapter calls it
    /// after every collection, under the ledger and history locks; it takes only the
    /// staging lock, a leaf. A batch that does not fit stays in the window.
    pub(crate) fn stage(&self, history: &mut LedgerHistory) {
        let mut staged = lock(&self.staged);
        if self.setting.is_journal() {
            // A refusal is counted in `refused_batches`; the window keeps the batch and
            // counts what leaves it unexported.
            let _ = history.export(&mut *staged);
        }
        staged.window = Some(WindowCounts::of(history));
        staged.collections = staged.collections.saturating_add(1);
    }

    /// Writes what waits in staging to the journal, opening it first when needed and the
    /// retry interval allows. Call it with no ledger or history lock held.
    pub(crate) fn flush(&self) -> FlushOutcome {
        self.export(false)
    }

    /// As [`Self::flush`]; `force_open` tries to open the journal regardless of the retry
    /// interval.
    fn export(&self, force_open: bool) -> FlushOutcome {
        if !self.setting.is_journal() {
            return FlushOutcome::NotConfigured;
        }
        let mut journal = lock(&self.journal);
        let outcome = self.export_locked(&mut journal, force_open);
        // The view a status read during the next export falls back to.
        *lock(&self.last_journal_view) = Some(self.journal_view(&journal));
        outcome
    }

    /// [`Self::export`] on the locked journal.
    fn export_locked(&self, journal: &mut JournalState, force_open: bool) -> FlushOutcome {
        journal.flushes = journal.flushes.saturating_add(1);
        if !journal.export.is_configured() {
            if let Some(outcome) = self.open(journal, force_open) {
                return outcome;
            }
        }
        let batch: Vec<HistoryEntry> = lock(&self.staged).entries.iter().cloned().collect();
        if batch.is_empty() {
            return FlushOutcome::Exported { entries: 0 };
        }
        let HistoryExport::Journal(sink) = &mut journal.export else {
            return FlushOutcome::NotConfigured;
        };
        let accepted = sink.accept(&batch);
        let through = sink.through();
        let (entries, waiting) = {
            let mut staged = lock(&self.staged);
            (staged.settle(through), staged.entries.len())
        };
        journal.exported = journal
            .exported
            .saturating_add(u64::try_from(entries).unwrap_or(u64::MAX));
        match accepted {
            Ok(()) => FlushOutcome::Exported { entries },
            Err(error) => {
                let reason = error.to_string();
                journal.fail(reason.clone(), waiting);
                FlushOutcome::Refused { entries, reason }
            }
        }
    }

    /// Opens the journal unless the retry interval forbids it; `Some` when it is not open
    /// afterwards.
    fn open(&self, journal: &mut JournalState, force: bool) -> Option<FlushOutcome> {
        let now = Instant::now();
        if let Some(next) = journal.next_attempt.filter(|next| !force && now < *next) {
            return Some(FlushOutcome::NotOpen {
                reason: format!(
                    "the journal could not be opened; the next attempt is in {} s",
                    next.saturating_duration_since(now).as_secs()
                ),
            });
        }
        let opened = self
            .setting
            .destination()
            .and_then(|destination| HistoryExport::open(&destination).map_err(|e| e.to_string()));
        match opened {
            Ok((export, report)) => {
                journal.export = export;
                journal.opened = report.as_ref().map(Opened::of);
                journal.next_attempt = None;
                None
            }
            Err(error) => {
                let reason = format!("the journal could not be opened: {error}");
                let waiting = lock(&self.staged).entries.len();
                journal.fail(reason.clone(), waiting);
                journal.next_attempt = now.checked_add(OPEN_RETRY);
                Some(FlushOutcome::NotOpen { reason })
            }
        }
    }

    /// The journal's part of the status, from the locked journal state and its counts.
    fn journal_view(&self, journal: &JournalState) -> Value {
        let journal_state = match &journal.export {
            HistoryExport::Journal(open) => {
                let log = open.log();
                json!({
                    "state": "open",
                    "directory": log.owner().directory().display().to_string(),
                    "incarnation": log.owner().incarnation().get(),
                    "opened": encoded(journal.opened).unwrap_or(Value::Null),
                    "through": open.through(),
                    "last_sequence": log.last().map(|sequence| sequence.get()),
                    "totals": encoded(open.totals()).unwrap_or(Value::Null),
                    "retention": encoded(log.retention()).unwrap_or(Value::Null),
                    "log_totals": encoded(log.totals()).unwrap_or(Value::Null),
                })
            }
            HistoryExport::NotConfigured if self.setting.is_journal() => json!({
                "state": "not_open",
                "next_attempt_in_seconds": journal.next_attempt.map(|next| {
                    next.saturating_duration_since(Instant::now()).as_secs()
                }),
                "detail": "The journal opens on the first export after a collection, or with \
                           the export action.",
            }),
            HistoryExport::NotConfigured => Value::Null,
        };
        let last_failure = journal.last_failure.as_ref().map(|failure| {
            json!({
                "reason": failure.reason,
                "age_seconds": failure.at.elapsed().as_secs(),
                "waiting": failure.waiting,
            })
        });
        json!({
            "journal": journal_state,
            "exports": {
                "flushes": journal.flushes,
                "entries": journal.exported,
                "failures": journal.failures,
                "last_failure": last_failure,
            },
        })
    }

    /// The status of this export, from memory only, and without waiting for the journal:
    /// while an export writes, the journal part is the one known after the last export,
    /// marked in progress.
    pub(crate) fn status(&self) -> Result<Value, String> {
        let (window, collections, staged, refused) = {
            let staged = lock(&self.staged);
            (
                staged.window,
                staged.collections,
                staged.entries.len(),
                staged.refused_batches,
            )
        };
        let window = match window {
            Some(counts) => {
                let mut view = encoded(counts)?;
                view["collections"] = json!(collections);
                view
            }
            None => json!({
                "collections": 0,
                "detail": "The engine has not collected host ledger history in this run yet: \
                           no shared GPU admission has used the host ledger.",
            }),
        };
        let (mut journal_view, in_progress) = match self.journal.try_lock() {
            Ok(journal) => (self.journal_view(&journal), false),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                (self.journal_view(&poisoned.into_inner()), false)
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                let last = lock(&self.last_journal_view).clone().unwrap_or_else(|| {
                    json!({
                        "journal": {
                            "state": "opening",
                            "detail": "The first export is opening the journal now.",
                        },
                        "exports": { "flushes": 0, "entries": 0, "failures": 0, "last_failure": Value::Null },
                    })
                });
                (last, true)
            }
        };
        let schedule = self.schedule();
        journal_view["exports"]["in_progress"] = json!(in_progress);
        journal_view["exports"]["scheduling"] = json!({
            "worker_active": schedule.worker_active,
            "pending": schedule.pending,
            "requests": schedule.requests,
            "workers_started": schedule.workers_started,
            "coalesced": schedule.coalesced,
            "worker_runs": schedule.worker_runs,
        });
        if in_progress {
            journal_view["journal"]["in_progress"] = json!(true);
            journal_view["journal"]["detail"] = json!(
                "An export is writing to the journal now; this is the journal as of the last \
                 export."
            );
        }
        let destination = self.setting.view();
        Ok(json!({
            "state": destination["state"].clone(),
            "destination": destination,
            "journal": journal_view["journal"].take(),
            "window": window,
            "staged": {
                "entries": staged,
                "max_entries": MAX_STAGED,
                "refused_batches": refused,
            },
            "exports": journal_view["exports"].take(),
        }))
    }
}

/// Writes what `exporter` staged. Under the engine's runtime the write goes to the one
/// background worker of this exporter: started here if none runs, or served by the one
/// running before it exits (module documentation, scheduling), so the caller never waits
/// for storage and no second worker queues behind a slow journal. Without a runtime the
/// write happens here, on the caller's thread, and does wait for storage. Call it with no
/// ledger or history lock held.
pub(crate) fn export_in_background(exporter: Arc<HistoryExporter>) {
    if !exporter.is_configured() {
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            if lock(&exporter.schedule).request() {
                let lease = WorkerLease {
                    exporter: Arc::clone(&exporter),
                    exited: false,
                };
                drop(runtime.spawn_blocking(move || exporter.run_worker(lease)));
            }
        }
        Err(_) => {
            exporter.flush();
        }
    }
}

static ENGINE: LazyLock<Arc<HistoryExporter>> =
    LazyLock::new(|| Arc::new(HistoryExporter::new(HistorySetting::from_environment())));

/// The engine's one history export, configured from the environment on first use.
pub(crate) fn engine() -> Arc<HistoryExporter> {
    Arc::clone(&ENGINE)
}

/// The `ledger_history` method on `exporter`: `status` (the default) or `export`.
pub(crate) fn respond(exporter: &HistoryExporter, action: Option<&str>) -> Result<Value, String> {
    match action.unwrap_or("status") {
        "status" => exporter.status(),
        "export" => {
            let outcome = exporter.export(true);
            Ok(json!({ "export": encoded(&outcome)?, "status": exporter.status()? }))
        }
        other => Err(format!(
            "Unknown ledger history action '{other}'. Use status or export."
        )),
    }
}

/// The `ledger_history` automation method: `status` (the default) or `export`.
pub(crate) fn dispatch(action: Option<String>) -> Result<Value, String> {
    respond(&engine(), action.as_deref())
}

#[cfg(test)]
impl HistoryExporter {
    /// Holds the journal lock, as an export writing to storage does.
    pub(crate) fn hold_journal(&self) -> MutexGuard<'_, JournalState> {
        lock(&self.journal)
    }

    /// Entries waiting in staging.
    pub(crate) fn staged(&self) -> usize {
        lock(&self.staged).entries.len()
    }

    /// Every record of the journal, with the owner incarnation that appended it.
    pub(crate) fn journal_records(&self) -> Vec<(u64, crate::foundation::ledger::JournalRecord)> {
        use crate::foundation::events::{LogEntry, ReadItem};
        let journal = lock(&self.journal);
        let Some(open) = journal.export.journal() else {
            return Vec::new();
        };
        let log = open.log();
        let mut cursor = log.start();
        let mut records = Vec::new();
        loop {
            let batch = log.read(&cursor, 256).unwrap();
            for item in batch.items {
                if let ReadItem::Entry {
                    owner,
                    entry: LogEntry::Record(record),
                    ..
                } = item
                {
                    records.push((owner.get(), record));
                }
            }
            cursor = batch.cursor;
            if batch.caught_up {
                return records;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn absolute(name: &str) -> OsString {
        std::env::temp_dir().join(name).into_os_string()
    }

    #[test]
    fn settings_need_an_absolute_directory_and_bounded_whole_numbers() {
        assert_eq!(
            HistorySetting::from_values(None, None, None),
            HistorySetting::NotConfigured
        );
        assert_eq!(
            HistorySetting::from_values(Some(OsStr::new("")), None, None),
            HistorySetting::NotConfigured
        );
        assert!(matches!(
            HistorySetting::from_values(Some(OsStr::new("relative/history")), None, None),
            HistorySetting::Invalid {
                setting: HISTORY_DIR_SETTING,
                ..
            }
        ));

        let directory = absolute("ledger-history");
        let HistorySetting::Journal { bounds, .. } =
            HistorySetting::from_values(Some(&directory), None, Some(OsStr::new("")))
        else {
            panic!("an absolute directory configures the journal");
        };
        assert_eq!(
            bounds,
            journal_bounds(DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES)
        );
        assert_eq!(
            (bounds.segment_bytes, bounds.segment_entries),
            (4 << 20, 65_536)
        );
        assert_eq!(bounds.validate(), Ok(()));
        let HistorySetting::Journal { bounds, .. } = HistorySetting::from_values(
            Some(&directory),
            Some(OsStr::new(" 1048576 ")),
            Some(OsStr::new("1024")),
        ) else {
            panic!("the smallest bounds configure the journal");
        };
        assert_eq!(
            (bounds.max_bytes, bounds.segment_bytes),
            (1 << 20, 64 * 1024)
        );
        assert_eq!((bounds.max_entries, bounds.segment_entries), (1_024, 64));
        assert_eq!(bounds.validate(), Ok(()));

        for (bytes, entries, setting) in [
            ("1048575", "", HISTORY_MAX_BYTES_SETTING),
            ("64MiB", "", HISTORY_MAX_BYTES_SETTING),
            ("1099511627777", "", HISTORY_MAX_BYTES_SETTING),
            ("", "1023", HISTORY_MAX_ENTRIES_SETTING),
            ("", "-1", HISTORY_MAX_ENTRIES_SETTING),
        ] {
            let parsed = HistorySetting::from_values(
                Some(&directory),
                Some(OsStr::new(bytes)),
                Some(OsStr::new(entries)),
            );
            assert!(
                matches!(&parsed, HistorySetting::Invalid { setting: named, .. } if *named == setting),
                "{bytes} {entries}: {parsed:?}"
            );
            assert_eq!(parsed.destination(), Ok(HistoryDestination::NotConfigured));
        }
    }

    #[test]
    fn the_method_answers_whether_configured_or_not() {
        let quiet = HistoryExporter::not_configured();
        assert_eq!(quiet.flush(), FlushOutcome::NotConfigured);
        let status = respond(&quiet, None).unwrap();
        assert_eq!(status["state"], "not_configured");
        assert!(status["destination"]["remedy"]
            .as_str()
            .unwrap()
            .contains(HISTORY_DIR_SETTING));
        assert!(status["journal"].is_null());
        assert_eq!(status["window"]["collections"], 0);
        assert_eq!(status["exports"]["flushes"], 0);
        let exported = respond(&quiet, Some("export")).unwrap();
        assert_eq!(exported["export"]["outcome"], "not_configured");

        let invalid = HistoryExporter::new(HistorySetting::from_values(
            Some(OsStr::new("relative/history")),
            None,
            None,
        ));
        let status = respond(&invalid, Some("status")).unwrap();
        assert_eq!(status["state"], "invalid");
        assert!(status["destination"]["remedy"]
            .as_str()
            .unwrap()
            .contains("absolute"));
        assert_eq!(invalid.flush(), FlushOutcome::NotConfigured);
        assert!(!std::path::Path::new("relative").exists());

        let directory = tempfile::tempdir().unwrap();
        let place = directory.path().join("history");
        let configured = HistoryExporter::new(HistorySetting::from_values(
            Some(place.as_os_str()),
            None,
            None,
        ));
        let status = respond(&configured, None).unwrap();
        assert_eq!(status["state"], "configured");
        assert_eq!(status["journal"]["state"], "not_open");
        assert!(!place.exists(), "the status touches no storage");
        let exported = respond(&configured, Some("export")).unwrap();
        assert_eq!(exported["export"]["outcome"], "exported");
        let status = &exported["status"];
        assert_eq!(status["journal"]["state"], "open");
        assert_eq!(status["journal"]["opened"]["created"], true);
        assert_eq!(status["journal"]["through"], 0);
        assert_eq!(
            status["destination"]["bounds"]["max_bytes"],
            DEFAULT_MAX_BYTES
        );
        assert!(place.is_dir());

        let error = respond(&configured, Some("forget")).unwrap_err();
        assert!(error.contains("Use status or export"), "{error}");
        // Whatever the variables say on this computer, the engine's method answers and
        // reading its status opens nothing.
        let engine = dispatch(None).unwrap();
        assert!(engine["state"].is_string(), "{engine}");
    }

    /// Review finding R1: the schedule starts one worker, coalesces requests into it,
    /// has the worker write again for a request that arrived while it wrote, and lets
    /// the next request start a worker once the previous exited or never ran.
    #[test]
    fn the_schedule_runs_one_worker_and_serves_requests_that_arrive_while_it_writes() {
        let mut schedule = Schedule::default();
        assert!(schedule.request(), "the first request starts a worker");
        assert!(!schedule.request(), "the second is coalesced into it");
        assert_eq!(
            (
                schedule.workers_started,
                schedule.coalesced,
                schedule.requests
            ),
            (1, 1, 2)
        );
        schedule.begin_run();
        assert!(!schedule.pending, "the worker took both requests");
        assert!(
            !schedule.request(),
            "a request during the write is coalesced too"
        );
        assert!(schedule.end_run(), "and the worker writes again for it");
        schedule.begin_run();
        assert!(
            !schedule.end_run(),
            "nothing arrived meanwhile: the worker exits"
        );
        assert!(!schedule.worker_active);
        assert_eq!(schedule.worker_runs, 2);
        assert!(schedule.request(), "the next request starts a new worker");
        schedule.worker_gone();
        assert!(
            schedule.pending && !schedule.worker_active,
            "a worker that never ran leaves the request pending"
        );
        assert!(schedule.request(), "which the next worker serves");
        assert_eq!(schedule.workers_started, 3);
    }

    #[test]
    fn a_status_read_while_an_export_writes_shows_the_last_known_journal_in_progress() {
        let directory = tempfile::tempdir().unwrap();
        let exporter = HistoryExporter::new(HistorySetting::from_values(
            Some(directory.path().join("history").as_os_str()),
            None,
            None,
        ));
        // Before any export: the journal was never seen, and nothing waits.
        let held = exporter.hold_journal();
        let status = exporter.status().unwrap();
        assert_eq!(status["exports"]["in_progress"], true);
        assert_eq!(status["journal"]["state"], "opening");
        assert_eq!(status["journal"]["in_progress"], true);
        drop(held);
        assert_eq!(exporter.flush(), FlushOutcome::Exported { entries: 0 });
        let status = exporter.status().unwrap();
        assert_eq!(status["exports"]["in_progress"], false);
        assert_eq!(status["journal"]["state"], "open");
        assert!(status["journal"].get("in_progress").is_none());
        // During a write, the journal as of the last export, marked in progress.
        let held = exporter.hold_journal();
        let status = exporter.status().unwrap();
        assert_eq!(status["exports"]["in_progress"], true);
        assert_eq!(status["journal"]["state"], "open");
        assert_eq!(status["journal"]["in_progress"], true);
        assert_eq!(status["exports"]["flushes"], 1);
        assert_eq!(status["exports"]["scheduling"]["workers_started"], 0);
        drop(held);
    }
}

#[cfg(test)]
mod default_tests {
    use super::*;

    #[test]
    fn the_journal_defaults_to_the_data_folder_unless_the_owner_set_or_turned_it_off() {
        let data = std::env::temp_dir().join("yougori-history-default-test");
        let data = data.as_path();
        let setting = HistorySetting::from_values_with_default(None, None, None, Some(data));
        assert!(
            matches!(&setting, HistorySetting::Journal { directory, .. } if directory == &data.join(DEFAULT_FOLDER)),
            "{setting:?}"
        );
        let setting = HistorySetting::from_values_with_default(
            Some(OsStr::new("off")),
            None,
            None,
            Some(data),
        );
        assert_eq!(setting, HistorySetting::NotConfigured);
        let explicit = std::env::temp_dir().join("yougori-history-explicit-test");
        let setting = HistorySetting::from_values_with_default(
            Some(explicit.as_os_str()),
            None,
            None,
            Some(data),
        );
        assert!(
            matches!(&setting, HistorySetting::Journal { directory, .. } if directory == &explicit),
            "{setting:?}"
        );
        let setting = HistorySetting::from_values_with_default(None, None, None, None);
        assert_eq!(setting, HistorySetting::NotConfigured);
    }
}
