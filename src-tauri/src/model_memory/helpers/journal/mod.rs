//! Durable rollout state: every helper rollout decision and every runner start and stop on
//! one CORE-06 durable stream with one owner, replayed on restart (G08 in
//! docs/combined-plan-leftover-tasks.md: "persist rollout state" and "record rollout
//! decisions with CORE-08 evidence"; GPU-W11, lines 1321 and 1328–1329; S2 CORE-06 and
//! CORE-08; the S08 / M18 / G08 / E05 paragraph of docs/combined-plan-remaining-only.md:
//! "rollback resistance").
//!
//! A [`RolloutJournal`] owns one [`DurableLog`] of [`JournalRecord`]s under its one
//! [`StreamOwner`](crate::foundation::events::StreamOwner), and the [`HelperRollouts`] and
//! [`RunnerPins`] it keeps. Each decision is judged by the rollout on a copy first; its
//! record is appended, and only once it is durable does the decision take effect. A
//! refused decision or a failed append changes nothing.
//!
//! - Evidence by identity. A trial is recorded with the signed component of the helper
//!   bundle it ran ([`RolloutJournal::record`]); its record keeps the digest of the run
//!   records, CORE-08's judgement and the component ([`RecordedEvidence`]), never a
//!   provenance. A promotion and the removal of source injection take an
//!   [`EvidenceReference`] built again from the run records, which must name the measured
//!   pass the track holds and the verified signature of the version's bundle; otherwise
//!   they are refused ([`EvidenceRefusal`]).
//! - Restart. [`RolloutJournal::open`] replays the stream (the `replay` module): every
//!   decision goes through the rollout again and must do what it recorded; rollbacks below
//!   a track's floor, unknown versions and unwithdrawn quarantined versions in force are
//!   refused; gaps make the tracks they touch fall back, never forward; running runners
//!   keep exactly what they started with. After a gap the journal restates its state at
//!   once, so the next replay starts after it.
//! - Retention. Before an append would let the stream since the last complete restatement
//!   outgrow half of what retention keeps (bounds less one segment), the journal restates
//!   every track and running runner ([`JournalRecord::RestatementBegins`]); retention may
//!   then drop what came before. A restatement that cannot fit is refused
//!   ([`JournalError::NoRoom`]) before anything is written. Sizes are estimated from each
//!   record's encoding with a margin above the stored line's framing.
//! - Withdrawal. [`RolloutJournal::withdraw`] records the owner's decision to withdraw a
//!   version, such as one whose bundle the catalog quarantined after its key was revoked:
//!   it is rolled back as failure evidence would roll it back, in every track naming it.
//!
//! The line digests of the durable log detect a changed or cut record and a removed
//! segment; they are not signatures, and someone able to rewrite the stream's files and
//! digests can forge records the replay's own checks do not catch.
//!
//! # Production callers
//!
//! `model_runner` is not changed. A production caller would, at engine start after the
//! catalog is opened with the owner's trust roots, call [`RolloutJournal::open`] on its
//! own directory (stream `model-memory.helper-rollouts`, owner `model-memory.rollouts`)
//! with [`HelperAdmission::admissibility`](super::HelperAdmission::admissibility) and
//! [`OnQuarantine::Refuse`], and keep the journal in place of a bare [`HelperRollouts`]
//! and [`RunnerPins`]. Then:
//!
//! 1. The U01/U02 rollout actions call [`RolloutJournal::propose`],
//!    [`RolloutJournal::promote`], [`RolloutJournal::remove_source_injection`] and
//!    [`RolloutJournal::withdraw`]; promotion and removal with
//!    [`EvidenceReference::of`] over `Provenance::of_records` of the stored run records
//!    and the bundle's [`SignedComponent`] from the run's `SignedBuildIdentity`.
//! 2. `run_model_at_revision`, `run_registry_model`, `local::run_verified` and
//!    `refresh_server` call [`RolloutJournal::select`] per helper, open the bundles as
//!    before, then [`RolloutJournal::start_runner`]; on stop, [`RolloutJournal::stop_runner`].
//! 3. The measurement collector calls [`RolloutJournal::record`] with each trial's
//!    [`RolloutEvidence`] and the bundle's [`SignedComponent`].
//! 4. After [`ReplayReport::fell_back`] or a refusal, the host reconciles the restored
//!    runners against the processes actually running and restarts those
//!    [`RunnerPins::running_on`] lists for a withdrawn version.

mod record;
mod replay;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use self::replay::Replay;
use super::evidence::{check_component, check_decision, EvidenceReference, EvidenceRefusal};
use super::identity::{HelperPin, HelperPinId, PinAdmissibility};
use super::manifest::{HelperId, HelperVersion};
use super::rollout::restore::TrackState;
use super::rollout::{
    DefaultPath, HelperRollouts, Promotion, RecordOutcome, RolloutEvent, RolloutEvidence,
    RolloutRefusal, RolloutStage, RunnerHelpers, SelectionRefusal, SourceInjection,
    SourceInjectionRemoval, TrialVerdict,
};
use super::runners::{PinningRefusal, RunnerInstance, RunnerPins, RunnerStart};
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogEntry, LogError,
    LogMarker, OpenReport, ProducerId, SequenceRange,
};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::report::Label;
use crate::foundation::signing::SignedComponent;

pub use record::{
    JournalRecord, RecordedAbiRefusal, RecordedCandidate, RecordedDefault, RecordedEvidence,
    RecordedFallback, RecordedOutcome, RecordedPinRefusal, RecordedProof, RecordedRunner,
    RecordedSelection, RecordedServing, RecordedSkip, RecordedSourceInjection, RecordedTarget,
    RecordedTrack, RecordedVerdict, TrackPosition,
};
pub use replay::{FellBack, OnQuarantine, ReplayRefusal};

/// Items one read of the replay asks for; the replay reads until it is caught up.
const REPLAY_BATCH_ITEMS: usize = 1_024;
/// Bytes added to a record's encoding for its stored line: the line digest, the sequence,
/// the owner incarnation, the entry tag and the newline take less.
const LINE_MARGIN_BYTES: u64 = 192;

/// Entries and estimated bytes of a stretch of the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    entries: u64,
    bytes: u64,
}

impl Span {
    fn encoded<T: serde::Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        });
        Self {
            entries: 1,
            bytes: bytes.saturating_add(LINE_MARGIN_BYTES),
        }
    }

    fn of_entry(entry: &LogEntry<JournalRecord>) -> Self {
        Self::encoded(entry)
    }

    fn of_record(record: &JournalRecord) -> Self {
        Self::encoded(&LogEntry::Record(record))
    }

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

/// The owner's decision to withdraw a helper version, such as one whose bundle the
/// catalog quarantined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// The role that decided, such as `release-owner`.
    pub decided_by: Label,
    pub reason: Label,
}

/// What a withdrawal did to one track.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackWithdrawal {
    pub helper: HelperId,
    pub backend: Backend,
    /// The rollback, or `None` when the version was only a rollback target.
    pub outcome: Option<RecordOutcome>,
}

/// What opening the journal found and did.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayReport {
    /// What opening the durable stream found.
    pub opened: OpenReport,
    /// Records read.
    pub records: u64,
    /// Where the last complete restatement the replay started from began.
    pub restatement: Option<EventSequence>,
    /// What owners found when they opened the stream, in order.
    pub markers: Vec<(EventSequence, LogMarker)>,
    /// Sequences the replay never got, and why.
    pub gaps: Vec<(SequenceRange, GapReason)>,
    /// Tracks that lost records in a gap and fell back.
    pub fell_back: Vec<FellBack>,
    /// Quarantined versions withdrawn by this open ([`OnQuarantine::Withdraw`]).
    pub withdrawn: Vec<HelperPinId>,
    /// Whether this open restated the state, after a gap.
    pub restated: bool,
}

/// Why the journal refused an open or a decision. A refused decision changed nothing.
#[derive(Clone, Debug, PartialEq)]
pub enum JournalError {
    /// The rollout refused the decision.
    Rollout(RolloutRefusal),
    /// The runner's helpers were refused.
    Pinning(PinningRefusal),
    /// The decision's evidence was refused.
    Evidence(EvidenceRefusal),
    /// The replay refused the stream; nothing of it is in force.
    Replay(ReplayRefusal),
    /// Storage refused or failed; the decision did not take effect.
    Log(LogError),
    /// The log's bounds leave no room to restate the rollout state with this record
    /// without retention dropping what no restatement holds. Nothing was written.
    NoRoom {
        needed_entries: u64,
        needed_bytes: u64,
        budget_entries: u64,
        budget_bytes: u64,
    },
    /// Half of the bounds less one segment is zero: no restatement could ever fit.
    BoundsTooSmall,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rollout(refusal) => refusal.fmt(f),
            Self::Pinning(refusal) => refusal.fmt(f),
            Self::Evidence(refusal) => refusal.fmt(f),
            Self::Replay(refusal) => refusal.fmt(f),
            Self::Log(error) => write!(f, "the rollout stream failed: {error}"),
            Self::NoRoom {
                needed_entries,
                needed_bytes,
                budget_entries,
                budget_bytes,
            } => write!(
                f,
                "restating the rollout state takes {needed_entries} entries and about \
                 {needed_bytes} bytes; the log's bounds leave {budget_entries} entries and \
                 {budget_bytes} bytes"
            ),
            Self::BoundsTooSmall => {
                f.write_str("the log's bounds leave no room to restate the rollout state")
            }
        }
    }
}

impl std::error::Error for JournalError {}

impl From<RolloutRefusal> for JournalError {
    fn from(refusal: RolloutRefusal) -> Self {
        Self::Rollout(refusal)
    }
}

/// The rollout of every helper and the helpers of every running runner, kept durably
/// (CORE-06; G08). One owner at a time.
#[derive(Debug)]
pub struct RolloutJournal {
    log: DurableLog<JournalRecord>,
    rollouts: HelperRollouts,
    runners: RunnerPins,
    /// The runners started through the journal and not stopped.
    running: BTreeSet<RunnerInstance>,
    /// The number of each track's last record.
    records: BTreeMap<(HelperId, Backend), u64>,
    since: Span,
    budget: Span,
    segment_bytes: u64,
}

impl RolloutJournal {
    /// Takes ownership of the rollout stream `stream` in `directory` for `owner`, creating
    /// it if the directory holds none, recovers it as [`DurableLog::open`] does, and
    /// replays it. Every version in force is checked through `admissible`, the catalog's;
    /// a quarantined one the stream never withdrew is refused or withdrawn now, as
    /// `on_quarantine` says. Refuses while any owner holds the stream.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        config: LogConfig,
        admissible: &dyn PinAdmissibility,
        on_quarantine: OnQuarantine,
    ) -> Result<(Self, ReplayReport), JournalError> {
        config
            .validate()
            .map_err(|error| JournalError::Log(LogError::Config(error)))?;
        let budget = Span {
            entries: config.max_entries.saturating_sub(config.segment_entries) / 2,
            bytes: config.max_bytes.saturating_sub(config.segment_bytes) / 2,
        };
        if budget.entries == 0 || budget.bytes == 0 {
            return Err(JournalError::BoundsTooSmall);
        }
        let (log, opened) =
            DurableLog::open(directory, stream, owner, config).map_err(JournalError::Log)?;
        let mut replay = Replay::new();
        let mut cursor = log.start();
        loop {
            let batch = log
                .read(&cursor, REPLAY_BATCH_ITEMS)
                .map_err(JournalError::Log)?;
            let finished = batch.caught_up || batch.items.is_empty();
            for item in batch.items {
                replay.fold(item).map_err(JournalError::Replay)?;
            }
            cursor = batch.cursor;
            if finished {
                break;
            }
        }
        let records = replay.records;
        let restatement = replay.restatement;
        let since = replay.since;
        let markers = std::mem::take(&mut replay.markers);
        let gaps = std::mem::take(&mut replay.gaps);
        let restored = replay
            .finish(admissible, &on_quarantine)
            .map_err(JournalError::Replay)?;
        let mut journal = Self {
            log,
            rollouts: restored.rollouts,
            runners: restored.runners,
            running: restored.running,
            records: restored
                .tracks
                .iter()
                .map(|(key, meta)| (key.clone(), meta.records))
                .collect(),
            since,
            budget,
            segment_bytes: config.segment_bytes,
        };
        let mut withdrawn = Vec::new();
        if let OnQuarantine::Withdraw(decision) = &on_quarantine {
            for pin in restored.to_withdraw {
                journal.withdraw(pin, decision.clone(), admissible)?;
                withdrawn.push(pin);
            }
        }
        if restored.lost {
            journal.restate(Span::default())?;
        }
        let report = ReplayReport {
            opened,
            records,
            restatement,
            markers,
            gaps,
            fell_back: restored.fell_back,
            withdrawn,
            restated: restored.lost,
        };
        Ok((journal, report))
    }

    /// Makes `pin` the shadow candidate of its helper on `backend`, as
    /// [`HelperRollouts::propose`] does, once its record is durable.
    pub fn propose(
        &mut self,
        pin: HelperPin,
        backend: Backend,
        admissible: &dyn PinAdmissibility,
    ) -> Result<(), JournalError> {
        let mut next = self.rollouts.clone();
        next.propose(pin.clone(), backend, admissible)?;
        let track = self.position(&next, &pin.helper, backend)?;
        self.commit(JournalRecord::Proposed { track, pin }, Some(next), None)
    }

    /// Records one trial as [`HelperRollouts::record`] does, with `component`, the signed
    /// component of the bundle the trial ran: it must be that of the version's bundle, and
    /// verified for a pass. A failure rolls the track back once its record is durable.
    pub fn record(
        &mut self,
        evidence: RolloutEvidence,
        component: SignedComponent,
        admissible: &dyn PinAdmissibility,
    ) -> Result<RecordOutcome, JournalError> {
        let reference = EvidenceReference::of(&evidence.provenance, component)
            .map_err(|error| RolloutRefusal::Evidence { error })?;
        let backend = evidence.runner.backend;
        let (helper, held) = self
            .held(backend, evidence.pin)
            .ok_or(RolloutRefusal::UnknownPin { pin: evidence.pin })?;
        check_component(
            reference.component(),
            &held,
            evidence.verdict == TrialVerdict::Passed,
        )
        .map_err(|mismatch| {
            JournalError::Evidence(EvidenceRefusal::Bundle {
                pin: evidence.pin,
                mismatch,
            })
        })?;
        let mut next = self.rollouts.clone();
        let outcome = next.record(evidence.clone(), admissible)?;
        let track = self.position(&next, &helper, backend)?;
        let record = JournalRecord::Trial {
            track,
            pin: evidence.pin,
            runner: evidence.runner,
            stage: evidence.stage,
            verdict: RecordedVerdict::from(&evidence.verdict),
            evidence: RecordedEvidence::from(&reference),
            outcome: recorded_outcome(&next, Some(&outcome)),
        };
        self.commit(record, Some(next), None)?;
        Ok(outcome)
    }

    /// Moves the candidate of `helper` on `backend` one stage on, as
    /// [`HelperRollouts::promote`] does, on the measured pass `reference` names: it must be
    /// the one the track holds at the candidate's stage, with the verified signature of the
    /// candidate's bundle.
    pub fn promote(
        &mut self,
        helper: &HelperId,
        backend: Backend,
        reference: &EvidenceReference,
        admissible: &dyn PinAdmissibility,
    ) -> Result<Promotion, JournalError> {
        let state = self
            .rollouts
            .track_state(helper, backend)
            .ok_or(RolloutRefusal::UnknownTrack)?;
        let candidate = state.candidate.ok_or(RolloutRefusal::NoCandidate)?;
        check_decision(
            reference,
            &candidate.pin,
            candidate.stage,
            candidate.measured_pass,
        )
        .map_err(JournalError::Evidence)?;
        let mut next = self.rollouts.clone();
        let promotion = next.promote(helper, backend, admissible)?;
        let track = self.position(&next, helper, backend)?;
        let record = JournalRecord::Promoted {
            track,
            pin: promotion.pin,
            from: promotion.from,
            to: promotion.to,
            evidence: RecordedEvidence::from(reference),
        };
        self.commit(record, Some(next), None)?;
        Ok(promotion)
    }

    /// Records the owner's decision to remove source injection from the track of `helper`
    /// on `backend`, as [`HelperRollouts::remove_source_injection`] does, on the measured
    /// pass of the default as the backend default that `reference` names, with the verified
    /// signature of the default's bundle.
    pub fn remove_source_injection(
        &mut self,
        helper: &HelperId,
        backend: Backend,
        decision: SourceInjectionRemoval,
        reference: &EvidenceReference,
    ) -> Result<(), JournalError> {
        let state = self
            .rollouts
            .track_state(helper, backend)
            .ok_or(RolloutRefusal::UnknownTrack)?;
        if state.source_injection != SourceInjection::Retained {
            return Err(RolloutRefusal::SourceInjectionAlreadyRemoved.into());
        }
        let DefaultPath::Bundle { pin: default } = &state.default else {
            return Err(RolloutRefusal::ReplacementNotProven.into());
        };
        let proven = state.proven.get(&default.id()).copied();
        check_decision(reference, default, RolloutStage::BackendDefault, proven)
            .map_err(JournalError::Evidence)?;
        let mut next = self.rollouts.clone();
        next.remove_source_injection(helper, backend, decision.clone())?;
        let track = self.position(&next, helper, backend)?;
        let record = JournalRecord::SourceInjectionRemoved {
            track,
            replacement: default.id(),
            evidence: RecordedEvidence::from(reference),
            decided_by: decision.decided_by,
            reason: decision.reason,
        };
        self.commit(record, Some(next), None)
    }

    /// Records the owner's decision to withdraw `pin` from every track naming it as a
    /// candidate, default or rollback target: each is rolled back as failure evidence
    /// would roll it back, and the version is never proposed again. Running runners keep
    /// it until they stop; [`RunnerPins::running_on`] lists them.
    pub fn withdraw(
        &mut self,
        pin: HelperPinId,
        decision: Withdrawal,
        admissible: &dyn PinAdmissibility,
    ) -> Result<Vec<TrackWithdrawal>, JournalError> {
        let tracks: Vec<(HelperId, Backend)> = self
            .rollouts
            .track_states()
            .into_iter()
            .filter(|(_, _, state)| names(state, pin))
            .map(|(helper, backend, _)| (helper, backend))
            .collect();
        let mut withdrawn = Vec::new();
        for (helper, backend) in tracks {
            let mut next = self.rollouts.clone();
            let outcome = next.withdraw(&helper, backend, pin, decision.reason.clone(), admissible);
            let track = self.position(&next, &helper, backend)?;
            let record = JournalRecord::Withdrawn {
                track,
                pin,
                decided_by: decision.decided_by.clone(),
                reason: decision.reason.clone(),
                outcome: recorded_outcome(&next, outcome.as_ref()),
            };
            self.commit(record, Some(next), None)?;
            withdrawn.push(TrackWithdrawal {
                helper,
                backend,
                outcome,
            });
        }
        Ok(withdrawn)
    }

    /// What a new runner on `runner` starts with for `helper`, as
    /// [`HelperRollouts::select`] says.
    pub fn select(
        &self,
        helper: &HelperId,
        runner: &BackendRelease,
        opted_in: bool,
        admissible: &dyn PinAdmissibility,
    ) -> Result<RunnerHelpers, SelectionRefusal> {
        self.rollouts.select(helper, runner, opted_in, admissible)
    }

    /// Records what `runner` on `release` starts with, as [`RunnerPins::start`] does, once
    /// its record is durable.
    pub fn start_runner(
        &mut self,
        runner: RunnerInstance,
        release: BackendRelease,
        selected: Vec<RunnerHelpers>,
    ) -> Result<RunnerStart, JournalError> {
        let mut next = self.runners.clone();
        let start = next
            .start(runner, release, selected)
            .map_err(JournalError::Pinning)?
            .clone();
        let record = JournalRecord::RunnerStarted {
            start: RecordedRunner::from(&start),
        };
        self.commit(record, None, Some(next))?;
        self.running.insert(start.runner.clone());
        Ok(start)
    }

    /// Records that `runner` stopped and returns what it ran with; `None`, with nothing
    /// recorded, when it was not running.
    pub fn stop_runner(
        &mut self,
        runner: &RunnerInstance,
    ) -> Result<Option<RunnerStart>, JournalError> {
        if self.runners.get(runner).is_none() {
            return Ok(None);
        }
        let mut next = self.runners.clone();
        let stopped = next.stop(runner);
        let record = JournalRecord::RunnerStopped {
            runner: runner.clone(),
        };
        self.commit(record, None, Some(next))?;
        self.running.remove(runner);
        Ok(stopped)
    }

    /// The rollout, as the stream left it.
    pub fn rollouts(&self) -> &HelperRollouts {
        &self.rollouts
    }

    /// The running runners' helpers.
    pub fn runners(&self) -> &RunnerPins {
        &self.runners
    }

    /// The floor of the track of `helper` on `backend`: the newest version it saw. No
    /// version at or below it is proposed again.
    pub fn floor(&self, helper: &HelperId, backend: Backend) -> Option<HelperVersion> {
        self.rollouts
            .track_state(helper, backend)
            .and_then(|state| state.floor)
    }

    /// The stream itself, for reads, cursors, retention and totals. Only the journal's
    /// own methods append to it.
    pub fn log(&self) -> &DurableLog<JournalRecord> {
        &self.log
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), JournalError> {
        self.log.close().map_err(JournalError::Log)
    }

    /// The track on `backend` whose candidate or default `pin` names, and that version.
    fn held(&self, backend: Backend, pin: HelperPinId) -> Option<(HelperId, HelperPin)> {
        self.rollouts
            .track_states()
            .into_iter()
            .filter(|(_, track_backend, _)| *track_backend == backend)
            .find_map(|(helper, _, state)| {
                let candidate = state
                    .candidate
                    .map(|candidate| candidate.pin)
                    .filter(|candidate| candidate.id() == pin);
                let default = match state.default {
                    DefaultPath::Bundle { pin: default } if default.id() == pin => Some(default),
                    _ => None,
                };
                candidate.or(default).map(|held| (helper, held))
            })
    }

    /// The position of the next record of the track of `helper` on `backend`, with the
    /// floor `next` leaves it.
    fn position(
        &self,
        next: &HelperRollouts,
        helper: &HelperId,
        backend: Backend,
    ) -> Result<TrackPosition, JournalError> {
        let floor = next
            .track_state(helper, backend)
            .and_then(|state| state.floor)
            .ok_or(RolloutRefusal::UnknownTrack)?;
        let record = self
            .records
            .get(&(helper.clone(), backend))
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(TrackPosition {
            helper: helper.clone(),
            backend,
            record,
            floor,
        })
    }

    /// Appends `record`, restating the state first when appending alone would let the
    /// stream since the last restatement outgrow the budget; then puts `rollouts` and
    /// `runners` in place.
    fn commit(
        &mut self,
        record: JournalRecord,
        rollouts: Option<HelperRollouts>,
        runners: Option<RunnerPins>,
    ) -> Result<(), JournalError> {
        let cost = Span::of_record(&record);
        if !self.since.plus(cost).within(self.budget) {
            self.restate(cost)?;
        }
        let position = record
            .track()
            .map(|track| ((track.helper.clone(), track.backend), track.record));
        self.log.append(record).map_err(JournalError::Log)?;
        self.since = self.since.plus(cost);
        if let Some((key, number)) = position {
            self.records.insert(key, number);
        }
        if let Some(rollouts) = rollouts {
            self.rollouts = rollouts;
        }
        if let Some(runners) = runners {
            self.runners = runners;
        }
        Ok(())
    }

    /// Restates every track and running runner, with room for `then` after it within the
    /// budget; refused before anything is written when it cannot fit.
    fn restate(&mut self, then: Span) -> Result<(), JournalError> {
        let states = self.rollouts.track_states();
        let runners: Vec<RecordedRunner> = self
            .running
            .iter()
            .filter_map(|runner| self.runners.get(runner))
            .map(RecordedRunner::from)
            .collect();
        let mut records = vec![JournalRecord::RestatementBegins {
            tracks: count(&states),
            runners: count(&runners),
        }];
        for (part, (helper, backend, state)) in (1_u64..).zip(&states) {
            let number = self
                .records
                .get(&(helper.clone(), *backend))
                .copied()
                .unwrap_or(0);
            let floor = state.floor.ok_or(RolloutRefusal::UnknownTrack)?;
            let track = RecordedTrack::of(helper.clone(), *backend, number, floor, state);
            records.push(JournalRecord::RestatedTrack {
                part,
                track: Box::new(track),
            });
        }
        for (part, start) in (1_u64..).zip(runners) {
            records.push(JournalRecord::RestatedRunner { part, start });
        }
        let cost = records.iter().fold(Span::default(), |span, record| {
            span.plus(Span::of_record(record))
        });
        let fits_segment = records
            .iter()
            .all(|record| Span::of_record(record).bytes <= self.segment_bytes);
        let needed = cost.plus(then);
        if !fits_segment || !needed.within(self.budget) {
            return Err(JournalError::NoRoom {
                needed_entries: needed.entries,
                needed_bytes: needed.bytes,
                budget_entries: self.budget.entries,
                budget_bytes: self.budget.bytes,
            });
        }
        let mut appended = Span::default();
        for record in records {
            let size = Span::of_record(&record);
            if let Err(error) = self.log.append(record) {
                // An incomplete restatement holds nothing; what it appended counts after
                // the last complete one.
                self.since = self.since.plus(appended);
                return Err(JournalError::Log(error));
            }
            appended = appended.plus(size);
        }
        self.since = appended;
        Ok(())
    }
}

/// Whether `state` holds `pin` as its candidate, its default or a rollback target that has
/// not failed.
fn names(state: &TrackState, pin: HelperPinId) -> bool {
    let candidate = state
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.pin.id() == pin);
    let default =
        matches!(&state.default, DefaultPath::Bundle { pin: default } if default.id() == pin);
    let previous =
        !state.failed.contains(&pin) && state.previous.iter().any(|earlier| earlier.id() == pin);
    candidate || default || previous
}

/// The written outcome of a trial or withdrawal `next` just applied.
fn recorded_outcome(next: &HelperRollouts, outcome: Option<&RecordOutcome>) -> RecordedOutcome {
    match outcome {
        Some(RecordOutcome::RolledBack { to, .. }) => {
            let skipped = match next.records().last().map(|record| &record.event) {
                Some(RolloutEvent::RolledBack { skipped, .. }) => skipped
                    .iter()
                    .map(|(pin, refusal)| RecordedSkip {
                        pin: *pin,
                        refusal: RecordedPinRefusal::from(refusal),
                    })
                    .collect(),
                _ => Vec::new(),
            };
            RecordedOutcome::RolledBack {
                to: RecordedTarget::from(to),
                skipped,
            }
        }
        Some(RecordOutcome::Recorded) | None => RecordedOutcome::Recorded {},
    }
}

fn count<T>(items: &[T]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}
