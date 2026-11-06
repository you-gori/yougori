//! The replay of the durable rollout stream on restart (G08: "persist rollout state";
//! S2 CORE-06 restart recovery; S08 rollback resistance).
//!
//! The replay starts from the last complete restatement, or from the start of the stream,
//! and applies every decision after it through [`HelperRollouts`] itself: proposals and
//! promotions through `propose` and `promote`, trials through `record_judged` with the
//! digest and judgement recorded with them, rollbacks with the versions they passed over,
//! and checks that each replays to what it recorded. It reads no provenance back. It
//! refuses, with a typed [`ReplayRefusal`] and nothing put in force:
//!
//! - a record outside what the journal writes, and a decision the rollout refuses or that
//!   replays to another outcome than it recorded (a rewritten record);
//! - a track whose records skip or repeat a number where no gap of the stream accounts
//!   for it (a record removed or reordered);
//! - a record that lowers its track's floor, or proposes a version at or below it: an old
//!   version offered again (the floor is the newest version the track saw);
//! - a record naming a version its track never introduced, a version in force that the
//!   catalog does not hold, and one the catalog quarantined that the stream neither
//!   withdrew nor holds as failed, unless the owner chose to withdraw such versions now
//!   ([`OnQuarantine::Withdraw`]).
//!
//! Gaps are explicit ([`GapReason`]). A track that lost records in a gap, or whose last
//! record precedes one, falls back and never moves forward: its candidate is dropped (not
//! failed), it keeps the last good pinned version the surviving records establish, or
//! source injection, and after the gap only records that move it back apply (failures and
//! withdrawals), while every record still raises its floor. A running runner is restored
//! with exactly what it started with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::super::evidence::check_component;
use super::super::identity::{HelperPin, HelperPinId, PinAdmissibility, PinRefusal};
use super::super::manifest::{HelperId, HelperVersion};
use super::super::rollout::restore::{JudgedEvidence, TrackState};
use super::super::rollout::{
    DefaultPath, HelperRollouts, Promotion, RecordOutcome, RolloutEvent, RolloutRefusal,
    SourceInjectionRemoval, TrialVerdict,
};
use super::super::runners::{RunnerInstance, RunnerPins};
use super::record::{
    skipped_refusals, JournalRecord, RecordedEvidence, RecordedOutcome, RecordedRunner,
    RecordedSkip, RecordedTarget, RecordedTrack, TrackPosition,
};
use super::{Span, Withdrawal};
use crate::foundation::catalog::IntegrityFailure;
use crate::foundation::events::{
    EventSequence, GapReason, LogEntry, LogMarker, ReadItem, SequenceRange,
};
use crate::foundation::evidence::Backend;
use crate::foundation::ids::Digest;
use crate::foundation::report::Label;

/// What the replay does with a version in force that the catalog quarantined and the
/// stream never withdrew.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnQuarantine {
    /// Refuse the stream: fail closed until the owner decides.
    Refuse,
    /// The owner's decision: withdraw each such version as failure evidence would, and
    /// record the withdrawal.
    Withdraw(Withdrawal),
}

/// Why the replay refused the stream. Nothing of it was put in force.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplayRefusal {
    /// A record is outside what the journal writes.
    BadRecord {
        sequence: EventSequence,
        detail: &'static str,
    },
    /// A track's record carries another number than the next one, and no gap of the stream
    /// accounts for the difference: records were removed or reordered.
    Discontinuous {
        sequence: EventSequence,
        helper: HelperId,
        backend: Backend,
        expected: u64,
        found: u64,
    },
    /// A record lowers its track's floor.
    FloorLowered {
        sequence: EventSequence,
        helper: HelperId,
        backend: Backend,
        floor: HelperVersion,
        found: HelperVersion,
    },
    /// A proposal of a version at or below its track's floor: an old version offered again
    /// as an upgrade.
    BelowFloor {
        sequence: EventSequence,
        helper: HelperId,
        backend: Backend,
        floor: HelperVersion,
        proposed: HelperVersion,
    },
    /// A record names a version its track never introduced.
    NotIntroduced {
        sequence: EventSequence,
        pin: HelperPinId,
    },
    /// The rollout refuses a recorded decision.
    Refused {
        sequence: EventSequence,
        refusal: RolloutRefusal,
    },
    /// A recorded decision replays to another outcome, or rests on other evidence, than it
    /// recorded.
    Diverged {
        sequence: EventSequence,
        detail: &'static str,
    },
    /// The catalog does not hold a version the stream puts in force.
    UnknownHelper {
        pin: HelperPinId,
        refusal: PinRefusal,
    },
    /// The catalog quarantined a version the stream puts in force, and the stream never
    /// withdrew it.
    QuarantinedHelper {
        pin: HelperPinId,
        reason: IntegrityFailure,
    },
}

impl fmt::Display for ReplayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRecord { sequence, detail } => {
                write!(f, "rollout record {sequence} is refused: {detail}")
            }
            Self::Discontinuous {
                sequence,
                helper,
                backend,
                expected,
                found,
            } => write!(
                f,
                "rollout record {sequence} is record {found} of {helper} on {backend} where \
                 {expected} was due, and no gap accounts for it"
            ),
            Self::FloorLowered {
                sequence,
                helper,
                backend,
                floor,
                found,
            } => write!(
                f,
                "rollout record {sequence} lowers the floor of {helper} on {backend} from \
                 {floor} to {found}"
            ),
            Self::BelowFloor {
                sequence,
                helper,
                backend,
                floor,
                proposed,
            } => write!(
                f,
                "rollout record {sequence} proposes {helper} {proposed} on {backend}, not newer \
                 than its floor {floor}"
            ),
            Self::NotIntroduced { sequence, .. } => write!(
                f,
                "rollout record {sequence} names a helper version its track never introduced"
            ),
            Self::Refused { sequence, refusal } => {
                write!(f, "rollout record {sequence} does not replay: {refusal}")
            }
            Self::Diverged { sequence, detail } => {
                write!(
                    f,
                    "rollout record {sequence} does not replay as recorded: {detail}"
                )
            }
            Self::UnknownHelper { refusal, .. } => {
                write!(
                    f,
                    "the rollout stream names an unknown helper version: {refusal}"
                )
            }
            Self::QuarantinedHelper { .. } => f.write_str(
                "the rollout stream puts a quarantined helper version in force and never \
                 withdrew it",
            ),
        }
    }
}

impl std::error::Error for ReplayRefusal {}

/// A track that lost records in a gap and fell back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FellBack {
    pub helper: HelperId,
    pub backend: Backend,
    /// The candidate it dropped; it was not failed, and its version stays below the floor.
    pub dropped: Option<HelperPin>,
    /// What new runners of the backend serve by default now.
    pub default: DefaultPath,
    pub floor: Option<HelperVersion>,
}

/// Admissibility as a recorded decision saw it: every version but those it passed over.
struct AsRecorded<'a>(&'a BTreeMap<HelperPinId, PinRefusal>);

impl PinAdmissibility for AsRecorded<'_> {
    fn check(&self, pin: &HelperPin) -> Result<(), PinRefusal> {
        match self.0.get(&pin.id()) {
            Some(refusal) => Err(refusal.clone()),
            None => Ok(()),
        }
    }
}

/// What the replay knows of one track's records.
#[derive(Clone, Copy, Debug)]
pub(super) struct TrackMeta {
    /// The number of the track's last record read.
    pub(super) records: u64,
    /// The highest floor its records recorded.
    pub(super) floor: Option<HelperVersion>,
    /// Gaps read since the last restatement when the track's last record was.
    seen_gaps: u64,
    /// Records of the track are missing: only records that move it back apply.
    affected: bool,
}

impl TrackMeta {
    fn new() -> Self {
        Self {
            records: 0,
            floor: None,
            seen_gaps: 0,
            affected: false,
        }
    }
}

/// A restatement being read, not yet complete.
struct Pending {
    sequence: EventSequence,
    tracks: u64,
    runners: u64,
    restated_tracks: Vec<RecordedTrack>,
    restated_runners: Vec<(EventSequence, RecordedRunner)>,
    span: Span,
}

/// What a finished replay puts in force.
pub(super) struct Restored {
    pub(super) rollouts: HelperRollouts,
    pub(super) runners: RunnerPins,
    pub(super) running: BTreeSet<RunnerInstance>,
    pub(super) tracks: BTreeMap<(HelperId, Backend), TrackMeta>,
    pub(super) fell_back: Vec<FellBack>,
    /// Quarantined versions in force the owner chose to withdraw now.
    pub(super) to_withdraw: Vec<HelperPinId>,
    /// Whether a gap followed the last complete restatement.
    pub(super) lost: bool,
}

/// The replay of one stream, item by item.
pub(super) struct Replay {
    rollouts: HelperRollouts,
    /// Every running runner, with the sequence of the record that started or restated it.
    runners: BTreeMap<RunnerInstance, (EventSequence, RecordedRunner)>,
    tracks: BTreeMap<(HelperId, Backend), TrackMeta>,
    /// Gaps read since the last complete restatement.
    gaps_since: u64,
    pending: Option<Pending>,
    withdrawn: BTreeSet<HelperPinId>,
    pub(super) gaps: Vec<(SequenceRange, GapReason)>,
    pub(super) markers: Vec<(EventSequence, LogMarker)>,
    /// Where the last complete restatement began.
    pub(super) restatement: Option<EventSequence>,
    /// The stream from the last complete restatement, or from its start.
    pub(super) since: Span,
    pub(super) records: u64,
}

impl Replay {
    pub(super) fn new() -> Self {
        Self {
            rollouts: HelperRollouts::new(),
            runners: BTreeMap::new(),
            tracks: BTreeMap::new(),
            gaps_since: 0,
            pending: None,
            withdrawn: BTreeSet::new(),
            gaps: Vec::new(),
            markers: Vec::new(),
            restatement: None,
            since: Span::default(),
            records: 0,
        }
    }

    /// Folds one item of the stream in, in order.
    pub(super) fn fold(&mut self, item: ReadItem<JournalRecord>) -> Result<(), ReplayRefusal> {
        match item {
            ReadItem::Gap { missing, reason } => {
                self.pending = None;
                self.gaps_since = self.gaps_since.saturating_add(1);
                self.gaps.push((missing, reason));
            }
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Marker(marker),
                ..
            } => {
                self.pending = None;
                self.since = self
                    .since
                    .plus(Span::of_entry(&LogEntry::<JournalRecord>::Marker(
                        marker.clone(),
                    )));
                self.markers.push((sequence, marker));
            }
            ReadItem::Entry {
                sequence,
                entry: LogEntry::Record(record),
                ..
            } => {
                let size = Span::of_record(&record);
                self.since = self.since.plus(size);
                self.records = self.records.saturating_add(1);
                self.record(sequence, record, size)?;
            }
        }
        Ok(())
    }

    fn record(
        &mut self,
        sequence: EventSequence,
        record: JournalRecord,
        size: Span,
    ) -> Result<(), ReplayRefusal> {
        match record {
            JournalRecord::RestatementBegins { tracks, runners } => {
                self.pending = Some(Pending {
                    sequence,
                    tracks,
                    runners,
                    restated_tracks: Vec::new(),
                    restated_runners: Vec::new(),
                    span: size,
                });
                self.complete()
            }
            JournalRecord::RestatedTrack { part, track } => {
                match self.pending.as_mut() {
                    Some(pending)
                        if part <= pending.tracks
                            && part == count(&pending.restated_tracks).saturating_add(1) =>
                    {
                        pending.restated_tracks.push(*track);
                        pending.span = pending.span.plus(size);
                    }
                    // A part without its beginning changes nothing: retention may have
                    // dropped the beginning, or a stop interrupted the restatement.
                    _ => self.pending = None,
                }
                self.complete()
            }
            JournalRecord::RestatedRunner { part, start } => {
                distinct_helpers(sequence, &start)?;
                match self.pending.as_mut() {
                    Some(pending)
                        if count(&pending.restated_tracks) == pending.tracks
                            && part <= pending.runners
                            && part == count(&pending.restated_runners).saturating_add(1) =>
                    {
                        pending.restated_runners.push((sequence, start));
                        pending.span = pending.span.plus(size);
                    }
                    _ => self.pending = None,
                }
                self.complete()
            }
            decision => {
                self.pending = None;
                self.decision(sequence, decision)
            }
        }
    }

    /// Puts a restatement in place once its last part is read.
    fn complete(&mut self) -> Result<(), ReplayRefusal> {
        let done = self.pending.as_ref().is_some_and(|pending| {
            count(&pending.restated_tracks) == pending.tracks
                && count(&pending.restated_runners) == pending.runners
        });
        if !done {
            return Ok(());
        }
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let bad = |detail| ReplayRefusal::BadRecord {
            sequence: pending.sequence,
            detail,
        };
        let mut rollouts = HelperRollouts::new();
        let mut tracks = BTreeMap::new();
        for track in pending.restated_tracks {
            let key = (track.helper.clone(), track.backend);
            if track
                .pins()
                .any(|pin| pin.helper != track.helper || pin.version > track.floor)
            {
                return Err(bad(
                    "a restated track names another helper or a version above its floor",
                ));
            }
            if let Some(known) = self.tracks.get(&key) {
                if let Some(floor) = known.floor.filter(|floor| track.floor < *floor) {
                    return Err(ReplayRefusal::FloorLowered {
                        sequence: pending.sequence,
                        helper: track.helper,
                        backend: track.backend,
                        floor,
                        found: track.floor,
                    });
                }
                if track.records < known.records {
                    return Err(ReplayRefusal::Discontinuous {
                        sequence: pending.sequence,
                        helper: track.helper,
                        backend: track.backend,
                        expected: known.records,
                        found: track.records,
                    });
                }
            }
            let meta = TrackMeta {
                records: track.records,
                floor: Some(track.floor),
                ..TrackMeta::new()
            };
            if tracks.insert(key.clone(), meta).is_some() {
                return Err(bad("a restatement restates a track twice"));
            }
            let (helper, backend) = key;
            rollouts.restore_track(helper, backend, track.state());
        }
        if self.tracks.keys().any(|key| !tracks.contains_key(key)) {
            return Err(bad("a restatement leaves out a track"));
        }
        let mut runners = BTreeMap::new();
        for (sequence, start) in pending.restated_runners {
            if runners
                .insert(start.runner.clone(), (sequence, start))
                .is_some()
            {
                return Err(bad("a restatement restates a runner twice"));
            }
        }
        self.rollouts = rollouts;
        self.runners = runners;
        self.tracks = tracks;
        self.gaps_since = 0;
        self.restatement = Some(pending.sequence);
        self.since = pending.span;
        Ok(())
    }

    /// Checks a track record's number and floor, and says whether the record may move the
    /// track forward: `false` once the track lost records in a gap.
    fn position(
        &mut self,
        sequence: EventSequence,
        position: &TrackPosition,
    ) -> Result<bool, ReplayRefusal> {
        let gaps = self.gaps_since;
        let meta = self
            .tracks
            .entry((position.helper.clone(), position.backend))
            .or_insert_with(TrackMeta::new);
        let expected = meta.records.saturating_add(1);
        if position.record != expected {
            if position.record > expected && meta.seen_gaps < gaps {
                meta.affected = true;
            } else {
                return Err(ReplayRefusal::Discontinuous {
                    sequence,
                    helper: position.helper.clone(),
                    backend: position.backend,
                    expected,
                    found: position.record,
                });
            }
        }
        if let Some(floor) = meta.floor.filter(|floor| position.floor < *floor) {
            return Err(ReplayRefusal::FloorLowered {
                sequence,
                helper: position.helper.clone(),
                backend: position.backend,
                floor,
                found: position.floor,
            });
        }
        meta.records = position.record;
        meta.floor = Some(position.floor);
        meta.seen_gaps = gaps;
        Ok(!meta.affected)
    }

    /// The track's state before a decision that does not change its floor, which must be
    /// the recorded one.
    fn state_at(
        &self,
        sequence: EventSequence,
        position: &TrackPosition,
        pin: HelperPinId,
    ) -> Result<TrackState, ReplayRefusal> {
        let state = self
            .rollouts
            .track_state(&position.helper, position.backend)
            .ok_or(ReplayRefusal::NotIntroduced { sequence, pin })?;
        if state.floor != Some(position.floor) {
            return Err(ReplayRefusal::Diverged {
                sequence,
                detail: "its floor is not its track's",
            });
        }
        Ok(state)
    }

    fn decision(
        &mut self,
        sequence: EventSequence,
        record: JournalRecord,
    ) -> Result<(), ReplayRefusal> {
        let bad = |detail| ReplayRefusal::BadRecord { sequence, detail };
        match record {
            JournalRecord::Proposed { track, pin } => {
                if pin.helper != track.helper || !pin.supports_backend(track.backend) {
                    return Err(bad(
                        "a proposal names a version of another helper or backend",
                    ));
                }
                if pin.version != track.floor {
                    return Err(bad("a proposal's floor is not its version"));
                }
                let floor = self
                    .tracks
                    .get(&(track.helper.clone(), track.backend))
                    .and_then(|meta| meta.floor);
                if let Some(floor) = floor.filter(|floor| pin.version <= *floor) {
                    return Err(ReplayRefusal::BelowFloor {
                        sequence,
                        helper: track.helper,
                        backend: track.backend,
                        floor,
                        proposed: pin.version,
                    });
                }
                if self.position(sequence, &track)? {
                    self.rollouts
                        .propose(pin, track.backend, &AsRecorded(&BTreeMap::new()))
                        .map_err(|refusal| ReplayRefusal::Refused { sequence, refusal })?;
                }
            }
            JournalRecord::Trial {
                track,
                pin,
                runner,
                stage,
                verdict,
                evidence,
                outcome,
            } => {
                if runner.backend != track.backend {
                    return Err(bad("a trial ran on another backend than its track's"));
                }
                let verdict = TrialVerdict::from(verdict);
                if !self.position(sequence, &track)? {
                    if let TrialVerdict::Failed { reason } = verdict {
                        self.withdraw_after_gap(&track, pin, reason, &outcome);
                    }
                    return Ok(());
                }
                let state = self.state_at(sequence, &track, pin)?;
                let held =
                    held_pin(&state, pin).ok_or(ReplayRefusal::NotIntroduced { sequence, pin })?;
                let passed = verdict == TrialVerdict::Passed;
                if check_component(&evidence.component, held, passed).is_err() {
                    return Err(bad("a trial's evidence names another bundle"));
                }
                let refused = refusals(&outcome);
                let judged = JudgedEvidence {
                    pin,
                    runner,
                    stage,
                    verdict,
                    digest: evidence.records,
                    measured: evidence.measured,
                };
                let replayed = self
                    .rollouts
                    .record_judged(judged, &AsRecorded(&refused))
                    .map_err(|refusal| ReplayRefusal::Refused { sequence, refusal })?;
                self.same_outcome(sequence, Some(&replayed), &outcome)?;
            }
            JournalRecord::Promoted {
                track,
                pin,
                from,
                to,
                evidence,
            } => {
                if !self.position(sequence, &track)? {
                    return Ok(());
                }
                let state = self.state_at(sequence, &track, pin)?;
                let candidate = state
                    .candidate
                    .filter(|candidate| candidate.pin.id() == pin)
                    .ok_or(ReplayRefusal::NotIntroduced { sequence, pin })?;
                rests_on(sequence, &evidence, &candidate.pin, candidate.measured_pass)?;
                let promotion = self
                    .rollouts
                    .promote(&track.helper, track.backend, &AsRecorded(&BTreeMap::new()))
                    .map_err(|refusal| ReplayRefusal::Refused { sequence, refusal })?;
                if promotion != (Promotion { pin, from, to }) {
                    return Err(ReplayRefusal::Diverged {
                        sequence,
                        detail: "a promotion replays to other stages",
                    });
                }
            }
            JournalRecord::SourceInjectionRemoved {
                track,
                replacement,
                evidence,
                decided_by,
                reason,
            } => {
                if !self.position(sequence, &track)? {
                    return Ok(());
                }
                let state = self.state_at(sequence, &track, replacement)?;
                let default = match &state.default {
                    DefaultPath::Bundle { pin } if pin.id() == replacement => pin,
                    _ => {
                        return Err(ReplayRefusal::NotIntroduced {
                            sequence,
                            pin: replacement,
                        })
                    }
                };
                rests_on(
                    sequence,
                    &evidence,
                    default,
                    state.proven.get(&replacement).copied(),
                )?;
                self.rollouts
                    .remove_source_injection(
                        &track.helper,
                        track.backend,
                        SourceInjectionRemoval { decided_by, reason },
                    )
                    .map_err(|refusal| ReplayRefusal::Refused { sequence, refusal })?;
            }
            JournalRecord::Withdrawn {
                track,
                pin,
                reason,
                outcome,
                ..
            } => {
                self.withdrawn.insert(pin);
                if !self.position(sequence, &track)? {
                    self.withdraw_after_gap(&track, pin, reason, &outcome);
                    return Ok(());
                }
                self.state_at(sequence, &track, pin)?;
                let refused = refusals(&outcome);
                let replayed = self.rollouts.withdraw(
                    &track.helper,
                    track.backend,
                    pin,
                    reason,
                    &AsRecorded(&refused),
                );
                self.same_outcome(sequence, replayed.as_ref(), &outcome)?;
            }
            JournalRecord::RunnerStarted { start } => {
                // Restarting a running runner needs a stop in between, unless a gap may
                // hold it.
                distinct_helpers(sequence, &start)?;
                if self.runners.contains_key(&start.runner) && self.gaps_since == 0 {
                    return Err(bad("a running runner starts again"));
                }
                self.runners.insert(start.runner.clone(), (sequence, start));
            }
            JournalRecord::RunnerStopped { runner } => {
                if self.runners.remove(&runner).is_none() && self.gaps_since == 0 {
                    return Err(bad("a runner that is not running stops"));
                }
            }
            JournalRecord::RestatementBegins { .. }
            | JournalRecord::RestatedTrack { .. }
            | JournalRecord::RestatedRunner { .. } => {}
        }
        Ok(())
    }

    /// Applies a failure or withdrawal of `pin` to a track that lost records: it only moves
    /// the track back. A track the replay holds nothing of starts from its floor.
    fn withdraw_after_gap(
        &mut self,
        track: &TrackPosition,
        pin: HelperPinId,
        reason: Label,
        outcome: &RecordedOutcome,
    ) {
        if self
            .rollouts
            .track_state(&track.helper, track.backend)
            .is_none()
        {
            self.rollouts.restore_track(
                track.helper.clone(),
                track.backend,
                TrackState::fresh(Some(track.floor)),
            );
        }
        let refused = refusals(outcome);
        self.rollouts.withdraw(
            &track.helper,
            track.backend,
            pin,
            reason,
            &AsRecorded(&refused),
        );
    }

    /// Checks that a replayed trial or withdrawal did what was recorded: kept, or rolled
    /// back to the same target, passing over the same versions.
    fn same_outcome(
        &self,
        sequence: EventSequence,
        replayed: Option<&RecordOutcome>,
        recorded: &RecordedOutcome,
    ) -> Result<(), ReplayRefusal> {
        let same = match (replayed, recorded) {
            (None | Some(RecordOutcome::Recorded), RecordedOutcome::Recorded {}) => true,
            (
                Some(RecordOutcome::RolledBack { to, .. }),
                RecordedOutcome::RolledBack {
                    to: target,
                    skipped,
                },
            ) => {
                RecordedTarget::from(to) == *target && last_skipped(&self.rollouts) == ids(skipped)
            }
            _ => false,
        };
        if same {
            Ok(())
        } else {
            Err(ReplayRefusal::Diverged {
                sequence,
                detail: "it rolls back otherwise than recorded",
            })
        }
    }

    /// Ends the replay: tracks that lost records fall back, every version in force is
    /// checked against the catalog through `admissible`, and the runners are restored.
    pub(super) fn finish(
        mut self,
        admissible: &dyn PinAdmissibility,
        on_quarantine: &OnQuarantine,
    ) -> Result<Restored, ReplayRefusal> {
        let gaps = self.gaps_since;
        let mut fell_back = Vec::new();
        for ((helper, backend), meta) in &mut self.tracks {
            // A gap after the track's last record may hold records of it too.
            if !meta.affected && meta.seen_gaps >= gaps {
                continue;
            }
            meta.affected = true;
            let mut state = self
                .rollouts
                .track_state(helper, *backend)
                .unwrap_or_else(|| TrackState::fresh(meta.floor));
            let dropped = state.candidate.take().map(|candidate| candidate.pin);
            state.floor = state.floor.max(meta.floor);
            // Removing source injection moves a track forward; it needs a pass again.
            state.proven.clear();
            fell_back.push(FellBack {
                helper: helper.clone(),
                backend: *backend,
                dropped,
                default: state.default.clone(),
                floor: state.floor,
            });
            self.rollouts.restore_track(helper.clone(), *backend, state);
        }
        let to_withdraw = self.check_catalog(admissible, on_quarantine)?;
        let mut runners = RunnerPins::new();
        let mut running = BTreeSet::new();
        for (sequence, start) in self.runners.values() {
            runners
                .start(
                    start.runner.clone(),
                    start.release.clone(),
                    start.selections(),
                )
                .map_err(|_| ReplayRefusal::BadRecord {
                    sequence: *sequence,
                    detail: "a runner's selections name a helper twice",
                })?;
            running.insert(start.runner.clone());
        }
        Ok(Restored {
            rollouts: self.rollouts,
            runners,
            running,
            tracks: self.tracks,
            fell_back,
            to_withdraw,
            lost: gaps > 0,
        })
    }

    /// Checks every version in force (defaults, candidates, rollback targets that have not
    /// failed, and what running runners loaded) against the catalog. A quarantined version
    /// the stream withdrew, or that its track holds as failed, is never offered again and
    /// passes. Returns the quarantined versions the owner chose to withdraw.
    fn check_catalog(
        &self,
        admissible: &dyn PinAdmissibility,
        on_quarantine: &OnQuarantine,
    ) -> Result<Vec<HelperPinId>, ReplayRefusal> {
        let mut in_force: BTreeMap<HelperPinId, &HelperPin> = BTreeMap::new();
        let mut in_tracks = BTreeSet::new();
        let mut settled = self.withdrawn.clone();
        let states = self.rollouts.track_states();
        for (_, _, state) in &states {
            settled.extend(state.failed.iter().copied());
            let default = match &state.default {
                DefaultPath::Bundle { pin } => Some(pin),
                DefaultPath::SourceInjection | DefaultPath::Unavailable => None,
            };
            let previous = state
                .previous
                .iter()
                .filter(|pin| !state.failed.contains(&pin.id()));
            for pin in default
                .into_iter()
                .chain(previous)
                .chain(state.candidate.as_ref().map(|candidate| &candidate.pin))
            {
                in_tracks.insert(pin.id());
                in_force.insert(pin.id(), pin);
            }
        }
        for (_, start) in self.runners.values() {
            for pin in start.pins() {
                in_force.insert(pin.id(), pin);
            }
        }
        let mut to_withdraw = Vec::new();
        for (id, pin) in in_force {
            match admissible.check(pin) {
                Ok(()) | Err(PinRefusal::IncompatibleAbi { .. }) => {}
                Err(PinRefusal::Quarantined { .. }) if settled.contains(&id) => {}
                Err(PinRefusal::Quarantined { reason }) => match on_quarantine {
                    OnQuarantine::Withdraw(_) => {
                        if in_tracks.contains(&id) {
                            to_withdraw.push(id);
                        }
                    }
                    OnQuarantine::Refuse => {
                        return Err(ReplayRefusal::QuarantinedHelper { pin: id, reason })
                    }
                },
                Err(refusal @ (PinRefusal::NotPublished | PinRefusal::Inconsistent)) => {
                    return Err(ReplayRefusal::UnknownHelper { pin: id, refusal })
                }
            }
        }
        Ok(to_withdraw)
    }
}

/// Refuses a runner record that selects one helper twice.
fn distinct_helpers(sequence: EventSequence, start: &RecordedRunner) -> Result<(), ReplayRefusal> {
    let helpers: BTreeSet<&HelperId> = start
        .helpers
        .iter()
        .map(|selected| &selected.helper)
        .collect();
    if helpers.len() == start.helpers.len() {
        Ok(())
    } else {
        Err(ReplayRefusal::BadRecord {
            sequence,
            detail: "a runner record selects a helper twice",
        })
    }
}

fn count<T>(items: &[T]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}

/// The candidate or default of `state` that `pin` names.
fn held_pin(state: &TrackState, pin: HelperPinId) -> Option<&HelperPin> {
    let candidate = state
        .candidate
        .as_ref()
        .map(|candidate| &candidate.pin)
        .filter(|candidate| candidate.id() == pin);
    let default = match &state.default {
        DefaultPath::Bundle { pin: default } if default.id() == pin => Some(default),
        _ => None,
    };
    candidate.or(default)
}

/// Checks that a recorded decision rests on the measured pass `held` the track holds for
/// `pin`, with the verified signature of its bundle.
fn rests_on(
    sequence: EventSequence,
    evidence: &RecordedEvidence,
    pin: &HelperPin,
    held: Option<Digest>,
) -> Result<(), ReplayRefusal> {
    let rests = evidence.measured
        && held == Some(evidence.records)
        && check_component(&evidence.component, pin, true).is_ok();
    if rests {
        Ok(())
    } else {
        Err(ReplayRefusal::Diverged {
            sequence,
            detail: "the decision names other evidence than the measured pass it rested on",
        })
    }
}

fn refusals(outcome: &RecordedOutcome) -> BTreeMap<HelperPinId, PinRefusal> {
    match outcome {
        RecordedOutcome::RolledBack { skipped, .. } => skipped_refusals(skipped),
        RecordedOutcome::Recorded {} => BTreeMap::new(),
    }
}

fn ids(skipped: &[RecordedSkip]) -> Vec<HelperPinId> {
    skipped.iter().map(|skip| skip.pin).collect()
}

/// The versions the rollout's last rollback passed over.
pub(super) fn last_skipped(rollouts: &HelperRollouts) -> Vec<HelperPinId> {
    match rollouts.records().last().map(|record| &record.event) {
        Some(RolloutEvent::RolledBack { skipped, .. }) => {
            skipped.iter().map(|(pin, _)| *pin).collect()
        }
        _ => Vec::new(),
    }
}
