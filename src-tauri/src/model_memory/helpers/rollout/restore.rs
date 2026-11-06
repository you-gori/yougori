//! The state hooks through which the durable rollout journal ([`super::super::journal`])
//! restates and restores tracks (G08: "persist rollout state"; GPU-W11, line 1328).
//!
//! A track still changes only by the decisions of [`HelperRollouts`]. The journal replays
//! recorded trials through [`HelperRollouts::record_judged`], with the digest and the
//! judgement CORE-08 made when they were recorded, and reads back no provenance. It copies
//! a track out ([`TrackState`]) to restate it, puts a restated or fallen-back track in
//! place, and withdraws a version as failure evidence would ([`HelperRollouts::withdraw`]),
//! through the same rollback.

use std::collections::{BTreeMap, BTreeSet};

use super::super::identity::{HelperPin, HelperPinId, PinAdmissibility};
use super::super::manifest::{HelperId, HelperVersion};
use super::{
    Candidate, DefaultPath, HelperRollouts, RecordOutcome, RolloutStage, SourceInjection, Track,
    TrialVerdict,
};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::Digest;
use crate::foundation::report::Label;

/// A trial after CORE-08 judged its provenance: the pinned version, the runner and stage it
/// ran at, the verdict, the digest of its run records, and whether they are a Yougori
/// measurement, the only kind that promotes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct JudgedEvidence {
    pub(in super::super) pin: HelperPinId,
    pub(in super::super) runner: BackendRelease,
    pub(in super::super) stage: RolloutStage,
    pub(in super::super) verdict: TrialVerdict,
    pub(in super::super) digest: Digest,
    pub(in super::super) measured: bool,
}

/// A track's candidate, with the evidence it holds at its stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct CandidateState {
    pub(in super::super) pin: HelperPin,
    pub(in super::super) stage: RolloutStage,
    /// The digest of the latest measured pass at `stage`.
    pub(in super::super) measured_pass: Option<Digest>,
    pub(in super::super) fake_passes: u64,
}

/// A copy of one track's whole state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct TrackState {
    pub(in super::super) default: DefaultPath,
    /// Earlier defaults, oldest first: the rollback targets.
    pub(in super::super) previous: Vec<HelperPin>,
    pub(in super::super) candidate: Option<CandidateState>,
    pub(in super::super) failed: BTreeSet<HelperPinId>,
    /// Defaults with a measured pass as the backend default, and its evidence.
    pub(in super::super) proven: BTreeMap<HelperPinId, Digest>,
    /// The newest version the track saw: no version at or below it is proposed again.
    pub(in super::super) floor: Option<HelperVersion>,
    pub(in super::super) source_injection: SourceInjection,
}

impl TrackState {
    /// A track that never rolled anything out and saw no version above `floor`.
    pub(in super::super) fn fresh(floor: Option<HelperVersion>) -> Self {
        Self::from(&Track {
            newest: floor,
            ..Track::new()
        })
    }
}

impl From<&Track> for TrackState {
    fn from(track: &Track) -> Self {
        Self {
            default: track.default.clone(),
            previous: track.previous.clone(),
            candidate: track.candidate.as_ref().map(|candidate| CandidateState {
                pin: candidate.pin.clone(),
                stage: candidate.stage,
                measured_pass: candidate.measured_pass,
                fake_passes: candidate.fake_passes,
            }),
            failed: track.failed.clone(),
            proven: track.proven.clone(),
            floor: track.newest,
            source_injection: track.source_injection.clone(),
        }
    }
}

impl From<TrackState> for Track {
    fn from(state: TrackState) -> Self {
        Self {
            default: state.default,
            previous: state.previous,
            candidate: state.candidate.map(|candidate| Candidate {
                pin: candidate.pin,
                stage: candidate.stage,
                measured_pass: candidate.measured_pass,
                fake_passes: candidate.fake_passes,
            }),
            failed: state.failed,
            proven: state.proven,
            newest: state.floor,
            source_injection: state.source_injection,
        }
    }
}

impl HelperRollouts {
    /// A copy of every track, in key order.
    pub(in super::super) fn track_states(&self) -> Vec<(HelperId, Backend, TrackState)> {
        self.tracks
            .iter()
            .map(|((helper, backend), track)| (helper.clone(), *backend, TrackState::from(track)))
            .collect()
    }

    /// A copy of the track of `helper` on `backend`.
    pub(in super::super) fn track_state(
        &self,
        helper: &HelperId,
        backend: Backend,
    ) -> Option<TrackState> {
        self.tracks
            .get(&(helper.clone(), backend))
            .map(TrackState::from)
    }

    /// Puts `state` in place as the track of `helper` on `backend`. Nothing is appended to
    /// [`HelperRollouts::records`]: the decisions that led there are the journal's.
    pub(in super::super) fn restore_track(
        &mut self,
        helper: HelperId,
        backend: Backend,
        state: TrackState,
    ) {
        self.tracks.insert((helper, backend), Track::from(state));
    }

    /// Withdraws `pin` from the track of `helper` on `backend` as failure evidence would: a
    /// candidate is withdrawn, a default is rolled back to the last good pinned version or
    /// to source injection, and a rollback target is passed over from now on. The version
    /// is never proposed again. Returns the rollback, or `None` when `pin` was not the
    /// candidate or the default (it is marked failed all the same) or there is no track.
    pub(in super::super) fn withdraw(
        &mut self,
        helper: &HelperId,
        backend: Backend,
        pin: HelperPinId,
        reason: Label,
        admissible: &dyn PinAdmissibility,
    ) -> Option<RecordOutcome> {
        let key = (helper.clone(), backend);
        let track = self.tracks.get_mut(&key)?;
        let candidate = track
            .candidate
            .as_ref()
            .filter(|candidate| candidate.pin.id() == pin)
            .map(|candidate| candidate.stage);
        let default = track
            .default
            .pin()
            .filter(|default| default.id() == pin)
            .map(|_| RolloutStage::BackendDefault);
        match candidate.or(default) {
            Some(stage) => Some(self.roll_back(&key, pin, stage, reason, admissible)),
            None => {
                track.failed.insert(pin);
                None
            }
        }
    }
}
