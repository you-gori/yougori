//! Shadow, opt-in and backend-default rollout of helper versions, with automatic rollback
//! and a recorded retirement of source injection (GPU-W11, line 1328: "Roll out in
//! shadow-observation, opt-in, then backend-specific default stages"; line 1329: "Retain
//! model loader-policy rollback"; line 1330: "remove obsolete loops after replacement is
//! proven"; G08).
//!
//! One track per helper and backend:
//!
//! - a proposed version starts as the **shadow** candidate: runners load it beside what
//!   serves, run it and compare, and it never serves ([`RunnerHelpers::shadow`]);
//! - promoted, it is the **opt-in** candidate: it serves only runners that opted in;
//! - promoted again, it is the **backend default** for new runners of that backend, and
//!   the version it replaced becomes a rollback target.
//!
//! Promotion needs recorded passing evidence at the candidate's current stage, on a runner
//! the version supports, from a Yougori measurement: CORE-08 [`Provenance`] whose
//! evidence a release claim accepts. A fake-substrate pass is recorded and promotes
//! nothing (S12 G0). Failure evidence from any substrate rolls back at once: a failing
//! candidate is withdrawn, and a failing default is replaced by the most recent earlier
//! default that has not failed and is still admissible, or else by the source-injection
//! path. A failed version is never proposed again, and a rollout only moves forward: a
//! candidate is newer than every version its track saw, so an old signed version cannot
//! be offered again as an upgrade.
//!
//! Source injection, the superseded path, stays the fallback of every track: new runners
//! use it before any default exists, after a rollback with no good version left, and when
//! the default does not support or may not serve their runner. It is removed only by
//! [`HelperRollouts::remove_source_injection`], a recorded decision accepted only after the
//! default passed as the backend default on measured evidence; no promotion or rollback
//! ever removes it.
//!
//! Selection never changes a running runner: what a runner started with is recorded in
//! [`RunnerPins`](super::RunnerPins), and a promotion or rollback applies to new runners
//! only. Every decision is appended to [`HelperRollouts::records`].

pub(super) mod restore;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use self::restore::JudgedEvidence;
use super::identity::{HelperPin, HelperPinId, PinAdmissibility, PinRefusal};
use super::manifest::{HelperId, HelperVersion};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::Digest;
use crate::foundation::report::{Label, Provenance, ReportError};

/// Where a version stands in its track.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStage {
    /// Runs beside the serving path and compares; never serves.
    Shadow,
    /// Serves runners that opted in.
    OptIn,
    /// Serves new runners of the backend by default.
    BackendDefault,
}

impl fmt::Display for RolloutStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shadow => "shadow",
            Self::OptIn => "opt-in",
            Self::BackendDefault => "backend default",
        })
    }
}

/// What a trial showed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum TrialVerdict {
    /// The version behaved as required at its stage (in shadow: its results agreed with
    /// the serving path's).
    Passed,
    /// It did not; the reason is a short public label.
    Failed { reason: Label },
}

/// One recorded trial of a pinned version on one runner at one stage, with the CORE-08
/// provenance of the records it was judged from.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RolloutEvidence {
    pub pin: HelperPinId,
    pub runner: BackendRelease,
    pub stage: RolloutStage,
    pub verdict: TrialVerdict,
    pub provenance: Provenance,
}

/// What new runners of a backend serve by default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum DefaultPath {
    /// The superseded source-injection path.
    SourceInjection,
    /// A pinned bundle.
    Bundle { pin: HelperPin },
    /// Nothing: source injection was removed by a recorded decision and no good version
    /// is left. New runners are refused until a version is promoted again.
    Unavailable,
}

impl DefaultPath {
    fn pin(&self) -> Option<&HelperPin> {
        match self {
            Self::Bundle { pin } => Some(pin),
            Self::SourceInjection | Self::Unavailable => None,
        }
    }
}

/// What a new runner loads to serve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum ServingHelper {
    /// The superseded source-injection path, unchanged.
    SourceInjection,
    /// The pinned bundle, opened through the catalog.
    Bundle { pin: HelperPin },
}

/// Why a backend's default bundle did not serve a runner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum FallbackReason {
    /// The default does not support the runner's exact backend version.
    RunnerNotSupported { pin: HelperPinId },
    /// The default may not be loaded now.
    NotAdmissible {
        pin: HelperPinId,
        refusal: PinRefusal,
    },
}

/// The helper a new runner starts with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunnerHelpers {
    pub helper: HelperId,
    pub runner: BackendRelease,
    pub serve: ServingHelper,
    /// A shadow candidate the runner loads beside, to run and compare only.
    pub shadow: Option<HelperPin>,
    /// Why source injection serves although a default bundle exists.
    pub fallback: Option<FallbackReason>,
}

/// Why no helper can serve a new runner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum SelectionRefusal {
    /// Source injection was removed and no good version is left.
    Unavailable,
    /// The default cannot serve this runner and source injection was removed.
    DefaultUnusable { reason: FallbackReason },
}

impl fmt::Display for SelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str(
                "no helper version can serve: source injection was removed and every \
                 version failed",
            ),
            Self::DefaultUnusable { .. } => f.write_str(
                "the default helper cannot serve this runner and source injection was removed",
            ),
        }
    }
}

impl std::error::Error for SelectionRefusal {}

/// The owner's decision to remove source injection from one track.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInjectionRemoval {
    /// The role that decided, such as `release-owner`.
    pub decided_by: Label,
    pub reason: Label,
}

/// Whether a track still has the source-injection fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source_injection", rename_all = "snake_case")]
pub enum SourceInjection {
    Retained,
    /// Removed by a recorded decision after `replacement` passed as the default on the
    /// measured `evidence`.
    Removed {
        replacement: HelperPinId,
        evidence: Digest,
        decided_by: Label,
        reason: Label,
    },
}

/// Where a rollback left a track.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum RollbackTarget {
    SourceInjection,
    Bundle { pin: HelperPinId },
    Unavailable,
}

/// One decision or observation of a track.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RolloutEvent {
    Proposed {
        pin: HelperPinId,
        version: HelperVersion,
    },
    Evidence {
        pin: HelperPinId,
        stage: RolloutStage,
        runner: BackendRelease,
        passed: bool,
        /// The digest of the records behind it.
        evidence: Digest,
        /// Whether the evidence is a Yougori measurement, which alone promotes.
        measured: bool,
    },
    Promoted {
        pin: HelperPinId,
        from: RolloutStage,
        to: RolloutStage,
        evidence: Digest,
    },
    /// The default passed as the backend default on measured evidence.
    Proven { pin: HelperPinId, evidence: Digest },
    RolledBack {
        failed: HelperPinId,
        stage: RolloutStage,
        reason: Label,
        to: RollbackTarget,
        /// Earlier defaults passed over, and why.
        skipped: Vec<(HelperPinId, PinRefusal)>,
    },
    SourceInjectionRemoved {
        replacement: HelperPinId,
        evidence: Digest,
        decided_by: Label,
        reason: Label,
    },
}

/// One appended record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RolloutRecord {
    pub sequence: u64,
    pub helper: HelperId,
    pub backend: Backend,
    pub event: RolloutEvent,
}

/// What recording evidence did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded,
    /// Failure evidence rolled the track back; new runners now get `to`.
    RolledBack {
        failed: HelperPinId,
        stage: RolloutStage,
        to: RollbackTarget,
    },
}

/// One promotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Promotion {
    pub pin: HelperPinId,
    pub from: RolloutStage,
    pub to: RolloutStage,
}

/// Why a rollout step was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum RolloutRefusal {
    /// The version supports no runner of this backend.
    BackendNotSupported {
        pin: HelperPinId,
        backend: Backend,
    },
    /// The version may not be loaded now.
    NotAdmissible {
        pin: HelperPinId,
        refusal: PinRefusal,
    },
    /// One candidate at a time per track.
    CandidateInFlight {
        candidate: HelperPinId,
    },
    /// A version that failed is never proposed again.
    PreviouslyFailed {
        pin: HelperPinId,
    },
    /// A rollout moves only to a version newer than every version the track saw; going
    /// back is a rollback to a pinned version.
    NotNewer {
        proposed: HelperVersion,
        newest: HelperVersion,
    },
    /// No track for this helper and backend.
    UnknownTrack,
    NoCandidate,
    /// No passing evidence at the candidate's stage.
    NoPassingEvidence {
        stage: RolloutStage,
    },
    /// Only fake-substrate passes at the candidate's stage: they promote nothing.
    FakeSubstrateOnly {
        stage: RolloutStage,
    },
    /// The evidence names no candidate or default of the runner's backend.
    UnknownPin {
        pin: HelperPinId,
    },
    /// The evidence was gathered at another stage than the version is at.
    StageMismatch {
        expected: RolloutStage,
        found: RolloutStage,
    },
    /// The evidence ran on a runner the version does not support.
    RunnerNotSupported {
        pin: HelperPinId,
        runner: BackendRelease,
    },
    /// The evidence names no records (an unreproduced third-party claim).
    Evidence {
        error: ReportError,
    },
    /// Source injection is removed only after the default passed as the backend default.
    ReplacementNotProven,
    SourceInjectionAlreadyRemoved,
}

impl fmt::Display for RolloutRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotSupported { backend, .. } => {
                write!(f, "the helper version supports no {backend} runner")
            }
            Self::NotAdmissible { refusal, .. } => refusal.fmt(f),
            Self::CandidateInFlight { .. } => {
                f.write_str("another helper version is already rolling out on this backend")
            }
            Self::PreviouslyFailed { .. } => f.write_str("this helper version failed before"),
            Self::NotNewer { proposed, newest } => write!(
                f,
                "helper version {proposed} is not newer than {newest}; use a rollback to go back"
            ),
            Self::UnknownTrack => f.write_str("no rollout exists for this helper and backend"),
            Self::NoCandidate => f.write_str("no helper version is rolling out"),
            Self::NoPassingEvidence { stage } => {
                write!(f, "no passing evidence was recorded at the {stage} stage")
            }
            Self::FakeSubstrateOnly { stage } => write!(
                f,
                "only fake-substrate passes were recorded at the {stage} stage; they promote \
                 nothing"
            ),
            Self::UnknownPin { .. } => {
                f.write_str("the evidence names no rolling-out or default helper version")
            }
            Self::StageMismatch { expected, found } => write!(
                f,
                "the evidence is from the {found} stage; the version is at the {expected} stage"
            ),
            Self::RunnerNotSupported { runner, .. } => {
                write!(f, "the helper version does not support {runner}")
            }
            Self::Evidence { error } => write!(f, "the evidence is not usable: {error}"),
            Self::ReplacementNotProven => f.write_str(
                "source injection is removed only after the default helper passed as the \
                 backend default",
            ),
            Self::SourceInjectionAlreadyRemoved => {
                f.write_str("source injection was already removed")
            }
        }
    }
}

impl std::error::Error for RolloutRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    pin: HelperPin,
    /// Shadow or opt-in.
    stage: RolloutStage,
    /// The latest measured pass at `stage`.
    measured_pass: Option<Digest>,
    fake_passes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Track {
    default: DefaultPath,
    /// Earlier defaults, oldest first: the rollback targets.
    previous: Vec<HelperPin>,
    candidate: Option<Candidate>,
    failed: BTreeSet<HelperPinId>,
    /// Defaults with a measured pass as the backend default, and its evidence.
    proven: BTreeMap<HelperPinId, Digest>,
    /// The newest version ever proposed on the track.
    newest: Option<HelperVersion>,
    source_injection: SourceInjection,
}

impl Track {
    fn new() -> Self {
        Self {
            default: DefaultPath::SourceInjection,
            previous: Vec::new(),
            candidate: None,
            failed: BTreeSet::new(),
            proven: BTreeMap::new(),
            newest: None,
            source_injection: SourceInjection::Retained,
        }
    }
}

/// A track as its owner sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrackView {
    pub default: DefaultPath,
    /// The candidate and its stage.
    pub candidate: Option<(HelperPin, RolloutStage)>,
    /// Earlier defaults, oldest first: the rollback targets.
    pub previous: Vec<HelperPin>,
    pub failed: Vec<HelperPinId>,
    pub source_injection: SourceInjection,
}

/// The rollout of every helper on every backend.
#[derive(Clone, Debug, Default)]
pub struct HelperRollouts {
    tracks: BTreeMap<(HelperId, Backend), Track>,
    records: Vec<RolloutRecord>,
}

impl HelperRollouts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every decision and observation, in order.
    pub fn records(&self) -> &[RolloutRecord] {
        &self.records
    }

    /// The track of `helper` on `backend`; `None` while it was never rolled out, when
    /// every runner uses source injection.
    pub fn track(&self, helper: &HelperId, backend: Backend) -> Option<TrackView> {
        let track = self.tracks.get(&(helper.clone(), backend))?;
        Some(TrackView {
            default: track.default.clone(),
            candidate: track
                .candidate
                .as_ref()
                .map(|candidate| (candidate.pin.clone(), candidate.stage)),
            previous: track.previous.clone(),
            failed: track.failed.iter().copied().collect(),
            source_injection: track.source_injection.clone(),
        })
    }

    fn append(&mut self, helper: &HelperId, backend: Backend, event: RolloutEvent) {
        let sequence = u64::try_from(self.records.len()).unwrap_or(u64::MAX);
        self.records.push(RolloutRecord {
            sequence,
            helper: helper.clone(),
            backend,
            event,
        });
    }

    /// Makes `pin` the shadow candidate of its helper on `backend`.
    pub fn propose(
        &mut self,
        pin: HelperPin,
        backend: Backend,
        admissible: &dyn PinAdmissibility,
    ) -> Result<(), RolloutRefusal> {
        let id = pin.id();
        if !pin.supports_backend(backend) {
            return Err(RolloutRefusal::BackendNotSupported { pin: id, backend });
        }
        admissible
            .check(&pin)
            .map_err(|refusal| RolloutRefusal::NotAdmissible { pin: id, refusal })?;
        let helper = pin.helper.clone();
        let version = pin.version;
        let track = self
            .tracks
            .entry((helper.clone(), backend))
            .or_insert_with(Track::new);
        if track.failed.contains(&id) {
            return Err(RolloutRefusal::PreviouslyFailed { pin: id });
        }
        if let Some(candidate) = &track.candidate {
            return Err(RolloutRefusal::CandidateInFlight {
                candidate: candidate.pin.id(),
            });
        }
        if let Some(newest) = track.newest.filter(|newest| version <= *newest) {
            return Err(RolloutRefusal::NotNewer {
                proposed: version,
                newest,
            });
        }
        track.newest = Some(version);
        track.candidate = Some(Candidate {
            pin,
            stage: RolloutStage::Shadow,
            measured_pass: None,
            fake_passes: 0,
        });
        self.append(
            &helper,
            backend,
            RolloutEvent::Proposed { pin: id, version },
        );
        Ok(())
    }

    /// Records one trial. A pass is kept for promotion (only a measured one counts); a
    /// failure rolls the track back at once.
    pub fn record(
        &mut self,
        evidence: RolloutEvidence,
        admissible: &dyn PinAdmissibility,
    ) -> Result<RecordOutcome, RolloutRefusal> {
        let digest = evidence
            .provenance
            .comparable_evidence()
            .map_err(|error| RolloutRefusal::Evidence { error })?;
        let measured = evidence.provenance.yougori_evidence().is_ok();
        let RolloutEvidence {
            pin,
            runner,
            stage,
            verdict,
            ..
        } = evidence;
        let judged = JudgedEvidence {
            pin,
            runner,
            stage,
            verdict,
            digest,
            measured,
        };
        self.record_judged(judged, admissible)
    }

    /// [`Self::record`] once CORE-08 judged the provenance: the durable journal replays a
    /// recorded trial through here and never reads a provenance back.
    pub(super) fn record_judged(
        &mut self,
        evidence: JudgedEvidence,
        admissible: &dyn PinAdmissibility,
    ) -> Result<RecordOutcome, RolloutRefusal> {
        let backend = evidence.runner.backend;
        let digest = evidence.digest;
        let measured = evidence.measured.then_some(digest);
        let (key, supported, stage) = self
            .tracks
            .iter()
            .filter(|((_, track_backend), _)| *track_backend == backend)
            .find_map(|(key, track)| {
                let candidate = track
                    .candidate
                    .as_ref()
                    .filter(|candidate| candidate.pin.id() == evidence.pin)
                    .map(|candidate| (&candidate.pin, candidate.stage));
                let default = track
                    .default
                    .pin()
                    .filter(|pin| pin.id() == evidence.pin)
                    .map(|pin| (pin, RolloutStage::BackendDefault));
                candidate
                    .or(default)
                    .map(|(pin, stage)| (key.clone(), pin.supports(&evidence.runner), stage))
            })
            .ok_or(RolloutRefusal::UnknownPin { pin: evidence.pin })?;
        if !supported {
            return Err(RolloutRefusal::RunnerNotSupported {
                pin: evidence.pin,
                runner: evidence.runner,
            });
        }
        if evidence.stage != stage {
            return Err(RolloutRefusal::StageMismatch {
                expected: stage,
                found: evidence.stage,
            });
        }
        let (helper, _) = key.clone();
        self.append(
            &helper,
            backend,
            RolloutEvent::Evidence {
                pin: evidence.pin,
                stage,
                runner: evidence.runner.clone(),
                passed: evidence.verdict == TrialVerdict::Passed,
                evidence: digest,
                measured: measured.is_some(),
            },
        );
        match evidence.verdict {
            TrialVerdict::Passed => {
                self.passed(&key, evidence.pin, stage, measured);
                Ok(RecordOutcome::Recorded)
            }
            TrialVerdict::Failed { reason } => {
                Ok(self.roll_back(&key, evidence.pin, stage, reason, admissible))
            }
        }
    }

    fn passed(
        &mut self,
        key: &(HelperId, Backend),
        pin: HelperPinId,
        stage: RolloutStage,
        measured: Option<Digest>,
    ) {
        let Some(track) = self.tracks.get_mut(key) else {
            return;
        };
        if stage != RolloutStage::BackendDefault {
            if let Some(candidate) = track.candidate.as_mut() {
                match measured {
                    Some(evidence) => candidate.measured_pass = Some(evidence),
                    None => candidate.fake_passes = candidate.fake_passes.saturating_add(1),
                }
            }
            return;
        }
        if let Some(evidence) = measured {
            track.proven.insert(pin, evidence);
            self.append(&key.0, key.1, RolloutEvent::Proven { pin, evidence });
        }
    }

    /// The automatic rollback after failure evidence for `failed` at `stage`.
    fn roll_back(
        &mut self,
        key: &(HelperId, Backend),
        failed: HelperPinId,
        stage: RolloutStage,
        reason: Label,
        admissible: &dyn PinAdmissibility,
    ) -> RecordOutcome {
        let Some(track) = self.tracks.get_mut(key) else {
            return RecordOutcome::Recorded;
        };
        track.failed.insert(failed);
        let mut skipped = Vec::new();
        if stage == RolloutStage::BackendDefault {
            let mut target = None;
            while let Some(earlier) = track.previous.pop() {
                let id = earlier.id();
                if track.failed.contains(&id) {
                    continue;
                }
                match admissible.check(&earlier) {
                    Ok(()) => {
                        target = Some(earlier);
                        break;
                    }
                    Err(refusal) => skipped.push((id, refusal)),
                }
            }
            track.default = match target {
                Some(pin) => DefaultPath::Bundle { pin },
                None if track.source_injection == SourceInjection::Retained => {
                    DefaultPath::SourceInjection
                }
                None => DefaultPath::Unavailable,
            };
        } else {
            track.candidate = None;
        }
        let to = match &track.default {
            DefaultPath::SourceInjection => RollbackTarget::SourceInjection,
            DefaultPath::Bundle { pin } => RollbackTarget::Bundle { pin: pin.id() },
            DefaultPath::Unavailable => RollbackTarget::Unavailable,
        };
        self.append(
            &key.0,
            key.1,
            RolloutEvent::RolledBack {
                failed,
                stage,
                reason,
                to: to.clone(),
                skipped,
            },
        );
        RecordOutcome::RolledBack { failed, stage, to }
    }

    /// Moves the candidate of `helper` on `backend` one stage on, on a measured pass
    /// recorded at its current stage: shadow to opt-in, opt-in to backend default.
    pub fn promote(
        &mut self,
        helper: &HelperId,
        backend: Backend,
        admissible: &dyn PinAdmissibility,
    ) -> Result<Promotion, RolloutRefusal> {
        let track = self
            .tracks
            .get_mut(&(helper.clone(), backend))
            .ok_or(RolloutRefusal::UnknownTrack)?;
        let candidate = track
            .candidate
            .as_mut()
            .ok_or(RolloutRefusal::NoCandidate)?;
        let from = candidate.stage;
        let Some(evidence) = candidate.measured_pass else {
            return Err(if candidate.fake_passes > 0 {
                RolloutRefusal::FakeSubstrateOnly { stage: from }
            } else {
                RolloutRefusal::NoPassingEvidence { stage: from }
            });
        };
        let pin = candidate.pin.id();
        admissible
            .check(&candidate.pin)
            .map_err(|refusal| RolloutRefusal::NotAdmissible { pin, refusal })?;
        let to = if from == RolloutStage::Shadow {
            candidate.stage = RolloutStage::OptIn;
            candidate.measured_pass = None;
            candidate.fake_passes = 0;
            RolloutStage::OptIn
        } else {
            if let Some(promoted) = track.candidate.take() {
                let replaced = std::mem::replace(
                    &mut track.default,
                    DefaultPath::Bundle { pin: promoted.pin },
                );
                if let DefaultPath::Bundle { pin } = replaced {
                    track.previous.push(pin);
                }
            }
            RolloutStage::BackendDefault
        };
        self.append(
            helper,
            backend,
            RolloutEvent::Promoted {
                pin,
                from,
                to,
                evidence,
            },
        );
        Ok(Promotion { pin, from, to })
    }

    /// Records the owner's decision to remove source injection from the track of `helper`
    /// on `backend`. Accepted only while the default is a bundle with a measured pass as
    /// the backend default; nothing else ever removes it.
    pub fn remove_source_injection(
        &mut self,
        helper: &HelperId,
        backend: Backend,
        decision: SourceInjectionRemoval,
    ) -> Result<(), RolloutRefusal> {
        let track = self
            .tracks
            .get_mut(&(helper.clone(), backend))
            .ok_or(RolloutRefusal::UnknownTrack)?;
        if track.source_injection != SourceInjection::Retained {
            return Err(RolloutRefusal::SourceInjectionAlreadyRemoved);
        }
        let (replacement, evidence) = track
            .default
            .pin()
            .and_then(|pin| {
                let id = pin.id();
                track.proven.get(&id).map(|evidence| (id, *evidence))
            })
            .ok_or(RolloutRefusal::ReplacementNotProven)?;
        let SourceInjectionRemoval { decided_by, reason } = decision;
        track.source_injection = SourceInjection::Removed {
            replacement,
            evidence,
            decided_by: decided_by.clone(),
            reason: reason.clone(),
        };
        self.append(
            helper,
            backend,
            RolloutEvent::SourceInjectionRemoved {
                replacement,
                evidence,
                decided_by,
                reason,
            },
        );
        Ok(())
    }

    /// What a new runner on `runner` starts with for `helper`: the opt-in candidate if
    /// the runner opted in, else the backend default, else source injection; and the
    /// shadow candidate beside, which never serves.
    pub fn select(
        &self,
        helper: &HelperId,
        runner: &BackendRelease,
        opted_in: bool,
        admissible: &dyn PinAdmissibility,
    ) -> Result<RunnerHelpers, SelectionRefusal> {
        let mut selected = RunnerHelpers {
            helper: helper.clone(),
            runner: runner.clone(),
            serve: ServingHelper::SourceInjection,
            shadow: None,
            fallback: None,
        };
        let Some(track) = self.tracks.get(&(helper.clone(), runner.backend)) else {
            return Ok(selected);
        };
        let usable = |pin: &HelperPin| pin.supports(runner) && admissible.check(pin).is_ok();
        if let Some(candidate) = &track.candidate {
            match candidate.stage {
                RolloutStage::Shadow if usable(&candidate.pin) => {
                    selected.shadow = Some(candidate.pin.clone());
                }
                RolloutStage::OptIn if opted_in && usable(&candidate.pin) => {
                    selected.serve = ServingHelper::Bundle {
                        pin: candidate.pin.clone(),
                    };
                    return Ok(selected);
                }
                _ => {}
            }
        }
        let reason = match &track.default {
            DefaultPath::SourceInjection => return Ok(selected),
            DefaultPath::Unavailable => return Err(SelectionRefusal::Unavailable),
            DefaultPath::Bundle { pin } if !pin.supports(runner) => {
                FallbackReason::RunnerNotSupported { pin: pin.id() }
            }
            DefaultPath::Bundle { pin } => match admissible.check(pin) {
                Ok(()) => {
                    selected.serve = ServingHelper::Bundle { pin: pin.clone() };
                    return Ok(selected);
                }
                Err(refusal) => FallbackReason::NotAdmissible {
                    pin: pin.id(),
                    refusal,
                },
            },
        };
        if track.source_injection != SourceInjection::Retained {
            return Err(SelectionRefusal::DefaultUnusable { reason });
        }
        selected.fallback = Some(reason);
        Ok(selected)
    }
}
