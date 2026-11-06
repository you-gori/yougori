//! The records of the durable rollout stream, read strictly (G08: "persist rollout state";
//! S2 CORE-06 and CORE-08).
//!
//! Every rollout decision and every runner start and stop is one [`JournalRecord`]. A
//! record of a track carries its [`TrackPosition`]: its number in the track, so a replay
//! tells which tracks lost records in a gap, and the track's floor, which never goes down.
//! A decision names its evidence by identity ([`RecordedEvidence`]), never as a
//! provenance. A restatement ([`JournalRecord::RestatementBegins`] and its parts) restates
//! every track and every running runner, so retention may drop what came before it.
//!
//! The rollout and runner types write themselves but are not read back; the `Recorded*`
//! types here are their strict written forms, each converting both ways. Enum variants
//! without fields are written as empty structs, so unknown fields are refused for every
//! variant.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::abi::{HelperAbi, HelperAbiRefusal};
use super::super::evidence::EvidenceReference;
use super::super::identity::{HelperPin, HelperPinId, PinRefusal};
use super::super::manifest::{HelperId, HelperVersion};
use super::super::rollout::restore::{CandidateState, TrackState};
use super::super::rollout::{
    DefaultPath, FallbackReason, RollbackTarget, RolloutStage, RunnerHelpers, ServingHelper,
    SourceInjection, TrialVerdict,
};
use super::super::runners::{RunnerInstance, RunnerStart};
use crate::foundation::catalog::IntegrityFailure;
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::Digest;
use crate::foundation::report::Label;
use crate::foundation::signing::SignedComponent;

/// Where a record stands in its track.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackPosition {
    pub helper: HelperId,
    pub backend: Backend,
    /// The record's number in its track, from 1, continued across restatements.
    pub record: u64,
    /// The track's floor after the record: the newest version the track saw.
    pub floor: HelperVersion,
}

/// The CORE-08 evidence a decision rests on, by identity: the digest of the run records,
/// CORE-08's judgement of them when they were recorded, and the helper bundle's signed
/// component. Read back only to replay and check the decisions it was recorded with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEvidence {
    pub records: Digest,
    pub measured: bool,
    pub component: SignedComponent,
}

impl From<&EvidenceReference> for RecordedEvidence {
    fn from(reference: &EvidenceReference) -> Self {
        Self {
            records: reference.records(),
            measured: reference.is_measured(),
            component: reference.component().clone(),
        }
    }
}

/// The written form of [`TrialVerdict`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedVerdict {
    Passed {},
    Failed { reason: Label },
}

crate::foundation::strict_serde::strict_tag!(RecordedVerdict, "verdict");

impl From<&TrialVerdict> for RecordedVerdict {
    fn from(verdict: &TrialVerdict) -> Self {
        match verdict {
            TrialVerdict::Passed => Self::Passed {},
            TrialVerdict::Failed { reason } => Self::Failed {
                reason: reason.clone(),
            },
        }
    }
}

impl From<RecordedVerdict> for TrialVerdict {
    fn from(verdict: RecordedVerdict) -> Self {
        match verdict {
            RecordedVerdict::Passed {} => Self::Passed,
            RecordedVerdict::Failed { reason } => Self::Failed { reason },
        }
    }
}

/// The written form of [`RollbackTarget`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "path", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedTarget {
    SourceInjection {},
    Bundle { pin: HelperPinId },
    Unavailable {},
}

crate::foundation::strict_serde::strict_tag!(RecordedTarget, "path");

impl From<&RollbackTarget> for RecordedTarget {
    fn from(target: &RollbackTarget) -> Self {
        match target {
            RollbackTarget::SourceInjection => Self::SourceInjection {},
            RollbackTarget::Bundle { pin } => Self::Bundle { pin: *pin },
            RollbackTarget::Unavailable => Self::Unavailable {},
        }
    }
}

/// The written form of [`HelperAbiRefusal`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedAbiRefusal {
    MajorNotProvided {
        required: HelperAbi,
        provided: Vec<HelperAbi>,
    },
    MinorTooNew {
        required: HelperAbi,
        provided: HelperAbi,
    },
}

crate::foundation::strict_serde::strict_tag!(RecordedAbiRefusal, "refusal");

/// The written form of [`PinRefusal`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "pin", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedPinRefusal {
    Quarantined { reason: IntegrityFailure },
    NotPublished {},
    Inconsistent {},
    IncompatibleAbi { refusal: RecordedAbiRefusal },
}

crate::foundation::strict_serde::strict_tag!(RecordedPinRefusal, "pin");

impl From<&PinRefusal> for RecordedPinRefusal {
    fn from(refusal: &PinRefusal) -> Self {
        match refusal {
            PinRefusal::Quarantined { reason } => Self::Quarantined {
                reason: reason.clone(),
            },
            PinRefusal::NotPublished => Self::NotPublished {},
            PinRefusal::Inconsistent => Self::Inconsistent {},
            PinRefusal::IncompatibleAbi { refusal } => Self::IncompatibleAbi {
                refusal: match refusal {
                    HelperAbiRefusal::MajorNotProvided { required, provided } => {
                        RecordedAbiRefusal::MajorNotProvided {
                            required: *required,
                            provided: provided.clone(),
                        }
                    }
                    HelperAbiRefusal::MinorTooNew { required, provided } => {
                        RecordedAbiRefusal::MinorTooNew {
                            required: *required,
                            provided: *provided,
                        }
                    }
                },
            },
        }
    }
}

impl From<RecordedPinRefusal> for PinRefusal {
    fn from(refusal: RecordedPinRefusal) -> Self {
        match refusal {
            RecordedPinRefusal::Quarantined { reason } => Self::Quarantined { reason },
            RecordedPinRefusal::NotPublished {} => Self::NotPublished,
            RecordedPinRefusal::Inconsistent {} => Self::Inconsistent,
            RecordedPinRefusal::IncompatibleAbi { refusal } => Self::IncompatibleAbi {
                refusal: match refusal {
                    RecordedAbiRefusal::MajorNotProvided { required, provided } => {
                        HelperAbiRefusal::MajorNotProvided { required, provided }
                    }
                    RecordedAbiRefusal::MinorTooNew { required, provided } => {
                        HelperAbiRefusal::MinorTooNew { required, provided }
                    }
                },
            },
        }
    }
}

/// An earlier default a rollback passed over, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedSkip {
    pub pin: HelperPinId,
    pub refusal: RecordedPinRefusal,
}

/// What a trial or a withdrawal did to its track.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedOutcome {
    /// Kept: a pass, or a withdrawn version that was only a rollback target.
    Recorded {},
    /// The track rolled back to `to`, passing over `skipped`.
    RolledBack {
        to: RecordedTarget,
        skipped: Vec<RecordedSkip>,
    },
}

crate::foundation::strict_serde::strict_tag!(RecordedOutcome, "outcome");

/// The written form of [`DefaultPath`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "path", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedDefault {
    SourceInjection {},
    Bundle { pin: HelperPin },
    Unavailable {},
}

crate::foundation::strict_serde::strict_tag!(RecordedDefault, "path");

/// The written form of [`SourceInjection`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "source_injection",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[serde(remote = "Self")]
pub enum RecordedSourceInjection {
    Retained {},
    Removed {
        replacement: HelperPinId,
        evidence: Digest,
        decided_by: Label,
        reason: Label,
    },
}

crate::foundation::strict_serde::strict_tag!(RecordedSourceInjection, "source_injection");

/// A restated candidate with the evidence it holds at its stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedCandidate {
    pub pin: HelperPin,
    pub stage: RolloutStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_pass: Option<Digest>,
    pub fake_passes: u64,
}

/// A default with a measured pass as the backend default, and its evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedProof {
    pub pin: HelperPinId,
    pub evidence: Digest,
}

/// One track, restated whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedTrack {
    pub helper: HelperId,
    pub backend: Backend,
    /// The number of the track's last record.
    pub records: u64,
    pub floor: HelperVersion,
    pub default: RecordedDefault,
    /// Earlier defaults, oldest first.
    pub previous: Vec<HelperPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<RecordedCandidate>,
    pub failed: Vec<HelperPinId>,
    pub proven: Vec<RecordedProof>,
    pub source_injection: RecordedSourceInjection,
}

impl RecordedTrack {
    /// The written form of `state`, the track of `helper` on `backend` after record
    /// `records`.
    pub(super) fn of(
        helper: HelperId,
        backend: Backend,
        records: u64,
        floor: HelperVersion,
        state: &TrackState,
    ) -> Self {
        Self {
            helper,
            backend,
            records,
            floor,
            default: match &state.default {
                DefaultPath::SourceInjection => RecordedDefault::SourceInjection {},
                DefaultPath::Bundle { pin } => RecordedDefault::Bundle { pin: pin.clone() },
                DefaultPath::Unavailable => RecordedDefault::Unavailable {},
            },
            previous: state.previous.clone(),
            candidate: state.candidate.as_ref().map(|candidate| RecordedCandidate {
                pin: candidate.pin.clone(),
                stage: candidate.stage,
                measured_pass: candidate.measured_pass,
                fake_passes: candidate.fake_passes,
            }),
            failed: state.failed.iter().copied().collect(),
            proven: state
                .proven
                .iter()
                .map(|(pin, evidence)| RecordedProof {
                    pin: *pin,
                    evidence: *evidence,
                })
                .collect(),
            source_injection: match &state.source_injection {
                SourceInjection::Retained => RecordedSourceInjection::Retained {},
                SourceInjection::Removed {
                    replacement,
                    evidence,
                    decided_by,
                    reason,
                } => RecordedSourceInjection::Removed {
                    replacement: *replacement,
                    evidence: *evidence,
                    decided_by: decided_by.clone(),
                    reason: reason.clone(),
                },
            },
        }
    }

    /// Every pin the restated track names.
    pub(super) fn pins(&self) -> impl Iterator<Item = &HelperPin> {
        let default = match &self.default {
            RecordedDefault::Bundle { pin } => Some(pin),
            RecordedDefault::SourceInjection {} | RecordedDefault::Unavailable {} => None,
        };
        default
            .into_iter()
            .chain(self.previous.iter())
            .chain(self.candidate.as_ref().map(|candidate| &candidate.pin))
    }

    /// The track's state.
    pub(super) fn state(&self) -> TrackState {
        TrackState {
            default: match &self.default {
                RecordedDefault::SourceInjection {} => DefaultPath::SourceInjection,
                RecordedDefault::Bundle { pin } => DefaultPath::Bundle { pin: pin.clone() },
                RecordedDefault::Unavailable {} => DefaultPath::Unavailable,
            },
            previous: self.previous.clone(),
            candidate: self.candidate.as_ref().map(|candidate| CandidateState {
                pin: candidate.pin.clone(),
                stage: candidate.stage,
                measured_pass: candidate.measured_pass,
                fake_passes: candidate.fake_passes,
            }),
            failed: self.failed.iter().copied().collect(),
            proven: self
                .proven
                .iter()
                .map(|proof| (proof.pin, proof.evidence))
                .collect(),
            floor: Some(self.floor),
            source_injection: match &self.source_injection {
                RecordedSourceInjection::Retained {} => SourceInjection::Retained,
                RecordedSourceInjection::Removed {
                    replacement,
                    evidence,
                    decided_by,
                    reason,
                } => SourceInjection::Removed {
                    replacement: *replacement,
                    evidence: *evidence,
                    decided_by: decided_by.clone(),
                    reason: reason.clone(),
                },
            },
        }
    }
}

/// The written form of [`ServingHelper`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "path", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedServing {
    SourceInjection {},
    Bundle { pin: HelperPin },
}

crate::foundation::strict_serde::strict_tag!(RecordedServing, "path");

/// The written form of [`FallbackReason`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecordedFallback {
    RunnerNotSupported {
        pin: HelperPinId,
    },
    NotAdmissible {
        pin: HelperPinId,
        refusal: RecordedPinRefusal,
    },
}

crate::foundation::strict_serde::strict_tag!(RecordedFallback, "reason");

/// What a runner started with for one helper: the written form of [`RunnerHelpers`]
/// without the runner, which its [`RecordedRunner`] names once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedSelection {
    pub helper: HelperId,
    pub serve: RecordedServing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<HelperPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<RecordedFallback>,
}

/// What one running runner started with: the written form of [`RunnerStart`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedRunner {
    pub runner: RunnerInstance,
    pub release: BackendRelease,
    pub helpers: Vec<RecordedSelection>,
}

impl From<&RunnerStart> for RecordedRunner {
    fn from(start: &RunnerStart) -> Self {
        Self {
            runner: start.runner.clone(),
            release: start.release.clone(),
            helpers: start
                .helpers
                .values()
                .map(|selected| RecordedSelection {
                    helper: selected.helper.clone(),
                    serve: match &selected.serve {
                        ServingHelper::SourceInjection => RecordedServing::SourceInjection {},
                        ServingHelper::Bundle { pin } => {
                            RecordedServing::Bundle { pin: pin.clone() }
                        }
                    },
                    shadow: selected.shadow.clone(),
                    fallback: selected.fallback.as_ref().map(|fallback| match fallback {
                        FallbackReason::RunnerNotSupported { pin } => {
                            RecordedFallback::RunnerNotSupported { pin: *pin }
                        }
                        FallbackReason::NotAdmissible { pin, refusal } => {
                            RecordedFallback::NotAdmissible {
                                pin: *pin,
                                refusal: RecordedPinRefusal::from(refusal),
                            }
                        }
                    }),
                })
                .collect(),
        }
    }
}

impl RecordedRunner {
    /// The selections, as [`RunnerPins::start`](super::super::RunnerPins::start) takes them.
    pub(super) fn selections(&self) -> Vec<RunnerHelpers> {
        self.helpers
            .iter()
            .map(|selected| RunnerHelpers {
                helper: selected.helper.clone(),
                runner: self.release.clone(),
                serve: match &selected.serve {
                    RecordedServing::SourceInjection {} => ServingHelper::SourceInjection,
                    RecordedServing::Bundle { pin } => ServingHelper::Bundle { pin: pin.clone() },
                },
                shadow: selected.shadow.clone(),
                fallback: selected.fallback.clone().map(|fallback| match fallback {
                    RecordedFallback::RunnerNotSupported { pin } => {
                        FallbackReason::RunnerNotSupported { pin }
                    }
                    RecordedFallback::NotAdmissible { pin, refusal } => {
                        FallbackReason::NotAdmissible {
                            pin,
                            refusal: PinRefusal::from(refusal),
                        }
                    }
                }),
            })
            .collect()
    }

    /// Every pinned version the runner loaded, serving or shadow.
    pub(super) fn pins(&self) -> impl Iterator<Item = &HelperPin> {
        self.helpers.iter().flat_map(|selected| {
            let serving = match &selected.serve {
                RecordedServing::Bundle { pin } => Some(pin),
                RecordedServing::SourceInjection {} => None,
            };
            serving.into_iter().chain(selected.shadow.as_ref())
        })
    }
}

/// One record of the durable rollout stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalRecord {
    /// `pin` became the shadow candidate of its track.
    Proposed {
        track: TrackPosition,
        pin: HelperPin,
    },
    /// One trial of `pin` on `runner` at `stage`, and what it did.
    Trial {
        track: TrackPosition,
        pin: HelperPinId,
        runner: BackendRelease,
        stage: RolloutStage,
        verdict: RecordedVerdict,
        evidence: RecordedEvidence,
        outcome: RecordedOutcome,
    },
    /// The candidate moved one stage on, on the measured pass `evidence` names.
    Promoted {
        track: TrackPosition,
        pin: HelperPinId,
        from: RolloutStage,
        to: RolloutStage,
        evidence: RecordedEvidence,
    },
    /// The owner removed source injection after `replacement` passed as the default on the
    /// measured pass `evidence` names.
    SourceInjectionRemoved {
        track: TrackPosition,
        replacement: HelperPinId,
        evidence: RecordedEvidence,
        decided_by: Label,
        reason: Label,
    },
    /// The owner withdrew `pin` from the track, as failure evidence would.
    Withdrawn {
        track: TrackPosition,
        pin: HelperPinId,
        decided_by: Label,
        reason: Label,
        outcome: RecordedOutcome,
    },
    RunnerStarted {
        start: RecordedRunner,
    },
    RunnerStopped {
        runner: RunnerInstance,
    },
    /// A restatement of every track and every running runner begins: `tracks`
    /// [`JournalRecord::RestatedTrack`] records follow, then `runners`
    /// [`JournalRecord::RestatedRunner`] records. Once complete, everything before it is
    /// held in it.
    RestatementBegins {
        tracks: u64,
        runners: u64,
    },
    /// Track `part`, from 1, of the restatement that began last.
    RestatedTrack {
        part: u64,
        track: Box<RecordedTrack>,
    },
    /// Runner `part`, from 1, of the restatement that began last.
    RestatedRunner {
        part: u64,
        start: RecordedRunner,
    },
}

impl JournalRecord {
    /// The track a decision belongs to.
    pub fn track(&self) -> Option<&TrackPosition> {
        match self {
            Self::Proposed { track, .. }
            | Self::Trial { track, .. }
            | Self::Promoted { track, .. }
            | Self::SourceInjectionRemoved { track, .. }
            | Self::Withdrawn { track, .. } => Some(track),
            Self::RunnerStarted { .. }
            | Self::RunnerStopped { .. }
            | Self::RestatementBegins { .. }
            | Self::RestatedTrack { .. }
            | Self::RestatedRunner { .. } => None,
        }
    }
}

/// The skipped pins of a rollback as an admissibility map for its replay.
pub(super) fn skipped_refusals(skipped: &[RecordedSkip]) -> BTreeMap<HelperPinId, PinRefusal> {
    skipped
        .iter()
        .map(|skip| (skip.pin, PinRefusal::from(skip.refusal.clone())))
        .collect()
}
