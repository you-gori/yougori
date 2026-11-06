//! Model fidelity, the second evidence level (S9 lines 172 and 175; S7 line 127; S11
//! BENCH-04; S12 G2).
//!
//! The statistics are CORE-08's ([`ToolFidelity`], [`ToolFidelityEvidence`],
//! [`AlignmentKey`]). What is specific to the serving protocol is kept here: how an
//! assembled turn counts as a triggered call and how many of its calls are schema-valid,
//! and the rule that model fidelity is recorded only against a matched, licensed or
//! controlled, authorized reference. Without one, the record says the reference is
//! unavailable and why; it is never a pass (S12 G2).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::foundation::report::{
    AlignmentField, AlignmentKey, Label, ReportError, SuccessRate, ToolCallObservation,
    ToolFidelity, ToolFidelityEvidence,
};

use super::request::RequestProfile;
use super::turn::TurnOutcome;
use super::validation::schema_valid_calls;

/// One side of a paired item: an assembled outcome and the request it answered.
#[derive(Clone, Copy, Debug)]
pub struct PairSide<'a> {
    pub outcome: &'a TurnOutcome,
    pub request: &'a RequestProfile,
}

impl PairSide<'_> {
    /// Calls the turn triggered: those of a completed turn. Any other outcome triggered
    /// none, as a finish reason other than tool calls counts as "stop or others"; a
    /// disconnect or protocol fault therefore stays in the candidate's denominator.
    pub fn triggered_calls(&self) -> u32 {
        self.outcome.completed().map_or(0, |turn| {
            u32::try_from(turn.tool_calls().len()).unwrap_or(u32::MAX)
        })
    }

    /// Triggered calls whose arguments satisfy their declared schema.
    pub fn schema_valid_calls(&self) -> u32 {
        self.outcome.completed().map_or(0, |turn| {
            u32::try_from(schema_valid_calls(turn, self.request)).unwrap_or(u32::MAX)
        })
    }

    /// Whether the side reached a finish reason at all; a reference that did not cannot
    /// say whether a call should have been triggered.
    pub fn finished(&self) -> bool {
        self.outcome.finish().is_some()
    }
}

/// A paired item turned into a CORE-08 observation, or set aside because the reference
/// failed (S7 line 127 "paired reference runs").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PairObservation {
    Observed {
        observation: ToolCallObservation,
    },
    /// The reference reached no finish reason; the item has no trigger label and is
    /// counted here rather than guessed.
    ReferenceFailed {
        item: Label,
    },
}

/// Observes one paired item.
pub fn observe_pair(
    item: Label,
    reference: PairSide<'_>,
    candidate: PairSide<'_>,
) -> PairObservation {
    if !reference.finished() {
        return PairObservation::ReferenceFailed { item };
    }
    PairObservation::Observed {
        observation: ToolCallObservation {
            item,
            reference_calls: reference.triggered_calls(),
            candidate_calls: candidate.triggered_calls(),
            candidate_schema_valid_calls: candidate.schema_valid_calls(),
        },
    }
}

/// A paired corpus split into CORE-08 observations and items whose reference failed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PairedCorpus {
    pub observations: Vec<ToolCallObservation>,
    pub reference_failed: Vec<Label>,
}

impl PairedCorpus {
    /// Splits observed pairs from pairs whose reference failed.
    pub fn from_observations(pairs: impl IntoIterator<Item = PairObservation>) -> Self {
        let mut corpus = Self::default();
        for pair in pairs {
            match pair {
                PairObservation::Observed { observation } => corpus.observations.push(observation),
                PairObservation::ReferenceFailed { item } => corpus.reference_failed.push(item),
            }
        }
        corpus
    }
}

/// What kind of reference a comparison uses (S9 line 172: "a licensed official or
/// controlled reference").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// The model vendor's official service, used under its license.
    LicensedOfficial,
    /// A reference run Yougori controls, with the same model artifacts.
    Controlled,
    /// A source without a license for this use.
    Unlicensed,
}

/// A reference run that exists (S7 line 127: "paired, authorized reference runs").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReferenceRun {
    pub kind: ReferenceKind,
    /// Whether this comparison is authorized.
    pub authorized: bool,
    /// The tokenizer, template, weights, quantization and kernel configuration it ran.
    pub alignment: AlignmentKey,
}

/// The reference a comparison sought, and the run, if one exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReferenceSource {
    pub label: Label,
    pub run: Option<ReferenceRun>,
}

/// Why no matched reference was available: the recorded limit (S9 line 172).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReferenceUnavailable {
    NoReferenceRun,
    NotLicensed,
    NotAuthorized,
    /// The reference ran other settings; temperature zero does not make up for any of
    /// them (S7 line 127).
    SettingsMismatch {
        fields: Vec<AlignmentField>,
    },
}

impl fmt::Display for ReferenceUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReferenceRun => f.write_str("no reference run exists"),
            Self::NotLicensed => f.write_str("the reference is not licensed for this use"),
            Self::NotAuthorized => f.write_str("the comparison is not authorized"),
            Self::SettingsMismatch { fields } => {
                write!(f, "the reference ran different settings: {fields:?}")
            }
        }
    }
}

/// Model fidelity: measured against a matched reference, or the reference's absence and
/// its reason (S9 line 172).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelFidelity {
    Measured {
        reference: Label,
        metrics: ToolFidelity,
        /// Items set aside because the reference reached no finish reason.
        reference_failed: Vec<Label>,
    },
    ReferenceUnavailable {
        reference: Label,
        reason: ReferenceUnavailable,
    },
}

impl ModelFidelity {
    /// Records fidelity only when the reference is licensed or controlled, authorized and
    /// ran exactly the candidate's tokenizer, template, weights, quantization and kernel
    /// configuration; otherwise records why it is unavailable (S9 line 172; S12 G2).
    pub fn assess(
        candidate: &AlignmentKey,
        reference: &ReferenceSource,
        corpus: &PairedCorpus,
        task_success: SuccessRate,
    ) -> Result<Self, ReportError> {
        let unavailable = |reason| {
            Ok(Self::ReferenceUnavailable {
                reference: reference.label.clone(),
                reason,
            })
        };
        let Some(run) = &reference.run else {
            return unavailable(ReferenceUnavailable::NoReferenceRun);
        };
        if run.kind == ReferenceKind::Unlicensed {
            return unavailable(ReferenceUnavailable::NotLicensed);
        }
        if !run.authorized {
            return unavailable(ReferenceUnavailable::NotAuthorized);
        }
        let fields = candidate.differences(&run.alignment);
        if !fields.is_empty() {
            return unavailable(ReferenceUnavailable::SettingsMismatch { fields });
        }
        let mut items = BTreeSet::new();
        for item in corpus
            .observations
            .iter()
            .map(|observation| &observation.item)
            .chain(&corpus.reference_failed)
        {
            if !items.insert(item) {
                return Err(ReportError::DuplicatePairedItem);
            }
        }
        Ok(Self::Measured {
            reference: reference.label.clone(),
            metrics: ToolFidelity::from_observations(&corpus.observations, task_success)?,
            reference_failed: corpus.reference_failed.clone(),
        })
    }

    /// The CORE-08 BENCH-04 evidence: the metrics, or a recorded missing reference.
    pub fn evidence(&self) -> ToolFidelityEvidence {
        match self {
            Self::Measured { metrics, .. } => ToolFidelityEvidence::Measured {
                metrics: metrics.clone(),
            },
            Self::ReferenceUnavailable { reference, .. } => {
                ToolFidelityEvidence::ReferenceUnavailable {
                    reference: reference.clone(),
                }
            }
        }
    }
}
