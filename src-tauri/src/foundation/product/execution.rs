//! The requested execution category against the actual backend, and requested CORE-01
//! capabilities with their evidence (S2 CORE-07 "execution category, requested
//! capabilities, actual backend"; S1; S3.5; INT-07; VM part §1.3; VM-D4–VM-D6).
//!
//! The category matrix, admission and selection are CORE-01's ([`RuntimeRequirement`],
//! [`RuntimeOffer`], [`AdmittedRuntime`]); this module only shows their results. A
//! category is shown with its own recorded label, decision and sandbox flag
//! ([`CategoryShown`]), and reading one back refuses any other label, so no document can
//! show a labelled runtime as a VM sandbox. The choices a request offers are recomputed
//! from its requirement when read, an actual backend must be one its request admits, and
//! an actual backend is never merely asserted: admission rests on host or provider
//! evidence, never on a caller's label.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::evidence::{Evidence, Fact, VerifiedBy};
use super::refusal::Refusal;
use crate::foundation::evidence::{
    AdmittedRuntime, BackendRelease, Capability, ClockReading, EvidenceRefusal, Requirement,
    RuntimeOffer, RuntimeRequirement, RuntimeSubject, Satisfied, SourceClass,
};
use crate::foundation::ids::{Digest, ExecutionCategory};

/// An execution category with its recorded user-facing label, the decision that keeps a
/// labelled runtime, and whether it is a sandbox. Only a VM sandbox is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CategoryShown {
    category: ExecutionCategory,
    label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<&'static str>,
    sandbox: bool,
}

impl CategoryShown {
    pub const fn category(&self) -> ExecutionCategory {
        self.category
    }

    /// The recorded label, such as "GPU runtime (shared kernel), not a sandbox".
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// The recorded decision that keeps a labelled runtime; `None` for a VM sandbox.
    pub const fn decision(&self) -> Option<&'static str> {
        self.decision
    }

    /// Whether the category is a sandbox: only a VM sandbox is.
    pub const fn is_sandbox(&self) -> bool {
        self.sandbox
    }
}

impl From<ExecutionCategory> for CategoryShown {
    fn from(category: ExecutionCategory) -> Self {
        Self {
            category,
            label: category.label(),
            decision: category.decision(),
            sandbox: category.is_vm_sandbox(),
        }
    }
}

impl fmt::Display for CategoryShown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label)?;
        if let Some(decision) = self.decision {
            write!(f, " ({decision})")?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CategoryShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            category: ExecutionCategory,
            label: String,
            #[serde(default)]
            decision: Option<String>,
            sandbox: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        let shown = Self::from(wire.category);
        if wire.label != shown.label
            || wire.decision.as_deref() != shown.decision
            || wire.sandbox != shown.sandbox
        {
            return Err(serde::de::Error::custom(format!(
                "category {:?} is shown only as \"{}\"{}, never with another label, decision or \
                 sandbox flag",
                wire.category,
                shown.label,
                shown
                    .decision
                    .map(|decision| format!(" ({decision})"))
                    .unwrap_or_default()
            )));
        }
        Ok(shown)
    }
}

/// One category of the matrix for a request: whether the request allows it and, if not,
/// why (INT-07: the CLI and UI choose among labelled runtimes by their labels).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryChoice {
    pub category: CategoryShown,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

/// What a request requires of the execution category, and every category's standing
/// against it, in CORE-01's matrix order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestedExecution {
    requirement: RuntimeRequirement,
    choices: Vec<CategoryChoice>,
}

impl RequestedExecution {
    pub fn requirement(&self) -> &RuntimeRequirement {
        &self.requirement
    }

    pub fn choices(&self) -> &[CategoryChoice] {
        &self.choices
    }

    /// Whether the request admits `category`.
    pub fn allows(&self, category: ExecutionCategory) -> bool {
        self.choices
            .iter()
            .any(|choice| choice.category.category() == category && choice.allowed)
    }
}

impl From<&RuntimeRequirement> for RequestedExecution {
    fn from(requirement: &RuntimeRequirement) -> Self {
        let choices = requirement
            .matrix()
            .into_iter()
            .map(|(category, outcome)| CategoryChoice {
                category: CategoryShown::from(category),
                allowed: outcome.is_ok(),
                refusal: outcome.err().as_ref().map(Refusal::from),
            })
            .collect();
        Self {
            requirement: requirement.clone(),
            choices,
        }
    }
}

impl<'de> Deserialize<'de> for RequestedExecution {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            requirement: RuntimeRequirement,
            choices: Vec<CategoryChoice>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let expected = Self::from(&wire.requirement);
        if wire.choices != expected.choices {
            return Err(serde::de::Error::custom(
                "the category choices are not what the requirement admits and refuses",
            ));
        }
        Ok(expected)
    }
}

/// The runtime that actually runs the work: its category with its label, its backend
/// release and the instance digest CORE-01 evidence names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActualBackend {
    pub category: CategoryShown,
    pub release: BackendRelease,
    pub instance: Digest,
}

impl From<&RuntimeSubject> for ActualBackend {
    fn from(runtime: &RuntimeSubject) -> Self {
        Self {
            category: CategoryShown::from(runtime.category),
            release: runtime.release.clone(),
            instance: runtime.instance,
        }
    }
}

/// The requested category against the actual backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Execution {
    requested: RequestedExecution,
    actual: Fact<ActualBackend>,
}

impl Execution {
    /// The runtime CORE-01 admitted for `requirement`, on its category evidence at `now`
    /// (a reading of the registry that evaluated it). Host-probe evidence verifies the
    /// backend and a provider API observes it; evidence no longer current leaves the
    /// backend unavailable.
    pub fn admitted(
        requirement: &RuntimeRequirement,
        admitted: &AdmittedRuntime,
        now: ClockReading,
    ) -> Self {
        Self {
            requested: RequestedExecution::from(requirement),
            actual: Fact::from_satisfied(
                ActualBackend::from(admitted.runtime()),
                admitted.evidence(),
                now,
            ),
        }
    }

    /// CORE-01's selection among `offers`, in the caller's order of preference: the first
    /// admissible one, or every offer's refusal as one. Nothing is substituted.
    pub fn select(
        requirement: &RuntimeRequirement,
        offers: &[RuntimeOffer],
        now: ClockReading,
    ) -> Self {
        match requirement.select(offers) {
            Ok(admitted) => Self::admitted(requirement, &admitted, now),
            Err(selection) => Self::refused(requirement, Refusal::from(&selection)),
        }
    }

    /// No backend runs, with why and what the user can do.
    pub fn refused(requirement: &RuntimeRequirement, refusal: Refusal) -> Self {
        Self {
            requested: RequestedExecution::from(requirement),
            actual: Fact::unavailable(refusal),
        }
    }

    pub fn requested(&self) -> &RequestedExecution {
        &self.requested
    }

    pub fn actual(&self) -> &Fact<ActualBackend> {
        &self.actual
    }

    /// The execution when shown again ([`Fact::as_of`]).
    pub(super) fn with_actual(&self, actual: Fact<ActualBackend>) -> Self {
        Self {
            requested: self.requested.clone(),
            actual,
        }
    }

    /// An actual backend must be one its request admits, and stand on host or provider
    /// evidence, never on an assertion.
    pub fn check(&self) -> Result<(), ExecutionError> {
        let Some(actual) = self.actual.value() else {
            return Ok(());
        };
        let category = actual.category.category();
        if !self.requested.allows(category) {
            return Err(ExecutionError::NotAdmitted { category });
        }
        match self.actual.evidence() {
            Evidence::Verified {
                by:
                    VerifiedBy::HostProbe {
                        capability: Capability::RuntimeCategory,
                    },
                ..
            }
            | Evidence::Observed { .. } => Ok(()),
            Evidence::Asserted { .. } => Err(ExecutionError::AssertedBackend),
            Evidence::Verified { .. } | Evidence::Unavailable { .. } => {
                Err(ExecutionError::OtherEvidence)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Execution {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            requested: RequestedExecution,
            actual: Fact<ActualBackend>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let execution = Self {
            requested: wire.requested,
            actual: wire.actual,
        };
        execution.check().map_err(serde::de::Error::custom)?;
        Ok(execution)
    }
}

/// Why an execution is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    /// The actual backend's category is one the request refuses: a VM-required request
    /// can neither select nor degrade to a labelled runtime (S1, INT-07).
    NotAdmitted { category: ExecutionCategory },
    /// An actual backend shown on an assertion; admission needs host or provider evidence.
    AssertedBackend,
    /// An actual backend verified by anything but host-probe evidence of its category.
    OtherEvidence,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAdmitted { category } => write!(
                f,
                "the actual backend is \"{}\", which its request does not admit",
                category.label()
            ),
            Self::AssertedBackend => f.write_str(
                "an actual backend stands on host or provider evidence of its category, never \
                 on an assertion",
            ),
            Self::OtherEvidence => f.write_str(
                "an actual backend is verified only by host-probe evidence of its runtime category",
            ),
        }
    }
}

impl std::error::Error for ExecutionError {}

/// One requested CORE-01 capability with the evidence standing behind it, or why none
/// does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityCheck {
    capability: Capability,
    /// The weakest source the requirement accepts, after raising it to the capability's
    /// floor.
    required: SourceClass,
    evidence: Evidence,
}

impl CapabilityCheck {
    /// The outcome of evaluating `requirement`, at `now`, a reading of the registry that
    /// evaluated it.
    pub fn evaluate(
        requirement: &Requirement,
        outcome: &Result<Satisfied, EvidenceRefusal>,
        now: ClockReading,
    ) -> Self {
        let evidence = match outcome {
            Ok(satisfied) => Evidence::from_satisfied(satisfied, now),
            Err(refusal) => Evidence::Unavailable {
                refusal: Refusal::from(refusal),
            },
        };
        Self {
            capability: requirement.capability,
            required: requirement.effective_minimum(),
            evidence,
        }
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    pub fn required(&self) -> SourceClass {
        self.required
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub(super) fn with_evidence(&self, evidence: Evidence) -> Self {
        Self {
            capability: self.capability,
            required: self.required,
            evidence,
        }
    }

    /// The required source is at least the capability's floor; evidence weaker than the
    /// requirement never stands behind it (a guest report never satisfies a host-only
    /// requirement); only host-probe evidence of this capability verifies it.
    pub fn check(&self) -> Result<(), CapabilityCheckError> {
        if !self.required.satisfies(self.capability.weakest_source()) {
            return Err(CapabilityCheckError::BelowFloor);
        }
        if let Some(source) = self.evidence.source() {
            if !source.satisfies(self.required) {
                return Err(CapabilityCheckError::WeakerThanRequired {
                    source,
                    required: self.required,
                });
            }
        }
        match &self.evidence {
            Evidence::Verified {
                by: VerifiedBy::HostProbe { capability },
                ..
            } if *capability != self.capability => Err(CapabilityCheckError::OtherCapability),
            Evidence::Verified {
                by: VerifiedBy::ControlledCheck,
                ..
            } => Err(CapabilityCheckError::OtherCapability),
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for CapabilityCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            capability: Capability,
            required: SourceClass,
            evidence: Evidence,
        }
        let wire = Wire::deserialize(deserializer)?;
        let check = Self {
            capability: wire.capability,
            required: wire.required,
            evidence: wire.evidence,
        };
        check.check().map_err(serde::de::Error::custom)?;
        Ok(check)
    }
}

/// Why a capability check is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityCheckError {
    /// The required source is weaker than the capability's floor.
    BelowFloor,
    /// The evidence's source is weaker than the requirement.
    WeakerThanRequired {
        source: SourceClass,
        required: SourceClass,
    },
    /// Verified by anything but host-probe evidence of this capability.
    OtherCapability,
}

impl fmt::Display for CapabilityCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowFloor => {
                f.write_str("the required source is weaker than the capability's floor")
            }
            Self::WeakerThanRequired { source, required } => write!(
                f,
                "evidence from a {source} never stands behind a requirement for a {required}"
            ),
            Self::OtherCapability => {
                f.write_str("a capability is verified only by host-probe evidence of itself")
            }
        }
    }
}

impl std::error::Error for CapabilityCheckError {}
