//! The evidence checker (VM-W02; VM part §0.1 item 6, §2.4).
//!
//! It judges host predicates only through CORE-01: runtime-category evidence admitted
//! under `RuntimeRequirement::VmSandbox`, host-probe evidence of hypervisor availability,
//! and host-probe evidence that every block rule of the launch's perimeter profile is
//! enforced, all evaluated by the [`ProbeRegistry`] on its own clock. It writes no
//! second evidence model. It receives the requirement set and can only report each
//! predicate as verified or refused: evidence never removes or weakens a requirement,
//! and a guest report never meets a host-only predicate (CORE-01; VM-W09; VM-P50).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::budget::BudgetKey;
use super::predicate::{EvidenceBinding, PredicateCheck, RequirementSet, SecurityPredicate};
use super::tuple::PermissionTuple;
use crate::foundation::evidence::{
    Capability, CategoryRefusal, ClockSession, ConfigurationFingerprint, EvidenceRefusal,
    HypervisorSubject, ProbeRegistry, Requirement, RuntimeOffer, RuntimeRequirement,
    RuntimeSubject, Satisfied, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{Clock, Digest, MonotonicTime};
use crate::sandbox_contract::destinations::{PerimeterProfile, PerimeterTarget};

/// What the launch would run on, as the host knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchTargets {
    /// The exact runtime; its category must be confirmed by host or provider evidence.
    pub runtime: RuntimeSubject,
    /// The configuration in force for the runtime now.
    pub runtime_configuration: ConfigurationFingerprint,
    /// The hypervisor interface the launch would use.
    pub hypervisor: HypervisorSubject,
    /// The configuration in force for the hypervisor now.
    pub hypervisor_configuration: ConfigurationFingerprint,
    /// The oldest evidence the launch accepts.
    pub max_age: Duration,
    /// The perimeter the launch would run behind; `None` when none is declared, which
    /// leaves an independent-perimeter requirement unmet.
    pub perimeter: Option<LaunchPerimeter>,
}

/// The perimeter a launch would run behind (VM §4.4): where it is installed, its declared
/// profile, and the configuration in force for its rules now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPerimeter {
    pub target: PerimeterTarget,
    pub profile: PerimeterProfile,
    pub configuration: ConfigurationFingerprint,
}

/// One perimeter block rule CORE-01 did not show enforced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerimeterRuleRefusal {
    /// The digest of the block rule.
    pub rule: Digest,
    pub refusal: EvidenceRefusal,
}

strict_policy_enum! {
    /// How one required predicate was judged.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PredicateOutcome tag "outcome" {
        /// CORE-01 evidence met it; it is fresh until `fresh_until` on the registry clock.
        Verified {
            source: SourceClass,
            observed_at: MonotonicTime,
            fresh_until: MonotonicTime,
            detail: SupportDetail,
        },
        /// CORE-01 refused the evidence: missing, too weak a source (a guest report for a
        /// host-only check), changed configuration, stale, unsupported or inconclusive.
        EvidenceRefused { refusal: EvidenceRefusal },
        /// The runtime is a labelled runtime, never a VM sandbox (VM-D4–VM-D6).
        CategoryRefused { refusal: CategoryRefusal },
        /// No CORE-01 capability observes the predicate yet; it is not assumed.
        NoEvidenceCapability { needed: String },
        /// The launch declares no perimeter or a profile without block rules, so nothing
        /// can show an independent perimeter.
        NoPerimeterRules,
        /// CORE-01 did not show these block rules enforced; every rule must be.
        PerimeterRulesRefused { refused: Vec<PerimeterRuleRefusal> },
        /// The evidence checker was not asked about it.
        NotChecked,
        /// The contract has the property. This describes the contract, not enforcement.
        ContractHolds,
        /// The contract permits what the predicate forbids.
        ContractViolated { tuples: Vec<PermissionTuple> },
        /// The contract lacks budgets the predicate needs.
        ContractBudgetMissing { keys: Vec<BudgetKey> },
    }
}

impl PredicateOutcome {
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::ContractHolds)
    }

    fn verified(evidence: &Satisfied) -> Self {
        Self::Verified {
            source: evidence.source(),
            observed_at: evidence.observed_at(),
            fresh_until: evidence.fresh_until(),
            detail: evidence.detail().clone(),
        }
    }
}

impl fmt::Display for PredicateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified { source, .. } => write!(f, "verified by a {source}"),
            Self::EvidenceRefused { refusal } => write!(f, "{refusal}"),
            Self::CategoryRefused { refusal } => write!(f, "{refusal}"),
            Self::NoEvidenceCapability { needed } => write!(
                f,
                "no evidence capability observes it yet (needed: {needed}), so it is not \
                 assumed to hold"
            ),
            Self::NoPerimeterRules => f.write_str(
                "the launch declares no perimeter block rules, so nothing shows an independent \
                 perimeter",
            ),
            Self::PerimeterRulesRefused { refused } => {
                for (index, rule) in refused.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(
                        f,
                        "perimeter rule {} is not shown enforced: {}",
                        rule.rule, rule.refusal
                    )?;
                }
                Ok(())
            }
            Self::NotChecked => f.write_str("the evidence checker did not check it"),
            Self::ContractHolds => f.write_str("the contract has this property"),
            Self::ContractViolated { tuples } => {
                f.write_str("the contract permits ")?;
                for (index, tuple) in tuples.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "{tuple}")?;
                }
                Ok(())
            }
            Self::ContractBudgetMissing { keys } => {
                f.write_str("the contract declares no budget for ")?;
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" or ")?;
                    }
                    write!(f, "{key}")?;
                }
                Ok(())
            }
        }
    }
}

/// One predicate and how it was judged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateVerdict {
    pub predicate: SecurityPredicate,
    pub outcome: PredicateOutcome,
}

/// The host predicates of one requirement set as judged at one moment. Only the
/// [`EvidenceChecker`] makes one, and it cannot be read from untrusted data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceReport {
    session: ClockSession,
    checked_at: MonotonicTime,
    targets: LaunchTargets,
    verdicts: Vec<PredicateVerdict>,
}

impl EvidenceReport {
    /// The registry clock session the outcomes' times belong to.
    pub fn session(&self) -> ClockSession {
        self.session
    }

    pub fn checked_at(&self) -> MonotonicTime {
        self.checked_at
    }

    pub fn targets(&self) -> &LaunchTargets {
        &self.targets
    }

    /// One verdict per host predicate, in canonical predicate order.
    pub fn verdicts(&self) -> &[PredicateVerdict] {
        &self.verdicts
    }

    pub fn outcome(&self, predicate: SecurityPredicate) -> Option<&PredicateOutcome> {
        self.verdicts
            .iter()
            .find(|verdict| verdict.predicate == predicate)
            .map(|verdict| &verdict.outcome)
    }

    /// The earliest moment a verified outcome stops being fresh.
    pub fn fresh_until(&self) -> Option<MonotonicTime> {
        self.verdicts
            .iter()
            .filter_map(|verdict| match verdict.outcome {
                PredicateOutcome::Verified { fresh_until, .. } => Some(fresh_until),
                _ => None,
            })
            .min()
    }

    /// A report with chosen outcomes, for the exhaustive model only.
    #[cfg(test)]
    pub(super) fn from_verdicts(
        session: ClockSession,
        checked_at: MonotonicTime,
        targets: LaunchTargets,
        verdicts: Vec<PredicateVerdict>,
    ) -> Self {
        Self {
            session,
            checked_at,
            targets,
            verdicts,
        }
    }
}

/// The evidence checker (VM-W02), separate from the validator and the evaluator.
pub struct EvidenceChecker;

impl EvidenceChecker {
    /// Judges every host predicate in `required` against `registry` at its current time.
    /// Contract predicates are not evidence questions and are left to the planner.
    pub fn check<C: Clock>(
        registry: &ProbeRegistry<C>,
        required: &RequirementSet,
        targets: &LaunchTargets,
    ) -> EvidenceReport {
        let now = registry.now();
        let verdicts = required
            .iter()
            .filter_map(|predicate| match predicate.check() {
                PredicateCheck::HostEvidence(binding) => Some(PredicateVerdict {
                    predicate,
                    outcome: observe(registry, binding, targets),
                }),
                PredicateCheck::Contract(_) => None,
            })
            .collect();
        EvidenceReport {
            session: now.session(),
            checked_at: now.at(),
            targets: targets.clone(),
            verdicts,
        }
    }
}

fn observe<C: Clock>(
    registry: &ProbeRegistry<C>,
    binding: EvidenceBinding,
    targets: &LaunchTargets,
) -> PredicateOutcome {
    match binding {
        EvidenceBinding::VmSandboxCategory => {
            let requirement = RuntimeRequirement::VmSandbox;
            let refused = requirement
                .matrix()
                .into_iter()
                .find(|(category, _)| *category == targets.runtime.category)
                .and_then(|(_, row)| row.err());
            if let Some(refusal) = refused {
                return PredicateOutcome::CategoryRefused { refusal };
            }
            let offer = match RuntimeOffer::observe(
                registry,
                targets.runtime.clone(),
                targets.max_age,
                targets.runtime_configuration,
            ) {
                Ok(offer) => offer,
                Err(refusal) => return PredicateOutcome::EvidenceRefused { refusal },
            };
            match requirement.admit(&offer) {
                Ok(admitted) => PredicateOutcome::verified(admitted.evidence()),
                Err(refusal) => PredicateOutcome::CategoryRefused { refusal },
            }
        }
        EvidenceBinding::HypervisorAvailable => {
            let requirement = Requirement::host_only(
                Capability::HypervisorAvailable,
                Subject::Hypervisor(targets.hypervisor),
                targets.max_age,
                targets.hypervisor_configuration,
            );
            match registry.evaluate(&requirement) {
                Ok(evidence) => PredicateOutcome::verified(&evidence),
                Err(refusal) => PredicateOutcome::EvidenceRefused { refusal },
            }
        }
        EvidenceBinding::PerimeterRulesEnforced => perimeter_outcome(registry, targets),
        EvidenceBinding::NoCapabilityYet { needed } => PredicateOutcome::NoEvidenceCapability {
            needed: needed.to_owned(),
        },
    }
}

/// Every block rule of the launch's perimeter profile needs a fresh host-probe CORE-01
/// `Satisfied` for `PerimeterRuleEnforced` on its own subject; one refusal leaves the
/// predicate unmet, and a profile without block rules shows nothing.
fn perimeter_outcome<C: Clock>(
    registry: &ProbeRegistry<C>,
    targets: &LaunchTargets,
) -> PredicateOutcome {
    let Some(perimeter) = &targets.perimeter else {
        return PredicateOutcome::NoPerimeterRules;
    };
    let assessment = perimeter.profile.assess(
        registry,
        perimeter.target,
        targets.max_age,
        perimeter.configuration,
    );
    if !assessment.refused.is_empty() {
        return PredicateOutcome::PerimeterRulesRefused {
            refused: assessment
                .refused
                .into_iter()
                .map(|(rule, refusal)| PerimeterRuleRefusal {
                    rule: rule.digest(),
                    refusal,
                })
                .collect(),
        };
    }
    let mut evidence = assessment
        .enforced
        .iter()
        .map(|(_, enforced)| enforced.evidence());
    let Some(first) = evidence.next() else {
        return PredicateOutcome::NoPerimeterRules;
    };
    let (source, observed_at, fresh_until) = evidence.fold(
        (first.source(), first.observed_at(), first.fresh_until()),
        |(source, observed_at, fresh_until), next| {
            (
                source.min(next.source()),
                observed_at.min(next.observed_at()),
                fresh_until.min(next.fresh_until()),
            )
        },
    );
    PredicateOutcome::Verified {
        source,
        observed_at,
        fresh_until,
        detail: SupportDetail::PerimeterRuleEnforced,
    }
}
