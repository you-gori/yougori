//! Launch planning (VM part §2.4 lines 1797–1800; VM-W01; VM-P01, VM-P42).
//!
//! `launch_allowed = host evidence satisfies required_properties and the dependencies
//! the workload needs are permitted`. A refusal lists every removed essential authority
//! by name, with the layers that removed it, and every unmet predicate with its typed
//! reason, so a setup never launches silently lacking an essential capability.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::authorize::ActivePolicy;
use super::evidence::{
    EvidenceChecker, EvidenceReport, LaunchTargets, PredicateOutcome, PredicateVerdict,
};
use super::identity::ContractIdentity;
use super::layers::PolicyLayer;
use super::predicate::{DeploymentFacet, PredicateCheck, SecurityPredicate};
use super::resolve::ResolvedPolicy;
use super::tuple::{PermissionTuple, RoleName};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::{ClockReading, ClockSession, ProbeRegistry};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, PolicyEpoch, TenantId};

strict_policy_enum! {
    /// One reason a launch was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum LaunchRefusalReason tag "reason" {
        /// The workload needs this authority and the intersection removed it (§2.4
        /// line 1800).
        RequiredAuthorityRemoved {
            tuple: PermissionTuple,
            excluded_by: BTreeSet<PolicyLayer>,
        },
        /// A required predicate is not met.
        RequirementUnmet {
            predicate: SecurityPredicate,
            outcome: PredicateOutcome,
        },
        /// Nothing verified rests on host evidence, so the plan would have no freshness
        /// bound.
        NoHostEvidence,
    }
}

impl fmt::Display for LaunchRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredAuthorityRemoved { tuple, excluded_by } => {
                write!(f, "the workload needs {tuple}, but ")?;
                for (index, layer) in excluded_by.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" and ")?;
                    }
                    write!(f, "{layer}")?;
                }
                f.write_str(
                    " does not permit it; the launch is refused rather than started without it",
                )
            }
            Self::RequirementUnmet { predicate, outcome } => {
                write!(f, "{predicate} is required: {outcome}")
            }
            Self::NoHostEvidence => {
                f.write_str("no requirement was verified by host evidence; the launch is refused")
            }
        }
    }
}

/// Why a launch was refused: every reason found, never empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRefusal {
    pub contract: ContractIdentity,
    pub reasons: Vec<LaunchRefusalReason>,
}

impl fmt::Display for LaunchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, reason) in self.reasons.iter().enumerate() {
            if index > 0 {
                f.write_str(". ")?;
            }
            write!(f, "{reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LaunchRefusal {}

/// One deployment facet with the required predicates it holds and how each was judged.
/// Facets are reported separately and never combined into a score (VM §1.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetReport {
    pub facet: DeploymentFacet,
    pub verdicts: Vec<PredicateVerdict>,
}

/// An allowed launch. Only [`plan_launch`] makes one. It records the contract identity
/// beside the evidence verdicts; the identity is not one of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchPlan {
    contract: ContractIdentity,
    resolved: ResolvedPolicy,
    targets: LaunchTargets,
    verdicts: Vec<PredicateVerdict>,
    evidence_session: ClockSession,
    fresh_until: MonotonicTime,
}

/// Plans a launch: checks host predicates through the [`EvidenceChecker`], contract
/// predicates against the resolved contract, and every essential dependency against the
/// permitted set.
pub fn plan_launch<C: Clock>(
    resolved: &ResolvedPolicy,
    registry: &ProbeRegistry<C>,
    targets: &LaunchTargets,
) -> Result<LaunchPlan, LaunchRefusal> {
    let report = EvidenceChecker::check(registry, resolved.requirements(), targets);
    decide(resolved, resolved.identity(), &report)
}

/// The launch decision over one evidence report; `contract` is `resolved.identity()`.
pub(super) fn decide(
    resolved: &ResolvedPolicy,
    contract: ContractIdentity,
    report: &EvidenceReport,
) -> Result<LaunchPlan, LaunchRefusal> {
    let mut reasons: Vec<LaunchRefusalReason> = resolved
        .missing_dependencies()
        .map(|removed| LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: removed.tuple.clone(),
            excluded_by: removed.excluded_by.clone(),
        })
        .collect();
    let mut verdicts = Vec::new();
    for predicate in resolved.requirements().iter() {
        let outcome = match predicate.check() {
            PredicateCheck::Contract(constraint) => {
                constraint.evaluate(resolved.permitted(), resolved.budgets())
            }
            PredicateCheck::HostEvidence(_) => report
                .outcome(predicate)
                .cloned()
                .unwrap_or(PredicateOutcome::NotChecked),
        };
        if !outcome.is_satisfied() {
            reasons.push(LaunchRefusalReason::RequirementUnmet {
                predicate,
                outcome: outcome.clone(),
            });
        }
        verdicts.push(PredicateVerdict { predicate, outcome });
    }
    let fresh_until = report.fresh_until();
    if fresh_until.is_none() && reasons.is_empty() {
        reasons.push(LaunchRefusalReason::NoHostEvidence);
    }
    match fresh_until {
        Some(fresh_until) if reasons.is_empty() => Ok(LaunchPlan {
            contract,
            resolved: resolved.clone(),
            targets: report.targets().clone(),
            verdicts,
            evidence_session: report.session(),
            fresh_until,
        }),
        _ => Err(LaunchRefusal { contract, reasons }),
    }
}

/// Who the plan is activated for: the tenant and execution from the host's own records,
/// the role this VM plays, and the generations the coordination authority (CORE-04)
/// assigned when it made authority active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationBinding {
    pub tenant: TenantId,
    pub execution: ExecutionId,
    pub role: RoleName,
    pub generations: SandboxGenerations,
}

strict_policy_enum! {
    /// Why an allowed plan could not be activated.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ActivationRefusal tag "refusal" {
        /// The policy changed after planning; plan again under the new epoch.
        PolicyEpochMismatch { planned: PolicyEpoch, current: PolicyEpoch },
        /// The clock reading is from another session than the plan's evidence.
        EvidenceOtherClock,
        /// The plan's evidence is no longer fresh; plan again.
        EvidenceExpired { fresh_until: MonotonicTime, now: MonotonicTime },
        /// The role appears in no tuple of a contract that has tuples.
        UnknownRole { role: RoleName },
    }
}

impl fmt::Display for ActivationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyEpochMismatch { planned, current } => write!(
                f,
                "the plan was made under policy epoch {planned}, but epoch {current} is in \
                 force; plan again"
            ),
            Self::EvidenceOtherClock => f.write_str(
                "the clock reading belongs to another clock session than the plan's evidence; \
                 plan again",
            ),
            Self::EvidenceExpired { .. } => {
                f.write_str("the plan's evidence is no longer fresh; plan again")
            }
            Self::UnknownRole { role } => {
                write!(f, "the contract has no tuple for sandbox role \"{role}\"")
            }
        }
    }
}

impl std::error::Error for ActivationRefusal {}

impl LaunchPlan {
    pub fn contract(&self) -> ContractIdentity {
        self.contract
    }

    pub fn resolved(&self) -> &ResolvedPolicy {
        &self.resolved
    }

    pub fn targets(&self) -> &LaunchTargets {
        &self.targets
    }

    /// One verdict per required predicate, in canonical predicate order.
    pub fn verdicts(&self) -> &[PredicateVerdict] {
        &self.verdicts
    }

    /// The registry clock session of the plan's evidence.
    pub fn evidence_session(&self) -> ClockSession {
        self.evidence_session
    }

    /// The earliest moment one of the plan's verified outcomes stops being fresh.
    pub fn fresh_until(&self) -> MonotonicTime {
        self.fresh_until
    }

    /// Every §1.3 facet with its required predicates and verdicts, including facets
    /// with no requirement, which are listed empty rather than omitted.
    pub fn facets(&self) -> Vec<FacetReport> {
        DeploymentFacet::ALL
            .into_iter()
            .map(|facet| FacetReport {
                facet,
                verdicts: self
                    .verdicts
                    .iter()
                    .filter(|verdict| verdict.predicate.facet() == facet)
                    .cloned()
                    .collect(),
            })
            .collect()
    }

    /// Binds the plan to the generations the coordination authority made active, at a
    /// moment read from the registry that produced the plan's evidence. Tuples bound to
    /// another authorization epoch are stale and drop out.
    pub fn activate(
        &self,
        binding: ActivationBinding,
        now: ClockReading,
    ) -> Result<ActivePolicy, ActivationRefusal> {
        let planned = self.resolved.policy_epoch();
        if binding.generations.policy != planned {
            return Err(ActivationRefusal::PolicyEpochMismatch {
                planned,
                current: binding.generations.policy,
            });
        }
        if now.session() != self.evidence_session {
            return Err(ActivationRefusal::EvidenceOtherClock);
        }
        if now.at() > self.fresh_until {
            return Err(ActivationRefusal::EvidenceExpired {
                fresh_until: self.fresh_until,
                now: now.at(),
            });
        }
        let roles: BTreeSet<RoleName> = self
            .resolved
            .permitted()
            .iter()
            .chain(self.resolved.dependencies().iter())
            .map(|tuple| tuple.principal.role)
            .collect();
        if !roles.is_empty() && !roles.contains(&binding.role) {
            return Err(ActivationRefusal::UnknownRole { role: binding.role });
        }
        Ok(ActivePolicy::bind(
            self.contract,
            binding,
            self.resolved.permitted(),
            self.resolved.approvals().clone(),
            self.resolved.budgets().clone(),
        ))
    }
}
