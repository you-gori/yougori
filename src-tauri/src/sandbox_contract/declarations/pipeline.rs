//! Read → compile → validate → resolve → plan in one call (VM-W37 "validate and preview
//! the resolved policy"; VM-W54 "UI and CLI resolve the same policy").
//!
//! Every step is V01's except reading and compiling: the declaration only produces a
//! request, and [`resolve`] and [`plan_launch`] decide what is permitted and whether the
//! launch is allowed.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::compile::CompiledDeclaration;
use super::noninteractive::{decide_non_interactive, NonInteractiveDecision};
use super::preview::{PolicyPreview, PreviewInputs};
use super::refusal::RefusalReport;
use super::schema::read_declaration;
use crate::foundation::evidence::ProbeRegistry;
use crate::foundation::ids::{AuthorizationEpoch, Clock};
use crate::sandbox_contract::policy::{
    plan_launch, resolve, ApprovalGrant, ContractIdentity, Delegation, IssuerIdentity, LaunchPlan,
    LaunchRefusal, LaunchTargets, ProductPolicy, ResolvedPolicy, WorkloadRequest,
};

/// A launch refusal that was not made for the resolved policy it was paired with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeMismatch {
    pub resolved: ContractIdentity,
    pub planned: ContractIdentity,
}

impl fmt::Display for OutcomeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the launch outcome is for contract {}, not the resolved contract {}",
            self.planned, self.resolved
        )
    }
}

impl std::error::Error for OutcomeMismatch {}

#[derive(Clone, Copy, Debug)]
enum State<'a> {
    Planned(&'a LaunchPlan),
    Refused(&'a LaunchRefusal),
    NotPlanned,
}

/// A resolved policy with what planning made of it: a plan, a refusal for that same
/// contract, or no planning yet (host evidence not checked).
#[derive(Clone, Copy, Debug)]
pub struct LaunchOutcome<'a> {
    resolved: &'a ResolvedPolicy,
    state: State<'a>,
}

impl<'a> LaunchOutcome<'a> {
    pub fn planned(plan: &'a LaunchPlan) -> Self {
        Self {
            resolved: plan.resolved(),
            state: State::Planned(plan),
        }
    }

    /// Refuses a refusal made for another contract.
    pub fn refused(
        resolved: &'a ResolvedPolicy,
        refusal: &'a LaunchRefusal,
    ) -> Result<Self, OutcomeMismatch> {
        let identity = resolved.identity();
        if refusal.contract != identity {
            return Err(OutcomeMismatch {
                resolved: identity,
                planned: refusal.contract,
            });
        }
        Ok(Self {
            resolved,
            state: State::Refused(refusal),
        })
    }

    pub fn not_planned(resolved: &'a ResolvedPolicy) -> Self {
        Self {
            resolved,
            state: State::NotPlanned,
        }
    }

    /// The outcome of [`plan_launch`] on `resolved`.
    pub fn from_result(
        resolved: &'a ResolvedPolicy,
        result: &'a Result<LaunchPlan, LaunchRefusal>,
    ) -> Result<Self, OutcomeMismatch> {
        match result {
            Ok(plan) => {
                let identity = resolved.identity();
                if plan.contract() != identity {
                    return Err(OutcomeMismatch {
                        resolved: identity,
                        planned: plan.contract(),
                    });
                }
                Ok(Self::planned(plan))
            }
            Err(refusal) => Self::refused(resolved, refusal),
        }
    }

    pub fn resolved(&self) -> &'a ResolvedPolicy {
        self.resolved
    }

    pub fn plan(&self) -> Option<&'a LaunchPlan> {
        match self.state {
            State::Planned(plan) => Some(plan),
            State::Refused(_) | State::NotPlanned => None,
        }
    }

    pub fn refusal(&self) -> Option<&'a LaunchRefusal> {
        match self.state {
            State::Refused(refusal) => Some(refusal),
            State::Planned(_) | State::NotPlanned => None,
        }
    }
}

/// Everything one declaration produced, from compilation to the launch decision.
#[derive(Clone, Debug)]
pub struct Evaluation {
    compiled: CompiledDeclaration,
    request: WorkloadRequest,
    resolved: ResolvedPolicy,
    launch: Result<LaunchPlan, LaunchRefusal>,
}

impl Evaluation {
    pub fn compiled(&self) -> &CompiledDeclaration {
        &self.compiled
    }

    pub fn request(&self) -> &WorkloadRequest {
        &self.request
    }

    pub fn resolved(&self) -> &ResolvedPolicy {
        &self.resolved
    }

    pub fn launch(&self) -> &Result<LaunchPlan, LaunchRefusal> {
        &self.launch
    }

    pub fn outcome(&self) -> LaunchOutcome<'_> {
        match &self.launch {
            Ok(plan) => LaunchOutcome::planned(plan),
            Err(refusal) => LaunchOutcome {
                resolved: &self.resolved,
                state: State::Refused(refusal),
            },
        }
    }

    /// The preview; `grants` and `epoch` mark approvals a valid grant already covers.
    pub fn preview(
        &self,
        grants: &[ApprovalGrant],
        epoch: Option<AuthorizationEpoch>,
        issuer: Option<IssuerIdentity>,
    ) -> PolicyPreview {
        PolicyPreview::build(&PreviewInputs {
            context: self.compiled.context(),
            request: &self.request,
            outcome: self.outcome(),
            grants,
            epoch,
            issuer,
        })
    }

    pub fn decide_non_interactive(
        &self,
        grants: &[ApprovalGrant],
        epoch: AuthorizationEpoch,
    ) -> NonInteractiveDecision {
        decide_non_interactive(self.outcome(), grants, epoch)
    }
}

/// Reads, compiles and validates a declaration, resolves it against the product policy
/// and delegation, and plans the launch against host evidence. Refuses with codes when
/// the declaration or V01 validation refuses; a launch refusal is part of the result,
/// so the preview can show it.
pub fn evaluate<C: Clock>(
    text: &str,
    product: &ProductPolicy,
    delegation: &Delegation,
    registry: &ProbeRegistry<C>,
    targets: &LaunchTargets,
) -> Result<Evaluation, RefusalReport> {
    let declaration = read_declaration(text)?;
    let compiled = declaration.compile()?;
    let request = compiled.validate()?;
    let resolved = resolve(product, &request, delegation);
    let launch = plan_launch(&resolved, registry, targets);
    Ok(Evaluation {
        compiled,
        request,
        resolved,
        launch,
    })
}
