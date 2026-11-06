//! VM-W01/VM-W02: the sandbox policy contract
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §1.3, §2.2–§2.4, §10.1,
//! §12.2 VM-P01/VM-P42/VM-P46/VM-P47, §12.3 model 1; S1, S3).
//!
//! Permissions and requirements compose differently (VM §2.4):
//!
//! ```text
//! permitted           = product_ceiling ∩ requested ∩ delegated
//! required_properties = product_requirements ∪ workload_requirements
//! launch_allowed      = host evidence satisfies required_properties
//!                       and the dependencies the workload needs are permitted
//! ```
//!
//! - A permission is a tuple (principal, operation, resource, context, generation)
//!   ([`PermissionTuple`]); a [`PermissionSet`] intersects and unions exactly.
//! - Required properties are [`SecurityPredicate`]s, accumulated by union. They are
//!   predicates over separately recorded deployment facets (§1.3), never an ordered tier
//!   where "smaller" means safer; old tiers map to predicate sets or a typed migration
//!   refusal ([`LegacyTier`]).
//! - Required approvals accumulate ([`ApprovalSet`] has a union and no intersection);
//!   budgets take minima only within one resource and accounting scope ([`BudgetSet`]).
//! - The [`Validator`] checks well-formedness, permission containment and supported
//!   combinations; [`resolve`] applies the algebra; the [`EvidenceChecker`] judges host
//!   predicates only through CORE-01 ([`crate::foundation::evidence`]); [`plan_launch`]
//!   refuses with a typed reason naming every removed authority and unmet predicate; the
//!   runtime [`Evaluator`] checks the actual principal, operation, endpoint, generation,
//!   remaining quota and current policy epoch.
//! - A [`ContractIdentity`] (a domain-separated digest of the canonical encoding) names
//!   a contract and an [`IssuerIdentity`] names who issued it. Neither is evidence that
//!   anything enforces the contract (§2.4 line 1804), and no evidence input accepts one.
//! - Evidence can only refuse. The requirement set is fixed before evidence is read, so
//!   bad, stale or guest-reported evidence never lowers it (VM-W02), and a guest report
//!   never satisfies a host-only predicate (CORE-01, VM-W09).
//!
//! Most host predicates have no CORE-01 capability yet ([`EvidenceBinding`]); requiring
//! one refuses the launch with [`PredicateOutcome::NoEvidenceCapability`] rather than
//! assuming it holds. The independent perimeter is judged by CORE-01's
//! `PerimeterRuleEnforced`, one host-probe requirement per block rule of the launch's
//! perimeter profile ([`LaunchPerimeter`]); every rule must be satisfied. Contract predicates describe what the contract grants, never that
//! a mechanism enforces it.
//!
//! §12.3 model 1 is checked by exhaustive enumeration in the tests (`model.rs`). Bounds:
//! four tuple patterns over two roles, three operations and three resources, one of
//! them bound to authorization epoch 1, with generations judged over {epoch 1, epoch 2,
//! any other epoch}; three host predicates; every product ceiling, request, dependency
//! subset, delegation, product and workload requirement set and evidence outcome drawn
//! from those (884,736 launch decisions), plus runtime authorization of every action in
//! the allowed states, every contract constraint over every subset of eight tuples,
//! approval accumulation over two rules and budget minima over three keys. Assumptions:
//! evidence is abstracted to a satisfied/unsatisfied verdict per predicate (CORE-01
//! evaluation is tested separately), and layers are already validated. The check proves
//! the model and this code within those bounds only; it says nothing about larger
//! inputs, the operating system, the hypervisor, providers or hardware (§12.3).

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. The pattern is the one in
/// `foundation/report/mod.rs`, kept local so this module depends on no other's macros.
macro_rules! strict_policy_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

mod approval;
mod authorize;
mod budget;
mod evidence;
mod identity;
mod layers;
mod objectives;
mod plan;
mod predicate;
mod resolve;
mod tuple;
mod validate;

#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;

pub use approval::{ApprovalGrant, ApprovalKind, ApprovalRule, ApprovalSet};
pub use authorize::{
    ActivePolicy, Authorization, AuthorizationRefusal, AuthorizationRequest, BudgetSpend, Charges,
    Debit, Evaluator, EvaluatorRefusal,
};
pub use budget::{
    AccountingScope, Budget, BudgetKey, BudgetResource, BudgetSet, BudgetUnit, DuplicateBudget,
    VM_D12_IDLE_LIFETIME_SECONDS, VM_D12_SERVICE_RENEWAL_SECONDS,
    VM_D12_TASK_ABSOLUTE_LIFETIME_SECONDS,
};
pub use evidence::{
    EvidenceChecker, EvidenceReport, LaunchPerimeter, LaunchTargets, PerimeterRuleRefusal,
    PredicateOutcome, PredicateVerdict,
};
pub use identity::{ContractIdentity, IssuedContract, IssuerIdentity, RequestIdentity};
pub use layers::{
    ContractSchemaVersion, Delegation, DelegationDraft, PolicyLayer, ProductPolicy,
    ProductPolicyDraft, RequestDocument, RequestSource, SourceKind, UnsupportedContractSchema,
    WorkloadRequest, CONTRACT_SCHEMA_VERSION,
};
pub use objectives::{
    BoundError, Interpretation, Objective, ReductionFactor, ReductionUnit, ScopedReduction, Target,
    ValueProvenance, ZeroFailureBound,
};
pub use plan::{
    plan_launch, ActivationBinding, ActivationRefusal, FacetReport, LaunchPlan, LaunchRefusal,
    LaunchRefusalReason,
};
pub use predicate::{
    ContractConstraint, DeploymentFacet, EvidenceBinding, LegacyTier, MigrationRefusal,
    PredicateCheck, RequirementSet, SecurityPredicate,
};
pub use resolve::{resolve, RemovedPermission, ResolvedPolicy};
pub use tuple::{
    Action, Context, GenerationScope, Operation, OperationName, PermissionSet, PermissionTuple,
    Phase, Principal, ResourceKind, ResourceName, ResourceRef, RoleName, SourceName,
};
pub use validate::{ValidationIssue, ValidationRefusal, Validator};
