//! Runtime authorization (VM part §2.4 line 1804; VM-W02; VM-P13).
//!
//! The evaluator is separate from the validator and the evidence checker. Static
//! validation and an allowed plan are not enough: each request is checked against the
//! actual principal (the tenant and execution of the host's channel), the operation, the
//! endpoint, the generation, the remaining quota and the current policy epoch. An
//! [`Authorization`] is a decision record; it is not evidence that any mechanism
//! enforces the decision.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::approval::{ApprovalGrant, ApprovalKind, ApprovalRule, ApprovalSet};
use super::budget::{BudgetKey, BudgetResource, BudgetSet};
use super::identity::ContractIdentity;
use super::plan::ActivationBinding;
use super::tuple::{Action, Context, Operation, PermissionSet, Principal, ResourceRef, RoleName};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::ids::{
    AuthorizationEpoch, Digest, ExecutionId, PolicyEpoch, SandboxBootGeneration, TenantId,
};

/// A launch plan bound to one VM's generations. Only
/// [`LaunchPlan::activate`](super::LaunchPlan::activate) makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivePolicy {
    contract: ContractIdentity,
    tenant: TenantId,
    execution: ExecutionId,
    role: RoleName,
    generations: SandboxGenerations,
    actions: BTreeSet<Action>,
    approvals: ApprovalSet,
    budgets: BudgetSet,
}

impl ActivePolicy {
    pub(super) fn bind(
        contract: ContractIdentity,
        binding: ActivationBinding,
        permitted: &PermissionSet,
        approvals: ApprovalSet,
        budgets: BudgetSet,
    ) -> Self {
        let actions = permitted
            .actions_at(binding.generations.authorization)
            .into_iter()
            .filter(|action| action.principal.role == binding.role)
            .collect();
        Self {
            contract,
            tenant: binding.tenant,
            execution: binding.execution,
            role: binding.role,
            generations: binding.generations,
            actions,
            approvals,
            budgets,
        }
    }

    pub fn contract(&self) -> ContractIdentity {
        self.contract
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn role(&self) -> &RoleName {
        &self.role
    }

    pub fn generations(&self) -> SandboxGenerations {
        self.generations
    }

    /// The actions this VM may take at its authorization epoch.
    pub fn actions(&self) -> &BTreeSet<Action> {
        &self.actions
    }

    pub fn approvals(&self) -> &ApprovalSet {
        &self.approvals
    }

    pub fn budgets(&self) -> &BudgetSet {
        &self.budgets
    }
}

/// What one request would spend, in the units its name states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Charges {
    #[serde(default)]
    pub release_bytes: Option<u64>,
    #[serde(default)]
    pub release_effects: Option<u64>,
    /// The external effects a short-lived credential delivered by this request may
    /// authorize (§4.5 delegated budget).
    #[serde(default)]
    pub credential_effects: Option<u64>,
}

impl Charges {
    fn amount(&self, resource: BudgetResource) -> Option<u64> {
        match resource {
            BudgetResource::ReleaseBytes => self.release_bytes,
            BudgetResource::ReleaseEffects => self.release_effects,
            BudgetResource::ShortLivedCredentialEffects => self.credential_effects,
            BudgetResource::IdleLifetimeSeconds
            | BudgetResource::AbsoluteLifetimeSeconds
            | BudgetResource::ServiceRenewalSeconds => None,
        }
    }
}

/// One request as the host broker sees it. The tenant, execution and generations come
/// from the host's channel record, never from the guest's payload (VM-P29).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub tenant: TenantId,
    pub execution: ExecutionId,
    /// The generations the requesting channel was issued under.
    pub generations: SandboxGenerations,
    pub operation: Operation,
    /// The endpoint.
    pub resource: ResourceRef,
    pub context: Context,
    #[serde(default)]
    pub charges: Charges,
    /// The digest of the exact payload, for an exact release.
    #[serde(default)]
    pub payload: Option<Digest>,
}

/// Spending charged to one budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Debit {
    pub key: BudgetKey,
    pub amount: u64,
}

/// An allowed request, as a decision record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub contract: ContractIdentity,
    pub tenant: TenantId,
    pub execution: ExecutionId,
    pub generations: SandboxGenerations,
    pub action: Action,
    pub debits: Vec<Debit>,
    pub approvals_used: Vec<ApprovalRule>,
}

strict_policy_enum! {
    /// Why a request was refused. Nothing was spent and no approval was used.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AuthorizationRefusal tag "refusal" {
        /// The request's channel belongs to another tenant or execution.
        WrongPrincipal { tenant: TenantId, execution: ExecutionId },
        /// The policy epoch changed after activation; the policy must be planned again.
        PolicyEpochChanged { bound: PolicyEpoch, current: PolicyEpoch },
        /// The authorization epoch moved (revocation, recovery or a new boot); nothing
        /// bound to the old epoch is honoured again.
        AuthorizationRevoked { bound: AuthorizationEpoch, current: AuthorizationEpoch },
        /// The sandbox booted or was restored after activation.
        BootGenerationChanged {
            bound: SandboxBootGeneration,
            current: SandboxBootGeneration,
        },
        /// The request carries generations other than the current ones (VM-P13).
        StaleRequestGeneration {
            request: SandboxGenerations,
            current: SandboxGenerations,
        },
        /// The action is outside the permitted set at this epoch.
        NotPermitted { action: Action },
        /// A required approval has no valid grant.
        ApprovalRequired { rule: ApprovalRule },
        /// The operation spends a budgeted resource and the request did not state how
        /// much.
        ChargeMissing { resource: BudgetResource },
        /// The request would exceed a budget.
        QuotaExceeded { key: BudgetKey, remaining: u64, requested: u64 },
    }
}

impl fmt::Display for AuthorizationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPrincipal { execution, .. } => write!(
                f,
                "execution {execution} is not the principal this policy is bound to"
            ),
            Self::PolicyEpochChanged { bound, current } => write!(
                f,
                "the policy changed from epoch {bound} to {current}; plan again"
            ),
            Self::AuthorizationRevoked { bound, current } => write!(
                f,
                "authorization epoch {bound} was replaced by {current}; nothing bound to it is \
                 honoured again"
            ),
            Self::BootGenerationChanged { bound, current } => write!(
                f,
                "the sandbox boot generation moved from {bound} to {current}"
            ),
            Self::StaleRequestGeneration { request, current } => write!(
                f,
                "the request was issued under {request}, but {current} is current"
            ),
            Self::NotPermitted { action } => write!(f, "not permitted: {action}"),
            Self::ApprovalRequired { rule } => write!(f, "this needs {rule}"),
            Self::ChargeMissing { resource } => write!(
                f,
                "the request does not state the {resource} it would spend"
            ),
            Self::QuotaExceeded {
                key,
                remaining,
                requested,
            } => write!(
                f,
                "the budget for {key} has {remaining} left and the request needs {requested}"
            ),
        }
    }
}

impl std::error::Error for AuthorizationRefusal {}

strict_policy_enum! {
    /// Why the evaluator refused carried spending or an approval grant.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EvaluatorRefusal tag "refusal" {
        /// Carried spending belongs to another tenant or execution.
        SpendForOtherExecution,
        /// Spending in this scope does not outlive one activation.
        SpendNotCarried { key: BudgetKey },
        /// The grant is for another authorization epoch.
        ApprovalForOtherEpoch { grant: AuthorizationEpoch, bound: AuthorizationEpoch },
        /// No rule of the policy needs this grant.
        ApprovalNotRequired { rule: ApprovalRule },
        /// An exact-release grant without a payload, or another kind with one.
        ApprovalMalformed { rule: ApprovalRule },
    }
}

impl fmt::Display for EvaluatorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpendForOtherExecution => {
                f.write_str("the carried spending belongs to another tenant or execution")
            }
            Self::SpendNotCarried { key } => {
                write!(
                    f,
                    "spending on {key} does not carry over between activations"
                )
            }
            Self::ApprovalForOtherEpoch { grant, bound } => write!(
                f,
                "the approval was given at authorization epoch {grant}, not {bound}"
            ),
            Self::ApprovalNotRequired { rule } => {
                write!(f, "the policy does not require {rule}")
            }
            Self::ApprovalMalformed { rule } => write!(
                f,
                "the grant for {rule} must name a payload exactly when it approves an exact \
                 release"
            ),
        }
    }
}

impl std::error::Error for EvaluatorRefusal {}

/// Spending in scopes that outlive one activation (per execution or tenant), carried
/// from one activation of an execution to the next by the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetSpend {
    tenant: TenantId,
    execution: ExecutionId,
    spent: BTreeMap<BudgetKey, u64>,
}

impl BudgetSpend {
    /// Nothing spent yet.
    pub fn none(tenant: TenantId, execution: ExecutionId) -> Self {
        Self {
            tenant,
            execution,
            spent: BTreeMap::new(),
        }
    }

    pub fn spent(&self, key: &BudgetKey) -> u64 {
        self.spent.get(key).copied().unwrap_or(0)
    }

    pub fn entries(&self) -> impl Iterator<Item = Debit> + '_ {
        self.spent.iter().map(|(key, amount)| Debit {
            key: key.clone(),
            amount: *amount,
        })
    }
}

/// The runtime evaluator for one active policy (VM-W02).
#[derive(Clone, Debug)]
pub struct Evaluator {
    policy: ActivePolicy,
    spent: BTreeMap<BudgetKey, u64>,
    grants: Vec<ApprovalGrant>,
}

impl Evaluator {
    /// An evaluator starting from `carried`, which must be this execution's spending in
    /// scopes that carry over. Spending per generation or per channel starts at zero.
    pub fn new(policy: ActivePolicy, carried: BudgetSpend) -> Result<Self, EvaluatorRefusal> {
        if carried.tenant != policy.tenant || carried.execution != policy.execution {
            return Err(EvaluatorRefusal::SpendForOtherExecution);
        }
        if let Some(key) = carried.spent.keys().find(|key| !key.scope.carries_over()) {
            return Err(EvaluatorRefusal::SpendNotCarried { key: key.clone() });
        }
        Ok(Self {
            policy,
            spent: carried.spent,
            grants: Vec::new(),
        })
    }

    pub fn policy(&self) -> &ActivePolicy {
        &self.policy
    }

    /// Records an approval the host's approval flow obtained. Only grants for this
    /// policy's epoch and one of its required rules are kept.
    pub fn record_approval(&mut self, grant: ApprovalGrant) -> Result<(), EvaluatorRefusal> {
        let bound = self.policy.generations.authorization;
        if grant.epoch != bound {
            return Err(EvaluatorRefusal::ApprovalForOtherEpoch {
                grant: grant.epoch,
                bound,
            });
        }
        if !self.policy.approvals.contains(&grant.rule) {
            return Err(EvaluatorRefusal::ApprovalNotRequired { rule: grant.rule });
        }
        if !grant.is_well_formed() {
            return Err(EvaluatorRefusal::ApprovalMalformed { rule: grant.rule });
        }
        self.grants.push(grant);
        Ok(())
    }

    /// How much of the budget for `key` is left; `None` when nothing limits it.
    pub fn remaining(&self, key: &BudgetKey) -> Option<u64> {
        self.policy
            .budgets
            .limit(key)
            .map(|limit| limit.saturating_sub(self.spent.get(key).copied().unwrap_or(0)))
    }

    /// The spending to carry into the execution's next activation.
    pub fn carried_spend(&self) -> BudgetSpend {
        BudgetSpend {
            tenant: self.policy.tenant.clone(),
            execution: self.policy.execution.clone(),
            spent: self
                .spent
                .iter()
                .filter(|(key, _)| key.scope.carries_over())
                .map(|(key, amount)| (key.clone(), *amount))
                .collect(),
        }
    }

    /// Authorizes one request against `current`, the generations in the coordination
    /// authority's record now (CORE-04 `SandboxLifecycle::generations`). On success the
    /// request's spending is charged to every applicable budget and an exact-release
    /// grant is used up; on refusal nothing changes.
    pub fn authorize(
        &mut self,
        request: &AuthorizationRequest,
        current: SandboxGenerations,
    ) -> Result<Authorization, AuthorizationRefusal> {
        let bound = self.policy.generations;
        if current.policy != bound.policy {
            return Err(AuthorizationRefusal::PolicyEpochChanged {
                bound: bound.policy,
                current: current.policy,
            });
        }
        if current.authorization != bound.authorization {
            return Err(AuthorizationRefusal::AuthorizationRevoked {
                bound: bound.authorization,
                current: current.authorization,
            });
        }
        if current.boot != bound.boot {
            return Err(AuthorizationRefusal::BootGenerationChanged {
                bound: bound.boot,
                current: current.boot,
            });
        }
        if request.tenant != self.policy.tenant || request.execution != self.policy.execution {
            return Err(AuthorizationRefusal::WrongPrincipal {
                tenant: request.tenant.clone(),
                execution: request.execution.clone(),
            });
        }
        if request.generations != current {
            return Err(AuthorizationRefusal::StaleRequestGeneration {
                request: request.generations,
                current,
            });
        }
        let action = Action {
            principal: Principal {
                role: self.policy.role.clone(),
            },
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            context: request.context,
        };
        if !self.policy.actions.contains(&action) {
            return Err(AuthorizationRefusal::NotPermitted { action });
        }
        let mut used = Vec::new();
        for rule in self
            .policy
            .approvals
            .rules_for(&request.operation, &request.resource)
        {
            let grant = self.grants.iter().position(|grant| {
                grant.satisfies(rule, bound.authorization, request.payload.as_ref())
            });
            match grant {
                Some(index) => used.push((rule.clone(), index)),
                None => return Err(AuthorizationRefusal::ApprovalRequired { rule: rule.clone() }),
            }
        }
        let mut debits = Vec::new();
        for (key, limit) in self.policy.budgets.iter() {
            if !key.resource.is_spent_per_request()
                || !request.operation.consumes(key.resource)
                || !key.scope.applies_to(&request.resource)
            {
                continue;
            }
            let amount = request.charges.amount(key.resource).ok_or(
                AuthorizationRefusal::ChargeMissing {
                    resource: key.resource,
                },
            )?;
            let remaining = limit.saturating_sub(self.spent.get(key).copied().unwrap_or(0));
            if amount > remaining {
                return Err(AuthorizationRefusal::QuotaExceeded {
                    key: key.clone(),
                    remaining,
                    requested: amount,
                });
            }
            debits.push(Debit {
                key: key.clone(),
                amount,
            });
        }
        for debit in &debits {
            let spent = self.spent.entry(debit.key.clone()).or_insert(0);
            *spent = spent.saturating_add(debit.amount);
        }
        let mut spent_grants: Vec<usize> = used
            .iter()
            .filter(|(rule, _)| rule.kind == ApprovalKind::ExactRelease)
            .map(|(_, index)| *index)
            .collect();
        spent_grants.sort_unstable();
        spent_grants.dedup();
        for index in spent_grants.into_iter().rev() {
            self.grants.remove(index);
        }
        Ok(Authorization {
            contract: self.policy.contract,
            tenant: self.policy.tenant.clone(),
            execution: self.policy.execution.clone(),
            generations: bound,
            action,
            debits,
            approvals_used: used.into_iter().map(|(rule, _)| rule).collect(),
        })
    }
}
