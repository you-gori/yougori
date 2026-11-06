//! Authorization bases: standing delegation and individual approval (VM part §4.6 lines
//! 2014 and 2022; §10.4 line 2463; VM-W31; VM-P46), with central budget holds.
//!
//! A [`StandingDelegation`] is reused within its stated scope. It binds the principal
//! and the sandbox identity, not the boot generation, so a generation restart alone does
//! not ask again for already-approved actions; each attempt still gets a capability
//! bound to the current generation. Material scope changes, new destinations and new
//! operations need a new grant ([`ScopeChange::Material`]). Both bases bind the policy
//! epoch they were granted under, and a policy change requires them to be granted again.
//!
//! An [`IndividualApproval`] covers exactly one effect identity. For a reviewed change the
//! displayed artifact must be the description's payload, by content key, never by name.
//!
//! [`AuthorizationBook`] holds every effect and spend reservation centrally, so
//! concurrent effects can never spend the same remaining budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::canonical::len_u64;
use super::capability::{AuthorizationBasis, ExecutorIdentity, ExecutorName};
use super::description::{
    AccountRef, CostCeiling, Deadline, EffectDescription, EffectId, OperationKey, ReviewedArtifact,
    RouteRef, SandboxRef,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{DigestBuilder, MonotonicTime, PolicyEpoch, TenantId};

digest_handle!(
    /// A standing delegation, by the digest of its terms.
    DelegationId
);
digest_handle!(
    /// An individual approval, by the digest of its terms.
    ApprovalId
);

/// What a standing delegation covers (§4.6 line 2014: its stated scope).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationScope {
    pub principal: TenantId,
    /// The sandbox identity; not its boot generation.
    pub sandbox: SandboxRef,
    pub executor: ExecutorName,
    pub operations: BTreeSet<OperationKey>,
    pub routes: BTreeSet<RouteRef>,
    pub accounts: BTreeSet<AccountRef>,
    pub max_cost_per_effect: CostCeiling,
    pub max_wire_bytes_per_effect: u64,
}

/// The total a standing delegation may spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBudget {
    pub max_effects: u64,
    pub max_spend_microunits: u64,
}

/// A standing delegation (§4.6 line 2014; VM-W31 "pre-authorized narrow delegation").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingDelegation {
    pub scope: DelegationScope,
    pub budget: DelegationBudget,
    /// The policy epoch it was granted under.
    pub policy: PolicyEpoch,
    pub expires: Deadline,
}

/// One way a proposed scope is broader than the granted one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialChange {
    OtherPrincipal,
    OtherSandbox,
    OtherExecutor,
    NewOperation,
    NewDestination,
    NewAccount,
    HigherCost,
    MoreWireBytes,
    LargerBudget,
    LaterExpiry,
    OtherPolicy,
}

/// How a proposed delegation relates to a granted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeChange {
    Same,
    /// Within the granted scope: no new authorization is needed.
    Narrower,
    /// Broader in these ways: reauthorize (§4.6 line 2014).
    Material {
        changes: BTreeSet<MaterialChange>,
    },
}

impl StandingDelegation {
    pub fn id(&self) -> DelegationId {
        let scope = &self.scope;
        let builder = DigestBuilder::new("yougori/sandbox/standing-delegation/v1")
            .str(scope.principal.as_str())
            .digest(scope.sandbox.issuer.digest())
            .str(scope.sandbox.execution.as_str())
            .str(scope.executor.as_str());
        let builder = scope.operations.iter().fold(
            builder.u64(len_u64(scope.operations.len())),
            |b, operation| {
                b.str(operation.provider.as_str())
                    .str(operation.operation.as_str())
                    .u64(u64::from(operation.contract_version))
            },
        );
        let builder = scope
            .routes
            .iter()
            .fold(builder.u64(len_u64(scope.routes.len())), |b, route| {
                b.digest(route.digest())
            });
        let builder = scope
            .accounts
            .iter()
            .fold(builder.u64(len_u64(scope.accounts.len())), |b, account| {
                b.digest(account.digest())
            });
        DelegationId::new(
            builder
                .u64(scope.max_cost_per_effect.max_spend_microunits)
                .u64(scope.max_cost_per_effect.max_volume_units)
                .u64(scope.max_wire_bytes_per_effect)
                .u64(self.budget.max_effects)
                .u64(self.budget.max_spend_microunits)
                .u64(self.policy.get())
                .bytes(self.expires.clock.as_uuid().as_bytes())
                .u64(self.expires.at.as_nanos())
                .finish(),
        )
    }

    /// Whether the delegation covers `description` for `executor` now.
    pub fn covers(
        &self,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        check_deadline(self.expires, now, session)?;
        if policy != self.policy {
            return Err(ScopeViolation::PolicyChanged {
                granted: self.policy,
                current: policy,
            });
        }
        let scope = &self.scope;
        if description.principal() != &scope.principal {
            return Err(ScopeViolation::OtherPrincipal);
        }
        if description.sandbox() != &scope.sandbox {
            return Err(ScopeViolation::OtherSandbox);
        }
        if executor.name != scope.executor {
            return Err(ScopeViolation::OtherExecutor);
        }
        if !scope.operations.contains(description.operation()) {
            return Err(ScopeViolation::NewOperation);
        }
        if !scope.routes.contains(&description.destination().route) {
            return Err(ScopeViolation::NewDestination);
        }
        if !scope.accounts.contains(&description.resource().account) {
            return Err(ScopeViolation::NewAccount);
        }
        if !description.max_cost().within(&scope.max_cost_per_effect) {
            return Err(ScopeViolation::CostAboveCeiling);
        }
        if description.max_wire_bytes_out() > scope.max_wire_bytes_per_effect {
            return Err(ScopeViolation::WireBytesAboveCeiling);
        }
        Ok(())
    }

    /// How `proposed` relates to this grant: the same, narrower, or broader in ways that
    /// need reauthorization.
    pub fn change_to(&self, proposed: &StandingDelegation) -> ScopeChange {
        let (old, new) = (&self.scope, &proposed.scope);
        let mut changes = BTreeSet::new();
        let mut flag = |broader: bool, change| {
            if broader {
                changes.insert(change);
            }
        };
        flag(
            new.principal != old.principal,
            MaterialChange::OtherPrincipal,
        );
        flag(new.sandbox != old.sandbox, MaterialChange::OtherSandbox);
        flag(new.executor != old.executor, MaterialChange::OtherExecutor);
        flag(
            !new.operations.is_subset(&old.operations),
            MaterialChange::NewOperation,
        );
        flag(
            !new.routes.is_subset(&old.routes),
            MaterialChange::NewDestination,
        );
        flag(
            !new.accounts.is_subset(&old.accounts),
            MaterialChange::NewAccount,
        );
        flag(
            !new.max_cost_per_effect.within(&old.max_cost_per_effect),
            MaterialChange::HigherCost,
        );
        flag(
            new.max_wire_bytes_per_effect > old.max_wire_bytes_per_effect,
            MaterialChange::MoreWireBytes,
        );
        flag(
            proposed.budget.max_effects > self.budget.max_effects
                || proposed.budget.max_spend_microunits > self.budget.max_spend_microunits,
            MaterialChange::LargerBudget,
        );
        flag(
            proposed.expires.clock != self.expires.clock || proposed.expires.at > self.expires.at,
            MaterialChange::LaterExpiry,
        );
        flag(proposed.policy != self.policy, MaterialChange::OtherPolicy);
        if !changes.is_empty() {
            ScopeChange::Material { changes }
        } else if proposed == self {
            ScopeChange::Same
        } else {
            ScopeChange::Narrower
        }
    }
}

/// Approval of exactly one effect (VM-W31 "individual approval").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndividualApproval {
    effect: EffectId,
    principal: TenantId,
    sandbox: SandboxRef,
    reviewed: Option<ReviewedArtifact>,
    policy: PolicyEpoch,
    expires: Deadline,
}

impl IndividualApproval {
    /// Approves `description`. A reviewed artifact must be exactly its payload (§4.6 line
    /// 2022): the bytes displayed are the bytes that leave.
    pub fn for_description(
        description: &EffectDescription,
        reviewed: Option<ReviewedArtifact>,
        policy: PolicyEpoch,
        expires: Deadline,
    ) -> Result<Self, ScopeViolation> {
        if let Some(artifact) = reviewed {
            if description.payload() != Some(artifact.payload()) {
                return Err(ScopeViolation::ReviewedArtifactMismatch);
            }
        }
        Ok(Self {
            effect: description.id(),
            principal: description.principal().clone(),
            sandbox: description.sandbox().clone(),
            reviewed,
            policy,
            expires,
        })
    }

    pub fn id(&self) -> ApprovalId {
        let builder = DigestBuilder::new("yougori/sandbox/individual-approval/v1")
            .digest(self.effect.digest())
            .str(self.principal.as_str())
            .digest(self.sandbox.issuer.digest())
            .str(self.sandbox.execution.as_str());
        let builder = match self.reviewed {
            None => builder.u64(0),
            Some(artifact) => builder
                .u64(1)
                .digest(artifact.content.digest())
                .u64(artifact.length_bytes),
        };
        ApprovalId::new(
            builder
                .u64(self.policy.get())
                .bytes(self.expires.clock.as_uuid().as_bytes())
                .u64(self.expires.at.as_nanos())
                .finish(),
        )
    }

    pub fn effect(&self) -> EffectId {
        self.effect
    }

    pub fn sandbox(&self) -> &SandboxRef {
        &self.sandbox
    }

    /// Whether the approval covers `description` now.
    pub fn covers(
        &self,
        description: &EffectDescription,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        check_deadline(self.expires, now, session)?;
        if policy != self.policy {
            return Err(ScopeViolation::PolicyChanged {
                granted: self.policy,
                current: policy,
            });
        }
        if description.id() != self.effect {
            return Err(ScopeViolation::OtherEffect);
        }
        Ok(())
    }
}

fn check_deadline(
    deadline: Deadline,
    now: MonotonicTime,
    session: ClockSession,
) -> Result<(), ScopeViolation> {
    if deadline.clock != session {
        return Err(ScopeViolation::OtherClock);
    }
    if now >= deadline.at {
        return Err(ScopeViolation::Expired {
            expired_at: deadline.at,
        });
    }
    Ok(())
}

strict_tagged_enum! {
    /// Why an authorization basis does not cover an effect.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ScopeViolation (tag = "violation", wire = ScopeViolationWire, wire_name = "ScopeViolationWire") {
        OtherPrincipal,
        OtherSandbox,
        OtherExecutor,
        NewOperation,
        NewDestination,
        NewAccount,
        CostAboveCeiling,
        WireBytesAboveCeiling,
        Expired { expired_at: MonotonicTime },
        OtherClock,
        PolicyChanged { granted: PolicyEpoch, current: PolicyEpoch },
        OtherEffect,
        ReviewedArtifactMismatch,
        Revoked,
        UnknownBasis,
    }
}

impl fmt::Display for ScopeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherPrincipal => f.write_str("the grant is for another principal"),
            Self::OtherSandbox => f.write_str("the grant is for another sandbox"),
            Self::OtherExecutor => f.write_str("the grant is for another executor"),
            Self::NewOperation => f.write_str("the operation is outside the grant; ask again"),
            Self::NewDestination => f.write_str("the destination is outside the grant; ask again"),
            Self::NewAccount => f.write_str("the account is outside the grant; ask again"),
            Self::CostAboveCeiling => f.write_str("the cost is above the grant's ceiling"),
            Self::WireBytesAboveCeiling => {
                f.write_str("the wire bytes are above the grant's ceiling")
            }
            Self::Expired { expired_at } => {
                write!(f, "the grant expired at {} ns", expired_at.as_nanos())
            }
            Self::OtherClock => f.write_str("the grant's expiry is on another clock session"),
            Self::PolicyChanged { granted, current } => write!(
                f,
                "the grant was made under policy epoch {granted}, and the policy is now at \
                 {current}"
            ),
            Self::OtherEffect => f.write_str("the approval is for another effect"),
            Self::ReviewedArtifactMismatch => {
                f.write_str("the reviewed artifact is not the payload that would be sent")
            }
            Self::Revoked => f.write_str("the grant was revoked"),
            Self::UnknownBasis => f.write_str("no such grant exists"),
        }
    }
}

impl std::error::Error for ScopeViolation {}

strict_tagged_enum! {
    /// Why a budget hold was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BudgetRefusal (tag = "refusal", wire = BudgetRefusalWire, wire_name = "BudgetRefusalWire") {
        EffectsExhausted { max_effects: u64, committed_effects: u64 },
        SpendExhausted { requested_microunits: u64, available_microunits: u64 },
        /// The effect already holds a reservation.
        AlreadyHeld,
        /// The approval is held or used by an attempt.
        ApprovalInUse,
        NotHeld,
        NotInFlight,
        Scope { violation: ScopeViolation },
    }
}

impl fmt::Display for BudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EffectsExhausted {
                max_effects,
                committed_effects,
            } => write!(
                f,
                "{committed_effects} of {max_effects} effects are reserved or used"
            ),
            Self::SpendExhausted {
                requested_microunits,
                available_microunits,
            } => write!(
                f,
                "{requested_microunits} microunits requested, {available_microunits} left"
            ),
            Self::AlreadyHeld => f.write_str("the effect already holds a reservation"),
            Self::ApprovalInUse => f.write_str("the approval is held by an attempt or used"),
            Self::NotHeld => f.write_str("the effect holds no reservation"),
            Self::NotInFlight => f.write_str("the effect's reservation is not in flight"),
            Self::Scope { violation } => write!(f, "{violation}"),
        }
    }
}

impl std::error::Error for BudgetRefusal {}

/// Where a budget hold is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldState {
    /// Reserved before dispatch; returned if the effect never dispatches.
    Reserved,
    /// Consumed by a dispatch; settled by the outcome.
    InFlight,
}

/// One effect's budget hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetHold {
    pub effect: EffectId,
    pub basis: AuthorizationBasis,
    pub spend_microunits: u64,
    pub state: HoldState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationEntry {
    delegation: StandingDelegation,
    reserved_effects: u64,
    used_effects: u64,
    reserved_spend_microunits: u64,
    used_spend_microunits: u64,
    revoked_at: Option<MonotonicTime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalUse {
    Unused,
    Held,
    Used,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalEntry {
    approval: IndividualApproval,
    usage: ApprovalUse,
    revoked_at: Option<MonotonicTime>,
}

/// Every grant and every budget hold, kept centrally (§2.5 line 1815; VM-P32).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationBook {
    delegations: BTreeMap<DelegationId, DelegationEntry>,
    approvals: BTreeMap<ApprovalId, ApprovalEntry>,
    holds: BTreeMap<EffectId, BudgetHold>,
}

impl AuthorizationBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a delegation; granting the same terms again changes nothing.
    pub fn grant(&mut self, delegation: StandingDelegation) -> DelegationId {
        let id = delegation.id();
        self.delegations.entry(id).or_insert(DelegationEntry {
            delegation,
            reserved_effects: 0,
            used_effects: 0,
            reserved_spend_microunits: 0,
            used_spend_microunits: 0,
            revoked_at: None,
        });
        id
    }

    /// Records an approval; approving the same terms again changes nothing.
    pub fn approve(&mut self, approval: IndividualApproval) -> ApprovalId {
        let id = approval.id();
        self.approvals.entry(id).or_insert(ApprovalEntry {
            approval,
            usage: ApprovalUse::Unused,
            revoked_at: None,
        });
        id
    }

    pub fn delegation(&self, id: &DelegationId) -> Option<&StandingDelegation> {
        self.delegations.get(id).map(|entry| &entry.delegation)
    }

    /// Revokes a delegation: no new hold is granted under it.
    pub fn revoke_delegation(&mut self, id: &DelegationId, now: MonotonicTime) -> bool {
        match self.delegations.get_mut(id) {
            Some(entry) => {
                entry.revoked_at.get_or_insert(now);
                true
            }
            None => false,
        }
    }

    /// Revokes every delegation and approval of `sandbox` (§6.3 step 2).
    pub fn revoke_sandbox(&mut self, sandbox: &SandboxRef, now: MonotonicTime) {
        for entry in self.delegations.values_mut() {
            if &entry.delegation.scope.sandbox == sandbox {
                entry.revoked_at.get_or_insert(now);
            }
        }
        for entry in self.approvals.values_mut() {
            if &entry.approval.sandbox == sandbox {
                entry.revoked_at.get_or_insert(now);
            }
        }
    }

    /// Whether `basis` covers `description` for `executor` now.
    pub fn check(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        match basis {
            AuthorizationBasis::Delegation { delegation } => {
                let entry = self
                    .delegations
                    .get(delegation)
                    .ok_or(ScopeViolation::UnknownBasis)?;
                if entry.revoked_at.is_some() {
                    return Err(ScopeViolation::Revoked);
                }
                entry
                    .delegation
                    .covers(description, executor, policy, now, session)
            }
            AuthorizationBasis::Individual { approval } => {
                let entry = self
                    .approvals
                    .get(approval)
                    .ok_or(ScopeViolation::UnknownBasis)?;
                if entry.revoked_at.is_some() {
                    return Err(ScopeViolation::Revoked);
                }
                entry.approval.covers(description, policy, now, session)
            }
        }
    }

    /// Reserves one effect and `spend_microunits` under `basis` for `effect`, within the
    /// delegation's remaining budget or the approval's single use.
    pub fn reserve(
        &mut self,
        basis: AuthorizationBasis,
        effect: EffectId,
        spend_microunits: u64,
    ) -> Result<BudgetHold, BudgetRefusal> {
        if self.holds.contains_key(&effect) {
            return Err(BudgetRefusal::AlreadyHeld);
        }
        match basis {
            AuthorizationBasis::Delegation { delegation } => {
                let entry = self
                    .delegations
                    .get_mut(&delegation)
                    .ok_or(BudgetRefusal::Scope {
                        violation: ScopeViolation::UnknownBasis,
                    })?;
                if entry.revoked_at.is_some() {
                    return Err(BudgetRefusal::Scope {
                        violation: ScopeViolation::Revoked,
                    });
                }
                let budget = entry.delegation.budget;
                let committed_effects = entry.reserved_effects.saturating_add(entry.used_effects);
                if committed_effects >= budget.max_effects {
                    return Err(BudgetRefusal::EffectsExhausted {
                        max_effects: budget.max_effects,
                        committed_effects,
                    });
                }
                let available = budget.max_spend_microunits.saturating_sub(
                    entry
                        .reserved_spend_microunits
                        .saturating_add(entry.used_spend_microunits),
                );
                if spend_microunits > available {
                    return Err(BudgetRefusal::SpendExhausted {
                        requested_microunits: spend_microunits,
                        available_microunits: available,
                    });
                }
                entry.reserved_effects = entry.reserved_effects.saturating_add(1);
                entry.reserved_spend_microunits = entry
                    .reserved_spend_microunits
                    .saturating_add(spend_microunits);
            }
            AuthorizationBasis::Individual { approval } => {
                let entry = self
                    .approvals
                    .get_mut(&approval)
                    .ok_or(BudgetRefusal::Scope {
                        violation: ScopeViolation::UnknownBasis,
                    })?;
                if entry.revoked_at.is_some() {
                    return Err(BudgetRefusal::Scope {
                        violation: ScopeViolation::Revoked,
                    });
                }
                if entry.approval.effect != effect {
                    return Err(BudgetRefusal::Scope {
                        violation: ScopeViolation::OtherEffect,
                    });
                }
                if entry.usage != ApprovalUse::Unused {
                    return Err(BudgetRefusal::ApprovalInUse);
                }
                entry.usage = ApprovalUse::Held;
            }
        }
        let hold = BudgetHold {
            effect,
            basis,
            spend_microunits,
            state: HoldState::Reserved,
        };
        self.holds.insert(effect, hold);
        Ok(hold)
    }

    /// Consumes a reserved hold at the dispatch boundary; a second consume is refused, so
    /// one reservation backs one dispatch.
    pub fn consume(&mut self, effect: &EffectId) -> Result<(), BudgetRefusal> {
        let hold = self.holds.get_mut(effect).ok_or(BudgetRefusal::NotHeld)?;
        if hold.state != HoldState::Reserved {
            return Err(BudgetRefusal::NotHeld);
        }
        hold.state = HoldState::InFlight;
        Ok(())
    }

    /// Returns a hold that never dispatched.
    pub fn release(&mut self, effect: &EffectId) -> Result<(), BudgetRefusal> {
        match self.holds.get(effect) {
            Some(hold) if hold.state == HoldState::Reserved => {
                let hold = *hold;
                self.holds.remove(effect);
                self.unwind(&hold, false, 0);
                Ok(())
            }
            Some(_) => Err(BudgetRefusal::NotInFlight),
            None => Err(BudgetRefusal::NotHeld),
        }
    }

    /// Settles an in-flight hold: a committed effect uses one effect and its actual
    /// spend; one that certainly did not commit returns everything.
    pub fn settle(
        &mut self,
        effect: &EffectId,
        committed: bool,
        actual_spend_microunits: u64,
    ) -> Result<(), BudgetRefusal> {
        let hold = *self.holds.get(effect).ok_or(BudgetRefusal::NotHeld)?;
        if hold.state != HoldState::InFlight {
            return Err(BudgetRefusal::NotInFlight);
        }
        self.holds.remove(effect);
        self.unwind(&hold, committed, actual_spend_microunits);
        Ok(())
    }

    fn unwind(&mut self, hold: &BudgetHold, committed: bool, actual_spend_microunits: u64) {
        match hold.basis {
            AuthorizationBasis::Delegation { delegation } => {
                if let Some(entry) = self.delegations.get_mut(&delegation) {
                    entry.reserved_effects = entry.reserved_effects.saturating_sub(1);
                    entry.reserved_spend_microunits = entry
                        .reserved_spend_microunits
                        .saturating_sub(hold.spend_microunits);
                    if committed {
                        entry.used_effects = entry.used_effects.saturating_add(1);
                        entry.used_spend_microunits = entry
                            .used_spend_microunits
                            .saturating_add(actual_spend_microunits);
                    }
                }
            }
            AuthorizationBasis::Individual { approval } => {
                if let Some(entry) = self.approvals.get_mut(&approval) {
                    entry.usage = if committed {
                        ApprovalUse::Used
                    } else {
                        ApprovalUse::Unused
                    };
                }
            }
        }
    }

    pub fn hold(&self, effect: &EffectId) -> Option<&BudgetHold> {
        self.holds.get(effect)
    }

    /// Effects reserved, effects used, spend reserved and spend used under a delegation.
    pub fn delegation_usage(&self, id: &DelegationId) -> Option<(u64, u64, u64, u64)> {
        self.delegations.get(id).map(|entry| {
            (
                entry.reserved_effects,
                entry.used_effects,
                entry.reserved_spend_microunits,
                entry.used_spend_microunits,
            )
        })
    }

    /// A compact identity of the mutable state, for the §12.3 model search.
    pub(super) fn fingerprint(&self) -> Vec<u64> {
        let mut state = Vec::new();
        for entry in self.delegations.values() {
            state.extend([
                entry.reserved_effects,
                entry.used_effects,
                entry.reserved_spend_microunits,
                entry.used_spend_microunits,
            ]);
        }
        for (effect, hold) in &self.holds {
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&effect.digest().as_bytes()[..8]);
            state.extend([
                u64::from_be_bytes(prefix),
                hold.spend_microunits,
                u64::from(hold.state == HoldState::InFlight),
            ]);
        }
        state
    }

    /// Effects reserved or in flight, over every basis: the `outstanding_reserved_effects`
    /// of §2.5 line 1822.
    pub fn outstanding_effects(&self) -> u64 {
        len_u64(self.holds.len())
    }
}
