//! Per-tenant shares of the governor's speculative budget (GPU-W06 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1236: "per-tenant budgets" and
//! "Track queue fairness, aging and protection against starvation"; G05 in
//! docs/combined-plan-remaining-only.md: "Connect ... per-tenant limits, fairness/aging,
//! starvation bounds").
//!
//! The governor's `max_active` and `max_speculative_bytes` bound every tenant together,
//! first come first served, so one tenant's workflows can hold the whole speculative
//! budget and every other tenant's declared steps are declined until those preparations
//! end. [`PreparationGovernor::declare_within_share`] caps each tenant's part of it
//! ([`TenantShares`]): a new step is declined when its tenant already has `max_active`
//! preparations, or when its own demand and the shared prerequisites it would add would
//! take the tenant's speculative bytes past `max_speculative_bytes`. A tenant's share
//! bounds what the others can be kept from, so with shares that sum to no more than the
//! governor's own bounds no tenant is starved by another's speculation.
//!
//! What a re-declaration supersedes is credited first, exactly as
//! [`PreparationGovernor::declare`] supersedes it; steps the governor already prepares
//! pass; everything else is the governor's own declaration, with its lookahead, global
//! bounds, §2.9 value, deadlines and ledger. Queue order among waiting reservations stays
//! the ledger's [`QueueFairness`](crate::foundation::ledger::QueueFairness) (aging, tenant
//! turns, foreground first, bounded waits).
//!
//! # Shared prerequisites
//!
//! A shared prerequisite, such as a base model under several of a tenant's workflows, is
//! one CORE-03 reservation ([`SharedPrerequisites`](super::super::shared::SharedPrerequisites)),
//! counted once against the governor's `max_speculative_bytes` and charged once to the
//! tenant's CORE-03 budget. It is charged once to the tenant's share as well: its bytes
//! count in [`TenantUsage::speculative_bytes`] while no request uses it, however many of
//! the tenant's preparations hold it, exactly as the governor counts it. A step that
//! joins a prerequisite the tenant already holds is charged only its own demand; one that
//! needs a prerequisite the tenant does not hold yet is charged its bytes too, once per
//! declaration. The charge lasts as long as the reservation: until its last holder ends
//! or a request uses it, and a re-declaration is credited with a prerequisite only its
//! superseded preparations hold. Tenants never share one reservation (GPU S3.3; the
//! ledger shares an extent only within one tenant), so two tenants that need the same
//! base each hold and are charged their own copy, and the shares of all tenants add up to
//! what the governor counts, with nothing counted twice.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    bytes_of, DeclarationReport, DeclineReason, Phase, PreparationGovernor, PreparationMode,
    PrerequisiteKey, StepDecision, StepOutcome, WorkflowIntent,
};
use crate::foundation::coordination::LeaseState;
use crate::foundation::ids::{Clock, LeaseId, OperationId, TenantId};
use crate::foundation::ledger::Ledger;

/// One tenant's part of the governor's speculative budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantShare {
    /// Preparations admitted and not ended, at most.
    pub max_active: usize,
    /// Bytes of the tenant's speculative preparations' own demand and of its shared
    /// prerequisites no request uses yet, each once, at most.
    pub max_speculative_bytes: u64,
}

/// Every tenant's share: its own entry, or the default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantShares {
    pub default: TenantShare,
    pub tenants: BTreeMap<TenantId, TenantShare>,
}

impl TenantShares {
    /// `tenant`'s share.
    pub fn share(&self, tenant: &TenantId) -> TenantShare {
        self.tenants.get(tenant).copied().unwrap_or(self.default)
    }
}

/// What one tenant's preparations hold in the governor now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TenantUsage {
    /// Preparations admitted and not ended.
    pub active: usize,
    /// Own demand of its speculative preparations, plus each shared prerequisite it holds
    /// that no request uses yet, once (see the module documentation).
    pub speculative_bytes: u64,
}

/// A declaration within the tenant's share.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ShareDeclaration {
    /// Every step's decision in declared order. A step declined for the tenant's share
    /// carries [`DeclineReason::ActiveLimit`] or [`DeclineReason::SpeculativeBytes`] with
    /// the share's limit, and is listed in `limited`.
    pub report: DeclarationReport,
    /// Steps declined for the tenant's share rather than the governor's bounds.
    pub limited: Vec<OperationId>,
}

impl PreparationGovernor {
    /// What `tenant`'s preparations hold now.
    pub fn tenant_usage(&self, tenant: &TenantId) -> TenantUsage {
        let usage = self
            .active
            .values()
            .filter(|governed| governed.tenant() == tenant)
            .fold(TenantUsage::default(), |usage, governed| TenantUsage {
                active: usage.active.saturating_add(1),
                speculative_bytes: if governed.phase == Phase::Speculative {
                    usage
                        .speculative_bytes
                        .saturating_add(bytes_of(&governed.demand))
                } else {
                    usage.speculative_bytes
                },
            });
        TenantUsage {
            speculative_bytes: usage
                .speculative_bytes
                .saturating_add(self.prerequisite_charge(tenant)),
            ..usage
        }
    }

    /// The prerequisites `tenant` holds, each once. Every holder of a prerequisite is an
    /// active preparation, so they are all found through the active preparations.
    fn prerequisites_of(&self, tenant: &TenantId) -> BTreeSet<PrerequisiteKey> {
        self.active
            .values()
            .filter(|governed| governed.tenant() == tenant)
            .flat_map(|governed| governed.prerequisites.iter().copied())
            .collect()
    }

    /// Bytes of `tenant`'s prerequisites no request uses yet, each once.
    fn prerequisite_charge(&self, tenant: &TenantId) -> u64 {
        self.prerequisites_of(tenant)
            .into_iter()
            .fold(0u64, |total, key| {
                total.saturating_add(self.shared.speculative_bytes_of(tenant, key).unwrap_or(0))
            })
    }

    /// [`Self::declare`] within the declaring tenant's share (see the module
    /// documentation). Demand-only declines every step as `declare` does.
    pub fn declare_within_share<C: Clock>(
        &mut self,
        intent: WorkflowIntent,
        shares: &TenantShares,
        ledger: &mut Ledger<C>,
        leases: &dyn Fn(LeaseId) -> Option<LeaseState>,
        clock: &dyn Clock,
    ) -> ShareDeclaration {
        if matches!(self.mode, PreparationMode::DemandOnly { .. }) {
            return ShareDeclaration {
                report: self.declare(intent, ledger, leases, clock),
                limited: Vec::new(),
            };
        }
        let share = shares.share(&intent.tenant);
        let lookahead = self.config.max_lookahead;
        let named: BTreeSet<&OperationId> = intent
            .steps
            .iter()
            .take(lookahead)
            .map(|step| &step.operation)
            .collect();
        let mut usage = self.tenant_usage(&intent.tenant);
        // The declaration first supersedes the workflow's speculative preparations it no
        // longer names, as `declare` does.
        let mut leaving: BTreeMap<PrerequisiteKey, usize> = BTreeMap::new();
        for (operation, governed) in &self.active {
            if *governed.execution() == intent.execution
                && governed.phase == Phase::Speculative
                && !named.contains(operation)
            {
                usage.active = usage.active.saturating_sub(1);
                usage.speculative_bytes = usage
                    .speculative_bytes
                    .saturating_sub(bytes_of(&governed.demand));
                if *governed.tenant() == intent.tenant {
                    for key in &governed.prerequisites {
                        let holders = leaving.entry(*key).or_insert(0);
                        *holders = holders.saturating_add(1);
                    }
                }
            }
        }
        // A prerequisite only superseded preparations hold leaves with its last holder.
        let mut released = BTreeSet::new();
        for (key, holders) in leaving {
            if self.shared.holders(&intent.tenant, key) == holders {
                released.insert(key);
                usage.speculative_bytes = usage.speculative_bytes.saturating_sub(
                    self.shared
                        .speculative_bytes_of(&intent.tenant, key)
                        .unwrap_or(0),
                );
            }
        }
        let WorkflowIntent {
            execution,
            tenant,
            steps,
        } = intent;
        let mut passed = Vec::new();
        let mut decisions: Vec<(usize, StepDecision)> = Vec::new();
        let mut limited = Vec::new();
        // Prerequisites the tenant does not hold that an earlier step of this declaration
        // was already charged for.
        let mut charged: BTreeSet<PrerequisiteKey> = BTreeSet::new();
        for (index, step) in steps.into_iter().enumerate() {
            let decline = |reason| StepDecision {
                operation: step.operation.clone(),
                outcome: StepOutcome::Declined { reason },
            };
            if index >= lookahead {
                decisions.push((index, decline(DeclineReason::BeyondLookahead)));
                continue;
            }
            if self.active.contains_key(&step.operation) {
                passed.push((index, step));
                continue;
            }
            // A prerequisite the tenant will still hold is charged already; any other is
            // charged once.
            let mut joining = BTreeSet::new();
            let mut requested = bytes_of(&step.demand);
            for prerequisite in &step.prerequisites {
                let held = self.shared.holds(&tenant, prerequisite.key)
                    && !released.contains(&prerequisite.key);
                let fresh = !held && !charged.contains(&prerequisite.key);
                if fresh && joining.insert(prerequisite.key) {
                    requested = requested.saturating_add(bytes_of(&prerequisite.demand));
                }
            }
            let reason = if usage.active >= share.max_active {
                Some(DeclineReason::ActiveLimit {
                    max_active: share.max_active,
                })
            } else if usage.speculative_bytes.saturating_add(requested)
                > share.max_speculative_bytes
            {
                Some(DeclineReason::SpeculativeBytes {
                    requested,
                    held: usage.speculative_bytes,
                    limit: share.max_speculative_bytes,
                })
            } else {
                None
            };
            match reason {
                Some(reason) => {
                    limited.push(step.operation.clone());
                    decisions.push((index, decline(reason)));
                }
                None => {
                    // Counted as if admitted; the governor may still decline it, which
                    // only leaves the share less used.
                    usage.active = usage.active.saturating_add(1);
                    usage.speculative_bytes = usage.speculative_bytes.saturating_add(requested);
                    charged.extend(joining);
                    passed.push((index, step));
                }
            }
        }
        let positions: Vec<usize> = passed.iter().map(|(index, _)| *index).collect();
        let report = self.declare(
            WorkflowIntent {
                execution,
                tenant,
                steps: passed.into_iter().map(|(_, step)| step).collect(),
            },
            ledger,
            leases,
            clock,
        );
        decisions.extend(positions.into_iter().zip(report.steps));
        decisions.sort_by_key(|(index, _)| *index);
        ShareDeclaration {
            report: DeclarationReport {
                steps: decisions
                    .into_iter()
                    .map(|(_, decision)| decision)
                    .collect(),
                superseded: report.superseded,
            },
            limited,
        }
    }
}

#[cfg(test)]
mod tests;
