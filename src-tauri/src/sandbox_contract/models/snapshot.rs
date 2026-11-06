//! §12.3 model 5: snapshot and epoch interaction (VM §6.6, §6.3).
//!
//! One sandbox identity runs an original instance. Snapshots capture the instance's
//! generation, the epoch and revocation state as stored, its approval and its own view
//! of spent budget, and whether tenant inputs had arrived (golden or dirty). Restores make
//! clones; a pool accepts snapshots. Revocation advances the epoch, writes a tombstone and
//! removes every instance's authority.
//!
//! Bounds: at most two snapshots (both of the original), three instances (two restores),
//! one approval, one revocation, a budget of one unit and two spending attempts.
//! Assumptions: a restore that would get no authority is refused outright; a clone's
//! fresh generation comes from a host counter; approvals carry their generation and epoch.

use std::fmt;

use super::contract::{Defect, Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

const MAX_SNAPSHOTS: usize = 2;
const MAX_INSTANCES: usize = 3;
/// Budget units the identity may spend.
const BUDGET: u8 = 1;
const MAX_SPEND_ATTEMPTS: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Approval {
    generation: u8,
    epoch: u8,
    restored: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Instance {
    generation: u8,
    authority: bool,
    approval: Option<Approval>,
    budget_view: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Snap {
    pre_tenant: bool,
    generation: u8,
    epoch: u8,
    revoked: bool,
    approval: Option<Approval>,
    spent: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct SnapshotState {
    tenant: bool,
    approved: bool,
    epoch: u8,
    revoked: bool,
    tombstone: bool,
    next_generation: u8,
    used_generations: u8,
    instances: Vec<Instance>,
    snapshots: Vec<Snap>,
    pooled: u8,
    spent: u8,
    // History fields.
    spend_attempts: u8,
    true_spent: u8,
    ever_revoked: bool,
    duplicate_generation: bool,
    stale_approval_used: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SnapshotAction {
    TakeSnapshot,
    AttachTenant,
    Approve,
    Promote(usize),
    Revoke,
    Restore(usize),
    UseApproval(usize),
    Spend(usize),
}

impl fmt::Display for SnapshotAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TakeSnapshot => f.write_str("take snapshot"),
            Self::AttachTenant => f.write_str("attach tenant inputs"),
            Self::Approve => f.write_str("approve action"),
            Self::Promote(snapshot) => write!(f, "promote snapshot {snapshot} to pool"),
            Self::Revoke => f.write_str("revoke identity"),
            Self::Restore(snapshot) => write!(f, "restore snapshot {snapshot}"),
            Self::UseApproval(instance) => write!(f, "use approval on instance {instance}"),
            Self::Spend(instance) => write!(f, "spend budget on instance {instance}"),
        }
    }
}

fn bit(index: u8) -> u8 {
    1u8 << index
}

pub(super) struct SnapshotModel<'c> {
    config: &'c ModelConfig,
}

impl<'c> SnapshotModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn restore(&self, state: &SnapshotState, index: usize) -> Option<SnapshotState> {
        let config = self.config;
        let snap = *state.snapshots.get(index)?;
        let mut next = state.clone();
        let rollback = (config.has(Injection::SnapshotEpochRestored)
            && !config.enforces(Guard::DurableEpochOutsideSnapshot))
            || config.defect(Defect::EpochReadFromSnapshot);
        if rollback {
            next.epoch = snap.epoch;
            next.revoked = snap.revoked;
        }
        let tombstone_checked = config.enforces(Guard::TombstoneCheckOnRestore)
            && !config.defect(Defect::EpochReadFromSnapshot);
        if next.revoked || (tombstone_checked && next.tombstone) {
            return None;
        }
        let generation = if config.enforces(Guard::UniqueGeneration)
            && !config.defect(Defect::CloneKeepsGeneration)
        {
            let fresh = next.next_generation;
            next.next_generation += 1;
            fresh
        } else {
            snap.generation
        };
        next.duplicate_generation |= next.used_generations & bit(generation) != 0;
        next.used_generations |= bit(generation);
        let approval = if config.enforces(Guard::InvalidateApprovalsOnRestore) {
            None
        } else {
            snap.approval.map(|approval| Approval {
                restored: true,
                ..approval
            })
        };
        next.instances.push(Instance {
            generation,
            authority: true,
            approval,
            budget_view: snap.spent,
        });
        Some(next)
    }
}

impl TransitionSystem for SnapshotModel<'_> {
    type State = SnapshotState;
    type Action = SnapshotAction;

    fn kind(&self) -> ModelKind {
        ModelKind::Snapshot
    }

    fn initial_states(&self) -> Vec<SnapshotState> {
        vec![SnapshotState {
            tenant: false,
            approved: false,
            epoch: 1,
            revoked: false,
            tombstone: false,
            next_generation: 2,
            used_generations: bit(1),
            instances: vec![Instance {
                generation: 1,
                authority: true,
                approval: None,
                budget_view: 0,
            }],
            snapshots: Vec::new(),
            pooled: 0,
            spent: 0,
            spend_attempts: 0,
            true_spent: 0,
            ever_revoked: false,
            duplicate_generation: false,
            stale_approval_used: false,
        }]
    }

    fn successors(&self, state: &SnapshotState) -> Vec<(SnapshotAction, SnapshotState)> {
        use SnapshotAction as A;
        let config = self.config;
        let mut out = Vec::new();
        let Some(original) = state.instances.first().copied() else {
            return out;
        };
        if original.authority && state.snapshots.len() < MAX_SNAPSHOTS {
            let mut next = state.clone();
            next.snapshots.push(Snap {
                pre_tenant: !state.tenant,
                generation: original.generation,
                epoch: state.epoch,
                revoked: state.revoked,
                approval: original.approval,
                spent: original.budget_view,
            });
            out.push((A::TakeSnapshot, next));
        }
        if !state.tenant {
            let mut next = state.clone();
            next.tenant = true;
            out.push((A::AttachTenant, next));
        }
        if state.tenant && original.authority && !state.approved {
            let mut next = state.clone();
            next.approved = true;
            if let Some(first) = next.instances.first_mut() {
                first.approval = Some(Approval {
                    generation: original.generation,
                    epoch: state.epoch,
                    restored: false,
                });
            }
            out.push((A::Approve, next));
        }
        for (index, snap) in state.snapshots.iter().enumerate() {
            let pooled = state.pooled & bit(index as u8) != 0;
            let golden_only = config.enforces(Guard::GoldenOnlyPool)
                && !config.defect(Defect::DirtySnapshotPooled);
            if !pooled && (snap.pre_tenant || !golden_only) {
                let mut next = state.clone();
                next.pooled |= bit(index as u8);
                out.push((A::Promote(index), next));
            }
        }
        if !state.ever_revoked {
            let mut next = state.clone();
            next.epoch += 1;
            next.revoked = true;
            next.tombstone = true;
            next.ever_revoked = true;
            for instance in &mut next.instances {
                instance.authority = false;
            }
            out.push((A::Revoke, next));
        }
        if state.instances.len() < MAX_INSTANCES {
            for index in 0..state.snapshots.len() {
                if let Some(next) = self.restore(state, index) {
                    out.push((A::Restore(index), next));
                }
            }
        }
        for (index, instance) in state.instances.iter().enumerate() {
            if !instance.authority {
                continue;
            }
            if let Some(approval) = instance.approval {
                let bound =
                    approval.generation == instance.generation && approval.epoch == state.epoch;
                if bound || !config.enforces(Guard::ApprovalBoundToGeneration) {
                    let mut next = state.clone();
                    next.instances[index].approval = None;
                    next.stale_approval_used |= approval.restored || !bound;
                    out.push((A::UseApproval(index), next));
                }
            }
            if state.spend_attempts < MAX_SPEND_ATTEMPTS {
                let mut next = state.clone();
                let allowed = if config.enforces(Guard::HostBudgetLedger) {
                    next.spent += 1;
                    state.spent < BUDGET
                } else {
                    next.instances[index].budget_view += 1;
                    instance.budget_view < BUDGET
                };
                if allowed {
                    next.spend_attempts += 1;
                    next.true_spent += 1;
                    out.push((A::Spend(index), next));
                }
            }
        }
        out
    }

    fn holds(&self, invariant: InvariantId, state: &SnapshotState) -> bool {
        let resurrected =
            state.ever_revoked && state.instances.iter().any(|instance| instance.authority);
        match invariant {
            InvariantId::SnapshotCannotRevive => !resurrected && state.true_spent <= BUDGET,
            InvariantId::RevokedIdentityNotResurrected => !resurrected,
            InvariantId::RestoredCloneUniqueGeneration => !state.duplicate_generation,
            InvariantId::StaleApprovalsFail => !state.stale_approval_used,
            InvariantId::OnlyGoldenSnapshotsPooled => state
                .snapshots
                .iter()
                .enumerate()
                .all(|(index, snap)| state.pooled & bit(index as u8) == 0 || snap.pre_tenant),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::models::contract::check_model;
    use crate::sandbox_contract::models::explore::{Bounds, Exploration};

    fn check(config: &ModelConfig) -> Exploration {
        check_model(ModelKind::Snapshot, config, Bounds::DEFAULT).unwrap()
    }

    #[test]
    fn the_correct_snapshot_model_holds_under_the_threat_model() {
        for config in [ModelConfig::correct(), ModelConfig::threat_model()] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn older_persisted_state_cannot_resurrect_a_revoked_identity() {
        let restored = ModelConfig::correct().with_injections([Injection::SnapshotEpochRestored]);
        // One of the two guards is enough; both missing resurrects the identity.
        for guard in [
            Guard::DurableEpochOutsideSnapshot,
            Guard::TombstoneCheckOnRestore,
        ] {
            assert!(check(&restored.clone().without_guards([guard])).is_clean());
        }
        let both = restored.without_guards([
            Guard::DurableEpochOutsideSnapshot,
            Guard::TombstoneCheckOnRestore,
        ]);
        let result = check(&both);
        let violation = result
            .violation(InvariantId::RevokedIdentityNotResurrected)
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec!["take snapshot", "revoke identity", "restore snapshot 0"]
        );
        assert!(!result.holds(InvariantId::SnapshotCannotRevive));
    }

    #[test]
    fn a_restored_clone_gets_a_unique_generation_and_stale_approvals_fail() {
        let result = check(&ModelConfig::correct().with_defects([Defect::CloneKeepsGeneration]));
        let violation = result
            .violation(InvariantId::RestoredCloneUniqueGeneration)
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec!["take snapshot", "restore snapshot 0"]
        );
        // Approvals copied into a clone are refused by the generation binding.
        let copied = ModelConfig::correct().without_guards([Guard::InvalidateApprovalsOnRestore]);
        assert!(check(&copied).is_clean());
        let unbound = copied.without_guards([Guard::ApprovalBoundToGeneration]);
        let stale = check(&unbound)
            .violation(InvariantId::StaleApprovalsFail)
            .cloned()
            .unwrap();
        assert_eq!(
            stale.trace.steps,
            vec![
                "attach tenant inputs",
                "approve action",
                "take snapshot",
                "restore snapshot 0",
                "use approval on instance 1"
            ]
        );
    }

    #[test]
    fn only_golden_snapshots_enter_the_pool() {
        let result = check(&ModelConfig::correct().with_defects([Defect::DirtySnapshotPooled]));
        let violation = result
            .violation(InvariantId::OnlyGoldenSnapshotsPooled)
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec![
                "attach tenant inputs",
                "take snapshot",
                "promote snapshot 0 to pool"
            ]
        );
    }

    #[test]
    fn a_restore_cannot_spend_the_budget_again_while_the_host_keeps_the_ledger() {
        let result = check(&ModelConfig::correct().without_guards([Guard::HostBudgetLedger]));
        let violation = result.violation(InvariantId::SnapshotCannotRevive).unwrap();
        assert_eq!(
            violation.trace.steps.len(),
            4,
            "{:?}",
            violation.trace.steps
        );
        assert!(result.holds(InvariantId::RevokedIdentityNotResurrected));
    }
}
