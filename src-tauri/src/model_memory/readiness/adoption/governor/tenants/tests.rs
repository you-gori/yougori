//! Per-tenant shares against the real CORE-03 ledger on a manual clock.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Digest, ExecutionId, GpuDeviceKey, ManualClock, MonotonicTime,
};
use crate::foundation::ledger::{
    Amounts, CapacityDeclaration, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::foundation::report::Label;
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::graph::node::DurationEstimate;
use crate::model_memory::math::prefetch::Objective;
use crate::model_memory::readiness::adoption::governor::{
    ArrivalReport, DeclaredStep, GovernorConfig, RollbackCause,
};
use crate::model_memory::readiness::adoption::observed::{Basis, EstimateReason, Labelled};
use crate::model_memory::readiness::adoption::shared::{
    LedgerRelease, PrerequisiteDemand, PrerequisiteKey,
};
use crate::model_memory::readiness::intent::{CancelReason, PrepareBounds, PrepareWork};
use crate::model_memory::readiness::test_support::target;

const GB: u64 = 1_000_000_000;

fn test_digest(part: &str) -> Digest {
    digest("yougori/test/tenant-shares/v1", &[part.as_bytes()])
}

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: test_digest("workstation"),
        device: test_digest("gpu-0"),
    }
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

fn host_ledger(clock: &Arc<ManualClock>) -> Ledger<Arc<ManualClock>> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject {
            machine: test_digest("workstation"),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: Duration::from_secs(600),
            },
            grant_ttl: Duration::from_secs(600),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    );
    ledger
        .declare_capacity(
            ResourceKey::vram(gpu()),
            CapacityDeclaration {
                total: 160 * GB,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    for name in ["tenant-a", "tenant-b"] {
        ledger
            .set_tenant_budget(tenant(name), ResourceKey::vram(gpu()), u64::MAX)
            .unwrap();
    }
    ledger
}

fn governor() -> PreparationGovernor {
    let mut governor = PreparationGovernor::new(GovernorConfig {
        execution: ExecutionId::new("exe-placement-governor").unwrap(),
        prepare: PrepareBounds {
            max_lead: Duration::from_secs(900),
            max_retention_ttl: Duration::from_secs(120),
        },
        max_active: 4,
        max_lookahead: 3,
        max_speculative_bytes: 40 * GB,
        max_outcomes: 32,
        promotion_wait: Duration::from_secs(60),
        objective: Objective::new(1.0, 1e-9, 0.0, 0.0).unwrap(),
    })
    .unwrap();
    governor.enable_workflow_intent();
    governor
}

fn step(name: &str, gb: u64) -> DeclaredStep {
    DeclaredStep {
        operation: OperationId::new(format!("op-{name}")).unwrap(),
        target: target(name),
        deadline: MonotonicTime::from_nanos(300_000_000_000),
        retention_ttl: Duration::from_secs(60),
        work: vec![PrepareWork::Step {
            step: PreparationStep::InboundTransfer,
        }],
        assigned_request: None,
        lease: LeaseId::new(7),
        probability: 1.0,
        cost: Labelled {
            value: DurationEstimate::new(
                Duration::from_secs(4),
                Duration::from_secs(5),
                Duration::from_secs(8),
            )
            .unwrap(),
            basis: Basis::Estimated {
                source: Label::new("catalog-bytes-over-nominal-bandwidth").unwrap(),
                reason: EstimateReason::NoObservations,
            },
        },
        demand: Amounts::new().vram_bytes(gpu(), gb * GB),
        prerequisites: Vec::new(),
    }
}

fn intent(owner: &str, workflow: &str, steps: Vec<DeclaredStep>) -> WorkflowIntent {
    WorkflowIntent {
        execution: ExecutionId::new(format!("exe-{workflow}")).unwrap(),
        tenant: tenant(owner),
        steps,
    }
}

fn shares() -> TenantShares {
    TenantShares {
        default: TenantShare {
            max_active: 2,
            max_speculative_bytes: 20 * GB,
        },
        tenants: BTreeMap::new(),
    }
}

fn active(_: LeaseId) -> Option<LeaseState> {
    Some(LeaseState::Active)
}

fn admitted(declaration: &ShareDeclaration) -> Vec<&str> {
    declaration
        .report
        .steps
        .iter()
        .filter(|decision| matches!(decision.outcome, StepOutcome::Admitted { .. }))
        .map(|decision| decision.operation.as_str())
        .collect()
}

#[test]
fn one_tenant_cannot_take_the_whole_speculative_budget() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    // Without shares the first tenant takes three of the four slots and the second gets one.
    let mut plain = governor();
    plain.declare(
        intent(
            "tenant-a",
            "a1",
            vec![step("a1", 8), step("a2", 8), step("a3", 8)],
        ),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    let report = plain.declare(
        intent("tenant-b", "b1", vec![step("b1", 8), step("b2", 8)]),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(
        report.steps[1].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::ActiveLimit { max_active: 4 }
        }
    );

    // With shares each tenant keeps its part.
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    let first = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![step("a1", 8), step("a2", 8), step("a3", 8)],
        ),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&first), vec!["op-a1", "op-a2"]);
    assert_eq!(first.limited, vec![OperationId::new("op-a3").unwrap()]);
    assert_eq!(
        first.report.steps[2].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::ActiveLimit { max_active: 2 }
        }
    );
    assert_eq!(
        governor.tenant_usage(&tenant("tenant-a")),
        TenantUsage {
            active: 2,
            speculative_bytes: 16 * GB
        }
    );
    let second = governor.declare_within_share(
        intent("tenant-b", "b1", vec![step("b1", 8), step("b2", 8)]),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&second), vec!["op-b1", "op-b2"]);
    assert!(second.limited.is_empty());
}

#[test]
fn a_share_bounds_bytes_and_a_tenant_may_have_its_own() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    let declaration = governor.declare_within_share(
        intent("tenant-a", "a1", vec![step("a1", 12), step("a2", 12)]),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&declaration), vec!["op-a1"]);
    assert_eq!(
        declaration.report.steps[1].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::SpeculativeBytes {
                requested: 12 * GB,
                held: 12 * GB,
                limit: 20 * GB
            }
        }
    );
    let mut generous = shares();
    generous.tenants.insert(
        tenant("tenant-b"),
        TenantShare {
            max_active: 2,
            max_speculative_bytes: 24 * GB,
        },
    );
    let declaration = governor.declare_within_share(
        intent("tenant-b", "b1", vec![step("b1", 12), step("b2", 12)]),
        &generous,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&declaration), vec!["op-b1", "op-b2"]);
}

#[test]
fn a_redeclaration_is_credited_with_what_it_supersedes() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    let shares = shares();
    let first = governor.declare_within_share(
        intent("tenant-a", "a1", vec![step("a1", 8), step("a2", 8)]),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&first), vec!["op-a1", "op-a2"]);
    // The workflow's queue changed: a2 stays, a1 is superseded and a3 takes its place.
    let second = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![step("a2", 8), step("a3", 8), step("a4", 8), step("a5", 8)],
        ),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(second.report.superseded.len(), 1);
    assert_eq!(
        second.report.superseded[0].operation,
        OperationId::new("op-a1").unwrap()
    );
    assert_eq!(
        second.report.steps[0].outcome,
        StepOutcome::AlreadyPreparing
    );
    assert!(matches!(
        second.report.steps[1].outcome,
        StepOutcome::Admitted { .. }
    ));
    assert_eq!(second.limited, vec![OperationId::new("op-a4").unwrap()]);
    assert_eq!(
        second.report.steps[3].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::BeyondLookahead
        }
    );
    assert_eq!(
        governor.tenant_usage(&tenant("tenant-a")),
        TenantUsage {
            active: 2,
            speculative_bytes: 16 * GB
        }
    );
}

#[test]
fn demand_only_declines_every_step_as_the_governor_does() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    governor.roll_back(RollbackCause::Operator, &mut ledger, clock.as_ref());
    let declaration = governor.declare_within_share(
        intent("tenant-a", "a1", vec![step("a1", 8)]),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert!(declaration.limited.is_empty());
    assert_eq!(
        declaration.report.steps[0].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::DemandOnly {
                cause: RollbackCause::Operator
            }
        }
    );
    assert_eq!(
        governor.tenant_usage(&tenant("tenant-a")),
        TenantUsage::default()
    );
}

// ---------------------------------------------------------------------------------------
// Shared prerequisites charged against a tenant's share.

fn base(name: &str, gb: u64) -> PrerequisiteDemand {
    PrerequisiteDemand {
        key: PrerequisiteKey::new(test_digest(name)),
        demand: Amounts::new().vram_bytes(gpu(), gb * GB),
    }
}

fn on(base: PrerequisiteDemand, mut step: DeclaredStep) -> DeclaredStep {
    step.prerequisites.push(base);
    step
}

/// Open reservations of shared prerequisites in the ledger.
fn shared_reservations(ledger: &Ledger<Arc<ManualClock>>) -> usize {
    ledger
        .open_reservations()
        .filter(|record| {
            record
                .provenance()
                .operation
                .as_str()
                .starts_with("prereq-")
        })
        .count()
}

fn usage(active: usize, gb: u64) -> TenantUsage {
    TenantUsage {
        active,
        speculative_bytes: gb * GB,
    }
}

#[test]
fn a_shared_base_is_charged_once_to_its_tenants_share() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    // Two workflows of one tenant, each holding 2 GB itself on the same 10 GB base: 14 GB
    // of the 20 GB share, not 24.
    let first = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![on(base("base-7b", 10), step("a1", 2))],
        ),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&first), vec!["op-a1"]);
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(1, 12));
    let second = governor.declare_within_share(
        intent(
            "tenant-a",
            "a2",
            vec![on(base("base-7b", 10), step("a2", 2))],
        ),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&second), vec!["op-a2"]);
    assert!(second.limited.is_empty());
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(2, 14));
    // Once against capacity and the governor's bound too: one reservation, two holders.
    let key = base("base-7b", 10).key;
    assert_eq!(governor.shared().holders(&tenant("tenant-a"), key), 2);
    assert_eq!(governor.shared().speculative_bytes(), 10 * GB);
    assert_eq!(governor.speculative_bytes(), 14 * GB);
    assert_eq!(shared_reservations(&ledger), 1);
    assert_eq!(
        ledger.tenant_reserved(&tenant("tenant-a"), ResourceKey::vram(gpu())),
        14 * GB
    );
}

#[test]
fn a_step_is_charged_the_base_it_would_add() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    // A base larger than the share cannot ride in on a small step.
    let declaration = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![on(base("base-70b", 30), step("a1", 1))],
        ),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert!(admitted(&declaration).is_empty());
    assert_eq!(
        declaration.limited,
        vec![OperationId::new("op-a1").unwrap()]
    );
    assert_eq!(
        declaration.report.steps[0].outcome,
        StepOutcome::Declined {
            reason: DeclineReason::SpeculativeBytes {
                requested: 31 * GB,
                held: 0,
                limit: 20 * GB
            }
        }
    );
    assert_eq!(shared_reservations(&ledger), 0);
    // Two steps of one declaration on a base not held yet pay for it once.
    let declaration = governor.declare_within_share(
        intent(
            "tenant-a",
            "a2",
            vec![
                on(base("base-7b", 10), step("a2", 2)),
                on(base("base-7b", 10), step("a3", 2)),
            ],
        ),
        &shares(),
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&declaration), vec!["op-a2", "op-a3"]);
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(2, 14));
}

#[test]
fn the_charge_lasts_until_the_last_holder_ends_or_a_request_uses_the_base() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    for workflow in ["a1", "a2"] {
        governor.declare_within_share(
            intent(
                "tenant-a",
                workflow,
                vec![on(base("base-7b", 10), step(workflow, 2))],
            ),
            &shares(),
            &mut ledger,
            &active,
            clock.as_ref(),
        );
    }
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(2, 14));
    let key = base("base-7b", 10).key;
    // One holder ends: the base stays reserved and charged for the other.
    let outcome = governor
        .cancel(
            &OperationId::new("op-a1").unwrap(),
            CancelReason::Requester,
            &mut ledger,
            clock.as_ref(),
        )
        .unwrap();
    assert_eq!(
        outcome.released[1],
        LedgerRelease::StillShared { key, holders: 1 }
    );
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(1, 12));
    assert_eq!(shared_reservations(&ledger), 1);
    // A request promotes the other: the base serves demand and leaves the speculative
    // share, as it leaves the governor's speculative bytes.
    assert!(matches!(
        governor.request_arrived(&target("a2"), &mut ledger, clock.as_ref()),
        ArrivalReport::Promoted { .. }
    ));
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(1, 0));
    assert_eq!(governor.shared().speculative_bytes(), 0);
    // The last holder finishes: the base is released with it.
    let outcome = governor
        .finish(
            &OperationId::new("op-a2").unwrap(),
            &mut ledger,
            clock.as_ref(),
        )
        .unwrap();
    assert!(matches!(
        outcome.released[1],
        LedgerRelease::Returned { .. }
    ));
    assert_eq!(
        governor.tenant_usage(&tenant("tenant-a")),
        TenantUsage::default()
    );
    assert_eq!(shared_reservations(&ledger), 0);
}

#[test]
fn each_tenant_is_charged_its_own_copy_and_the_shares_add_up() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    for (owner, workflow) in [("tenant-a", "a1"), ("tenant-b", "b1")] {
        let declaration = governor.declare_within_share(
            intent(
                owner,
                workflow,
                vec![on(base("base-7b", 10), step(workflow, 2))],
            ),
            &shares(),
            &mut ledger,
            &active,
            clock.as_ref(),
        );
        assert_eq!(admitted(&declaration).len(), 1);
    }
    // Tenants never share a reservation, so each holds and is charged its own copy.
    assert_eq!(shared_reservations(&ledger), 2);
    let a = governor.tenant_usage(&tenant("tenant-a"));
    let b = governor.tenant_usage(&tenant("tenant-b"));
    assert_eq!((a, b), (usage(1, 12), usage(1, 12)));
    assert_eq!(
        a.speculative_bytes + b.speculative_bytes,
        governor.speculative_bytes()
    );
}

#[test]
fn a_redeclaration_is_credited_with_a_base_only_its_superseded_steps_hold() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10_000_000_000)));
    let mut ledger = host_ledger(&clock);
    let mut governor = governor();
    let shares = shares();
    governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![on(base("base-7b", 10), step("a1", 2))],
        ),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(1, 12));
    // a1 is superseded and its base leaves with it: a3 on another base fits, where 12 GB
    // more on top of the old 12 would not.
    let second = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![on(base("base-8b", 10), step("a3", 2))],
        ),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(second.report.superseded.len(), 1);
    assert_eq!(admitted(&second), vec!["op-a3"]);
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(1, 12));
    assert_eq!(shared_reservations(&ledger), 1);
    // Another workflow joins the new base; superseding a3 then credits only a3's own
    // demand, since the base stays for that workflow, and a4 joins it for free.
    governor.declare_within_share(
        intent(
            "tenant-a",
            "a2",
            vec![on(base("base-8b", 10), step("a2", 2))],
        ),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(2, 14));
    let third = governor.declare_within_share(
        intent(
            "tenant-a",
            "a1",
            vec![on(base("base-8b", 10), step("a4", 2))],
        ),
        &shares,
        &mut ledger,
        &active,
        clock.as_ref(),
    );
    assert_eq!(admitted(&third), vec!["op-a4"]);
    assert_eq!(governor.tenant_usage(&tenant("tenant-a")), usage(2, 14));
    assert_eq!(shared_reservations(&ledger), 1);
}
