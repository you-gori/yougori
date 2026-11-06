//! The §9.1 experiment on fakes (line 2336): one broadly authorized VM, manually separated
//! VMs and the compiler, with malicious outputs and cross-stage persistence attempts.
//!
//! Every number is modelled, not measured. A [`ComparisonRecord`] carries the CORE-08
//! fake-substrate provenance of the runs it came from, and its claim evidence is always
//! refused (S12 G0): it validates the comparison's shape and backs no security or
//! performance claim.
//!
//! Arm models. The broad VM holds every authority and shares all state. Manually
//! separated VMs give each step its own VM with exactly its authorities, hand data over
//! through a shared persistent workspace with one operator hand-off per crossing, and
//! have no content-ID gate, so approved-content lookups become registry requests by
//! name. The compiler arm is the rules-based plan. A malicious step tries to send its
//! compartment's history out through any unrestricted channel; the attempt is unsafe when
//! that history is private and blocked when no such channel is held. It also tries to
//! plant state that a later effect-holding step runs; that is blocked unless the two
//! share state.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::authority::Authority;
use super::compile::compile;
use super::label::Label;
use super::names::StepId;
use super::plan::{analyze, slot, to_u32, CrossingSource, PartitionPolicy};
use super::workflow::{Step, Workflow};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::{Provenance, ReportError, RunRecord};

/// Domain of [`ComparisonRecord::digest`].
pub const COMPARISON_DOMAIN: &str = "yougori/sandbox/partition/comparison/v1";

/// One arm of the comparison (line 2336).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arm {
    BroadVm,
    ManualSeparation,
    Compiler,
}

impl Arm {
    pub const ALL: [Self; 3] = [Self::BroadVm, Self::ManualSeparation, Self::Compiler];
}

/// Which steps behave maliciously in a case: their outputs try to exfiltrate and to
/// persist into later stages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttackPlan {
    pub malicious: BTreeSet<StepId>,
}

/// One arm's totals over every case (line 2336 measures).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArmMetrics {
    pub arm: Arm,
    pub cases: u32,
    pub completed: u32,
    pub vm_count: u32,
    pub max_authorities_per_vm: u32,
    pub authority_grants: u32,
    pub forbidden_combinations: u32,
    pub unsafe_release_attempts: u32,
    pub unsafe_releases_blocked: u32,
    pub persistence_attempts: u32,
    pub persistence_blocked: u32,
    pub approvals: u32,
    pub modelled_latency_ms: u64,
}

impl ArmMetrics {
    fn new(arm: Arm) -> Self {
        Self {
            arm,
            cases: 0,
            completed: 0,
            vm_count: 0,
            max_authorities_per_vm: 0,
            authority_grants: 0,
            forbidden_combinations: 0,
            unsafe_release_attempts: 0,
            unsafe_releases_blocked: 0,
            persistence_attempts: 0,
            persistence_blocked: 0,
            approvals: 0,
            modelled_latency_ms: 0,
        }
    }
}

/// One arm's layout of one workflow.
struct Layout {
    assignment: Vec<u32>,
    order: Vec<usize>,
    histories: Vec<Label>,
    authorities: Vec<BTreeSet<Authority>>,
    shared_state: bool,
    approvals: u32,
    latency_ms: u64,
}

fn layout(arm: Arm, workflow: &Workflow, policy: &PartitionPolicy) -> Option<Layout> {
    let steps = workflow.steps();
    match arm {
        Arm::BroadVm => {
            let assignment = vec![0u32; steps.len()];
            let order = workflow.default_order().to_vec();
            let analysis = analyze(workflow, policy, &assignment, &order);
            Some(Layout {
                authorities: analysis
                    .compartments
                    .iter()
                    .map(|state| state.authorities.clone())
                    .collect(),
                histories: analysis.step_history,
                assignment,
                order,
                shared_state: true,
                approvals: analysis.cost.approvals,
                latency_ms: analysis.cost.makespan_ms,
            })
        }
        Arm::ManualSeparation => {
            let assignment: Vec<u32> = (0..to_u32(steps.len())).collect();
            let order = workflow.default_order().to_vec();
            let analysis = analyze(workflow, policy, &assignment, &order);
            let mut workspace = Label::bottom();
            let mut histories = vec![Label::bottom(); steps.len()];
            for &index in &order {
                let Some(step) = steps.get(index) else {
                    continue;
                };
                let mut history = workspace.clone();
                for input in &step.inputs {
                    if let Some(label) = workflow.source_label(input) {
                        history.join_in(label);
                    }
                }
                history.join_in(&step.intrinsic_label());
                workspace.join_in(&history);
                if let Some(slot) = histories.get_mut(index) {
                    *slot = history;
                }
            }
            let authorities: Vec<BTreeSet<Authority>> = steps
                .iter()
                .map(|step| {
                    step.operations
                        .iter()
                        .map(|authority| match authority {
                            Authority::ApprovedContent => Authority::RegistryFetch,
                            other => other.clone(),
                        })
                        .collect()
                })
                .collect();
            let approved_vms = to_u32(
                authorities
                    .iter()
                    .filter(|held| {
                        held.iter()
                            .any(|authority| policy.operator_approved.contains(&authority.kind()))
                    })
                    .count(),
            );
            let operator_releases = to_u32(
                analysis
                    .releases
                    .iter()
                    .filter(|release| release.approval.is_operator())
                    .count(),
            );
            let handoffs = to_u32(
                analysis
                    .crossings
                    .iter()
                    .filter(|crossing| matches!(crossing.from, CrossingSource::Compartment { .. }))
                    .count(),
            );
            Some(Layout {
                assignment,
                order,
                histories,
                authorities,
                shared_state: true,
                approvals: approved_vms
                    .saturating_add(operator_releases)
                    .saturating_add(handoffs),
                latency_ms: analysis.cost.makespan_ms,
            })
        }
        Arm::Compiler => {
            let plan = compile(workflow, policy).ok()?;
            let assignment = plan.assignment().to_vec();
            let order: Vec<usize> = plan
                .order()
                .iter()
                .filter_map(|step| workflow.index_of(step))
                .collect();
            let analysis = analyze(workflow, policy, &assignment, &order);
            Some(Layout {
                authorities: analysis
                    .compartments
                    .iter()
                    .map(|state| state.authorities.clone())
                    .collect(),
                histories: analysis.step_history,
                assignment,
                order,
                shared_state: false,
                approvals: plan.cost().approvals,
                latency_ms: plan.cost().makespan_ms,
            })
        }
    }
}

/// Runs every case under every arm and totals the measures.
pub fn compare_arms(cases: &[(Workflow, AttackPlan)], policy: &PartitionPolicy) -> Vec<ArmMetrics> {
    let mut totals: Vec<ArmMetrics> = Arm::ALL.into_iter().map(ArmMetrics::new).collect();
    for (workflow, attack) in cases {
        for metrics in totals.iter_mut() {
            metrics.cases = metrics.cases.saturating_add(1);
            let Some(layout) = layout(metrics.arm, workflow, policy) else {
                continue;
            };
            metrics.completed = metrics.completed.saturating_add(1);
            metrics.vm_count = metrics
                .vm_count
                .saturating_add(to_u32(layout.authorities.len()));
            for held in &layout.authorities {
                metrics.max_authorities_per_vm =
                    metrics.max_authorities_per_vm.max(to_u32(held.len()));
                metrics.authority_grants =
                    metrics.authority_grants.saturating_add(to_u32(held.len()));
                metrics.forbidden_combinations = metrics
                    .forbidden_combinations
                    .saturating_add(to_u32(policy.conflicts.conflicts(held).len()));
            }
            metrics.approvals = metrics.approvals.saturating_add(layout.approvals);
            metrics.modelled_latency_ms = metrics
                .modelled_latency_ms
                .saturating_add(layout.latency_ms);
            let steps = workflow.steps();
            for (position, &index) in layout.order.iter().enumerate() {
                let (Some(step), Some(&compartment), Some(history)) = (
                    steps.get(index),
                    layout.assignment.get(index),
                    layout.histories.get(index),
                ) else {
                    continue;
                };
                if !attack.malicious.contains(&step.id) {
                    continue;
                }
                if !history.is_public() {
                    metrics.unsafe_release_attempts =
                        metrics.unsafe_release_attempts.saturating_add(1);
                    let open = layout
                        .authorities
                        .get(slot(compartment))
                        .is_some_and(|held| held.iter().any(Authority::is_unrestricted_release));
                    if !open {
                        metrics.unsafe_releases_blocked =
                            metrics.unsafe_releases_blocked.saturating_add(1);
                    }
                }
                for &later in layout.order.iter().skip(position.saturating_add(1)) {
                    if !steps.get(later).is_some_and(Step::holds_effect) {
                        continue;
                    }
                    metrics.persistence_attempts = metrics.persistence_attempts.saturating_add(1);
                    let shared =
                        layout.shared_state || layout.assignment.get(later) == Some(&compartment);
                    if !shared {
                        metrics.persistence_blocked = metrics.persistence_blocked.saturating_add(1);
                    }
                }
            }
        }
    }
    totals
}

/// Why a comparison record was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum ComparisonError {
    Report(ReportError),
    /// The numbers are modelled on fakes; a measured provenance would mislabel them.
    NotFakeSubstrate,
    Encoding,
}

impl fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Report(error) => error.fmt(f),
            Self::NotFakeSubstrate => f.write_str(
                "this comparison is modelled on fakes; it is recorded only with fake-substrate \
                 provenance",
            ),
            Self::Encoding => f.write_str("the comparison could not be encoded"),
        }
    }
}

impl std::error::Error for ComparisonError {}

/// The comparison's totals under the fake-substrate provenance of CORE-08.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComparisonRecord {
    provenance: Provenance,
    cases: u32,
    arms: Vec<ArmMetrics>,
    digest: Digest,
}

impl ComparisonRecord {
    /// Records `arms` with the provenance of the fake runs they came from; any
    /// provenance other than the fake substrate is refused.
    pub fn new(
        fake_runs: &[RunRecord],
        cases: u32,
        arms: Vec<ArmMetrics>,
    ) -> Result<Self, ComparisonError> {
        let provenance = Provenance::of_records(fake_runs).map_err(ComparisonError::Report)?;
        if !provenance.is_fake_substrate() {
            return Err(ComparisonError::NotFakeSubstrate);
        }
        let evidence = provenance
            .comparable_evidence()
            .map_err(ComparisonError::Report)?;
        let encoded = serde_json::to_vec(&arms).map_err(|_| ComparisonError::Encoding)?;
        let digest = DigestBuilder::new(COMPARISON_DOMAIN)
            .digest(&evidence)
            .u64(u64::from(cases))
            .bytes(&encoded)
            .finish();
        Ok(Self {
            provenance,
            cases,
            arms,
            digest,
        })
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn cases(&self) -> u32 {
        self.cases
    }

    pub fn arms(&self) -> &[ArmMetrics] {
        &self.arms
    }

    pub fn arm(&self, arm: Arm) -> Option<&ArmMetrics> {
        self.arms.iter().find(|metrics| metrics.arm == arm)
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The evidence a security or performance claim would need. Always refused: a
    /// fake-substrate run is not Yougori evidence (S12 G0).
    pub fn claim_evidence(&self) -> Result<Digest, ReportError> {
        self.provenance.yougori_evidence()
    }
}
