//! §12.3 model 6 as exhaustive small-state enumeration: private inputs cannot reach an
//! unrestricted output node except through a declared release contract.
//!
//! **State space.** One private source `p` (secrecy tag `repo`). Up to
//! [`MODEL6_MAX_STEPS`] steps `s0..s2`, each producing one immutable item `o_i` and
//! reading any subset of `p` and earlier items. Each step holds one of: nothing, read of
//! `repo`, arbitrary network access, or an exact release of its first produced input to
//! the public output under its own declared contract. Every crossing edge `o_j -> s_i`
//! may or may not have a declared contract. Every workflow the validator accepts is
//! checked under every set partition and every topological order.
//!
//! **Semantics**, written independently of the compiler: a compartment becomes tainted
//! when one of its steps reads `p`, holds the read authority, or reads a tainted item;
//! an item is tainted if its compartment was tainted when it was produced; within a
//! compartment every step can reach everything held there. A violation is a tainted
//! compartment holding an unrestricted channel, or a tainted item crossing compartments
//! with no declared contract. A release under a declared public contract is the
//! permitted path.
//!
//! **Assumptions.** The VM boundary holds, channels are exactly the modelled
//! authorities, and labels are assigned correctly at the sources. A pass shows only that
//! the acceptor implies the property in this bounded space; it proves nothing about the
//! Rust code at large, the hypervisor or hardware (§12.3).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::authority::Authority;
use super::compile::precheck;
use super::contract::{Approval, ContractDestination, ReleaseContract};
use super::label::{Integrity, Label, LabelOrigin};
use super::names::{ContractId, DataId, LabelTag, StepId};
use super::oracle::set_partitions;
use super::plan::{analyze, Budgets, CostWeights, PartitionPolicy};
use super::workflow::{SourceData, Step, StepCost, StepOutput, Workflow, WorkflowSpec};

/// Largest number of steps the model enumerates.
pub const MODEL6_MAX_STEPS: usize = 3;
const MAX_STORED_COUNTEREXAMPLES: usize = 8;

/// The model's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ModelBounds {
    pub max_steps: usize,
}

impl ModelBounds {
    /// The largest supported bound.
    pub const fn full() -> Self {
        Self {
            max_steps: MODEL6_MAX_STEPS,
        }
    }
}

/// The bounds asked for more than the model supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ModelBoundsError {
    pub max_steps: usize,
    pub supported: usize,
}

/// One accepted partition that breaks model 6.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Counterexample {
    pub spec: WorkflowSpec,
    pub assignment: Vec<u32>,
    pub order: Vec<StepId>,
    pub detail: String,
}

/// What the enumeration covered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModelReport {
    pub bounds: ModelBounds,
    pub workflows: u64,
    pub rejected_workflows: u64,
    pub candidates: u64,
    pub accepted: u64,
    pub violations: u64,
    /// The first few counterexamples, for executable tests.
    pub counterexamples: Vec<Counterexample>,
}

/// The policy the model runs the compiler's checks under: the plan's conflict relation,
/// every authority grantable, and budgets that never bind.
pub fn model_policy() -> PartitionPolicy {
    PartitionPolicy::new(
        CostWeights {
            vm_startup_ms: 1,
            startup_units_per_vm: 1,
            retention_units_per_vm_second: 1,
            transfer_bytes_per_ms: 1,
            transfer_units_per_mib: 1,
            delay_units_per_second: 1,
            approval_units: 1,
        },
        Budgets {
            max_vms: u32::MAX,
            max_concurrent_vms: u32::MAX,
            host_memory_mib: u64::MAX,
            vm_overhead_mib: 0,
            max_vm_lifetime_ms: u64::MAX,
            max_vm_idle_ms: u64::MAX,
            release_budget_bytes: u64::MAX,
        },
    )
}

/// The compiler's own acceptance: the workflow passes the compile precheck and the
/// partition and order break no constraint.
pub fn plan_acceptor(
    policy: &PartitionPolicy,
) -> impl Fn(&Workflow, &[u32], &[usize]) -> bool + '_ {
    move |workflow, assignment, order| {
        precheck(workflow, policy).is_ok()
            && analyze(workflow, policy, assignment, order)
                .violations
                .is_empty()
    }
}

/// Enumerates the bounded space and reports every partition `acceptor` accepts that
/// breaks model 6.
pub fn check_model6(
    bounds: ModelBounds,
    acceptor: &dyn Fn(&Workflow, &[u32], &[usize]) -> bool,
) -> Result<ModelReport, ModelBoundsError> {
    if bounds.max_steps == 0 || bounds.max_steps > MODEL6_MAX_STEPS {
        return Err(ModelBoundsError {
            max_steps: bounds.max_steps,
            supported: MODEL6_MAX_STEPS,
        });
    }
    let mut report = ModelReport {
        bounds,
        workflows: 0,
        rejected_workflows: 0,
        candidates: 0,
        accepted: 0,
        violations: 0,
        counterexamples: Vec::new(),
    };
    for steps in 1..=bounds.max_steps {
        let mut choices = vec![StepChoice::default(); steps];
        enumerate_steps(&mut choices, 0, &mut |choices| {
            check_choices(choices, acceptor, &mut report)
        });
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Default)]
struct StepChoice {
    /// Bit 0 is `p`; bit `j + 1` is `o_j`.
    inputs: u32,
    /// 0 nothing, 1 read, 2 network, 3 exact release.
    operation: u8,
}

fn enumerate_steps(
    choices: &mut Vec<StepChoice>,
    index: usize,
    visit: &mut dyn FnMut(&[StepChoice]),
) {
    if index >= choices.len() {
        visit(choices);
        return;
    }
    for inputs in 0..bit(index.saturating_add(1)) {
        for operation in 0..4u8 {
            if let Some(choice) = choices.get_mut(index) {
                *choice = StepChoice { inputs, operation };
            }
            enumerate_steps(choices, index.saturating_add(1), visit);
        }
    }
}

/// `1 << position`, or zero when it does not fit.
fn bit(position: usize) -> u32 {
    u32::try_from(position)
        .ok()
        .and_then(|position| 1u32.checked_shl(position))
        .unwrap_or(0)
}

/// Whether `choice` reads the item of step `producer`.
fn reads_item(choice: &StepChoice, producer: usize) -> bool {
    choice.inputs & bit(producer.saturating_add(1)) != 0
}

fn item_name(index: usize) -> String {
    format!("o{index}")
}

/// The inner edges `(j, i)`: step `i` reads `o_j`.
fn edges(choices: &[StepChoice]) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for (index, choice) in choices.iter().enumerate() {
        for producer in 0..index {
            if reads_item(choice, producer) {
                edges.push((producer, index));
            }
        }
    }
    edges
}

fn check_choices(
    choices: &[StepChoice],
    acceptor: &dyn Fn(&Workflow, &[u32], &[usize]) -> bool,
    report: &mut ModelReport,
) {
    let edges = edges(choices);
    for flags in 0..bit(edges.len()) {
        report.workflows = report.workflows.saturating_add(1);
        let Some(spec) = build_spec(choices, &edges, flags) else {
            report.rejected_workflows = report.rejected_workflows.saturating_add(1);
            continue;
        };
        let Ok(workflow) = Workflow::new(spec.clone()) else {
            report.rejected_workflows = report.rejected_workflows.saturating_add(1);
            continue;
        };
        let Some(orders) = workflow.topological_orders(usize::MAX) else {
            report.rejected_workflows = report.rejected_workflows.saturating_add(1);
            continue;
        };
        for assignment in set_partitions(choices.len()) {
            for order in &orders {
                report.candidates = report.candidates.saturating_add(1);
                if !acceptor(&workflow, &assignment, order) {
                    continue;
                }
                report.accepted = report.accepted.saturating_add(1);
                if let Some(detail) = leak(&workflow, &assignment, order) {
                    report.violations = report.violations.saturating_add(1);
                    if report.counterexamples.len() < MAX_STORED_COUNTEREXAMPLES {
                        report.counterexamples.push(Counterexample {
                            spec: spec.clone(),
                            assignment: assignment.clone(),
                            order: order
                                .iter()
                                .filter_map(|index| workflow.steps().get(*index))
                                .map(|step| step.id.clone())
                                .collect(),
                            detail,
                        });
                    }
                }
            }
        }
    }
}

fn build_spec(
    choices: &[StepChoice],
    edges: &[(usize, usize)],
    flags: u32,
) -> Option<WorkflowSpec> {
    let repo = LabelTag::new("repo".to_string()).ok()?;
    let private = DataId::new("p".to_string()).ok()?;
    let sources = vec![SourceData {
        id: private.clone(),
        label: Label::private(repo.clone(), Integrity::Trusted),
        origin: LabelOrigin::TrustedPolicy { rule: repo.clone() },
        size_bytes: 1,
    }];
    let mut steps = Vec::new();
    let mut contracts = Vec::new();
    for (index, choice) in choices.iter().enumerate() {
        let id = StepId::new(format!("s{index}")).ok()?;
        let mut inputs = Vec::new();
        if choice.inputs & 1 != 0 {
            inputs.push(private.clone());
        }
        for producer in 0..index {
            if reads_item(choice, producer) {
                inputs.push(DataId::new(item_name(producer)).ok()?);
            }
        }
        let mut operations = BTreeSet::new();
        match choice.operation {
            1 => {
                operations.insert(Authority::ReadPrivate {
                    source: repo.clone(),
                });
            }
            2 => {
                operations.insert(Authority::ArbitraryNetwork);
            }
            3 => {
                let released = inputs.iter().find(|input| **input != private)?.clone();
                let contract = ContractId::new(format!("release-s{index}")).ok()?;
                contracts.push(ReleaseContract {
                    id: contract.clone(),
                    item: released,
                    destination: ContractDestination::Public,
                    approval: Approval::Operator {
                        reviewer: LabelTag::new("operator".to_string()).ok()?,
                    },
                    max_bytes: u64::MAX,
                });
                operations.insert(Authority::ExactRelease { contract });
            }
            _ => {}
        }
        steps.push(Step {
            id,
            inputs,
            operations,
            outputs: vec![StepOutput {
                id: DataId::new(item_name(index)).ok()?,
                size_bytes: 1,
                immutable: true,
                declared_label: None,
            }],
            cost: StepCost {
                duration_ms: 1,
                memory_mib: 1,
            },
            volumes: BTreeSet::new(),
        });
    }
    for (position, (producer, consumer)) in edges.iter().enumerate() {
        if flags & bit(position) == 0 {
            continue;
        }
        contracts.push(ReleaseContract {
            id: ContractId::new(format!("c{producer}-{consumer}")).ok()?,
            item: DataId::new(item_name(*producer)).ok()?,
            destination: ContractDestination::Step {
                step: StepId::new(format!("s{consumer}")).ok()?,
            },
            approval: Approval::PolicyPreauthorized {
                rule: LabelTag::new("handoff".to_string()).ok()?,
            },
            max_bytes: u64::MAX,
        });
    }
    Some(WorkflowSpec {
        sources,
        steps,
        contracts,
    })
}

/// Model 6's semantics, independent of the compiler's evaluation.
fn leak(workflow: &Workflow, assignment: &[u32], order: &[usize]) -> Option<String> {
    let steps = workflow.steps();
    let mut tainted: BTreeMap<u32, bool> = BTreeMap::new();
    let mut item_taint: BTreeMap<&DataId, bool> = BTreeMap::new();
    let mut produced_in: BTreeMap<&DataId, u32> = BTreeMap::new();
    for source in workflow.sources().values() {
        item_taint.insert(&source.id, !source.label.is_public());
    }
    for &index in order {
        let (Some(step), Some(&compartment)) = (steps.get(index), assignment.get(index)) else {
            return Some(format!(
                "step {index} is outside the workflow or its assignment"
            ));
        };
        let mut now = tainted.get(&compartment).copied().unwrap_or(false);
        for input in &step.inputs {
            let taint = item_taint.get(input).copied().unwrap_or(false);
            if let Some(from) = produced_in.get(input) {
                let declared = workflow.contracts().values().any(|contract| {
                    contract.item == *input
                        && contract.destination
                            == ContractDestination::Step {
                                step: step.id.clone(),
                            }
                });
                if taint && *from != compartment && !declared {
                    return Some(format!(
                        "private data in {input} crosses into compartment {compartment} without a \
                         declared contract"
                    ));
                }
            }
            now |= taint;
        }
        now |= step
            .operations
            .iter()
            .any(|operation| matches!(operation, Authority::ReadPrivate { .. }));
        tainted.insert(compartment, now);
        for output in &step.outputs {
            item_taint.insert(&output.id, now);
            produced_in.insert(&output.id, compartment);
        }
    }
    for (step, &compartment) in steps.iter().zip(assignment) {
        if !tainted.get(&compartment).copied().unwrap_or(false) {
            continue;
        }
        if let Some(channel) = step.unrestricted_channels().next() {
            return Some(format!(
                "compartment {compartment} holds private data and {channel} (step {})",
                step.id
            ));
        }
    }
    None
}
