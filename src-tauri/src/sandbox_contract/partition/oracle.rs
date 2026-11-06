//! The exhaustive offline oracle for small workflows (VM part §9.1, line 2318: "bounded
//! graph search or ILP only as an offline oracle for small workflows").
//!
//! It evaluates every set partition of the steps (restricted growth strings) under every
//! topological order with the same objective and constraints as the rules, and keeps the
//! least cost; ties go to fewer VMs, then to the lexicographically first assignment and
//! order. Its bound is [`ORACLE_MAX_STEPS`]: Bell(7) = 877 partitions times at most 7! =
//! 5,040 orders. It is optimal only within its own model, never for a general task graph.

use serde::Serialize;

use super::compile::{precheck, CompileRefusal};
use super::plan::{
    analyze, build_plan, partition_violations, to_u32, to_u64, CompiledPlan, PartitionMethod,
    PartitionPolicy,
};
use super::workflow::Workflow;

/// Largest workflow the oracle searches.
pub const ORACLE_MAX_STEPS: usize = 7;
const ORACLE_MAX_ORDERS: usize = 5040;

/// What the oracle searched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OracleReport {
    pub partitions: u64,
    /// Partitions whose order-independent constraints held.
    pub admissible_partitions: u64,
    pub orders: u64,
    /// Partition and order pairs fully evaluated.
    pub evaluations: u64,
    pub feasible: u64,
}

/// Every restricted growth string of length `count`, in lexicographic order.
pub(super) fn set_partitions(count: usize) -> Vec<Vec<u32>> {
    let mut all = Vec::new();
    if count == 0 {
        return all;
    }
    let mut current = vec![0u32; count];
    extend(&mut current, 1, 0, &mut all);
    all
}

fn extend(current: &mut Vec<u32>, position: usize, highest: u32, all: &mut Vec<Vec<u32>>) {
    if position >= current.len() {
        all.push(current.clone());
        return;
    }
    for value in 0..=highest.saturating_add(1) {
        if let Some(slot) = current.get_mut(position) {
            *slot = value;
        }
        extend(current, position.saturating_add(1), highest.max(value), all);
    }
}

/// The least-cost feasible plan of a small workflow, and what was searched.
pub fn compile_exhaustive(
    workflow: &Workflow,
    policy: &PartitionPolicy,
) -> Result<(CompiledPlan, OracleReport), CompileRefusal> {
    let count = workflow.steps().len();
    if count > ORACLE_MAX_STEPS {
        return Err(CompileRefusal::TooLargeForOracle {
            steps: count,
            max: ORACLE_MAX_STEPS,
        });
    }
    precheck(workflow, policy)?;
    let orders =
        workflow
            .topological_orders(ORACLE_MAX_ORDERS)
            .ok_or(CompileRefusal::TooManyOrders {
                max: ORACLE_MAX_ORDERS,
            })?;
    let mut report = OracleReport {
        orders: to_u64(orders.len()),
        ..OracleReport::default()
    };
    type Best = ((u64, u32, Vec<u32>, Vec<usize>), Vec<u32>, Vec<usize>);
    let mut best: Option<Best> = None;
    for assignment in set_partitions(count) {
        report.partitions = report.partitions.saturating_add(1);
        if !partition_violations(workflow, policy, &assignment).is_empty() {
            continue;
        }
        report.admissible_partitions = report.admissible_partitions.saturating_add(1);
        for order in &orders {
            report.evaluations = report.evaluations.saturating_add(1);
            let analysis = analyze(workflow, policy, &assignment, order);
            if !analysis.violations.is_empty() {
                continue;
            }
            report.feasible = report.feasible.saturating_add(1);
            let key = (
                analysis.cost.total_units,
                analysis.cost.vm_count,
                assignment.clone(),
                order.clone(),
            );
            if best.as_ref().is_none_or(|(held, _, _)| key < *held) {
                best = Some((key, assignment.clone(), order.clone()));
            }
        }
    }
    let Some((_, assignment, order)) = best else {
        let single = vec![0u32; count];
        let separate: Vec<u32> = (0..to_u32(count)).collect();
        let default_order = workflow.default_order().to_vec();
        return Err(CompileRefusal::NoFeasiblePartition {
            evaluations: report.evaluations,
            single_vm: analyze(workflow, policy, &single, &default_order).violations,
            one_vm_per_step: analyze(workflow, policy, &separate, &default_order).violations,
        });
    };
    let analysis = analyze(workflow, policy, &assignment, &order);
    let plan = build_plan(
        workflow,
        policy,
        &assignment,
        &order,
        analysis,
        PartitionMethod::ExhaustiveOracle {
            evaluations: report.evaluations,
        },
        Vec::new(),
    );
    Ok((plan, report))
}
