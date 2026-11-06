//! The §9.1 objective and constraints for one partition and execution order, and the
//! compiled plan with its explanation (VM part §9.1, lines 2305–2316 and 2332).
//!
//! Model assumptions, stated once: compartments run in parallel and each runs its steps
//! one at a time in the execution order; a VM boots when the inputs of its first step
//! exist and lives until its last step ends; an item crossing into a compartment is
//! copied once, starting when it is produced, at the modelled bandwidth; source data is
//! imported into each compartment that reads it. A compartment holds the union of its
//! steps' authorities for its whole life, and its history is the join of everything that
//! entered it so far.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::authority::{Authority, AuthorityKind, Conflict, ConflictRelation};
use super::contract::{Approval, ConfidentialityStatus, ContractDestination};
use super::label::Label;
use super::names::{ContractId, DataId, LabelTag, StepId, VolumeId};
use super::workflow::{Step, Workflow};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, TrustScope};
use crate::foundation::transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

/// Domain of a compartment's [`TrustScope`] digest.
pub const COMPARTMENT_DOMAIN: &str = "yougori/sandbox/partition/compartment/v1";
/// VM-D12: idle limit of a task sandbox, 12 hours.
pub const VM_D12_TASK_IDLE_MS: u64 = 12 * 60 * 60 * 1000;
/// VM-D12: absolute lifetime of a task sandbox, 24 hours.
pub const VM_D12_TASK_ABSOLUTE_MS: u64 = 24 * 60 * 60 * 1000;

const MIB: u128 = 1 << 20;

/// Weights of the §9.1 objective (lines 2307–2308). All terms are in one cost unit the
/// caller chooses; the plan fixes no values, so none are defaulted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostWeights {
    /// Modelled time from a VM's start to when it can run a step.
    pub vm_startup_ms: u64,
    pub startup_units_per_vm: u64,
    pub retention_units_per_vm_second: u64,
    /// Modelled bandwidth of a crossing or source import; zero is refused.
    pub transfer_bytes_per_ms: u64,
    pub transfer_units_per_mib: u64,
    pub delay_units_per_second: u64,
    pub approval_units: u64,
}

/// Resource and lifetime budgets (line 2316).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub max_vms: u32,
    pub max_concurrent_vms: u32,
    pub host_memory_mib: u64,
    pub vm_overhead_mib: u64,
    pub max_vm_lifetime_ms: u64,
    pub max_vm_idle_ms: u64,
    /// Bytes all external releases together may carry (§2.5).
    pub release_budget_bytes: u64,
}

impl Budgets {
    /// The VM-D12 task-sandbox starting values (idle 12 h, absolute 24 h, 8 MiB general
    /// release budget) with the caller's capacity limits, which the plan does not fix.
    pub fn with_vm_d12_lifetimes(
        max_vms: u32,
        max_concurrent_vms: u32,
        host_memory_mib: u64,
        vm_overhead_mib: u64,
    ) -> Self {
        Self {
            max_vms,
            max_concurrent_vms,
            host_memory_mib,
            vm_overhead_mib,
            max_vm_lifetime_ms: VM_D12_TASK_ABSOLUTE_MS,
            max_vm_idle_ms: VM_D12_TASK_IDLE_MS,
            release_budget_bytes: VM_D12_GENERAL_RELEASE_BUDGET_BYTES,
        }
    }
}

/// Everything the compiler is told: the conflict relation, what host policy may grant at
/// all, which grants are operator-visible approvals, the objective's weights and the
/// budgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionPolicy {
    pub conflicts: ConflictRelation,
    pub grantable: BTreeSet<AuthorityKind>,
    pub operator_approved: BTreeSet<AuthorityKind>,
    pub weights: CostWeights,
    pub budgets: Budgets,
}

impl PartitionPolicy {
    /// The plan's conflict relation; every kind grantable; arbitrary network access and
    /// credential use counted as operator-visible approvals.
    pub fn new(weights: CostWeights, budgets: Budgets) -> Self {
        Self {
            conflicts: ConflictRelation::plan_default(),
            grantable: AuthorityKind::ALL.into_iter().collect(),
            operator_approved: [
                AuthorityKind::ArbitraryNetwork,
                AuthorityKind::UseCredential,
            ]
            .into_iter()
            .collect(),
            weights,
            budgets,
        }
    }
}

/// One broken constraint (lines 2312–2316).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "violation", rename_all = "snake_case")]
pub enum Violation {
    NotGrantable {
        step: StepId,
        authority: Authority,
    },
    /// Revocation is monotonic: a compartment never regains a revoked authority
    /// (§12.3 model 3).
    RevokedInCompartment {
        compartment: u32,
        authority: Authority,
    },
    ForbiddenCombination {
        compartment: u32,
        conflict: Conflict,
    },
    /// The compartment's history holds private data and it holds an unrestricted
    /// release channel (line 2320).
    HistoryForbidsRelease {
        compartment: u32,
        authority: Authority,
        secrecy: BTreeSet<LabelTag>,
    },
    CrossingWithoutContract {
        item: DataId,
        consumer: StepId,
        from: u32,
        to: u32,
    },
    ContractTooSmall {
        contract: ContractId,
        bytes: u64,
        max_bytes: u64,
    },
    /// Retained state belongs to one compartment; handing it to another needs an
    /// immutable artifact and a contract.
    RetainedStateSplit {
        volume: VolumeId,
        compartments: BTreeSet<u32>,
    },
    /// An effect authority beside retained state could persist into a later generation
    /// (line 2315).
    AuthorityPersisted {
        compartment: u32,
        volume: VolumeId,
        authority: Authority,
    },
    TooManyVms {
        vms: u32,
        max: u32,
    },
    TooManyConcurrentVms {
        at_ms: u64,
        vms: u32,
        max: u32,
    },
    MemoryExceeded {
        at_ms: u64,
        needed_mib: u64,
        host_mib: u64,
    },
    LifetimeExceeded {
        compartment: u32,
        alive_ms: u64,
        max_ms: u64,
    },
    IdleExceeded {
        compartment: u32,
        idle_ms: u64,
        max_ms: u64,
    },
    ReleaseBudgetExceeded {
        bytes: u64,
        limit_bytes: u64,
    },
    CostOverflow,
    /// The assignment or order does not cover the workflow's steps exactly once.
    MalformedAssignment {
        steps: u32,
        assigned: u32,
        ordered: u32,
    },
}

impl Violation {
    /// Whether the violation is about information flow rather than resources.
    pub fn is_flow(&self) -> bool {
        matches!(
            self,
            Self::ForbiddenCombination { .. }
                | Self::HistoryForbidsRelease { .. }
                | Self::CrossingWithoutContract { .. }
                | Self::RetainedStateSplit { .. }
                | Self::AuthorityPersisted { .. }
        )
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGrantable { step, authority } => write!(
                f,
                "step {step} needs {authority}, which host policy does not grant"
            ),
            Self::RevokedInCompartment {
                compartment,
                authority,
            } => write!(
                f,
                "compartment {compartment} had {authority} revoked; revocation is not undone"
            ),
            Self::ForbiddenCombination {
                compartment,
                conflict,
            } => write!(f, "compartment {compartment} would hold {conflict}"),
            Self::HistoryForbidsRelease {
                compartment,
                authority,
                secrecy,
            } => write!(
                f,
                "compartment {compartment} has held private data ({}) and would hold {authority}; \
                 revoking a read does not erase copied data",
                tags(secrecy)
            ),
            Self::CrossingWithoutContract {
                item,
                consumer,
                from,
                to,
            } => write!(
                f,
                "{item} would cross from compartment {from} to compartment {to} for step \
                 {consumer} without a release contract"
            ),
            Self::ContractTooSmall {
                contract,
                bytes,
                max_bytes,
            } => write!(
                f,
                "contract {contract} allows {max_bytes} bytes; the item has {bytes}"
            ),
            Self::RetainedStateSplit {
                volume,
                compartments,
            } => write!(
                f,
                "retained volume {volume} would be shared by compartments {}",
                compartments
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::AuthorityPersisted {
                compartment,
                volume,
                authority,
            } => write!(
                f,
                "compartment {compartment} would keep volume {volume} beside {authority}; \
                 retained state cannot carry authority into a later generation"
            ),
            Self::TooManyVms { vms, max } => write!(f, "{vms} VMs; the budget is {max}"),
            Self::TooManyConcurrentVms { at_ms, vms, max } => write!(
                f,
                "{vms} VMs would run at once at {at_ms} ms; the budget is {max}"
            ),
            Self::MemoryExceeded {
                at_ms,
                needed_mib,
                host_mib,
            } => write!(
                f,
                "{needed_mib} MiB would be needed at {at_ms} ms; the host budget is {host_mib} MiB"
            ),
            Self::LifetimeExceeded {
                compartment,
                alive_ms,
                max_ms,
            } => write!(
                f,
                "compartment {compartment} would live {alive_ms} ms; the limit is {max_ms} ms"
            ),
            Self::IdleExceeded {
                compartment,
                idle_ms,
                max_ms,
            } => write!(
                f,
                "compartment {compartment} would idle {idle_ms} ms; the limit is {max_ms} ms"
            ),
            Self::ReleaseBudgetExceeded { bytes, limit_bytes } => write!(
                f,
                "external releases would carry {bytes} bytes; the release budget is {limit_bytes}"
            ),
            Self::CostOverflow => f.write_str("the modelled cost does not fit in 64 bits"),
            Self::MalformedAssignment {
                steps,
                assigned,
                ordered,
            } => write!(
                f,
                "{assigned} assignments and {ordered} ordered steps do not cover the {steps} steps"
            ),
        }
    }
}

pub(super) fn tags(secrecy: &BTreeSet<LabelTag>) -> String {
    secrecy
        .iter()
        .map(LabelTag::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Where a crossing comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum CrossingSource {
    /// A workflow source imported under the consumer's read authority.
    Source,
    Compartment {
        compartment: u32,
    },
}

/// One item entering a compartment for one consuming step (line 2314).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Crossing {
    pub item: DataId,
    pub consumer: StepId,
    pub from: CrossingSource,
    pub to: u32,
    /// The contract covering a crossing between compartments; `None` for a source.
    pub contract: Option<ContractId>,
    /// Whether this crossing moved the bytes; later consumers in the same compartment
    /// read the copy already there.
    pub moved_bytes: u64,
    /// The label travels with the item (line 2320).
    pub label: Label,
}

/// One exact release to an external target or the public output (line 2327).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalRelease {
    pub contract: ContractId,
    pub item: DataId,
    pub step: StepId,
    pub destination: ContractDestination,
    pub approval: Approval,
    pub bytes: u64,
    /// Private tags stay attached: approval authorizes, it does not declassify.
    pub label: Label,
    pub confidentiality: ConfidentialityStatus,
}

/// When one step runs, in modelled milliseconds from the workflow's start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScheduledStep {
    pub step: StepId,
    pub compartment: u32,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// The §9.1 objective's terms for one plan (lines 2307–2308).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CostBreakdown {
    pub total_units: u64,
    pub vm_count: u32,
    pub approvals: u32,
    pub transferred_bytes: u64,
    pub makespan_ms: u64,
    pub vm_alive_ms: u64,
    pub startup_units: u64,
    pub retention_units: u64,
    pub transfer_units: u64,
    pub delay_units: u64,
    pub approval_units: u64,
}

/// One compartment: one VM's steps, authorities, history and retained volumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Compartment {
    pub index: u32,
    /// State is shared inside the scope; crossing it needs a contract (S3.3).
    pub trust_scope: TrustScope,
    pub steps: Vec<StepId>,
    pub authorities: BTreeSet<Authority>,
    /// Everything that entered the compartment (line 2320).
    pub history: Label,
    pub volumes: BTreeSet<VolumeId>,
    pub start_ms: u64,
    pub end_ms: u64,
    pub memory_mib: u64,
}

/// How a step was placed by the rules-based partitioner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum PlacementRule {
    /// Placed with the producer of most of its input bytes.
    JoinedProducer { compartment: u32 },
    /// Placed in an existing compartment that produced none of its inputs.
    JoinedExisting { compartment: u32 },
    /// Every existing compartment was refused for the listed reasons.
    NewCompartment { refused: Vec<(u32, Vec<Violation>)> },
}

/// One reason in a plan's or refusal's explanation (line 2332).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    Compartment {
        compartment: u32,
        steps: Vec<StepId>,
        authorities: BTreeSet<Authority>,
        history: Label,
    },
    Placed {
        step: StepId,
        rule: PlacementRule,
    },
    /// The two steps would conflict in one compartment.
    Separated {
        left: StepId,
        right: StepId,
        conflict: Conflict,
    },
    /// One step's private history and the other's unrestricted channel cannot share a
    /// compartment.
    SeparatedByHistory {
        private_step: StepId,
        release_step: StepId,
        authority: Authority,
        secrecy: BTreeSet<LabelTag>,
    },
    Crossing {
        crossing: Crossing,
    },
    Released {
        release: ExternalRelease,
    },
    /// The compartment's history holds private data, so it holds no unrestricted channel.
    HistoryAccounted {
        compartment: u32,
        secrecy: BTreeSet<LabelTag>,
    },
    /// Lazy content requests from a private compartment reveal selection, timing and
    /// misses: a permitted metadata channel, not noninterference (line 2389).
    MetadataChannel {
        compartment: u32,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compartment {
                compartment,
                steps,
                authorities,
                history,
            } => write!(
                f,
                "compartment {compartment} runs {} with [{}]; it holds {history}",
                steps
                    .iter()
                    .map(StepId::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                authorities
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Placed { step, rule } => match rule {
                PlacementRule::JoinedProducer { compartment } => write!(
                    f,
                    "step {step} joins compartment {compartment}, which produced most of its input"
                ),
                PlacementRule::JoinedExisting { compartment } => {
                    write!(f, "step {step} joins compartment {compartment}")
                }
                PlacementRule::NewCompartment { refused } => {
                    write!(f, "step {step} gets a new compartment")?;
                    for (compartment, violations) in refused {
                        for violation in violations {
                            write!(f, "; not {compartment}: {violation}")?;
                        }
                    }
                    Ok(())
                }
            },
            Self::Separated {
                left,
                right,
                conflict,
            } => write!(f, "steps {left} and {right} are separated: {conflict}"),
            Self::SeparatedByHistory {
                private_step,
                release_step,
                authority,
                secrecy,
            } => write!(
                f,
                "step {release_step} needs {authority}, so it is kept away from step \
                 {private_step}, which holds private data ({})",
                tags(secrecy)
            ),
            Self::Crossing { crossing } => {
                let from = match crossing.from {
                    CrossingSource::Source => "its source".to_string(),
                    CrossingSource::Compartment { compartment } => {
                        format!("compartment {compartment}")
                    }
                };
                match &crossing.contract {
                    Some(contract) => write!(
                        f,
                        "{} crosses from {from} to compartment {} for step {} under contract \
                         {contract}; it stays {}",
                        crossing.item, crossing.to, crossing.consumer, crossing.label
                    ),
                    None => write!(
                        f,
                        "{} is imported from {from} into compartment {} for step {}; it is {}",
                        crossing.item, crossing.to, crossing.consumer, crossing.label
                    ),
                }
            }
            Self::Released { release } => write!(
                f,
                "{} is released to {} by step {} under contract {}, authorized by {}; it is {}, \
                 and the approval is not a proof of confidentiality",
                release.item,
                release.destination,
                release.step,
                release.contract,
                release.approval,
                release.label
            ),
            Self::HistoryAccounted {
                compartment,
                secrecy,
            } => write!(
                f,
                "compartment {compartment} has held private data ({}), so it gets no \
                 unrestricted release channel",
                tags(secrecy)
            ),
            Self::MetadataChannel { compartment } => write!(
                f,
                "compartment {compartment} holds private data and requests approved objects: \
                 lazy fetches reveal selection, timing and misses (a permitted metadata channel, \
                 not noninterference); strict private mode prefetches"
            ),
        }
    }
}

/// The reasons of a plan or refusal, in order (line 2332).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Explanation {
    reasons: Vec<Reason>,
}

impl Explanation {
    pub fn new(reasons: Vec<Reason>) -> Self {
        Self { reasons }
    }

    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }

    /// One readable line per reason.
    pub fn lines(&self) -> Vec<String> {
        self.reasons.iter().map(ToString::to_string).collect()
    }
}

/// How a plan was found. Neither method claims universal optimality (line 2318).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum PartitionMethod {
    RulesBased,
    /// Least cost over every partition and execution order of a small workflow.
    ExhaustiveOracle {
        evaluations: u64,
    },
}

/// A feasible partition and execution order with its cost and explanation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompiledPlan {
    workflow: Digest,
    method: PartitionMethod,
    compartments: Vec<Compartment>,
    assignment: Vec<u32>,
    order: Vec<StepId>,
    crossings: Vec<Crossing>,
    releases: Vec<ExternalRelease>,
    schedule: Vec<ScheduledStep>,
    labels: BTreeMap<DataId, Label>,
    cost: CostBreakdown,
    explanation: Explanation,
}

impl CompiledPlan {
    pub fn workflow(&self) -> Digest {
        self.workflow
    }

    pub fn method(&self) -> &PartitionMethod {
        &self.method
    }

    pub fn compartments(&self) -> &[Compartment] {
        &self.compartments
    }

    /// The compartment of each step, in declaration order.
    pub fn assignment(&self) -> &[u32] {
        &self.assignment
    }

    /// The execution order.
    pub fn order(&self) -> &[StepId] {
        &self.order
    }

    pub fn crossings(&self) -> &[Crossing] {
        &self.crossings
    }

    pub fn releases(&self) -> &[ExternalRelease] {
        &self.releases
    }

    pub fn schedule(&self) -> &[ScheduledStep] {
        &self.schedule
    }

    /// Every item's label in this plan.
    pub fn labels(&self) -> &BTreeMap<DataId, Label> {
        &self.labels
    }

    pub fn cost(&self) -> &CostBreakdown {
        &self.cost
    }

    pub fn explanation(&self) -> &Explanation {
        &self.explanation
    }

    /// The compartment running `step`.
    pub fn compartment_of(&self, step: &StepId) -> Option<&Compartment> {
        self.compartments
            .iter()
            .find(|compartment| compartment.steps.contains(step))
    }
}

/// One compartment while it is evaluated.
#[derive(Clone, Debug)]
pub(super) struct CompartmentState {
    pub(super) steps: Vec<usize>,
    pub(super) authorities: BTreeSet<Authority>,
    pub(super) history: Label,
    pub(super) volumes: BTreeSet<VolumeId>,
    pub(super) memory_mib: u64,
    pub(super) start_ms: u64,
    pub(super) end_ms: u64,
    free_ms: u64,
    max_idle_ms: u64,
    started: bool,
}

impl CompartmentState {
    fn new() -> Self {
        Self {
            steps: Vec::new(),
            authorities: BTreeSet::new(),
            history: Label::bottom(),
            volumes: BTreeSet::new(),
            memory_mib: 0,
            start_ms: 0,
            end_ms: 0,
            free_ms: 0,
            max_idle_ms: 0,
            started: false,
        }
    }
}

/// Everything known about one partition and order, feasible or not.
#[derive(Clone, Debug)]
pub(super) struct Analysis {
    pub(super) compartments: Vec<CompartmentState>,
    pub(super) labels: BTreeMap<DataId, Label>,
    pub(super) crossings: Vec<Crossing>,
    pub(super) releases: Vec<ExternalRelease>,
    pub(super) schedule: Vec<ScheduledStep>,
    /// The compartment's history when each step ran, by declaration index.
    pub(super) step_history: Vec<Label>,
    pub(super) cost: CostBreakdown,
    pub(super) violations: Vec<Violation>,
}

/// A count or index as `u32`, saturating at `u32::MAX`. Compartment counts are bounded by
/// [`super::MAX_STEPS`] and the VM budget, so saturation never names a real compartment.
pub(super) fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// A count as `u64`, saturating.
pub(super) fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A compartment number as a vector position; one that cannot be represented is out of
/// range for every lookup.
pub(super) fn slot(compartment: u32) -> usize {
    usize::try_from(compartment).unwrap_or(usize::MAX)
}

/// The number of compartments an assignment uses.
pub(super) fn compartment_count(assignment: &[u32]) -> usize {
    assignment
        .iter()
        .map(|compartment| slot(*compartment).saturating_add(1))
        .max()
        .unwrap_or(0)
}

/// The refusal of an assignment or order that does not cover the steps exactly once.
fn malformed(
    workflow: &Workflow,
    assignment: &[u32],
    order: Option<&[usize]>,
) -> Option<Violation> {
    let steps = workflow.steps().len();
    let order_ok = order.is_none_or(|order| {
        let distinct: BTreeSet<usize> = order.iter().copied().collect();
        order.len() == steps
            && distinct.len() == steps
            && distinct.iter().all(|index| *index < steps)
    });
    let assignment_ok = assignment.len() == steps && compartment_count(assignment) <= steps.max(1);
    (!order_ok || !assignment_ok).then(|| Violation::MalformedAssignment {
        steps: to_u32(steps),
        assigned: to_u32(assignment.len()),
        ordered: order.map_or(0, |order| to_u32(order.len())),
    })
}

/// Constraints that hold or fail whatever the order: conflicts, retained state and
/// contract coverage of every crossing (lines 2313–2315).
pub(super) fn partition_violations(
    workflow: &Workflow,
    policy: &PartitionPolicy,
    assignment: &[u32],
) -> Vec<Violation> {
    if let Some(violation) = malformed(workflow, assignment, None) {
        return vec![violation];
    }
    let steps = workflow.steps();
    let count = compartment_count(assignment);
    let mut authorities = vec![BTreeSet::new(); count];
    let mut volumes: Vec<BTreeSet<VolumeId>> = vec![BTreeSet::new(); count];
    let mut volume_owners: BTreeMap<VolumeId, BTreeSet<u32>> = BTreeMap::new();
    for (step, compartment) in steps.iter().zip(assignment) {
        if let Some(held) = authorities.get_mut(slot(*compartment)) {
            held.extend(step.operations.iter().cloned());
        }
        for volume in &step.volumes {
            if let Some(kept) = volumes.get_mut(slot(*compartment)) {
                kept.insert(volume.clone());
            }
            volume_owners
                .entry(volume.clone())
                .or_default()
                .insert(*compartment);
        }
    }
    let mut violations = Vec::new();
    for ((compartment, held), kept) in authorities.iter().enumerate().zip(&volumes) {
        for conflict in policy.conflicts.conflicts(held) {
            violations.push(Violation::ForbiddenCombination {
                compartment: to_u32(compartment),
                conflict,
            });
        }
        for authority in held.iter().filter(|authority| authority.is_effect()) {
            for volume in kept {
                violations.push(Violation::AuthorityPersisted {
                    compartment: to_u32(compartment),
                    volume: volume.clone(),
                    authority: authority.clone(),
                });
            }
        }
    }
    for (volume, owners) in volume_owners {
        if owners.len() > 1 {
            violations.push(Violation::RetainedStateSplit {
                volume,
                compartments: owners,
            });
        }
    }
    for (step, to) in steps.iter().zip(assignment) {
        for input in &step.inputs {
            let Some(producer) = workflow.item(input).and_then(|item| item.producer) else {
                continue;
            };
            let Some(from) = assignment.get(producer).copied() else {
                continue;
            };
            if from == *to {
                continue;
            }
            match workflow.contract_for(input, &step.id) {
                None => violations.push(Violation::CrossingWithoutContract {
                    item: input.clone(),
                    consumer: step.id.clone(),
                    from,
                    to: *to,
                }),
                Some(contract) => {
                    let bytes = workflow.item(input).map_or(0, |item| item.size_bytes);
                    if bytes > contract.max_bytes {
                        violations.push(Violation::ContractTooSmall {
                            contract: contract.id.clone(),
                            bytes,
                            max_bytes: contract.max_bytes,
                        });
                    }
                }
            }
        }
    }
    for contract in workflow.contracts().values().filter(|c| c.is_external()) {
        let bytes = workflow
            .item(&contract.item)
            .map_or(0, |item| item.size_bytes);
        if bytes > contract.max_bytes {
            violations.push(Violation::ContractTooSmall {
                contract: contract.id.clone(),
                bytes,
                max_bytes: contract.max_bytes,
            });
        }
    }
    violations
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return 0;
    }
    numerator.div_ceil(denominator)
}

/// Evaluates one partition and order: labels, crossings, releases, schedule, every
/// constraint and the objective. `assignment` maps each step (declaration index) to a
/// compartment numbered from zero; `order` is a topological order.
pub(super) fn analyze(
    workflow: &Workflow,
    policy: &PartitionPolicy,
    assignment: &[u32],
    order: &[usize],
) -> Analysis {
    let steps = workflow.steps();
    if let Some(violation) = malformed(workflow, assignment, Some(order)) {
        return Analysis {
            compartments: Vec::new(),
            labels: BTreeMap::new(),
            crossings: Vec::new(),
            releases: Vec::new(),
            schedule: Vec::new(),
            step_history: vec![Label::bottom(); steps.len()],
            cost: CostBreakdown::default(),
            violations: vec![violation],
        };
    }
    let mut violations = partition_violations(workflow, policy, assignment);
    let weights = &policy.weights;
    let budgets = &policy.budgets;
    let count = compartment_count(assignment);
    let mut compartments: Vec<CompartmentState> =
        (0..count).map(|_| CompartmentState::new()).collect();
    for &index in order {
        let (Some(step), Some(compartment)) = (steps.get(index), assignment.get(index)) else {
            continue;
        };
        let Some(state) = compartments.get_mut(slot(*compartment)) else {
            continue;
        };
        state.steps.push(index);
        state.authorities.extend(step.operations.iter().cloned());
        state.volumes.extend(step.volumes.iter().cloned());
        state.memory_mib = state.memory_mib.max(step.cost.memory_mib);
    }
    let mut labels: BTreeMap<DataId, Label> = workflow
        .sources()
        .iter()
        .map(|(id, source)| (id.clone(), source.label.clone()))
        .collect();
    let mut available_ms: BTreeMap<DataId, u64> = BTreeMap::new();
    let mut arrivals: BTreeMap<(DataId, u32), u64> = BTreeMap::new();
    let mut crossings = Vec::new();
    let mut releases = Vec::new();
    let mut schedule = Vec::new();
    let mut step_history = vec![Label::bottom(); steps.len()];
    let mut transferred_bytes = 0u128;
    let bandwidth = u128::from(weights.transfer_bytes_per_ms.max(1));
    let mut overflow = false;
    let to_ms = |value: u128, overflow: &mut bool| -> u64 {
        u64::try_from(value).unwrap_or_else(|_| {
            *overflow = true;
            u64::MAX
        })
    };
    for &index in order {
        let (Some(step), Some(&compartment)) = (steps.get(index), assignment.get(index)) else {
            continue;
        };
        let mut existing_ms = 0u64;
        let mut arrival_ms = 0u64;
        let mut entering = Label::bottom();
        for input in &step.inputs {
            let Some(item) = workflow.item(input) else {
                continue;
            };
            let label = labels.get(input).cloned().unwrap_or_else(Label::bottom);
            let produced_ms = available_ms.get(input).copied().unwrap_or(0);
            existing_ms = existing_ms.max(produced_ms);
            let producer = item
                .producer
                .and_then(|producer| assignment.get(producer).copied());
            let arrived = if producer == Some(compartment) {
                produced_ms
            } else {
                let key = (input.clone(), compartment);
                let first = !arrivals.contains_key(&key);
                let moved = if first { item.size_bytes } else { 0 };
                let arrived = match arrivals.get(&key) {
                    Some(arrived) => *arrived,
                    None => {
                        let transfer = to_ms(
                            ceil_div(u128::from(item.size_bytes), bandwidth),
                            &mut overflow,
                        );
                        let arrived = produced_ms.saturating_add(transfer);
                        arrivals.insert(key, arrived);
                        transferred_bytes =
                            transferred_bytes.saturating_add(u128::from(item.size_bytes));
                        arrived
                    }
                };
                crossings.push(Crossing {
                    item: input.clone(),
                    consumer: step.id.clone(),
                    from: match producer {
                        Some(from) => CrossingSource::Compartment { compartment: from },
                        None => CrossingSource::Source,
                    },
                    to: compartment,
                    contract: producer
                        .and_then(|_| workflow.contract_for(input, &step.id))
                        .map(|contract| contract.id.clone()),
                    moved_bytes: moved,
                    label: label.clone(),
                });
                arrived
            };
            arrival_ms = arrival_ms.max(arrived);
            entering.join_in(&label);
        }
        let Some(state) = compartments.get_mut(slot(compartment)) else {
            continue;
        };
        state.history.join_in(&entering);
        state.history.join_in(&step.intrinsic_label());
        if let Some(history) = step_history.get_mut(index) {
            *history = state.history.clone();
        }
        if !state.started {
            state.started = true;
            state.start_ms = existing_ms;
            state.free_ms = existing_ms.saturating_add(weights.vm_startup_ms);
        } else {
            let idle_ms = arrival_ms.saturating_sub(state.free_ms);
            state.max_idle_ms = state.max_idle_ms.max(idle_ms);
        }
        let start_ms = arrival_ms.max(state.free_ms);
        let end_ms = start_ms.saturating_add(step.cost.duration_ms);
        state.free_ms = end_ms;
        state.end_ms = end_ms;
        schedule.push(ScheduledStep {
            step: step.id.clone(),
            compartment,
            start_ms,
            end_ms,
        });
        let history = state.history.clone();
        for output in &step.outputs {
            let label = match &output.declared_label {
                Some(declared) => history.join(declared),
                None => history.clone(),
            };
            labels.insert(output.id.clone(), label);
            available_ms.insert(output.id.clone(), end_ms);
        }
        for operation in &step.operations {
            let Authority::ExactRelease { contract } = operation else {
                continue;
            };
            let Some(contract) = workflow.contracts().get(contract) else {
                continue;
            };
            releases.push(ExternalRelease {
                contract: contract.id.clone(),
                item: contract.item.clone(),
                step: step.id.clone(),
                destination: contract.destination.clone(),
                approval: contract.approval.clone(),
                bytes: workflow
                    .item(&contract.item)
                    .map_or(0, |item| item.size_bytes),
                label: labels
                    .get(&contract.item)
                    .cloned()
                    .unwrap_or_else(Label::bottom),
                confidentiality: contract.approval.confidentiality(),
            });
        }
    }
    for (index, state) in compartments.iter().enumerate() {
        if state.history.is_public() {
            continue;
        }
        for authority in state
            .authorities
            .iter()
            .filter(|authority| authority.is_unrestricted_release())
        {
            violations.push(Violation::HistoryForbidsRelease {
                compartment: to_u32(index),
                authority: authority.clone(),
                secrecy: state.history.secrecy().clone(),
            });
        }
    }
    let vm_count = to_u32(count);
    if vm_count > budgets.max_vms {
        violations.push(Violation::TooManyVms {
            vms: vm_count,
            max: budgets.max_vms,
        });
    }
    for (index, state) in compartments.iter().enumerate() {
        let alive_ms = state.end_ms.saturating_sub(state.start_ms);
        if alive_ms > budgets.max_vm_lifetime_ms {
            violations.push(Violation::LifetimeExceeded {
                compartment: to_u32(index),
                alive_ms,
                max_ms: budgets.max_vm_lifetime_ms,
            });
        }
        if state.max_idle_ms > budgets.max_vm_idle_ms {
            violations.push(Violation::IdleExceeded {
                compartment: to_u32(index),
                idle_ms: state.max_idle_ms,
                max_ms: budgets.max_vm_idle_ms,
            });
        }
    }
    let mut starts: Vec<u64> = compartments.iter().map(|state| state.start_ms).collect();
    starts.sort_unstable();
    starts.dedup();
    let mut concurrency_reported = false;
    let mut memory_reported = false;
    for at_ms in starts {
        let active: Vec<&CompartmentState> = compartments
            .iter()
            .filter(|state| {
                state.start_ms == at_ms || (state.start_ms < at_ms && at_ms < state.end_ms)
            })
            .collect();
        let vms = to_u32(active.len());
        if vms > budgets.max_concurrent_vms && !concurrency_reported {
            concurrency_reported = true;
            violations.push(Violation::TooManyConcurrentVms {
                at_ms,
                vms,
                max: budgets.max_concurrent_vms,
            });
        }
        let needed_mib = active.iter().fold(0u64, |sum, state| {
            sum.saturating_add(state.memory_mib.saturating_add(budgets.vm_overhead_mib))
        });
        if needed_mib > budgets.host_memory_mib && !memory_reported {
            memory_reported = true;
            violations.push(Violation::MemoryExceeded {
                at_ms,
                needed_mib,
                host_mib: budgets.host_memory_mib,
            });
        }
    }
    let released = releases.iter().fold(0u128, |sum, release| {
        sum.saturating_add(u128::from(release.bytes))
    });
    let released_bytes = to_ms(released, &mut overflow);
    if released_bytes > budgets.release_budget_bytes {
        violations.push(Violation::ReleaseBudgetExceeded {
            bytes: released_bytes,
            limit_bytes: budgets.release_budget_bytes,
        });
    }
    let makespan_ms = schedule.iter().map(|step| step.end_ms).max().unwrap_or(0);
    let vm_alive = compartments.iter().fold(0u128, |sum, state| {
        sum.saturating_add(u128::from(state.end_ms.saturating_sub(state.start_ms)))
    });
    let approved_compartments = compartments
        .iter()
        .filter(|state| {
            state
                .authorities
                .iter()
                .any(|authority| policy.operator_approved.contains(&authority.kind()))
        })
        .count();
    let mut used_contracts: BTreeSet<&ContractId> = crossings
        .iter()
        .filter_map(|crossing| crossing.contract.as_ref())
        .collect();
    used_contracts.extend(releases.iter().map(|release| &release.contract));
    let operator_contracts = used_contracts
        .iter()
        .filter(|id| {
            workflow
                .contracts()
                .get(**id)
                .is_some_and(|contract| contract.approval.is_operator())
        })
        .count();
    let approvals = to_u32(approved_compartments.saturating_add(operator_contracts));
    let startup = u128::from(vm_count).saturating_mul(u128::from(weights.startup_units_per_vm));
    let retention = ceil_div(
        vm_alive.saturating_mul(u128::from(weights.retention_units_per_vm_second)),
        1000,
    );
    let transfer = ceil_div(
        transferred_bytes.saturating_mul(u128::from(weights.transfer_units_per_mib)),
        MIB,
    );
    let delay = ceil_div(
        u128::from(makespan_ms).saturating_mul(u128::from(weights.delay_units_per_second)),
        1000,
    );
    let approval = u128::from(approvals).saturating_mul(u128::from(weights.approval_units));
    let total = startup
        .saturating_add(retention)
        .saturating_add(transfer)
        .saturating_add(delay)
        .saturating_add(approval);
    let cost = CostBreakdown {
        total_units: to_ms(total, &mut overflow),
        vm_count,
        approvals,
        transferred_bytes: to_ms(transferred_bytes, &mut overflow),
        makespan_ms,
        vm_alive_ms: to_ms(vm_alive, &mut overflow),
        startup_units: to_ms(startup, &mut overflow),
        retention_units: to_ms(retention, &mut overflow),
        transfer_units: to_ms(transfer, &mut overflow),
        delay_units: to_ms(delay, &mut overflow),
        approval_units: to_ms(approval, &mut overflow),
    };
    if overflow {
        violations.push(Violation::CostOverflow);
    }
    violations.sort();
    violations.dedup();
    Analysis {
        compartments,
        labels,
        crossings,
        releases,
        schedule,
        step_history,
        cost,
        violations,
    }
}

/// The trust scope of compartment `index` of the workflow with `digest`.
pub(super) fn compartment_scope(workflow: Digest, index: u32) -> TrustScope {
    TrustScope::new(
        ExecutionCategory::VmSandbox,
        DigestBuilder::new(COMPARTMENT_DOMAIN)
            .digest(&workflow)
            .u64(u64::from(index))
            .finish(),
    )
}

/// The ids of the steps at `indices`.
fn step_ids(steps: &[Step], indices: &[usize]) -> Vec<StepId> {
    indices
        .iter()
        .filter_map(|index| steps.get(*index))
        .map(|step| step.id.clone())
        .collect()
}

/// Builds the plan of a feasible analysis with its explanation.
pub(super) fn build_plan(
    workflow: &Workflow,
    policy: &PartitionPolicy,
    assignment: &[u32],
    order: &[usize],
    analysis: Analysis,
    method: PartitionMethod,
    placements: Vec<Reason>,
) -> CompiledPlan {
    let steps = workflow.steps();
    let compartments: Vec<Compartment> = analysis
        .compartments
        .iter()
        .enumerate()
        .map(|(index, state)| Compartment {
            index: to_u32(index),
            trust_scope: compartment_scope(workflow.digest(), to_u32(index)),
            steps: step_ids(steps, &state.steps),
            authorities: state.authorities.clone(),
            history: state.history.clone(),
            volumes: state.volumes.clone(),
            start_ms: state.start_ms,
            end_ms: state.end_ms,
            memory_mib: state.memory_mib,
        })
        .collect();
    let mut reasons: Vec<Reason> = compartments
        .iter()
        .map(|compartment| Reason::Compartment {
            compartment: compartment.index,
            steps: compartment.steps.clone(),
            authorities: compartment.authorities.clone(),
            history: compartment.history.clone(),
        })
        .collect();
    reasons.extend(placements);
    let placed: Vec<(&Step, u32, &Label)> = steps
        .iter()
        .zip(assignment)
        .zip(&analysis.step_history)
        .map(|((step, compartment), history)| (step, *compartment, history))
        .collect();
    for (position, left) in placed.iter().enumerate() {
        for right in placed.iter().skip(position.saturating_add(1)) {
            if left.1 == right.1 {
                continue;
            }
            if let Some(reason) = separation(policy, (left.0, left.2), (right.0, right.2)) {
                reasons.push(reason);
            }
        }
    }
    reasons.extend(analysis.crossings.iter().map(|crossing| Reason::Crossing {
        crossing: crossing.clone(),
    }));
    reasons.extend(analysis.releases.iter().map(|release| Reason::Released {
        release: release.clone(),
    }));
    for compartment in &compartments {
        if compartment.history.is_public() {
            continue;
        }
        reasons.push(Reason::HistoryAccounted {
            compartment: compartment.index,
            secrecy: compartment.history.secrecy().clone(),
        });
        if compartment
            .authorities
            .contains(&Authority::ApprovedContent)
        {
            reasons.push(Reason::MetadataChannel {
                compartment: compartment.index,
            });
        }
    }
    CompiledPlan {
        workflow: workflow.digest(),
        method,
        compartments,
        assignment: assignment.to_vec(),
        order: step_ids(steps, order),
        crossings: analysis.crossings,
        releases: analysis.releases,
        schedule: analysis.schedule,
        labels: analysis.labels,
        cost: analysis.cost,
        explanation: Explanation::new(reasons),
    }
}

/// Why two steps in different compartments could not share one, if a constraint says so.
/// Each side is a step and the history its compartment had when it ran.
fn separation(
    policy: &PartitionPolicy,
    left: (&Step, &Label),
    right: (&Step, &Label),
) -> Option<Reason> {
    let mut together = left.0.operations.clone();
    together.extend(right.0.operations.iter().cloned());
    if let Some(conflict) = policy.conflicts.conflicts(&together).into_iter().next() {
        return Some(Reason::Separated {
            left: left.0.id.clone(),
            right: right.0.id.clone(),
            conflict,
        });
    }
    for (private, release) in [(left, right), (right, left)] {
        let history = private.1;
        if history.is_public() {
            continue;
        }
        if let Some(authority) = release.0.unrestricted_channels().next() {
            return Some(Reason::SeparatedByHistory {
                private_step: private.0.id.clone(),
                release_step: release.0.id.clone(),
                authority: authority.clone(),
                secrecy: history.secrecy().clone(),
            });
        }
    }
    None
}
