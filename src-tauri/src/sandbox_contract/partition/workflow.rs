//! The workflow DAG (VM part §9.1, line 2303): steps with labelled inputs, required
//! operations, labelled outputs and an execution cost, plus the workflow's explicit
//! release contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::authority::Authority;
use super::contract::ReleaseContract;
use super::label::{Label, LabelOrigin};
use super::names::{ContractId, DataId, LabelTag, StepId, VolumeId};
use crate::foundation::ids::{Digest, DigestBuilder};

/// Domain of [`Workflow::digest`].
pub const WORKFLOW_DOMAIN: &str = "yougori/sandbox/partition/workflow/v1";
/// Most steps one workflow may have.
pub const MAX_STEPS: usize = 64;
/// Most inputs, outputs, operations or volumes one step may name.
pub const MAX_STEP_ITEMS: usize = 64;

/// Data entering the workflow from outside, labelled by trusted policy or explicit
/// provenance (line 2320).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceData {
    pub id: DataId,
    pub label: Label,
    pub origin: LabelOrigin,
    pub size_bytes: u64,
}

/// One output of a step. Its label is derived from what its compartment holds when it
/// is produced; a declared label can only add to that (line 2320).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepOutput {
    pub id: DataId,
    pub size_bytes: u64,
    /// An immutable artifact, such as a proposed patch (line 2326). Only immutable items
    /// may leave the host under a contract.
    pub immutable: bool,
    #[serde(default)]
    pub declared_label: Option<Label>,
}

/// A step's modelled execution cost (line 2303).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepCost {
    pub duration_ms: u64,
    pub memory_mib: u64,
}

/// One workflow step (line 2303).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: StepId,
    pub inputs: Vec<DataId>,
    pub operations: BTreeSet<Authority>,
    pub outputs: Vec<StepOutput>,
    pub cost: StepCost,
    /// Retained volumes the step reads and writes; they persist across generations of its
    /// compartment (line 2315).
    #[serde(default)]
    pub volumes: BTreeSet<VolumeId>,
}

impl Step {
    /// What running the step adds to its compartment's history: every private source it
    /// may read, and untrusted integrity where untrusted code runs or fetched content
    /// arrives.
    pub fn intrinsic_label(&self) -> Label {
        let mut label = Label::bottom();
        for operation in &self.operations {
            if let Authority::ReadPrivate { source } = operation {
                label = label.with_secrecy(source.clone());
            }
            if operation.introduces_untrusted_state() {
                label = label.untrusted();
            }
        }
        label
    }

    /// The step's unrestricted release channels (§12.3 model 6).
    pub fn unrestricted_channels(&self) -> impl Iterator<Item = &Authority> {
        self.operations
            .iter()
            .filter(|operation| operation.is_unrestricted_release())
    }

    /// Whether the step holds an effect authority (line 2315).
    pub fn holds_effect(&self) -> bool {
        self.operations.iter().any(Authority::is_effect)
    }
}

/// A workflow as declared: sources, steps in declaration order and contracts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    pub sources: Vec<SourceData>,
    pub steps: Vec<Step>,
    pub contracts: Vec<ReleaseContract>,
}

/// Why a workflow was refused before any partitioning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum WorkflowError {
    NoSteps,
    TooManySteps {
        steps: usize,
        max: usize,
    },
    TooManyItems {
        step: StepId,
        items: usize,
        max: usize,
    },
    DuplicateStep {
        step: StepId,
    },
    DuplicateData {
        item: DataId,
    },
    DuplicateContract {
        contract: ContractId,
    },
    UnknownInput {
        step: StepId,
        item: DataId,
    },
    DuplicateInput {
        step: StepId,
        item: DataId,
    },
    Cycle {
        steps: Vec<StepId>,
    },
    /// Labels come from trusted policy and explicit provenance, never a model's
    /// assertion (line 2320).
    ModelAssertedLabel {
        item: DataId,
        model: LabelTag,
    },
    /// Private sources enter only through a read grant for their source.
    PrivateSourceWithoutReadAuthority {
        step: StepId,
        item: DataId,
        source: LabelTag,
    },
    /// A declared label may add to the derived label, never remove from it.
    DeclaredLabelBelowDerived {
        item: DataId,
        derived: Label,
        declared: Label,
    },
    UnknownContract {
        step: StepId,
        contract: ContractId,
    },
    ContractForUnknownItem {
        contract: ContractId,
        item: DataId,
    },
    /// Sources enter by read authority; contracts cover crossings between compartments
    /// and releases.
    ContractForSource {
        contract: ContractId,
        item: DataId,
    },
    ContractDestinationUnknown {
        contract: ContractId,
        step: StepId,
    },
    ContractDestinationDoesNotConsume {
        contract: ContractId,
        step: StepId,
        item: DataId,
    },
    ConflictingContracts {
        item: DataId,
        step: StepId,
    },
    /// Only immutable artifacts leave the host (line 2326).
    ReleaseOfMutableItem {
        contract: ContractId,
        item: DataId,
    },
    ExternalContractUnused {
        contract: ContractId,
    },
    ExternalContractUsedTwice {
        contract: ContractId,
    },
    ExactReleaseOnInternalContract {
        step: StepId,
        contract: ContractId,
    },
    ExactReleaseWithoutItem {
        step: StepId,
        contract: ContractId,
        item: DataId,
    },
    Encoding,
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSteps => f.write_str("the workflow has no steps"),
            Self::TooManySteps { steps, max } => {
                write!(f, "{steps} steps; a workflow may have at most {max}")
            }
            Self::TooManyItems { step, items, max } => {
                write!(f, "step {step} names {items} items; the limit is {max}")
            }
            Self::DuplicateStep { step } => write!(f, "step {step} is declared twice"),
            Self::DuplicateData { item } => write!(f, "data item {item} is declared twice"),
            Self::DuplicateContract { contract } => {
                write!(f, "contract {contract} is declared twice")
            }
            Self::UnknownInput { step, item } => {
                write!(f, "step {step} reads {item}, which nothing provides")
            }
            Self::DuplicateInput { step, item } => write!(f, "step {step} reads {item} twice"),
            Self::Cycle { steps } => write!(
                f,
                "the steps {} form a cycle; a workflow is a DAG",
                join(steps)
            ),
            Self::ModelAssertedLabel { item, model } => write!(
                f,
                "the label of {item} is an assertion by model {model}; labels come from trusted \
                 policy and explicit provenance"
            ),
            Self::PrivateSourceWithoutReadAuthority { step, item, source } => write!(
                f,
                "step {step} reads private source {item} without the read authority for {source}"
            ),
            Self::DeclaredLabelBelowDerived {
                item,
                derived,
                declared,
            } => write!(
                f,
                "{item} is declared {declared} but derives from {derived}; a declared label \
                 cannot remove a tag, only a release contract moves private data"
            ),
            Self::UnknownContract { step, contract } => {
                write!(f, "step {step} names unknown contract {contract}")
            }
            Self::ContractForUnknownItem { contract, item } => {
                write!(f, "contract {contract} covers unknown item {item}")
            }
            Self::ContractForSource { contract, item } => write!(
                f,
                "contract {contract} covers source {item}; sources enter by read authority"
            ),
            Self::ContractDestinationUnknown { contract, step } => {
                write!(f, "contract {contract} delivers to unknown step {step}")
            }
            Self::ContractDestinationDoesNotConsume {
                contract,
                step,
                item,
            } => write!(
                f,
                "contract {contract} delivers {item} to step {step}, which does not read it"
            ),
            Self::ConflictingContracts { item, step } => {
                write!(f, "more than one contract delivers {item} to step {step}")
            }
            Self::ReleaseOfMutableItem { contract, item } => write!(
                f,
                "contract {contract} releases {item}, which is not an immutable artifact"
            ),
            Self::ExternalContractUnused { contract } => write!(
                f,
                "release contract {contract} is not applied by any step's exact release"
            ),
            Self::ExternalContractUsedTwice { contract } => write!(
                f,
                "release contract {contract} is applied by more than one step"
            ),
            Self::ExactReleaseOnInternalContract { step, contract } => write!(
                f,
                "step {step} applies contract {contract}, which delivers to another step, not \
                 an external target"
            ),
            Self::ExactReleaseWithoutItem {
                step,
                contract,
                item,
            } => write!(
                f,
                "step {step} applies contract {contract} without reading its item {item}"
            ),
            Self::Encoding => f.write_str("the workflow could not be encoded"),
        }
    }
}

impl std::error::Error for WorkflowError {}

fn join<T: fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One item as the partitioner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Item {
    /// The producing step; `None` for a source.
    pub(super) producer: Option<usize>,
    pub(super) size_bytes: u64,
    pub(super) immutable: bool,
}

/// A validated workflow (line 2303).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workflow {
    spec: WorkflowSpec,
    step_index: BTreeMap<StepId, usize>,
    items: BTreeMap<DataId, Item>,
    sources: BTreeMap<DataId, SourceData>,
    contracts: BTreeMap<ContractId, ReleaseContract>,
    predecessors: Vec<BTreeSet<usize>>,
    static_labels: BTreeMap<DataId, Label>,
    order: Vec<usize>,
    digest: Digest,
}

impl Workflow {
    /// Validates `spec`: a DAG within bounds, accepted label origins, private sources
    /// read only under their read authority, declared labels never below derived ones,
    /// and contracts that each name one item and one destination.
    pub fn new(spec: WorkflowSpec) -> Result<Self, WorkflowError> {
        if spec.steps.is_empty() {
            return Err(WorkflowError::NoSteps);
        }
        if spec.steps.len() > MAX_STEPS {
            return Err(WorkflowError::TooManySteps {
                steps: spec.steps.len(),
                max: MAX_STEPS,
            });
        }
        let mut sources = BTreeMap::new();
        let mut items = BTreeMap::new();
        for source in &spec.sources {
            if let LabelOrigin::ModelAssertion { model } = &source.origin {
                return Err(WorkflowError::ModelAssertedLabel {
                    item: source.id.clone(),
                    model: model.clone(),
                });
            }
            let item = Item {
                producer: None,
                size_bytes: source.size_bytes,
                immutable: true,
            };
            if items.insert(source.id.clone(), item).is_some() {
                return Err(WorkflowError::DuplicateData {
                    item: source.id.clone(),
                });
            }
            sources.insert(source.id.clone(), source.clone());
        }
        let mut step_index = BTreeMap::new();
        for (index, step) in spec.steps.iter().enumerate() {
            let largest = step
                .inputs
                .len()
                .max(step.outputs.len())
                .max(step.operations.len())
                .max(step.volumes.len());
            if largest > MAX_STEP_ITEMS {
                return Err(WorkflowError::TooManyItems {
                    step: step.id.clone(),
                    items: largest,
                    max: MAX_STEP_ITEMS,
                });
            }
            if step_index.insert(step.id.clone(), index).is_some() {
                return Err(WorkflowError::DuplicateStep {
                    step: step.id.clone(),
                });
            }
            for output in &step.outputs {
                let item = Item {
                    producer: Some(index),
                    size_bytes: output.size_bytes,
                    immutable: output.immutable,
                };
                if items.insert(output.id.clone(), item).is_some() {
                    return Err(WorkflowError::DuplicateData {
                        item: output.id.clone(),
                    });
                }
            }
        }
        let mut predecessors = vec![BTreeSet::new(); spec.steps.len()];
        for (index, step) in spec.steps.iter().enumerate() {
            let mut seen = BTreeSet::new();
            for input in &step.inputs {
                if !seen.insert(input) {
                    return Err(WorkflowError::DuplicateInput {
                        step: step.id.clone(),
                        item: input.clone(),
                    });
                }
                let item = items
                    .get(input)
                    .ok_or_else(|| WorkflowError::UnknownInput {
                        step: step.id.clone(),
                        item: input.clone(),
                    })?;
                match item.producer {
                    Some(producer) => {
                        if let Some(before) = predecessors.get_mut(index) {
                            before.insert(producer);
                        }
                    }
                    None => {
                        if let Some(source) = sources.get(input) {
                            for tag in source.label.secrecy() {
                                let read = Authority::ReadPrivate {
                                    source: tag.clone(),
                                };
                                if !step.operations.contains(&read) {
                                    return Err(WorkflowError::PrivateSourceWithoutReadAuthority {
                                        step: step.id.clone(),
                                        item: input.clone(),
                                        source: tag.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        let order = kahn(&predecessors).ok_or_else(|| WorkflowError::Cycle {
            steps: cyclic_steps(&spec.steps, &predecessors),
        })?;
        let contracts = check_contracts(&spec, &step_index, &items)?;
        let static_labels = static_labels(&spec, &sources, &order)?;
        let encoded = serde_json::to_vec(&spec).map_err(|_| WorkflowError::Encoding)?;
        let digest = DigestBuilder::new(WORKFLOW_DOMAIN).bytes(&encoded).finish();
        Ok(Self {
            spec,
            step_index,
            items,
            sources,
            contracts,
            predecessors,
            static_labels,
            order,
            digest,
        })
    }

    /// The steps in declaration order.
    pub fn steps(&self) -> &[Step] {
        &self.spec.steps
    }

    /// The step named `id`.
    pub fn step(&self, id: &StepId) -> Option<&Step> {
        self.step_index
            .get(id)
            .and_then(|index| self.spec.steps.get(*index))
    }

    /// The workflow's sources.
    pub fn sources(&self) -> &BTreeMap<DataId, SourceData> {
        &self.sources
    }

    /// The workflow's contracts.
    pub fn contracts(&self) -> &BTreeMap<ContractId, ReleaseContract> {
        &self.contracts
    }

    /// The specification as declared.
    pub fn spec(&self) -> &WorkflowSpec {
        &self.spec
    }

    /// The digest of the declared specification under [`WORKFLOW_DOMAIN`].
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The label `item` has in every partition at least: derived from its inputs and
    /// the steps that produced it, with no compartment sharing.
    pub fn static_label(&self, item: &DataId) -> Option<&Label> {
        self.static_labels.get(item)
    }

    pub(super) fn index_of(&self, id: &StepId) -> Option<usize> {
        self.step_index.get(id).copied()
    }

    pub(super) fn item(&self, id: &DataId) -> Option<&Item> {
        self.items.get(id)
    }

    pub(super) fn source_label(&self, id: &DataId) -> Option<&Label> {
        self.sources.get(id).map(|source| &source.label)
    }

    /// One topological order: ready steps in declaration order.
    pub(super) fn default_order(&self) -> &[usize] {
        &self.order
    }

    /// The internal contract delivering `item` to `consumer`, if declared.
    pub(super) fn contract_for(
        &self,
        item: &DataId,
        consumer: &StepId,
    ) -> Option<&ReleaseContract> {
        self.contracts.values().find(|contract| {
            contract.item == *item && contract.destination_step() == Some(consumer)
        })
    }

    /// Every topological order, up to `limit` of them; `None` when there are more.
    pub(super) fn topological_orders(&self, limit: usize) -> Option<Vec<Vec<usize>>> {
        let count = self.spec.steps.len();
        let mut orders = Vec::new();
        let mut current = Vec::with_capacity(count);
        let mut placed = vec![false; count];
        let complete = extend_orders(
            &self.predecessors,
            &mut placed,
            &mut current,
            &mut orders,
            limit,
        );
        complete.then_some(orders)
    }
}

fn is_placed(placed: &[bool], index: usize) -> bool {
    placed.get(index).copied().unwrap_or(false)
}

fn set_placed(placed: &mut [bool], index: usize, value: bool) {
    if let Some(slot) = placed.get_mut(index) {
        *slot = value;
    }
}

/// Whether step `index` is unplaced and every step before it is placed.
fn is_ready(predecessors: &[BTreeSet<usize>], placed: &[bool], index: usize) -> bool {
    !is_placed(placed, index)
        && predecessors
            .get(index)
            .is_some_and(|before| before.iter().all(|step| is_placed(placed, *step)))
}

/// Kahn's algorithm, taking the earliest declared ready step each time; `None` on a cycle.
fn kahn(predecessors: &[BTreeSet<usize>]) -> Option<Vec<usize>> {
    let count = predecessors.len();
    let mut placed = vec![false; count];
    let mut order = Vec::with_capacity(count);
    while order.len() < count {
        let next = (0..count).find(|index| is_ready(predecessors, &placed, *index))?;
        set_placed(&mut placed, next, true);
        order.push(next);
    }
    Some(order)
}

fn cyclic_steps(steps: &[Step], predecessors: &[BTreeSet<usize>]) -> Vec<StepId> {
    let count = predecessors.len();
    let mut placed = vec![false; count];
    while let Some(index) = (0..count).find(|index| is_ready(predecessors, &placed, *index)) {
        set_placed(&mut placed, index, true);
    }
    steps
        .iter()
        .enumerate()
        .filter(|(index, _)| !is_placed(&placed, *index))
        .map(|(_, step)| step.id.clone())
        .collect()
}

/// Depth-first enumeration of linear extensions; returns false once `limit` is passed.
fn extend_orders(
    predecessors: &[BTreeSet<usize>],
    placed: &mut [bool],
    current: &mut Vec<usize>,
    orders: &mut Vec<Vec<usize>>,
    limit: usize,
) -> bool {
    if current.len() == placed.len() {
        if orders.len() >= limit {
            return false;
        }
        orders.push(current.clone());
        return true;
    }
    for index in 0..placed.len() {
        if !is_ready(predecessors, placed, index) {
            continue;
        }
        set_placed(placed, index, true);
        current.push(index);
        let complete = extend_orders(predecessors, placed, current, orders, limit);
        current.pop();
        set_placed(placed, index, false);
        if !complete {
            return false;
        }
    }
    true
}

fn check_contracts(
    spec: &WorkflowSpec,
    step_index: &BTreeMap<StepId, usize>,
    items: &BTreeMap<DataId, Item>,
) -> Result<BTreeMap<ContractId, ReleaseContract>, WorkflowError> {
    let mut contracts = BTreeMap::new();
    let mut routes = BTreeSet::new();
    for contract in &spec.contracts {
        let item =
            items
                .get(&contract.item)
                .ok_or_else(|| WorkflowError::ContractForUnknownItem {
                    contract: contract.id.clone(),
                    item: contract.item.clone(),
                })?;
        if item.producer.is_none() {
            return Err(WorkflowError::ContractForSource {
                contract: contract.id.clone(),
                item: contract.item.clone(),
            });
        }
        match contract.destination_step() {
            Some(step) => {
                let index = step_index.get(step).copied().ok_or_else(|| {
                    WorkflowError::ContractDestinationUnknown {
                        contract: contract.id.clone(),
                        step: step.clone(),
                    }
                })?;
                if !spec
                    .steps
                    .get(index)
                    .is_some_and(|consumer| consumer.inputs.contains(&contract.item))
                {
                    return Err(WorkflowError::ContractDestinationDoesNotConsume {
                        contract: contract.id.clone(),
                        step: step.clone(),
                        item: contract.item.clone(),
                    });
                }
                if !routes.insert((contract.item.clone(), step.clone())) {
                    return Err(WorkflowError::ConflictingContracts {
                        item: contract.item.clone(),
                        step: step.clone(),
                    });
                }
            }
            None => {
                if !item.immutable {
                    return Err(WorkflowError::ReleaseOfMutableItem {
                        contract: contract.id.clone(),
                        item: contract.item.clone(),
                    });
                }
            }
        }
        if contracts
            .insert(contract.id.clone(), contract.clone())
            .is_some()
        {
            return Err(WorkflowError::DuplicateContract {
                contract: contract.id.clone(),
            });
        }
    }
    let mut applied: BTreeMap<ContractId, usize> = BTreeMap::new();
    for step in &spec.steps {
        for operation in &step.operations {
            let Authority::ExactRelease { contract: id } = operation else {
                continue;
            };
            let contract = contracts
                .get(id)
                .ok_or_else(|| WorkflowError::UnknownContract {
                    step: step.id.clone(),
                    contract: id.clone(),
                })?;
            if !contract.is_external() {
                return Err(WorkflowError::ExactReleaseOnInternalContract {
                    step: step.id.clone(),
                    contract: id.clone(),
                });
            }
            if !step.inputs.contains(&contract.item) {
                return Err(WorkflowError::ExactReleaseWithoutItem {
                    step: step.id.clone(),
                    contract: id.clone(),
                    item: contract.item.clone(),
                });
            }
            let count = applied.entry(id.clone()).or_insert(0usize);
            *count = count.saturating_add(1);
        }
    }
    for contract in contracts.values().filter(|contract| contract.is_external()) {
        match applied.get(&contract.id).copied().unwrap_or(0) {
            0 => {
                return Err(WorkflowError::ExternalContractUnused {
                    contract: contract.id.clone(),
                })
            }
            1 => {}
            _ => {
                return Err(WorkflowError::ExternalContractUsedTwice {
                    contract: contract.id.clone(),
                })
            }
        }
    }
    Ok(contracts)
}

fn static_labels(
    spec: &WorkflowSpec,
    sources: &BTreeMap<DataId, SourceData>,
    order: &[usize],
) -> Result<BTreeMap<DataId, Label>, WorkflowError> {
    let mut labels: BTreeMap<DataId, Label> = sources
        .iter()
        .map(|(id, source)| (id.clone(), source.label.clone()))
        .collect();
    for step in order.iter().filter_map(|index| spec.steps.get(*index)) {
        let mut derived = step.intrinsic_label();
        for input in &step.inputs {
            if let Some(label) = labels.get(input) {
                derived.join_in(label);
            }
        }
        for output in &step.outputs {
            let label = match &output.declared_label {
                Some(declared) if !derived.flows_to(declared) => {
                    return Err(WorkflowError::DeclaredLabelBelowDerived {
                        item: output.id.clone(),
                        derived,
                        declared: declared.clone(),
                    })
                }
                Some(declared) => derived.join(declared),
                None => derived.clone(),
            };
            labels.insert(output.id.clone(), label);
        }
    }
    Ok(labels)
}
