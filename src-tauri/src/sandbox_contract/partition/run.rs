//! Labels and history while a compiled workflow runs (VM part §9.1, line 2320): revocation
//! never erases history, later network authority is checked against it, dynamic steps
//! pass the same checks, loops and callbacks never gain rights, retained state keeps its
//! label across generations without carrying authority (line 2315), and an exact release
//! applies only the approved content once (line 2327).
//!
//! The run starts from the state after the compiled steps ran: each compartment's history
//! is its plan history, and every retained volume carries that label.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::authority::{Authority, Conflict};
use super::contract::{Approval, ConfidentialityStatus, ContractDestination, ReleaseContract};
use super::label::Label;
use super::names::{ContractId, DataId, StepId, VolumeId};
use super::plan::{
    compartment_scope, slot, to_u32, CompiledPlan, Crossing, CrossingSource, Explanation,
    PartitionPolicy, PlacementRule, Reason, Violation,
};
use super::workflow::{Step, Workflow, MAX_STEP_ITEMS};
use crate::foundation::ids::{ContentKey, Digest, TrustScope};
use crate::foundation::transfer::{GeneralReleaseBudget, ReleaseBudgetExceeded};

strict_tagged_enum! {
/// Why a step joins a running workflow (line 2320).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DynamicOrigin (tag = "origin", wire = DynamicOriginWire, wire_name = "DynamicOriginWire") {
    /// A new step: it passes every check the compiler applies.
    Added,
    /// Another iteration of a step: at most that step's rights, in its compartment.
    LoopIteration { of: StepId },
    /// A callback of a step: at most that step's rights, in its compartment.
    Callback { of: StepId },
}
}

/// A step added while the workflow runs, with any contracts it brings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicStep {
    pub step: Step,
    pub origin: DynamicOrigin,
    pub contracts: Vec<ReleaseContract>,
}

/// Where a dynamic step was placed, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DynamicPlacement {
    pub step: StepId,
    pub compartment: u32,
    pub new_compartment: bool,
    pub explanation: Explanation,
}

/// What happens to retained volumes when a compartment restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedState {
    /// Volumes survive, with their labels, into the next generation.
    Keep,
    /// Volumes are destroyed with the old generation.
    Discard,
}

/// One exact release that was applied (line 2327).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReleaseRecord {
    pub contract: ContractId,
    pub item: DataId,
    pub destination: ContractDestination,
    pub approval: Approval,
    pub content: ContentKey,
    pub bytes: u64,
    /// The item's label is unchanged by the release (line 2320, line 2330).
    pub label: Label,
    pub confidentiality: ConfidentialityStatus,
}

/// Why a run-time change was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunRefusal {
    UnknownCompartment {
        compartment: u32,
    },
    NotHeld {
        compartment: u32,
        authority: Authority,
    },
    /// Revocation is monotonic (§12.3 model 3).
    Revoked {
        compartment: u32,
        authority: Authority,
    },
    NotGrantable {
        authority: Authority,
    },
    Conflict {
        compartment: u32,
        conflict: Conflict,
    },
    /// The history still holds private data; a revoked read does not erase it
    /// (line 2320).
    HistoryForbidsRelease {
        compartment: u32,
        authority: Authority,
        secrecy: BTreeSet<super::names::LabelTag>,
    },
    /// Retained state never sits beside an effect authority (line 2315).
    AuthorityPersisted {
        compartment: u32,
        volume: VolumeId,
        authority: Authority,
    },
    DuplicateStep {
        step: StepId,
    },
    DuplicateData {
        item: DataId,
    },
    UnknownInput {
        step: StepId,
        item: DataId,
    },
    TooManyItems {
        step: StepId,
    },
    PrivateSourceWithoutReadAuthority {
        step: StepId,
        item: DataId,
    },
    DeclaredLabelBelowDerived {
        item: DataId,
    },
    /// The step itself needs a forbidden combination (line 2338).
    IntrinsicConflict {
        step: StepId,
        conflicts: Vec<Conflict>,
    },
    UnknownParent {
        step: StepId,
        parent: StepId,
    },
    /// A loop or callback cannot gain rights its parent lacks (line 2320).
    CallbackWidensRights {
        step: StepId,
        parent: StepId,
        beyond: Vec<Authority>,
    },
    CallbackAddsContracts {
        step: StepId,
        parent: StepId,
    },
    CallbackNeedsCrossing {
        step: StepId,
        item: DataId,
    },
    ContractInvalid {
        contract: ContractId,
        detail: &'static str,
    },
    /// No compartment passes the checks; each candidate's reasons are listed.
    NoPlacement {
        step: StepId,
        refused: Vec<(Option<u32>, Vec<Violation>)>,
    },
    UnknownContract {
        contract: ContractId,
    },
    NotExternal {
        contract: ContractId,
    },
    AlreadyBound {
        contract: ContractId,
        bound: ContentKey,
    },
    NotBound {
        contract: ContractId,
    },
    /// The artifact differs from the one the release was approved for.
    ContentChanged {
        contract: ContractId,
        bound: ContentKey,
        presented: ContentKey,
    },
    AlreadyReleased {
        contract: ContractId,
    },
    ItemNotHeld {
        compartment: u32,
        item: DataId,
    },
    TooLarge {
        contract: ContractId,
        bytes: u64,
        max_bytes: u64,
    },
    ReleaseBudget {
        exceeded: ReleaseBudgetExceeded,
    },
    NotAChannel {
        authority: Authority,
    },
    GenerationExhausted {
        compartment: u32,
    },
}

impl fmt::Display for RunRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCompartment { compartment } => {
                write!(f, "there is no compartment {compartment}")
            }
            Self::NotHeld {
                compartment,
                authority,
            } => write!(f, "compartment {compartment} does not hold {authority}"),
            Self::Revoked {
                compartment,
                authority,
            } => write!(
                f,
                "{authority} was revoked from compartment {compartment}; revocation is not undone"
            ),
            Self::NotGrantable { authority } => {
                write!(f, "host policy does not grant {authority}")
            }
            Self::Conflict {
                compartment,
                conflict,
            } => write!(f, "compartment {compartment} would hold {conflict}"),
            Self::HistoryForbidsRelease {
                compartment,
                authority,
                secrecy,
            } => write!(
                f,
                "compartment {compartment} has held private data ({}); {authority} is refused \
                 because revoking a read does not erase copied data",
                super::plan::tags(secrecy)
            ),
            Self::AuthorityPersisted {
                compartment,
                volume,
                authority,
            } => write!(
                f,
                "compartment {compartment} keeps volume {volume}; {authority} would let retained \
                 state carry authority into a later generation"
            ),
            Self::DuplicateStep { step } => write!(f, "step {step} already exists"),
            Self::DuplicateData { item } => write!(f, "data item {item} already exists"),
            Self::UnknownInput { step, item } => {
                write!(f, "step {step} reads {item}, which nothing provides")
            }
            Self::TooManyItems { step } => write!(f, "step {step} names too many items"),
            Self::PrivateSourceWithoutReadAuthority { step, item } => write!(
                f,
                "step {step} reads private source {item} without its read authority"
            ),
            Self::DeclaredLabelBelowDerived { item } => write!(
                f,
                "the declared label of {item} would remove a tag its inputs carry"
            ),
            Self::IntrinsicConflict { step, conflicts } => write!(
                f,
                "step {step} itself needs {}; no placement separates one step's own authorities",
                conflicts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::UnknownParent { step, parent } => {
                write!(f, "step {step} repeats unknown step {parent}")
            }
            Self::CallbackWidensRights {
                step,
                parent,
                beyond,
            } => write!(
                f,
                "step {step} repeats {parent} but asks for {}, which {parent} does not hold",
                beyond
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::CallbackAddsContracts { step, parent } => write!(
                f,
                "step {step} repeats {parent} and may not bring new contracts"
            ),
            Self::CallbackNeedsCrossing { step, item } => write!(
                f,
                "step {step} would need {item} to cross into its parent's compartment"
            ),
            Self::ContractInvalid { contract, detail } => {
                write!(f, "contract {contract} is invalid: {detail}")
            }
            Self::NoPlacement { step, refused } => {
                write!(f, "no compartment can run step {step}")?;
                for (compartment, violations) in refused {
                    let name = compartment
                        .map(|index| format!("compartment {index}"))
                        .unwrap_or_else(|| "a new compartment".to_string());
                    for violation in violations {
                        write!(f, "; {name}: {violation}")?;
                    }
                }
                Ok(())
            }
            Self::UnknownContract { contract } => write!(f, "there is no contract {contract}"),
            Self::NotExternal { contract } => {
                write!(
                    f,
                    "contract {contract} does not release to an external target"
                )
            }
            Self::AlreadyBound { contract, bound } => {
                write!(f, "contract {contract} is already bound to {bound}")
            }
            Self::NotBound { contract } => write!(
                f,
                "contract {contract} has no approved content; bind it before releasing"
            ),
            Self::ContentChanged {
                contract,
                bound,
                presented,
            } => write!(
                f,
                "contract {contract} was approved for {bound}, not {presented}"
            ),
            Self::AlreadyReleased { contract } => {
                write!(f, "contract {contract} was already applied")
            }
            Self::ItemNotHeld { compartment, item } => {
                write!(f, "compartment {compartment} does not hold {item}")
            }
            Self::TooLarge {
                contract,
                bytes,
                max_bytes,
            } => write!(
                f,
                "contract {contract} allows {max_bytes} bytes; {bytes} were presented"
            ),
            Self::ReleaseBudget { exceeded } => exceeded.fmt(f),
            Self::NotAChannel { authority } => {
                write!(f, "{authority} is not an unrestricted channel")
            }
            Self::GenerationExhausted { compartment } => {
                write!(f, "compartment {compartment} has no further generation")
            }
        }
    }
}

impl std::error::Error for RunRefusal {}

#[derive(Clone, Debug)]
struct RunCompartment {
    trust_scope: TrustScope,
    generation: u64,
    authorities: BTreeSet<Authority>,
    revoked: BTreeSet<Authority>,
    history: Label,
    volumes: BTreeMap<VolumeId, Label>,
}

#[derive(Clone, Debug)]
struct RunItem {
    label: Label,
    producer: Option<u32>,
    immutable: bool,
    size_bytes: u64,
    held_by: BTreeSet<u32>,
}

/// A candidate compartment's state if the step joined it.
struct Candidate {
    authorities: BTreeSet<Authority>,
    history: Label,
    entering: Vec<(DataId, Option<ContractId>)>,
}

/// A compiled workflow's run-time label and authority state.
#[derive(Clone, Debug)]
pub struct PartitionRun {
    workflow: Digest,
    policy: PartitionPolicy,
    compartments: Vec<RunCompartment>,
    steps: BTreeMap<StepId, (u32, BTreeSet<Authority>)>,
    items: BTreeMap<DataId, RunItem>,
    contracts: BTreeMap<ContractId, ReleaseContract>,
    bindings: BTreeMap<ContractId, ContentKey>,
    released: BTreeSet<ContractId>,
    release_budget: GeneralReleaseBudget,
}

impl PartitionRun {
    /// The state after `plan`'s steps ran.
    pub fn start(workflow: &Workflow, plan: &CompiledPlan, policy: &PartitionPolicy) -> Self {
        let compartments = plan
            .compartments()
            .iter()
            .map(|compartment| RunCompartment {
                trust_scope: compartment.trust_scope,
                generation: 1,
                authorities: compartment.authorities.clone(),
                revoked: BTreeSet::new(),
                history: compartment.history.clone(),
                volumes: compartment
                    .volumes
                    .iter()
                    .map(|volume| (volume.clone(), compartment.history.clone()))
                    .collect(),
            })
            .collect();
        let assignment = plan.assignment();
        let steps = workflow
            .steps()
            .iter()
            .zip(assignment)
            .map(|(step, compartment)| (step.id.clone(), (*compartment, step.operations.clone())))
            .collect();
        let mut items: BTreeMap<DataId, RunItem> = BTreeMap::new();
        for (id, source) in workflow.sources() {
            items.insert(
                id.clone(),
                RunItem {
                    label: source.label.clone(),
                    producer: None,
                    immutable: true,
                    size_bytes: source.size_bytes,
                    held_by: BTreeSet::new(),
                },
            );
        }
        for (step, &compartment) in workflow.steps().iter().zip(assignment) {
            for output in &step.outputs {
                items.insert(
                    output.id.clone(),
                    RunItem {
                        label: plan
                            .labels()
                            .get(&output.id)
                            .cloned()
                            .unwrap_or_else(Label::bottom),
                        producer: Some(compartment),
                        immutable: output.immutable,
                        size_bytes: output.size_bytes,
                        held_by: BTreeSet::from([compartment]),
                    },
                );
            }
        }
        for crossing in plan.crossings() {
            if let Some(item) = items.get_mut(&crossing.item) {
                item.held_by.insert(crossing.to);
            }
        }
        Self {
            workflow: workflow.digest(),
            policy: policy.clone(),
            compartments,
            steps,
            items,
            contracts: workflow.contracts().clone(),
            bindings: BTreeMap::new(),
            released: BTreeSet::new(),
            release_budget: GeneralReleaseBudget::with_limit(policy.budgets.release_budget_bytes),
        }
    }

    pub fn compartment_count(&self) -> usize {
        self.compartments.len()
    }

    /// Everything that has entered the compartment in its current generation.
    pub fn history(&self, compartment: u32) -> Option<&Label> {
        self.compartments
            .get(slot(compartment))
            .map(|state| &state.history)
    }

    pub fn authorities(&self, compartment: u32) -> Option<&BTreeSet<Authority>> {
        self.compartments
            .get(slot(compartment))
            .map(|state| &state.authorities)
    }

    pub fn generation(&self, compartment: u32) -> Option<u64> {
        self.compartments
            .get(slot(compartment))
            .map(|state| state.generation)
    }

    pub fn trust_scope(&self, compartment: u32) -> Option<TrustScope> {
        self.compartments
            .get(slot(compartment))
            .map(|state| state.trust_scope)
    }

    /// The label a retained volume carries (line 2320).
    pub fn volume_label(&self, compartment: u32, volume: &VolumeId) -> Option<&Label> {
        self.compartments
            .get(slot(compartment))
            .and_then(|state| state.volumes.get(volume))
    }

    pub fn label(&self, item: &DataId) -> Option<&Label> {
        self.items.get(item).map(|item| &item.label)
    }

    /// The compartment running `step`.
    pub fn compartment_of(&self, step: &StepId) -> Option<u32> {
        self.steps.get(step).map(|(compartment, _)| *compartment)
    }

    pub fn release_budget(&self) -> &GeneralReleaseBudget {
        &self.release_budget
    }

    fn state(&self, compartment: u32) -> Result<&RunCompartment, RunRefusal> {
        self.compartments
            .get(slot(compartment))
            .ok_or(RunRefusal::UnknownCompartment { compartment })
    }

    /// Removes an authority. The history stays: data already copied is not erased
    /// (line 2320).
    pub fn revoke(&mut self, compartment: u32, authority: &Authority) -> Result<(), RunRefusal> {
        let state = self
            .compartments
            .get_mut(slot(compartment))
            .ok_or(RunRefusal::UnknownCompartment { compartment })?;
        if !state.authorities.remove(authority) {
            return Err(RunRefusal::NotHeld {
                compartment,
                authority: authority.clone(),
            });
        }
        state.revoked.insert(authority.clone());
        Ok(())
    }

    /// Grants a further authority after the same checks as compilation, against the
    /// compartment's whole history (line 2320).
    pub fn grant(&mut self, compartment: u32, authority: Authority) -> Result<(), RunRefusal> {
        let state = self.state(compartment)?;
        if state.revoked.contains(&authority) {
            return Err(RunRefusal::Revoked {
                compartment,
                authority,
            });
        }
        if !self.policy.grantable.contains(&authority.kind()) {
            return Err(RunRefusal::NotGrantable { authority });
        }
        if let Some(conflict) = self
            .policy
            .conflicts
            .conflicts_with(&state.authorities, &authority)
            .into_iter()
            .next()
        {
            return Err(RunRefusal::Conflict {
                compartment,
                conflict,
            });
        }
        if authority.is_unrestricted_release() && !state.history.is_public() {
            return Err(RunRefusal::HistoryForbidsRelease {
                compartment,
                authority,
                secrecy: state.history.secrecy().clone(),
            });
        }
        if authority.is_effect() {
            if let Some(volume) = state.volumes.keys().next() {
                return Err(RunRefusal::AuthorityPersisted {
                    compartment,
                    volume: volume.clone(),
                    authority,
                });
            }
        }
        let mut intrinsic = Label::bottom();
        if let Authority::ReadPrivate { source } = &authority {
            intrinsic = intrinsic.with_secrecy(source.clone());
        }
        if authority.introduces_untrusted_state() {
            intrinsic = intrinsic.untrusted();
        }
        let state = self
            .compartments
            .get_mut(slot(compartment))
            .ok_or(RunRefusal::UnknownCompartment { compartment })?;
        state.history.join_in(&intrinsic);
        for label in state.volumes.values_mut() {
            label.join_in(&intrinsic);
        }
        state.authorities.insert(authority);
        Ok(())
    }

    /// An attacker in the compartment tries to send what it holds through `channel`.
    /// Enforcement is by authority: it succeeds only if the compartment holds the channel,
    /// and returns the label of what could leave.
    pub fn emit(&self, compartment: u32, channel: &Authority) -> Result<Label, RunRefusal> {
        let state = self.state(compartment)?;
        if !channel.is_unrestricted_release() {
            return Err(RunRefusal::NotAChannel {
                authority: channel.clone(),
            });
        }
        if !state.authorities.contains(channel) {
            return Err(RunRefusal::NotHeld {
                compartment,
                authority: channel.clone(),
            });
        }
        Ok(state.history.clone())
    }

    /// Starts the compartment's next generation. Kept volumes bring their labels, so the
    /// new generation's history starts from them; authorities are never restored by a
    /// restart, and revocations persist (line 2315; §12.3 model 3).
    pub fn restart(
        &mut self,
        compartment: u32,
        retained: RetainedState,
    ) -> Result<u64, RunRefusal> {
        let state = self
            .compartments
            .get_mut(slot(compartment))
            .ok_or(RunRefusal::UnknownCompartment { compartment })?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(RunRefusal::GenerationExhausted { compartment })?;
        if retained == RetainedState::Discard {
            state.volumes.clear();
        }
        let mut history = Label::bottom();
        for label in state.volumes.values() {
            history.join_in(label);
        }
        for authority in &state.authorities {
            if let Authority::ReadPrivate { source } = authority {
                history = history.with_secrecy(source.clone());
            }
            if authority.introduces_untrusted_state() {
                history = history.untrusted();
            }
        }
        state.history = history;
        state.generation = generation;
        for item in self.items.values_mut() {
            item.held_by.remove(&compartment);
        }
        Ok(generation)
    }

    /// Binds an external contract to the exact approved artifact (line 2327).
    pub fn bind_release(
        &mut self,
        contract: &ContractId,
        content: ContentKey,
    ) -> Result<(), RunRefusal> {
        let declared = self
            .contracts
            .get(contract)
            .ok_or_else(|| RunRefusal::UnknownContract {
                contract: contract.clone(),
            })?;
        if !declared.is_external() {
            return Err(RunRefusal::NotExternal {
                contract: contract.clone(),
            });
        }
        if let Some(bound) = self.bindings.get(contract) {
            if *bound != content {
                return Err(RunRefusal::AlreadyBound {
                    contract: contract.clone(),
                    bound: *bound,
                });
            }
            return Ok(());
        }
        self.bindings.insert(contract.clone(), content);
        Ok(())
    }

    /// Applies an exact release once: the compartment holds the contract's authority and
    /// item, the content is the approved content, and the bytes fit the contract and the
    /// release budget (§2.5). The item keeps its label.
    pub fn release(
        &mut self,
        compartment: u32,
        contract: &ContractId,
        content: ContentKey,
        bytes: u64,
    ) -> Result<ReleaseRecord, RunRefusal> {
        let state = self.state(compartment)?;
        let authority = Authority::ExactRelease {
            contract: contract.clone(),
        };
        if !state.authorities.contains(&authority) {
            return Err(RunRefusal::NotHeld {
                compartment,
                authority,
            });
        }
        let declared =
            self.contracts
                .get(contract)
                .cloned()
                .ok_or_else(|| RunRefusal::UnknownContract {
                    contract: contract.clone(),
                })?;
        if self.released.contains(contract) {
            return Err(RunRefusal::AlreadyReleased {
                contract: contract.clone(),
            });
        }
        let bound = *self
            .bindings
            .get(contract)
            .ok_or_else(|| RunRefusal::NotBound {
                contract: contract.clone(),
            })?;
        if bound != content {
            return Err(RunRefusal::ContentChanged {
                contract: contract.clone(),
                bound,
                presented: content,
            });
        }
        let item = self
            .items
            .get(&declared.item)
            .filter(|item| item.held_by.contains(&compartment))
            .ok_or_else(|| RunRefusal::ItemNotHeld {
                compartment,
                item: declared.item.clone(),
            })?;
        if bytes > declared.max_bytes {
            return Err(RunRefusal::TooLarge {
                contract: contract.clone(),
                bytes,
                max_bytes: declared.max_bytes,
            });
        }
        let label = item.label.clone();
        self.release_budget
            .charge(bytes)
            .map_err(|exceeded| RunRefusal::ReleaseBudget { exceeded })?;
        self.released.insert(contract.clone());
        Ok(ReleaseRecord {
            contract: contract.clone(),
            item: declared.item.clone(),
            destination: declared.destination.clone(),
            confidentiality: declared.approval.confidentiality(),
            approval: declared.approval,
            content,
            bytes,
            label,
        })
    }

    /// The label an item has when it crosses now: an immutable artifact keeps the label
    /// it was produced with; a mutable item may have absorbed its producer's later history.
    fn crossing_label(&self, item: &RunItem) -> Label {
        let mut label = item.label.clone();
        if !item.immutable {
            if let Some(state) = item
                .producer
                .and_then(|producer| self.compartments.get(slot(producer)))
            {
                label.join_in(&state.history);
            }
        }
        label
    }

    fn contract_for<'a>(
        &'a self,
        extra: &'a [ReleaseContract],
        item: &DataId,
        consumer: &StepId,
    ) -> Option<&'a ReleaseContract> {
        self.contracts
            .values()
            .chain(extra.iter())
            .find(|contract| {
                contract.item == *item && contract.destination_step() == Some(consumer)
            })
    }

    /// What placing `step` in `target` (or a new compartment) would break.
    fn check(
        &self,
        step: &Step,
        extra: &[ReleaseContract],
        target: Option<u32>,
    ) -> (Vec<Violation>, Candidate) {
        let to = target.unwrap_or(to_u32(self.compartments.len()));
        let current = target.and_then(|target| self.compartments.get(slot(target)));
        let mut violations = Vec::new();
        let mut authorities = current
            .map(|state| state.authorities.clone())
            .unwrap_or_default();
        let mut history = current
            .map(|state| state.history.clone())
            .unwrap_or_else(Label::bottom);
        if let Some(state) = current {
            for authority in step.operations.intersection(&state.revoked) {
                violations.push(Violation::RevokedInCompartment {
                    compartment: to,
                    authority: authority.clone(),
                });
            }
        }
        authorities.extend(step.operations.iter().cloned());
        for conflict in self.policy.conflicts.conflicts(&authorities) {
            violations.push(Violation::ForbiddenCombination {
                compartment: to,
                conflict,
            });
        }
        let mut volumes: BTreeSet<VolumeId> = current
            .map(|state| state.volumes.keys().cloned().collect())
            .unwrap_or_default();
        for volume in &step.volumes {
            for (index, other) in self.compartments.iter().enumerate() {
                if to_u32(index) != to && other.volumes.contains_key(volume) {
                    violations.push(Violation::RetainedStateSplit {
                        volume: volume.clone(),
                        compartments: [to_u32(index), to].into_iter().collect(),
                    });
                }
            }
            volumes.insert(volume.clone());
        }
        for authority in authorities.iter().filter(|authority| authority.is_effect()) {
            for volume in &volumes {
                violations.push(Violation::AuthorityPersisted {
                    compartment: to,
                    volume: volume.clone(),
                    authority: authority.clone(),
                });
            }
        }
        let mut entering = Vec::new();
        for input in &step.inputs {
            let Some(item) = self.items.get(input) else {
                continue;
            };
            if item.held_by.contains(&to) && target.is_some() {
                history.join_in(&item.label);
                continue;
            }
            history.join_in(&self.crossing_label(item));
            match item.producer {
                None => entering.push((input.clone(), None)),
                Some(from) => match self.contract_for(extra, input, &step.id) {
                    None => violations.push(Violation::CrossingWithoutContract {
                        item: input.clone(),
                        consumer: step.id.clone(),
                        from,
                        to,
                    }),
                    Some(contract) if item.size_bytes > contract.max_bytes => {
                        violations.push(Violation::ContractTooSmall {
                            contract: contract.id.clone(),
                            bytes: item.size_bytes,
                            max_bytes: contract.max_bytes,
                        })
                    }
                    Some(contract) => entering.push((input.clone(), Some(contract.id.clone()))),
                },
            }
        }
        history.join_in(&step.intrinsic_label());
        if !history.is_public() {
            for authority in authorities
                .iter()
                .filter(|authority| authority.is_unrestricted_release())
            {
                violations.push(Violation::HistoryForbidsRelease {
                    compartment: to,
                    authority: authority.clone(),
                    secrecy: history.secrecy().clone(),
                });
            }
        }
        if target.is_none() && to_u32(self.compartments.len()) >= self.policy.budgets.max_vms {
            violations.push(Violation::TooManyVms {
                vms: to_u32(self.compartments.len()).saturating_add(1),
                max: self.policy.budgets.max_vms,
            });
        }
        (
            violations,
            Candidate {
                authorities,
                history,
                entering,
            },
        )
    }

    fn validate_dynamic(&self, dynamic: &DynamicStep) -> Result<(), RunRefusal> {
        let step = &dynamic.step;
        if self.steps.contains_key(&step.id) {
            return Err(RunRefusal::DuplicateStep {
                step: step.id.clone(),
            });
        }
        let largest = step
            .inputs
            .len()
            .max(step.outputs.len())
            .max(step.operations.len())
            .max(step.volumes.len())
            .max(dynamic.contracts.len());
        if largest > MAX_STEP_ITEMS {
            return Err(RunRefusal::TooManyItems {
                step: step.id.clone(),
            });
        }
        let mut outputs = BTreeSet::new();
        for output in &step.outputs {
            if self.items.contains_key(&output.id) || !outputs.insert(&output.id) {
                return Err(RunRefusal::DuplicateData {
                    item: output.id.clone(),
                });
            }
        }
        for input in &step.inputs {
            let item = self
                .items
                .get(input)
                .ok_or_else(|| RunRefusal::UnknownInput {
                    step: step.id.clone(),
                    item: input.clone(),
                })?;
            if item.producer.is_none() {
                for tag in item.label.secrecy() {
                    let read = Authority::ReadPrivate {
                        source: tag.clone(),
                    };
                    if !step.operations.contains(&read) {
                        return Err(RunRefusal::PrivateSourceWithoutReadAuthority {
                            step: step.id.clone(),
                            item: input.clone(),
                        });
                    }
                }
            }
        }
        if let Some(authority) = step
            .operations
            .iter()
            .find(|authority| !self.policy.grantable.contains(&authority.kind()))
        {
            return Err(RunRefusal::NotGrantable {
                authority: authority.clone(),
            });
        }
        let conflicts = self.policy.conflicts.conflicts(&step.operations);
        if !conflicts.is_empty() {
            return Err(RunRefusal::IntrinsicConflict {
                step: step.id.clone(),
                conflicts,
            });
        }
        for contract in &dynamic.contracts {
            let invalid = |detail| RunRefusal::ContractInvalid {
                contract: contract.id.clone(),
                detail,
            };
            if self.contracts.contains_key(&contract.id) {
                return Err(invalid("a contract with this name exists"));
            }
            let item = self
                .items
                .get(&contract.item)
                .ok_or_else(|| invalid("it covers an unknown item"))?;
            if item.producer.is_none() {
                return Err(invalid("sources enter by read authority, not by contract"));
            }
            if !step.inputs.contains(&contract.item) {
                return Err(invalid("the new step does not read its item"));
            }
            match contract.destination_step() {
                Some(destination) if *destination != step.id => {
                    return Err(invalid("it delivers to a step other than the new one"))
                }
                Some(_) => {}
                None => {
                    if !item.immutable {
                        return Err(invalid("only immutable artifacts leave the host"));
                    }
                    let applies = Authority::ExactRelease {
                        contract: contract.id.clone(),
                    };
                    if !step.operations.contains(&applies) {
                        return Err(invalid("the new step does not apply it"));
                    }
                }
            }
        }
        for operation in &step.operations {
            if let Authority::ExactRelease { contract } = operation {
                let declared = self
                    .contracts
                    .get(contract)
                    .or_else(|| dynamic.contracts.iter().find(|c| c.id == *contract))
                    .ok_or_else(|| RunRefusal::UnknownContract {
                        contract: contract.clone(),
                    })?;
                if !declared.is_external() {
                    return Err(RunRefusal::NotExternal {
                        contract: contract.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Adds a step to the running workflow after the same checks as compilation
    /// (line 2320). A loop iteration or callback runs in its parent's compartment with at
    /// most its parent's current rights and no new contracts; any other step is placed
    /// in the compartment producing most of its inputs, then any other, then a new one.
    pub fn add_step(&mut self, dynamic: DynamicStep) -> Result<DynamicPlacement, RunRefusal> {
        self.validate_dynamic(&dynamic)?;
        let step = &dynamic.step;
        let candidates: Vec<Option<u32>> = match &dynamic.origin {
            DynamicOrigin::LoopIteration { of } | DynamicOrigin::Callback { of } => {
                let (parent_compartment, parent_rights) =
                    self.steps
                        .get(of)
                        .cloned()
                        .ok_or_else(|| RunRefusal::UnknownParent {
                            step: step.id.clone(),
                            parent: of.clone(),
                        })?;
                if !dynamic.contracts.is_empty() {
                    return Err(RunRefusal::CallbackAddsContracts {
                        step: step.id.clone(),
                        parent: of.clone(),
                    });
                }
                let current = &self.state(parent_compartment)?.authorities;
                let beyond: Vec<Authority> = step
                    .operations
                    .iter()
                    .filter(|authority| {
                        !parent_rights.contains(*authority) || !current.contains(*authority)
                    })
                    .cloned()
                    .collect();
                if !beyond.is_empty() {
                    return Err(RunRefusal::CallbackWidensRights {
                        step: step.id.clone(),
                        parent: of.clone(),
                        beyond,
                    });
                }
                if let Some(input) = step.inputs.iter().find(|input| {
                    !self
                        .items
                        .get(*input)
                        .is_some_and(|item| item.held_by.contains(&parent_compartment))
                }) {
                    return Err(RunRefusal::CallbackNeedsCrossing {
                        step: step.id.clone(),
                        item: input.clone(),
                    });
                }
                vec![Some(parent_compartment)]
            }
            DynamicOrigin::Added => {
                let mut held: BTreeMap<u32, u64> = BTreeMap::new();
                for input in &step.inputs {
                    if let Some(item) = self.items.get(input) {
                        for compartment in &item.held_by {
                            let bytes = held.entry(*compartment).or_insert(0);
                            *bytes = bytes.saturating_add(item.size_bytes);
                        }
                    }
                }
                let mut ranked: Vec<(u32, u64)> = held.into_iter().collect();
                ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
                let mut candidates: Vec<Option<u32>> = ranked
                    .iter()
                    .map(|(compartment, _)| Some(*compartment))
                    .collect();
                for compartment in 0..to_u32(self.compartments.len()) {
                    if !candidates.contains(&Some(compartment)) {
                        candidates.push(Some(compartment));
                    }
                }
                candidates.push(None);
                candidates
            }
        };
        let mut refused = Vec::new();
        for target in candidates {
            let (violations, candidate) = self.check(step, &dynamic.contracts, target);
            if violations.is_empty() {
                return self.apply(dynamic, target, candidate, refused);
            }
            refused.push((target, violations));
        }
        Err(RunRefusal::NoPlacement {
            step: step.id.clone(),
            refused,
        })
    }

    fn apply(
        &mut self,
        dynamic: DynamicStep,
        target: Option<u32>,
        candidate: Candidate,
        refused: Vec<(Option<u32>, Vec<Violation>)>,
    ) -> Result<DynamicPlacement, RunRefusal> {
        let step = dynamic.step;
        let mut outputs = Vec::new();
        for output in &step.outputs {
            let label = match &output.declared_label {
                Some(declared) if !candidate.history.flows_to(declared) => {
                    return Err(RunRefusal::DeclaredLabelBelowDerived {
                        item: output.id.clone(),
                    })
                }
                Some(declared) => candidate.history.join(declared),
                None => candidate.history.clone(),
            };
            outputs.push((output, label));
        }
        let compartment = match target {
            Some(index) => index,
            None => {
                let index = u32::try_from(self.compartments.len()).map_err(|_| {
                    RunRefusal::NoPlacement {
                        step: step.id.clone(),
                        refused: vec![(
                            None,
                            vec![Violation::TooManyVms {
                                vms: u32::MAX,
                                max: self.policy.budgets.max_vms,
                            }],
                        )],
                    }
                })?;
                self.compartments.push(RunCompartment {
                    trust_scope: compartment_scope(self.workflow, index),
                    generation: 1,
                    authorities: BTreeSet::new(),
                    revoked: BTreeSet::new(),
                    history: Label::bottom(),
                    volumes: BTreeMap::new(),
                });
                index
            }
        };
        let rule = match target {
            None => PlacementRule::NewCompartment {
                refused: refused
                    .into_iter()
                    .filter_map(|(target, violations)| target.map(|index| (index, violations)))
                    .collect(),
            },
            Some(index)
                if step.inputs.iter().any(|input| {
                    self.items
                        .get(input)
                        .is_some_and(|item| item.held_by.contains(&index))
                }) =>
            {
                PlacementRule::JoinedProducer { compartment: index }
            }
            Some(index) => PlacementRule::JoinedExisting { compartment: index },
        };
        let mut reasons = vec![Reason::Placed {
            step: step.id.clone(),
            rule,
        }];
        for (item, contract) in &candidate.entering {
            if let Some(entry) = self.items.get(item) {
                reasons.push(Reason::Crossing {
                    crossing: Crossing {
                        item: item.clone(),
                        consumer: step.id.clone(),
                        from: match entry.producer {
                            Some(from) => CrossingSource::Compartment { compartment: from },
                            None => CrossingSource::Source,
                        },
                        to: compartment,
                        contract: contract.clone(),
                        moved_bytes: entry.size_bytes,
                        label: self.crossing_label(entry),
                    },
                });
            }
        }
        if let Some(state) = self.compartments.get_mut(slot(compartment)) {
            state.authorities = candidate.authorities.clone();
            state.history = candidate.history.clone();
            for volume in &step.volumes {
                state
                    .volumes
                    .entry(volume.clone())
                    .or_insert_with(Label::bottom);
            }
            for label in state.volumes.values_mut() {
                label.join_in(&candidate.history);
            }
            if !state.history.is_public() {
                reasons.push(Reason::HistoryAccounted {
                    compartment,
                    secrecy: state.history.secrecy().clone(),
                });
            }
        }
        for input in &step.inputs {
            if let Some(item) = self.items.get_mut(input) {
                item.held_by.insert(compartment);
            }
        }
        for (output, label) in outputs {
            self.items.insert(
                output.id.clone(),
                RunItem {
                    label,
                    producer: Some(compartment),
                    immutable: output.immutable,
                    size_bytes: output.size_bytes,
                    held_by: BTreeSet::from([compartment]),
                },
            );
        }
        for contract in dynamic.contracts {
            self.contracts.insert(contract.id.clone(), contract);
        }
        self.steps
            .insert(step.id.clone(), (compartment, step.operations.clone()));
        Ok(DynamicPlacement {
            step: step.id.clone(),
            compartment,
            new_compartment: target.is_none(),
            explanation: Explanation::new(reasons),
        })
    }
}
