//! The simple rules-based partitioner (VM part §9.1, line 2318: "use a simple rules-based
//! partition first").
//!
//! Steps are taken in one topological order. Each joins the compartment that produced
//! most of its input bytes if every constraint still holds, otherwise the first other
//! compartment that keeps them, otherwise a new compartment. The result is evaluated with
//! the same objective and constraints as the oracle; it is a heuristic with no optimality
//! claim. A step that itself needs a forbidden combination is not split: its boundary is
//! explained instead (line 2338).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::authority::{Authority, Conflict};
use super::label::Label;
use super::names::{DataId, LabelTag, StepId, VolumeId};
use super::plan::{
    analyze, build_plan, slot, tags, to_u32, CompiledPlan, PartitionMethod, PartitionPolicy,
    PlacementRule, Reason, Violation,
};
use super::workflow::{Step, Workflow};

/// Why no plan was produced; each refusal explains itself (line 2332).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CompileRefusal {
    /// Every step's required actions must be available (line 2312).
    NotGrantable {
        step: StepId,
        authority: Authority,
    },
    /// The step itself needs private data beside an unrestricted channel or a forbidden
    /// combination: partitioning cannot separate one step's own authorities, so the
    /// boundary is explained rather than forced (line 2338).
    BroadReleaseBoundary {
        step: StepId,
        conflicts: Vec<Conflict>,
        secrecy: BTreeSet<LabelTag>,
        channels: Vec<Authority>,
    },
    /// The step keeps retained state beside an effect authority (line 2315).
    RetainedEffect {
        step: StepId,
        volume: VolumeId,
        authority: Authority,
    },
    /// The modelled bandwidth is zero.
    InvalidWeights,
    /// The rules found no compartment for a step; the reasons per candidate are listed.
    NoPlacement {
        step: StepId,
        refused: Vec<(Option<u32>, Vec<Violation>)>,
    },
    /// The rules' partition breaks a budget.
    Infeasible {
        violations: Vec<Violation>,
    },
    /// The oracle found no feasible partition; the single-VM and one-VM-per-step
    /// layouts show why.
    NoFeasiblePartition {
        evaluations: u64,
        single_vm: Vec<Violation>,
        one_vm_per_step: Vec<Violation>,
    },
    TooLargeForOracle {
        steps: usize,
        max: usize,
    },
    TooManyOrders {
        max: usize,
    },
}

impl fmt::Display for CompileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |violations: &[Violation]| {
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };
        match self {
            Self::NotGrantable { step, authority } => write!(
                f,
                "step {step} needs {authority}, which host policy does not grant"
            ),
            Self::BroadReleaseBoundary {
                step,
                conflicts,
                secrecy,
                channels,
            } => {
                write!(f, "step {step} itself needs")?;
                for conflict in conflicts {
                    write!(f, " {conflict};")?;
                }
                if !secrecy.is_empty() {
                    write!(
                        f,
                        " private data ({}) beside {};",
                        tags(secrecy),
                        channels
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                f.write_str(
                    " no partition separates one step's own authorities, so none is forced. The \
                     task legitimately needs broad private-data release: run it under an \
                     explicit profile with an approved release contract, or narrow the step",
                )
            }
            Self::RetainedEffect {
                step,
                volume,
                authority,
            } => write!(
                f,
                "step {step} keeps volume {volume} beside {authority}; retained state cannot \
                 carry authority into a later generation"
            ),
            Self::InvalidWeights => f.write_str("the modelled transfer bandwidth is zero"),
            Self::NoPlacement { step, refused } => {
                write!(f, "no compartment can run step {step}")?;
                for (compartment, violations) in refused {
                    match compartment {
                        Some(compartment) => {
                            write!(f, "; compartment {compartment}: {}", list(violations))?
                        }
                        None => write!(f, "; a new compartment: {}", list(violations))?,
                    }
                }
                Ok(())
            }
            Self::Infeasible { violations } => {
                write!(
                    f,
                    "the rules' partition is infeasible: {}",
                    list(violations)
                )
            }
            Self::NoFeasiblePartition {
                evaluations,
                single_vm,
                one_vm_per_step,
            } => write!(
                f,
                "none of {evaluations} partitions and orders is feasible; one VM: {}; one VM \
                 per step: {}",
                list(single_vm),
                list(one_vm_per_step)
            ),
            Self::TooLargeForOracle { steps, max } => write!(
                f,
                "{steps} steps; the exhaustive oracle is for at most {max}"
            ),
            Self::TooManyOrders { max } => {
                write!(f, "the workflow has more than {max} execution orders")
            }
        }
    }
}

impl std::error::Error for CompileRefusal {}

/// Checks that hold for every partition: grantable actions, steps whose own needs are a
/// broad release, and retained state beside an effect.
pub(super) fn precheck(
    workflow: &Workflow,
    policy: &PartitionPolicy,
) -> Result<(), CompileRefusal> {
    if policy.weights.transfer_bytes_per_ms == 0 {
        return Err(CompileRefusal::InvalidWeights);
    }
    for step in workflow.steps() {
        if let Some(authority) = step
            .operations
            .iter()
            .find(|authority| !policy.grantable.contains(&authority.kind()))
        {
            return Err(CompileRefusal::NotGrantable {
                step: step.id.clone(),
                authority: authority.clone(),
            });
        }
        let conflicts = policy.conflicts.conflicts(&step.operations);
        let mut history = step.intrinsic_label();
        for input in &step.inputs {
            if let Some(label) = workflow.static_label(input) {
                history.join_in(label);
            }
        }
        let channels: Vec<Authority> = step.unrestricted_channels().cloned().collect();
        let private_release = !history.is_public() && !channels.is_empty();
        if !conflicts.is_empty() || private_release {
            return Err(CompileRefusal::BroadReleaseBoundary {
                step: step.id.clone(),
                conflicts,
                secrecy: if private_release {
                    history.secrecy().clone()
                } else {
                    BTreeSet::new()
                },
                channels: if private_release {
                    channels
                } else {
                    Vec::new()
                },
            });
        }
        if let Some(authority) = step.operations.iter().find(|a| a.is_effect()) {
            if let Some(volume) = step.volumes.iter().next() {
                return Err(CompileRefusal::RetainedEffect {
                    step: step.id.clone(),
                    volume: volume.clone(),
                    authority: authority.clone(),
                });
            }
        }
    }
    Ok(())
}

/// A compartment while the rules place steps.
#[derive(Clone, Debug)]
struct Partial {
    authorities: BTreeSet<Authority>,
    history: Label,
    volumes: BTreeSet<VolumeId>,
}

struct Rules<'a> {
    workflow: &'a Workflow,
    policy: &'a PartitionPolicy,
    assignment: Vec<Option<u32>>,
    compartments: Vec<Partial>,
    labels: BTreeMap<DataId, Label>,
    volume_owner: BTreeMap<VolumeId, u32>,
}

impl Rules<'_> {
    /// What placing step `index` in `target` (or a new compartment) would break.
    fn check(&self, step: &Step, target: Option<u32>) -> (Vec<Violation>, Partial) {
        let to = target.unwrap_or(to_u32(self.compartments.len()));
        let mut partial = target
            .and_then(|target| self.compartments.get(slot(target)).cloned())
            .unwrap_or(Partial {
                authorities: BTreeSet::new(),
                history: Label::bottom(),
                volumes: BTreeSet::new(),
            });
        partial.authorities.extend(step.operations.iter().cloned());
        partial.volumes.extend(step.volumes.iter().cloned());
        let mut violations: Vec<Violation> = self
            .policy
            .conflicts
            .conflicts(&partial.authorities)
            .into_iter()
            .map(|conflict| Violation::ForbiddenCombination {
                compartment: to,
                conflict,
            })
            .collect();
        for volume in &step.volumes {
            if let Some(owner) = self.volume_owner.get(volume) {
                if *owner != to {
                    violations.push(Violation::RetainedStateSplit {
                        volume: volume.clone(),
                        compartments: [*owner, to].into_iter().collect(),
                    });
                }
            }
        }
        for authority in partial.authorities.iter().filter(|a| a.is_effect()) {
            for volume in &partial.volumes {
                violations.push(Violation::AuthorityPersisted {
                    compartment: to,
                    volume: volume.clone(),
                    authority: authority.clone(),
                });
            }
        }
        for input in &step.inputs {
            if let Some(label) = self.labels.get(input) {
                partial.history.join_in(label);
            }
            let Some(item) = self.workflow.item(input) else {
                continue;
            };
            let Some(from) = item.producer.and_then(|producer| self.placed(producer)) else {
                continue;
            };
            if from == to {
                continue;
            }
            match self.workflow.contract_for(input, &step.id) {
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
                Some(_) => {}
            }
        }
        partial.history.join_in(&step.intrinsic_label());
        if !partial.history.is_public() {
            for authority in partial
                .authorities
                .iter()
                .filter(|authority| authority.is_unrestricted_release())
            {
                violations.push(Violation::HistoryForbidsRelease {
                    compartment: to,
                    authority: authority.clone(),
                    secrecy: partial.history.secrecy().clone(),
                });
            }
        }
        (violations, partial)
    }

    /// The compartment step `index` was placed in, if it was.
    fn placed(&self, index: usize) -> Option<u32> {
        self.assignment.get(index).copied().flatten()
    }

    fn place(&mut self, index: usize, step: &Step, target: Option<u32>, partial: Partial) -> u32 {
        let to = match target {
            Some(target) => target,
            None => {
                self.compartments.push(partial.clone());
                to_u32(self.compartments.len().saturating_sub(1))
            }
        };
        if let Some(held) = self.compartments.get_mut(slot(to)) {
            *held = partial.clone();
        }
        if let Some(placed) = self.assignment.get_mut(index) {
            *placed = Some(to);
        }
        for volume in &step.volumes {
            self.volume_owner.insert(volume.clone(), to);
        }
        for output in &step.outputs {
            let label = match &output.declared_label {
                Some(declared) => partial.history.join(declared),
                None => partial.history.clone(),
            };
            self.labels.insert(output.id.clone(), label);
        }
        to
    }

    /// Existing compartments in preference order: producers of the most input bytes
    /// first, then the rest by index.
    fn candidates(&self, step: &Step) -> Vec<(u32, bool)> {
        let mut produced: BTreeMap<u32, u64> = BTreeMap::new();
        for input in &step.inputs {
            if let Some(item) = self.workflow.item(input) {
                if let Some(from) = item.producer.and_then(|producer| self.placed(producer)) {
                    let bytes = produced.entry(from).or_insert(0);
                    *bytes = bytes.saturating_add(item.size_bytes);
                }
            }
        }
        let mut producers: Vec<(u32, u64)> = produced.into_iter().collect();
        producers.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        let mut candidates: Vec<(u32, bool)> = producers
            .iter()
            .map(|(compartment, _)| (*compartment, true))
            .collect();
        for compartment in 0..to_u32(self.compartments.len()) {
            if !candidates.iter().any(|(seen, _)| *seen == compartment) {
                candidates.push((compartment, false));
            }
        }
        candidates
    }
}

/// The rules-based partition of `workflow` (line 2318), evaluated and explained; or an
/// explained refusal.
pub fn compile(
    workflow: &Workflow,
    policy: &PartitionPolicy,
) -> Result<CompiledPlan, CompileRefusal> {
    precheck(workflow, policy)?;
    let mut rules = Rules {
        workflow,
        policy,
        assignment: vec![None; workflow.steps().len()],
        compartments: Vec::new(),
        labels: workflow
            .sources()
            .iter()
            .map(|(id, source)| (id.clone(), source.label.clone()))
            .collect(),
        volume_owner: BTreeMap::new(),
    };
    let order = workflow.default_order().to_vec();
    let mut placements = Vec::new();
    for &index in &order {
        let Some(step) = workflow.steps().get(index) else {
            continue;
        };
        let step_id = step.id.clone();
        let mut refused = Vec::new();
        let mut placed = None;
        for (compartment, producer) in rules.candidates(step) {
            let (violations, partial) = rules.check(step, Some(compartment));
            if violations.is_empty() {
                placed = Some((Some(compartment), producer, partial));
                break;
            }
            refused.push((compartment, violations));
        }
        let (target, rule, partial) = match placed {
            Some((target, true, partial)) => (
                target,
                PlacementRule::JoinedProducer {
                    compartment: target.unwrap_or(0),
                },
                partial,
            ),
            Some((target, false, partial)) => (
                target,
                PlacementRule::JoinedExisting {
                    compartment: target.unwrap_or(0),
                },
                partial,
            ),
            None => {
                let (violations, partial) = rules.check(step, None);
                if !violations.is_empty() {
                    let mut all: Vec<(Option<u32>, Vec<Violation>)> = refused
                        .into_iter()
                        .map(|(compartment, violations)| (Some(compartment), violations))
                        .collect();
                    all.push((None, violations));
                    return Err(CompileRefusal::NoPlacement {
                        step: step_id,
                        refused: all,
                    });
                }
                (None, PlacementRule::NewCompartment { refused }, partial)
            }
        };
        rules.place(index, step, target, partial);
        placements.push(Reason::Placed {
            step: step_id,
            rule,
        });
    }
    let Some(assignment) = rules
        .assignment
        .iter()
        .copied()
        .collect::<Option<Vec<u32>>>()
    else {
        return Err(CompileRefusal::Infeasible {
            violations: vec![Violation::MalformedAssignment {
                steps: to_u32(workflow.steps().len()),
                assigned: to_u32(rules.assignment.iter().flatten().count()),
                ordered: to_u32(order.len()),
            }],
        });
    };
    let analysis = analyze(workflow, policy, &assignment, &order);
    if !analysis.violations.is_empty() {
        return Err(CompileRefusal::Infeasible {
            violations: analysis.violations,
        });
    }
    Ok(build_plan(
        workflow,
        policy,
        &assignment,
        &order,
        analysis,
        PartitionMethod::RulesBased,
        placements,
    ))
}
