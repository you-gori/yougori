//! The first prototype on a fake substrate (GPU §4.15, line 870).
//!
//! [`compare_policies`] runs one declared workflow under ordinary caching, next-model
//! prefetch, GPU-N1 alone (the committed bundle planner) and the compiled plan, over seeded
//! independent trials with the same branch draws and duration variation for every policy.
//! It charges planning time (compile once, replans when they happen), unused preparation
//! and retained memory. Every stage of every run becomes a CORE-08 [`RunRecord`] on the
//! fake, time-controlled substrate, so each side's provenance is
//! [`Provenance::FakeSubstrate`]: it validates the comparison and backs no performance,
//! improvement or release claim (S12 G0; rollout decision "T12 → T02"). Host memory,
//! energy and price are not measured.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::ids::{Clock, ManualClock, MonotonicTime, OperationId};
use crate::foundation::report::{
    AttemptIdentity, AttemptRole, Baseline, CacheTier, ClockId, ColdProvenance, ComparisonReport,
    ComparisonSide, EffectClass, EventKind, EventRecorder, ExperimentDesign, Label,
    LatencyObjective, MatchedConfiguration, Measured, ModeFidelity, ModelAtArrival, NonNegative,
    NotMeasuredReason, Objective, ObjectivePlan, ObjectiveVector, Outcome, PrefillMode, Provenance,
    Quantile, RunMeasurements, RunRecord, RunSubstrate, Scenario, StartState, StartTemperature,
    StateComparison, TracePattern, MIN_INDEPENDENT_TRIALS,
};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::residency::retention::Lru;

use super::decision::{
    decide_amortization, AmortizationDecision, AmortizationInput, WorkflowVerdict,
};
use super::declaration::{Aggregation, CheckedWorkflow, TreeNode, WorkflowDeclaration};
use super::model::{Context, CostModel, Knowledge, Transition};
use super::online::{BundleRetention, NextModelPrefetch, OnlinePolicy, OrdinaryCaching};
use super::plan::{compile, ReadinessPlan};
use super::recipes::{HoldAuthority, ObjectHoldAuthority};
use super::runtime::{BoundaryObservation, BoundaryOutcome, PlanRuntime};
use super::{ResourceSet, TransitionError};

/// How the trials run.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TrialConfig {
    /// Independent trials; at least CORE-08's minimum.
    pub trials: u32,
    pub seed: u64,
    /// Relative variation of realized durations, uniform either side, in [0, 0.5].
    pub variation: f64,
    /// How often this workflow is expected to run, from its history (line 872).
    pub expected_runs: u64,
}

/// One policy's results over every trial.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PolicySummary {
    pub policy: String,
    pub trials: u32,
    pub stages: u64,
    /// Readiness seconds plus every charge, per run.
    pub mean_charged_seconds: f64,
    /// The same without the one-time compile charge.
    pub mean_charged_seconds_without_compile: f64,
    pub mean_readiness_seconds: f64,
    pub compile_seconds: f64,
    /// Planning time spent during runs: the plan's replans, or an online planner's work.
    pub replanning_seconds: f64,
    pub unused_preparation_bytes: u64,
    pub moved_bytes: u64,
    pub retained_byte_seconds: f64,
    pub peak_bytes: u64,
    pub deadline_misses: u64,
    pub replans: u32,
    /// Always the fake substrate here.
    pub provenance: Provenance,
    pub objectives: ObjectiveVector,
}

/// The line 870 comparison of one workflow.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrototypeComparison {
    pub workflow: String,
    pub plan: PolicySummary,
    pub baselines: Vec<PolicySummary>,
    /// CORE-08's report: the plan against the ordinary workflow (LRU) and the strongest
    /// upstream baseline.
    pub report: ComparisonReport,
    pub verdict: WorkflowVerdict,
    pub amortization: AmortizationDecision,
}

enum Driver<'s> {
    Plan {
        plan: ReadinessPlan,
        runtime: PlanRuntime,
    },
    Online(Box<dyn OnlinePolicy + 's>),
}

struct PolicyRun {
    summary: PolicySummary,
    records: Vec<RunRecord>,
}

/// Runs the line 870 comparison of `declaration` named `workflow`, with `template`
/// supplying the descriptive fields of every record (host, build, launch, client, model
/// fixture).
pub fn compare_policies(
    workflow: &str,
    declaration: &WorkflowDeclaration,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    clock: &dyn Clock,
    template: &RunRecord,
    config: &TrialConfig,
) -> Result<PrototypeComparison, TransitionError> {
    if config.trials < MIN_INDEPENDENT_TRIALS {
        return Err(TransitionError::TooFewTrials {
            trials: config.trials,
            required: MIN_INDEPENDENT_TRIALS,
        });
    }
    if !(0.0..=0.5).contains(&config.variation) {
        return Err(TransitionError::Internal {
            what: "variation must lie in [0, 0.5]",
        });
    }
    let plan = compile(declaration, holds, objects, clock)?;
    let checked = plan.workflow().clone();
    let runtime = PlanRuntime::new(plan.clone());
    let candidate = run_policy(
        &checked,
        "plan",
        Driver::Plan { plan, runtime },
        config,
        template,
        holds,
        objects,
        clock,
    )?;
    let ordinary = run_policy(
        &checked,
        "lru",
        Driver::Online(Box::new(OrdinaryCaching::new(Lru))),
        config,
        template,
        holds,
        objects,
        clock,
    )?;
    let prefetch = run_policy(
        &checked,
        "next-model",
        Driver::Online(Box::new(NextModelPrefetch::new(Lru))),
        config,
        template,
        holds,
        objects,
        clock,
    )?;
    let bundle = run_policy(
        &checked,
        "gpu-n1",
        Driver::Online(Box::new(BundleRetention::new()?)),
        config,
        template,
        holds,
        objects,
        clock,
    )?;
    let side = |run: &PolicyRun| -> Result<ComparisonSide, TransitionError> {
        let first = run.records.first().ok_or(TransitionError::Internal {
            what: "a run records at least one stage",
        })?;
        Ok(ComparisonSide {
            name: Label::new(run.summary.policy.clone())?,
            provenance: run.summary.provenance.clone(),
            configuration: MatchedConfiguration::from_record(first)?,
            temperature: StartTemperature::Warm,
            fidelity: ModeFidelity::BitIdentical,
            accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
            objectives: run.summary.objectives.clone(),
        })
    };
    let design = ExperimentDesign {
        effect: EffectClass::CacheOrPredictor,
        independent_trials: config.trials,
        trace: TracePattern::Mixed { seed: config.seed },
        components: vec![Label::new("compiled-transition-plan")?],
        ablated_components: Vec::new(),
    };
    let report = ComparisonReport::new(
        ObjectivePlan::new(Objective::TimeToFirstToken, 0.05)?,
        StateComparison::WarmLoad,
        design,
        Vec::new(),
        side(&candidate)?,
        Baseline::Measured {
            sides: vec![side(&ordinary)?],
        },
        Baseline::Measured {
            sides: vec![side(&prefetch)?, side(&bundle)?],
        },
    )?;
    let baselines = vec![ordinary.summary, prefetch.summary, bundle.summary];
    let strongest = baselines
        .iter()
        .fold(None::<&PolicySummary>, |best, summary| match best {
            Some(current) if current.mean_charged_seconds <= summary.mean_charged_seconds => {
                Some(current)
            }
            _ => Some(summary),
        })
        .ok_or(TransitionError::Internal {
            what: "three baselines ran",
        })?;
    let verdict = WorkflowVerdict {
        workflow: workflow.to_string(),
        plan_charged_seconds: candidate.summary.mean_charged_seconds,
        strongest_baseline: strongest.policy.clone(),
        baseline_charged_seconds: strongest.mean_charged_seconds,
        fake_substrate: candidate.summary.provenance.is_fake_substrate(),
    };
    let amortization = decide_amortization(&AmortizationInput {
        compile_seconds: candidate.summary.compile_seconds,
        savings_per_run_seconds: strongest.mean_charged_seconds
            - candidate.summary.mean_charged_seconds_without_compile,
        expected_runs: config.expected_runs,
    })?;
    Ok(PrototypeComparison {
        workflow: workflow.to_string(),
        plan: candidate.summary,
        baselines,
        report,
        verdict,
        amortization,
    })
}

const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

fn uniform(rng: &mut SeededRng) -> f64 {
    rng.below(1_000_001) as f64 / 1_000_000.0
}

/// The branch the fake workflow takes: by the evidence probabilities, uniformly where
/// there is none.
fn draw(rng: &mut SeededRng, entry: &TreeNode) -> Option<usize> {
    match entry.aggregation {
        Aggregation::Leaf => None,
        Aggregation::Single => entry.children.first().copied(),
        Aggregation::WorstCase => {
            let count = entry.children.len() as u64;
            entry.children.get(rng.below(count) as usize).copied()
        }
        Aggregation::Expected => {
            let point = uniform(rng);
            let mut cumulative = 0.0;
            for (child, weight) in entry.children.iter().zip(&entry.weights) {
                cumulative += weight;
                if point <= cumulative {
                    return Some(*child);
                }
            }
            entry.children.last().copied()
        }
    }
}

fn set_of(workflow: &CheckedWorkflow, keys: &[super::declaration::ResourceKey]) -> ResourceSet {
    keys.iter()
        .filter_map(|key| workflow.resource_index(key))
        .fold(ResourceSet::EMPTY, ResourceSet::with)
}

fn seconds(value: f64) -> Result<Duration, TransitionError> {
    Duration::try_from_secs_f64(value.max(0.0))
        .map_err(|_| TransitionError::DurationOutOfRange { seconds: value })
}

/// Everything one stage of one run measured on the fake.
struct StageRun<'t> {
    transition: &'t Transition,
    required: ResourceSet,
    readiness_seconds: f64,
    decode_seconds: f64,
    waiting_seconds: f64,
    moved_bytes: u64,
    storage_read_bytes: u64,
}

fn run_policy(
    workflow: &CheckedWorkflow,
    code: &str,
    mut driver: Driver<'_>,
    config: &TrialConfig,
    template: &RunRecord,
    holds: &dyn HoldAuthority,
    objects: &dyn ObjectHoldAuthority,
    clock: &dyn Clock,
) -> Result<PolicyRun, TransitionError> {
    let tree = &workflow.tree;
    let mut model = CostModel::new(workflow, tree, clock);
    let weights = workflow.weights;
    let compile_seconds = match &driver {
        Driver::Plan { plan, .. } => plan.planning_seconds(),
        Driver::Online(_) => 0.0,
    };
    let mut records = Vec::new();
    let mut readiness_all = Vec::new();
    let mut charged_total = 0.0;
    let mut readiness_total = 0.0;
    let mut unused_total = 0u64;
    let mut moved_total = 0u64;
    let mut read_total = 0u64;
    let mut retained_byte_seconds_total = 0.0;
    let mut resident_byte_seconds = 0.0;
    let mut stage_seconds_total = 0.0;
    let mut peak_bytes = 0u64;
    let mut misses = 0u64;
    let mut stages = 0u64;
    let mut replanning_total = 0.0;
    let mut replans = 0u32;
    for trial in 0..config.trials {
        let mut rng = SeededRng::new(config.seed ^ u64::from(trial).wrapping_mul(GOLDEN_GAMMA));
        if let Driver::Plan { plan, runtime } = &mut driver {
            *runtime = PlanRuntime::new(plan.clone());
        }
        let mut context = Context::initial(workflow.initial);
        let mut node = 0usize;
        let mut step = 0u64;
        let mut previous_seconds = None;
        let mut pending: BTreeMap<usize, u64> = BTreeMap::new();
        let mut trial_charge = if trial == 0 { compile_seconds } else { 0.0 };
        let mut trial_unused = 0u64;
        let mut trial_retained = 0.0;
        loop {
            let entry = tree.get(node).ok_or(TransitionError::Internal {
                what: "tree node out of range",
            })?;
            let stage = &workflow.stages[entry.stage];
            let factor = 1.0 + config.variation * (2.0 * uniform(&mut rng) - 1.0);
            let (configuration, planned_prefetch, knowledge) = match &mut driver {
                Driver::Plan { runtime, .. } => {
                    let observation = BoundaryObservation {
                        next_stage: stage.id.clone(),
                        presented: stage
                            .requires
                            .iter()
                            .map(|at| workflow.resources[at].identity.clone())
                            .collect(),
                        usable_vram: workflow.budgets.usable_vram,
                        previous_stage_seconds: previous_seconds,
                        holds,
                        objects,
                    };
                    let before = runtime.replanning_seconds();
                    let directive = match runtime.advance(&observation, clock)? {
                        BoundaryOutcome::Planned(directive)
                        | BoundaryOutcome::Replanned { directive, .. }
                        | BoundaryOutcome::Online {
                            directive: Some(directive),
                            ..
                        } => directive,
                        BoundaryOutcome::Online {
                            directive: None, ..
                        } => {
                            return Err(TransitionError::Internal {
                                what: "the fake substrate presents only declared input",
                            })
                        }
                    };
                    let spent = runtime.replanning_seconds() - before;
                    trial_charge += spent;
                    replanning_total += spent;
                    replans = replans.max(runtime.replans());
                    let knowledge = if runtime.is_online() {
                        Knowledge::Online
                    } else {
                        Knowledge::Declared
                    };
                    (
                        set_of(workflow, &directive.config),
                        Some(set_of(workflow, &directive.prefetch)),
                        knowledge,
                    )
                }
                Driver::Online(policy) => {
                    let before = policy.planning_work_units();
                    let config = policy.configure(&mut model, &context, node, step)?;
                    let spent = policy.planning_work_units().saturating_sub(before) as f64
                        * workflow.curves.planning_seconds_per_work_unit;
                    trial_charge += spent;
                    replanning_total += spent;
                    (config, None, Knowledge::Online)
                }
            };
            let transition = model
                .transition(&context, node, configuration, knowledge)?
                .map_err(|infeasibility| TransitionError::OnlineNoRoom {
                    policy: code.to_string(),
                    stage: stage.id.clone(),
                    infeasibility,
                })?;
            let prefetch = match (&mut driver, planned_prefetch) {
                (_, Some(prefetch)) => prefetch,
                (Driver::Online(policy), None) => {
                    policy.prepare(&mut model, node, configuration, transition.copies, step)?
                }
                (Driver::Plan { .. }, None) => ResourceSet::EMPTY,
            };
            let readiness = transition.readiness.expected_seconds * factor;
            let stage_seconds = stage.duration_seconds() * factor;
            for at in stage.requires.iter() {
                pending.remove(&at);
            }
            for (at, _) in &transition.evictions {
                if let Some(bytes) = pending.remove(at) {
                    trial_unused = trial_unused.saturating_add(bytes);
                }
            }
            for at in prefetch.iter() {
                pending.insert(at, workflow.resources[at].bytes);
            }
            let prefetch_bytes = workflow.bytes(prefetch);
            let moved = transition
                .loaded_bytes
                .saturating_add(transition.written_back_bytes)
                .saturating_add(prefetch_bytes);
            let read = transition
                .storage_read_bytes
                .saturating_add(workflow.bytes(prefetch.difference(transition.copies)));
            let extra = workflow.bytes(configuration.difference(stage.requires));
            trial_retained += extra as f64 * stage_seconds;
            resident_byte_seconds += workflow.bytes(configuration) as f64 * stage_seconds;
            stage_seconds_total += stage_seconds;
            peak_bytes = peak_bytes.max(transition.peak.peak_bytes);
            if stage
                .deadline_seconds
                .is_some_and(|deadline| readiness > deadline)
            {
                misses += 1;
            }
            readiness_all.push(readiness);
            readiness_total += readiness;
            trial_charge += readiness;
            moved_total = moved_total.saturating_add(moved);
            read_total = read_total.saturating_add(read);
            stages += 1;
            let waiting =
                (readiness - (stage.prefill_seconds + stage.response_seconds) * factor).max(0.0);
            records.push(stage_record(
                workflow,
                template,
                code,
                trial,
                step,
                &StageRun {
                    transition: &transition,
                    required: stage.requires,
                    readiness_seconds: readiness,
                    decode_seconds: stage.decode_seconds * factor,
                    waiting_seconds: waiting,
                    moved_bytes: moved,
                    storage_read_bytes: read,
                },
            )?);
            previous_seconds = Some(stage_seconds);
            let Some(child) = draw(&mut rng, entry) else {
                break;
            };
            context = model.context_after(node, configuration, prefetch, transition.copies)?;
            node = child;
            step += 1;
        }
        trial_unused = trial_unused.saturating_add(pending.values().sum::<u64>());
        trial_charge += weights.preparation_seconds_per_byte * trial_unused as f64
            + weights.retained_seconds_per_byte_second * trial_retained;
        unused_total = unused_total.saturating_add(trial_unused);
        retained_byte_seconds_total += trial_retained;
        charged_total += trial_charge;
    }
    let trials = f64::from(config.trials);
    let provenance = Provenance::of_records(&records)?;
    let objective_nanos = workflow
        .stages
        .iter()
        .filter_map(|stage| stage.deadline_seconds)
        .fold(10.0, f64::max)
        * 1e9;
    let measured = |value: f64| -> Result<Measured<NonNegative>, TransitionError> {
        Ok(Measured::measured(NonNegative::new(value)?))
    };
    let not = Measured::not_measured;
    let objectives = ObjectiveVector {
        time_to_first_token_quantile: Quantile::P95,
        latency_objective: LatencyObjective {
            quantile: Quantile::P95,
            max_time_to_first_token_nanos: objective_nanos as u64,
        },
        time_to_first_token_nanos: measured(nearest_rank(&readiness_all, 0.95) * 1e9)?,
        throughput_under_latency_objective_tokens_per_second: not(NotMeasuredReason::NotApplicable),
        peak_gpu_memory_bytes: measured(peak_bytes as f64)?,
        retained_gpu_memory_bytes: measured(if stage_seconds_total > 0.0 {
            resident_byte_seconds / stage_seconds_total
        } else {
            0.0
        })?,
        peak_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        retained_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        transferred_bytes: measured(moved_total as f64 / trials)?,
        storage_read_bytes: measured(read_total as f64 / trials)?,
        preparation_cost_usd: not(NotMeasuredReason::NotApplicable),
        cost_per_completed_request_usd: not(NotMeasuredReason::NotApplicable),
        energy_per_completed_request_joules: not(NotMeasuredReason::InstrumentUnavailable),
        reliability_success_rate: measured(if stages > 0 {
            (stages - misses) as f64 / stages as f64
        } else {
            0.0
        })?,
    };
    let policy = match &driver {
        Driver::Plan { .. } => code.to_string(),
        Driver::Online(policy) => policy.name(),
    };
    Ok(PolicyRun {
        summary: PolicySummary {
            policy,
            trials: config.trials,
            stages,
            mean_charged_seconds: charged_total / trials,
            mean_charged_seconds_without_compile: (charged_total - compile_seconds) / trials,
            mean_readiness_seconds: readiness_total / trials,
            compile_seconds,
            replanning_seconds: replanning_total,
            unused_preparation_bytes: unused_total,
            moved_bytes: moved_total,
            retained_byte_seconds: retained_byte_seconds_total,
            peak_bytes,
            deadline_misses: misses,
            replans,
            provenance,
            objectives,
        },
        records,
    })
}

/// The nearest-rank quantile of `values`; zero for none.
fn nearest_rank(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = ((quantile * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// One stage of one fake run as a CORE-08 serving record on the fake substrate.
fn stage_record(
    workflow: &CheckedWorkflow,
    template: &RunRecord,
    code: &str,
    trial: u32,
    step: u64,
    run: &StageRun<'_>,
) -> Result<RunRecord, TransitionError> {
    let operation = OperationId::new(format!("op-{code}-{trial}-{step}"))?;
    let transition = run.transition;
    let demand = !transition.demand.is_empty()
        || transition.unhidden_preparation_seconds > 0.0
        || transition.write_back_seconds > 0.0;
    let state = if demand {
        StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: if transition.retained.intersection(run.required).is_empty() {
                CacheTier::LocalDisk
            } else {
                CacheTier::GpuMemory
            },
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }
    } else {
        StartState {
            temperature: StartTemperature::Hot,
            model_at_arrival: ModelAtArrival::ReadyToServe,
            cache_tier: CacheTier::GpuMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }
    };
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut recorder = EventRecorder::new(
        operation.clone(),
        ClockId::new(Label::new("fake-substrate")?),
        &clock,
    );
    recorder.record(EventKind::RequestAccepted);
    recorder.record(EventKind::RequestDequeued);
    if demand {
        recorder.record(EventKind::LoadStarted);
        clock.advance(seconds(run.waiting_seconds)?);
        recorder.record(EventKind::LoadCompleted);
        clock.advance(seconds(run.readiness_seconds - run.waiting_seconds)?);
    } else {
        clock.advance(seconds(run.readiness_seconds)?);
    }
    recorder.record(EventKind::TokenEmitted);
    clock.advance(seconds(run.decode_seconds)?);
    recorder.record(EventKind::RequestCompleted);
    let mut record = template.clone();
    record.attempt = AttemptIdentity {
        bench: template.attempt.bench,
        variant: Label::new(code)?,
        execution: template.attempt.execution.clone(),
        operation,
        role: AttemptRole::Initial,
        burst: trial,
        deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
    };
    record.scenario = Scenario::Serving;
    record.substrate = RunSubstrate::FakeTimeControlled;
    record.model = template.model.clone().map(|mut model| {
        model.weights = workflow.digest();
        model
    });
    record.state = Measured::measured(state);
    record.price = Measured::not_measured(NotMeasuredReason::NotApplicable);
    let not = |reason| Measured::not_measured(reason);
    record.measurements = RunMeasurements {
        output_tokens: Measured::measured(1),
        prefill_tokens_per_second: not(NotMeasuredReason::NotApplicable),
        aggregate_decode_tokens_per_second: not(NotMeasuredReason::NotApplicable),
        speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
        peak_gpu_memory_bytes: Measured::measured(transition.peak.peak_bytes),
        retained_gpu_memory_bytes: Measured::measured(
            workflow
                .bytes(transition.config)
                .min(transition.peak.peak_bytes),
        ),
        peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
        retained_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
        peak_pinned_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
        transferred_bytes: Measured::measured(run.moved_bytes),
        storage_read_bytes: Measured::measured(run.storage_read_bytes),
        energy_joules: not(NotMeasuredReason::InstrumentUnavailable),
        offload: Measured::not_measured(NotMeasuredReason::NotApplicable),
        reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
        first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
        owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
    };
    record.events = recorder.into_events();
    record.outcome = Outcome::Succeeded;
    record.validate()?;
    Ok(record)
}
