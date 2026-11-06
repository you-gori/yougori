//! BENCH-02 on fake runners (S11 line 194): A/B/A switches in every state a mode is
//! compatible with, with both S8 switch clocks, the GPU §2.1 switch overhead,
//! cache/weight/KV/graph status, tails and correctness; and the short repeated-switch run
//! of BENCH-07 (line 199), which detects a leak as a trend and makes no multi-day claim.

use std::collections::BTreeSet;

use super::corpus::{Fixture, NonceSource};
use super::faults::{FaultRecord, RecycleEvent};
use super::load::RunnerFactory;
use super::profile::{seconds, RunnerMode};
use super::resources::{
    trend_lines, CanaryTally, ResourceSample, ResourceSnapshot, ResourceTrendLine, TrendPolicy,
};
use super::rng::SeededRng;
use super::runner::{
    CanaryVerdict, FakeRunner, ModelStatus, RequestPlan, RetryPolicy, Script, ServeOutcome,
    UserScript,
};
use super::BenchError;
use crate::foundation::evidence::{BackendModeRules, BackendRelease, ModeRefusal, Optimization};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::report::{
    switch_overhead, ArrivalMode, AttemptLedger, BenchId, ClockReading, IntervalKind, Label,
    LatencyClaim, LatencyObjective, LatencySummary, LoadDescription, Measured, NoLeakClaim,
    NonNegative, NoncePlacement, NotMeasuredReason, ObjectiveVector, PercentileMethod, Quantile,
    ResourceTrend, RunRecord, RunSubstrate, SoakEvidence, StartTemperature, StateComparison,
    SwitchMode, SwitchOverhead, TrackedResource,
};
use crate::model_memory::math::bounds::{OverallSpeedup, ReadinessDispatchSpeedup, SpeedupKind};

/// The state model B is in before a switch (BENCH-02: "cold/warm/retained/sleep/preload
/// where actually compatible").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetState {
    /// Never read on this fake: a fresh disposable runner for every cycle (S8).
    Cold,
    /// In the host page cache.
    Warm,
    /// Resident in its own process.
    Retained,
    /// Asleep under a version-supported sleep.
    Sleep,
    /// Zero-copy preloaded into pinned host memory.
    Preload,
}

impl TargetState {
    pub const ALL: [Self; 5] = [
        Self::Cold,
        Self::Warm,
        Self::Retained,
        Self::Sleep,
        Self::Preload,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Retained => "retained",
            Self::Sleep => "sleep",
            Self::Preload => "preload",
        }
    }
}

/// One BENCH-02 cell: a runner mode and the state of model B.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SwitchCell {
    pub mode: RunnerMode,
    pub state: TargetState,
}

impl SwitchCell {
    fn variant(&self, leg: &str) -> Result<Label, BenchError> {
        Ok(Label::new(format!(
            "{}-{}-{leg}",
            self.mode.slug(),
            self.state.slug()
        ))?)
    }
}

/// Why a cell is not run. It is recorded as such, never filled in (S11: "untested
/// combinations are recorded as such").
#[derive(Clone, Debug, PartialEq)]
pub enum CellRefusal {
    /// The state belongs to another mode, as sleep belongs to version-supported sleep.
    StateNeedsOtherMode,
    /// S8 names a cold start only as a cold process start; a cold load inside a running
    /// process has no switch label.
    NoSwitchLabel,
    /// The release's backend-mode rules refuse it (S7; CORE-01): on vLLM 0.31.0,
    /// zero-copy preloaded weights cannot use sleep weight offloading.
    Mode(ModeRefusal),
    /// The fake cannot hold the state; names the limiting resource.
    Capacity {
        resource: &'static str,
        required_bytes: u64,
        available_bytes: u64,
    },
}

/// The S8 switch label of a compatible cell, or why the cell cannot run.
pub fn compatibility(
    cell: SwitchCell,
    release: &BackendRelease,
    rules: &BackendModeRules,
) -> Result<SwitchMode, CellRefusal> {
    let mut modes = cell.mode.backend_modes();
    if cell.state == TargetState::Preload {
        modes.insert(Optimization::ZeroCopyPreload);
    }
    rules.check(release, &modes).map_err(CellRefusal::Mode)?;
    use RunnerMode::{FullProcessRestart, RetainedProcess, VerifiedReload, VersionSupportedSleep};
    use TargetState::{Cold, Preload, Retained, Sleep, Warm};
    match (cell.mode, cell.state) {
        (RetainedProcess, Retained) => Ok(SwitchMode::HotDispatch),
        (VersionSupportedSleep, Sleep) => Ok(SwitchMode::Wake),
        (VerifiedReload | FullProcessRestart, Warm | Preload) => Ok(SwitchMode::WarmReload),
        (FullProcessRestart, Cold) => Ok(SwitchMode::ColdProcessStart),
        (VerifiedReload, Cold) => Err(CellRefusal::NoSwitchLabel),
        _ => Err(CellRefusal::StateNeedsOtherMode),
    }
}

/// An A/B/A script: A served, then `cycles` times a switch to B and a switch back. In a
/// BENCH-02 cell each switch is followed by the same request on the now-ready model, the
/// already-ready execution GPU §2.1 measures switch overhead against.
#[derive(Clone, Debug, PartialEq)]
pub struct AbaSpec {
    pub model_a: Label,
    pub model_b: Label,
    pub fixture_a: Fixture,
    pub fixture_b: Fixture,
    pub placement: NoncePlacement,
    pub max_output_tokens: u32,
    /// The scripted gap after the last output, disclosed (S8).
    pub controlled_gap_nanos: u64,
    pub cycles: u32,
    /// Independent runs of a BENCH-02 cell, each on a fresh runner and recorded as its
    /// own burst (S11: "enough independent launches"; §1.1 independent trials). A cold
    /// cell runs every cycle on a fresh runner, so it makes `trials × cycles` runs. The
    /// BENCH-07 short run is one runner by design: a trend needs one process lineage.
    pub trials: u32,
    pub deadline_nanos: u64,
    pub timeout_nanos: u64,
}

/// One direction of a cell's switches.
#[derive(Clone, Debug, PartialEq)]
pub struct LegReport {
    /// Every attempt, failures included (S8).
    pub ledger: AttemptLedger,
    pub switch_mode: SwitchMode,
    /// S8 switching clock: the last output of the previous model to the first output of
    /// this one, with the controlled gap disclosed.
    pub last_output_to_first_output: LatencySummary,
    /// S8: this model's request accepted to its first token.
    pub request_to_first_token: LatencySummary,
    /// The same request on the now-ready model right after each switch, failures
    /// included (§2.1 "an already-ready execution of the same request").
    pub ready: AttemptLedger,
    /// §2.1 switch overhead of each successful switch whose ready execution succeeded
    /// hot: the switched request accepted to its first token, less the same for the
    /// ready execution. Failed pairs stay in the two ledgers.
    pub switch_overheads: Vec<SwitchOverhead>,
    /// Cache, weight, KV and graph status on arrival and at the first token.
    pub status_at_arrival: Vec<ModelStatus>,
    pub status_at_first_token: Vec<ModelStatus>,
    /// The same requested response every time (state-corruption canaries).
    pub canaries: CanaryTally,
    pub temperature: StartTemperature,
}

impl LegReport {
    /// The GPU §1.3 objective vector of this leg's switches, so fake cells can go through
    /// the CORE-08 comparison discipline (FAST-01: "CPU fixtures validate schema and
    /// comparisons"). First-token time is the resolved percentile the latency objective
    /// names; a low-resolution one is refused (S8, S11). Memory is the largest peak and
    /// retained amount of any attempt, bytes moved are the mean per attempt and
    /// reliability is the success rate of every initial attempt. Throughput is not
    /// measured by a switch, prices do not apply to a fake and energy has no instrument.
    pub fn objectives(
        &self,
        latency_objective: LatencyObjective,
    ) -> Result<ObjectiveVector, BenchError> {
        let claim =
            LatencyClaim::from_summary(&self.request_to_first_token, latency_objective.quantile)?;
        let records = self.ledger.records();
        let values = |field: fn(&RunRecord) -> &Measured<u64>| -> Vec<u64> {
            records
                .iter()
                .filter_map(|record| field(record).value().copied())
                .collect()
        };
        let largest = |field| -> Result<Measured<NonNegative>, BenchError> {
            Ok(match values(field).into_iter().max() {
                Some(bytes) => Measured::measured(NonNegative::new(bytes as f64)?),
                None => Measured::not_measured(NotMeasuredReason::NotRecorded),
            })
        };
        let mean = |field| -> Result<Measured<NonNegative>, BenchError> {
            let values = values(field);
            if values.is_empty() {
                return Ok(Measured::not_measured(NotMeasuredReason::NotRecorded));
            }
            let total: u128 = values.iter().map(|bytes| u128::from(*bytes)).sum();
            Ok(Measured::measured(NonNegative::new(
                total as f64 / values.len() as f64,
            )?))
        };
        Ok(ObjectiveVector {
            time_to_first_token_quantile: latency_objective.quantile,
            latency_objective,
            time_to_first_token_nanos: Measured::measured(NonNegative::new(claim.value_nanos())?),
            throughput_under_latency_objective_tokens_per_second: Measured::not_measured(
                NotMeasuredReason::NotApplicable,
            ),
            peak_gpu_memory_bytes: largest(|record| &record.measurements.peak_gpu_memory_bytes)?,
            retained_gpu_memory_bytes: largest(|record| {
                &record.measurements.retained_gpu_memory_bytes
            })?,
            peak_host_memory_bytes: largest(|record| &record.measurements.peak_host_memory_bytes)?,
            retained_host_memory_bytes: largest(|record| {
                &record.measurements.retained_host_memory_bytes
            })?,
            transferred_bytes: mean(|record| &record.measurements.transferred_bytes)?,
            storage_read_bytes: mean(|record| &record.measurements.storage_read_bytes)?,
            preparation_cost_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
            cost_per_completed_request_usd: Measured::not_measured(
                NotMeasuredReason::NotApplicable,
            ),
            energy_per_completed_request_joules: Measured::not_measured(
                NotMeasuredReason::InstrumentUnavailable,
            ),
            reliability_success_rate: Measured::measured(NonNegative::new(
                self.ledger.success_rate()?.rate(),
            )?),
        })
    }
}

/// A measured cell.
#[derive(Clone, Debug, PartialEq)]
pub struct CellReport {
    pub cell: SwitchCell,
    /// The serving of A that opens each A/B/A script.
    pub a_serving: AttemptLedger,
    pub to_b: LegReport,
    pub back_to_a: LegReport,
    /// Preparation of B's state that enables the switch (§2.2: "Report the retained
    /// memory and preparation enabling dispatch"): the longest of any run of the cell.
    pub preparation_nanos: u64,
    /// What B's state keeps beside A, measured right after the preparation.
    pub retained: ResourceSnapshot,
    pub starts: Vec<RunRecord>,
    pub recycles: Vec<RecycleEvent>,
    pub faults: Vec<FaultRecord>,
}

/// A cell's result.
#[derive(Clone, Debug, PartialEq)]
pub enum CellOutcome {
    Measured(Box<CellReport>),
    NotRun {
        cell: SwitchCell,
        reason: CellRefusal,
    },
}

fn prepare(runner: &mut FakeRunner, state: TargetState, model: &Label) -> Result<u64, BenchError> {
    match state {
        TargetState::Cold => {
            runner.require_cold(model)?;
            Ok(0)
        }
        TargetState::Warm => runner.warm_host_copy(model),
        TargetState::Retained => runner.retain(model),
        TargetState::Sleep => runner.prepare_asleep(model),
        TargetState::Preload => runner.preload(model),
    }
}

/// Whether an A/B/A script follows each switch with the same request on the ready model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadyExecutions {
    /// BENCH-02: the §2.1 switch overhead needs them.
    AfterEachSwitch,
    /// BENCH-07: switches and wakes only.
    None,
}

fn aba_script(
    runner: &FakeRunner,
    cell: SwitchCell,
    spec: &AbaSpec,
    cycles: u32,
    burst: u32,
    ready: ReadyExecutions,
    recycle_after_switches: Option<u64>,
) -> Result<Script, BenchError> {
    let mut nonces = NonceSource::new(SeededRng::new(runner.seed()).fork(), spec.placement);
    let plan = |nonces: &mut NonceSource,
                variant: Label,
                model: &Label,
                fixture: &Fixture,
                switch: bool|
     -> Result<RequestPlan, BenchError> {
        Ok(RequestPlan {
            variant,
            model: model.clone(),
            request: nonces.render(fixture)?,
            max_output_tokens: spec.max_output_tokens,
            deadline_nanos: spec.deadline_nanos,
            timeout_nanos: spec.timeout_nanos,
            gap_before_nanos: if switch { spec.controlled_gap_nanos } else { 0 },
            switch_from_previous: switch,
            burst,
            check_response: switch,
        })
    };
    let mut requests = vec![plan(
        &mut nonces,
        cell.variant("a-serving")?,
        &spec.model_a,
        &spec.fixture_a,
        false,
    )?];
    let legs = [
        ("to-b", "b-ready", &spec.model_b, &spec.fixture_b),
        ("back-to-a", "a-ready", &spec.model_a, &spec.fixture_a),
    ];
    for _ in 0..cycles {
        for (switch_leg, ready_leg, model, fixture) in legs {
            requests.push(plan(
                &mut nonces,
                cell.variant(switch_leg)?,
                model,
                fixture,
                true,
            )?);
            if ready == ReadyExecutions::AfterEachSwitch {
                requests.push(plan(
                    &mut nonces,
                    cell.variant(ready_leg)?,
                    model,
                    fixture,
                    false,
                )?);
            }
        }
    }
    Ok(Script {
        bench: BenchId::Bench02,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at: runner.clock().now(),
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches,
    })
}

/// Records of one variant, in order.
fn of_variant(outcomes: &[ServeOutcome], variant: &Label) -> Vec<RunRecord> {
    outcomes
        .iter()
        .flat_map(|outcome| outcome.records.iter())
        .filter(|record| &record.attempt.variant == variant)
        .cloned()
        .collect()
}

/// §2.1 switch overhead of every switch of `variant` against the ready execution that
/// follows it in the same run. A BENCH-02 script has one user and no retries, so the
/// k-th switch and the k-th ready execution of a run belong together.
fn switch_overheads(
    outcomes: &[ServeOutcome],
    variant: &Label,
    ready_variant: &Label,
) -> Result<Vec<SwitchOverhead>, BenchError> {
    let mut overheads = Vec::new();
    for outcome in outcomes {
        let switches = outcome
            .records
            .iter()
            .filter(|record| &record.attempt.variant == variant);
        let readies = outcome
            .records
            .iter()
            .filter(|record| &record.attempt.variant == ready_variant);
        for (switched, ready) in switches.zip(readies) {
            let ready_hot = ready
                .state
                .value()
                .is_some_and(|state| state.temperature == StartTemperature::Hot);
            if switched.is_success() && ready.is_success() && ready_hot {
                overheads.push(switch_overhead(switched, ready)?);
            }
        }
    }
    Ok(overheads)
}

fn leg_report(
    outcomes: &[ServeOutcome],
    variant: &Label,
    ready_variant: &Label,
) -> Result<LegReport, BenchError> {
    let records = of_variant(outcomes, variant);
    let first = records.first().ok_or(BenchError::WrongState {
        operation: "leg report",
        reason: "the leg has no attempt",
    })?;
    let switch_mode = match first.scenario {
        crate::foundation::report::Scenario::Switching { mode, .. } => mode,
        _ => {
            return Err(BenchError::WrongState {
                operation: "leg report",
                reason: "a leg holds switching attempts",
            })
        }
    };
    let temperature =
        first
            .state
            .value()
            .map(|state| state.temperature)
            .ok_or(BenchError::WrongState {
                operation: "leg report",
                reason: "a switching attempt records its state on arrival",
            })?;
    let mut status_at_arrival = Vec::new();
    let mut status_at_first_token = Vec::new();
    let mut canaries = CanaryTally::default();
    for record in &records {
        for outcome in outcomes {
            if let Some(status) = outcome.statuses.get(&record.attempt.operation) {
                status_at_arrival.push(status.model_at_arrival);
                if let Some(at_first) = status.model_at_first_token {
                    status_at_first_token.push(at_first);
                }
            }
        }
    }
    for record in &records {
        let verdict = outcomes
            .iter()
            .find_map(|outcome| outcome.statuses.get(&record.attempt.operation))
            .and_then(|status| status.canary);
        match verdict {
            Some(CanaryVerdict::Passed) => canaries.passed += 1,
            Some(CanaryVerdict::Failed) => canaries.failed += 1,
            Some(CanaryVerdict::NotComparable) => canaries.not_comparable += 1,
            None => {}
        }
    }
    let ledger = AttemptLedger::from_records(records)?;
    let method = PercentileMethod::NearestRank;
    Ok(LegReport {
        last_output_to_first_output: LatencySummary::from_ledger(
            &ledger,
            IntervalKind::SwitchLastOutputToFirstOutput,
            method,
        )?,
        request_to_first_token: LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            method,
        )?,
        ledger,
        switch_mode,
        ready: AttemptLedger::from_records(of_variant(outcomes, ready_variant))?,
        switch_overheads: switch_overheads(outcomes, variant, ready_variant)?,
        status_at_arrival,
        status_at_first_token,
        canaries,
        temperature,
    })
}

/// Runs one BENCH-02 cell on runners from `factory`, whose profile must be in the cell's
/// mode: `spec.trials` independent runs, each its own burst. An incompatible or
/// infeasible cell is returned as not run, with its reason. A cold cell uses a fresh
/// runner for every cycle, since nothing here makes a used fake cold again (S8).
pub fn run_cell(
    factory: &RunnerFactory,
    cell: SwitchCell,
    spec: &AbaSpec,
) -> Result<CellOutcome, BenchError> {
    if factory.profile.mode != cell.mode {
        return Err(BenchError::InvalidParameter {
            field: "cell",
            reason: "the factory's profile is in another mode",
        });
    }
    if let Err(reason) = compatibility(cell, &factory.profile.release, &factory.rules) {
        return Ok(CellOutcome::NotRun { cell, reason });
    }
    if spec.cycles == 0 {
        return Err(BenchError::InvalidParameter {
            field: "cycles",
            reason: "at least one A/B/A cycle",
        });
    }
    if spec.trials == 0 {
        return Err(BenchError::InvalidParameter {
            field: "trials",
            reason: "at least one independent trial",
        });
    }
    let independent = cell.state == TargetState::Cold;
    let (runs, cycles) = if independent {
        (
            spec.cycles
                .checked_mul(spec.trials)
                .ok_or(BenchError::Overflow)?,
            1,
        )
    } else {
        (spec.trials, spec.cycles)
    };
    let mut outcomes = Vec::new();
    let mut starts = Vec::new();
    let mut preparation_nanos = 0u64;
    let mut retained = ResourceSnapshot::ZERO;
    let mut faults = Vec::new();
    for run in 0..runs {
        let (mut runner, start) =
            factory.started(10_000 + u64::from(run), &spec.model_a, BenchId::Bench02)?;
        starts.push(start);
        let before = runner.snapshot();
        let nanos = match prepare(&mut runner, cell.state, &spec.model_b) {
            Ok(nanos) => nanos,
            Err(BenchError::Capacity {
                resource,
                required_bytes,
                available_bytes,
            }) => {
                return Ok(CellOutcome::NotRun {
                    cell,
                    reason: CellRefusal::Capacity {
                        resource,
                        required_bytes,
                        available_bytes,
                    },
                })
            }
            Err(other) => return Err(other),
        };
        preparation_nanos = preparation_nanos.max(nanos);
        retained = retained.max(&runner.snapshot().saturating_sub(&before));
        let script = aba_script(
            &runner,
            cell,
            spec,
            cycles,
            run,
            ReadyExecutions::AfterEachSwitch,
            None,
        )?;
        outcomes.push(runner.serve(&script)?);
        faults.extend(runner.fault_log().iter().cloned());
    }
    let a_serving =
        AttemptLedger::from_records(of_variant(&outcomes, &cell.variant("a-serving")?))?;
    let to_b = leg_report(&outcomes, &cell.variant("to-b")?, &cell.variant("b-ready")?)?;
    let back_to_a = leg_report(
        &outcomes,
        &cell.variant("back-to-a")?,
        &cell.variant("a-ready")?,
    )?;
    let recycles = outcomes
        .iter()
        .flat_map(|outcome| outcome.recycles.iter().cloned())
        .collect();
    Ok(CellOutcome::Measured(Box::new(CellReport {
        cell,
        a_serving,
        to_b,
        back_to_a,
        preparation_nanos,
        retained,
        starts,
        recycles,
        faults,
    })))
}

/// Every BENCH-02 cell: each runner mode against each state of B.
#[derive(Clone, Debug, PartialEq)]
pub struct SwitchMatrix {
    pub cells: Vec<CellOutcome>,
}

/// A readiness comparison of two cells (GPU §2.2): a readiness/dispatch ratio that
/// carries the candidate's retained memory and preparation, labelled by the start states
/// it compares (§2.1).
#[derive(Clone, Debug, PartialEq)]
pub struct ReadinessComparison {
    pub baseline: SwitchCell,
    pub candidate: SwitchCell,
    pub states: StateComparison,
    pub speedup: ReadinessDispatchSpeedup,
}

impl ReadinessComparison {
    /// The ratio as a cold-load improvement, which only a cold-versus-cold comparison is
    /// (§2.1: "Do not call warm-versus-cold comparisons cold-load improvements").
    pub fn cold_load_improvement(&self) -> Result<f64, BenchError> {
        if self.states == StateComparison::ColdLoad {
            Ok(self.speedup.ratio())
        } else {
            Err(BenchError::NotColdLoad)
        }
    }

    /// What the ratio describes: readiness and dispatch, never generation throughput.
    pub fn kind(&self) -> SpeedupKind {
        self.speedup.kind()
    }

    /// GPU §2.2 Amdahl bound on a whole workflow in which switching takes
    /// `switching_fraction` of the time.
    pub fn workflow_bound(&self, switching_fraction: f64) -> Result<OverallSpeedup, BenchError> {
        Ok(OverallSpeedup::amdahl(
            switching_fraction,
            self.speedup.ratio(),
        )?)
    }
}

/// The T02 start-state label of a comparison; a cold candidate against a warmer
/// baseline has none.
fn state_comparison(
    candidate: StartTemperature,
    baseline: StartTemperature,
) -> Result<StateComparison, BenchError> {
    let states = match (candidate, baseline) {
        (StartTemperature::Cold, StartTemperature::Cold) => StateComparison::ColdLoad,
        (StartTemperature::Warm, StartTemperature::Warm) => StateComparison::WarmLoad,
        (StartTemperature::Hot, StartTemperature::Hot) => StateComparison::HotDispatch,
        (_, StartTemperature::Cold) => StateComparison::WarmVersusCold,
        _ => {
            return Err(BenchError::InvalidParameter {
                field: "comparison",
                reason: "a colder candidate than its baseline has no state label",
            })
        }
    };
    states.check(candidate, baseline)?;
    Ok(states)
}

fn median_seconds(summary: &LatencySummary) -> Result<f64, BenchError> {
    summary
        .percentile(Quantile::P50)
        .and_then(|estimate| estimate.value_nanos.value().copied())
        .map(|nanos| nanos / 1e9)
        .ok_or(BenchError::WrongState {
            operation: "readiness",
            reason: "the cell has no successful switch",
        })
}

impl SwitchMatrix {
    /// Runs every cell: `factory`'s profile in each mode, against each state of B.
    pub fn run(factory: &RunnerFactory, spec: &AbaSpec) -> Result<Self, BenchError> {
        let mut cells = Vec::new();
        for mode in RunnerMode::ALL {
            let mut moded = factory.clone();
            moded.profile.mode = mode;
            for state in TargetState::ALL {
                cells.push(run_cell(&moded, SwitchCell { mode, state }, spec)?);
            }
        }
        Ok(Self { cells })
    }

    pub fn measured(&self) -> impl Iterator<Item = &CellReport> {
        self.cells.iter().filter_map(|outcome| match outcome {
            CellOutcome::Measured(report) => Some(report.as_ref()),
            CellOutcome::NotRun { .. } => None,
        })
    }

    pub fn outcome(&self, cell: SwitchCell) -> Option<&CellOutcome> {
        self.cells.iter().find(|outcome| match outcome {
            CellOutcome::Measured(report) => report.cell == cell,
            CellOutcome::NotRun { cell: other, .. } => *other == cell,
        })
    }

    /// The ordinary user workflow baseline (§2.1): a full process restart with the
    /// weights in the page cache.
    pub fn ordinary_workflow_baseline(&self) -> Option<&CellReport> {
        self.measured().find(|report| {
            report.cell
                == SwitchCell {
                    mode: RunnerMode::FullProcessRestart,
                    state: TargetState::Warm,
                }
        })
    }

    /// The strongest compatible baseline (§2.1): the measured cell with the lowest median
    /// time from B's request to B's first token.
    pub fn strongest_compatible_baseline(&self) -> Option<&CellReport> {
        self.measured()
            .filter_map(|report| {
                median_seconds(&report.to_b.request_to_first_token)
                    .ok()
                    .map(|median| (median, report))
            })
            .min_by(|left, right| left.0.total_cmp(&right.0))
            .map(|(_, report)| report)
    }

    /// The readiness ratio of `candidate` over `baseline` on the median time from B's
    /// request to B's first token, which leaves out the disclosed gap, with the
    /// candidate's retained VRAM and preparation (GPU §2.2).
    pub fn readiness(
        baseline: &CellReport,
        candidate: &CellReport,
    ) -> Result<ReadinessComparison, BenchError> {
        let states = state_comparison(candidate.to_b.temperature, baseline.to_b.temperature)?;
        let speedup = ReadinessDispatchSpeedup::new(
            median_seconds(&baseline.to_b.request_to_first_token)?,
            median_seconds(&candidate.to_b.request_to_first_token)?,
            candidate.retained.vram_bytes,
            seconds(candidate.preparation_nanos),
        )?;
        Ok(ReadinessComparison {
            baseline: baseline.cell,
            candidate: candidate.cell,
            states,
            speedup,
        })
    }
}

/// The short repeated-switch run of BENCH-07.
#[derive(Clone, Debug, PartialEq)]
pub struct ShortRunReport {
    pub cell: SwitchCell,
    pub switches: u64,
    pub simulated_nanos: u64,
    /// The tracked resources after every return to A, when the runner is idle.
    pub samples: Vec<ResourceSample>,
    pub trends: Vec<ResourceTrendLine>,
    /// Every recycle, each with its latency and cost (S10).
    pub recycles: Vec<RecycleEvent>,
    pub canaries: CanaryTally,
    /// Every attempt of the run, failures included (S8): the opening serving of A and
    /// the switches each way.
    pub a_serving: AttemptLedger,
    pub to_b: AttemptLedger,
    pub back_to_a: AttemptLedger,
    /// Least-squares drift of the switch clock to B per cycle; a short run's p99 drift is
    /// not measurable.
    pub switch_clock_drift_nanos_per_cycle: f64,
    policy: TrendPolicy,
}

impl ShortRunReport {
    /// Resources whose trend shows a leak in any recycle segment.
    pub fn leaking(&self) -> BTreeSet<TrackedResource> {
        self.trends
            .iter()
            .filter(|line| line.leaking)
            .map(|line| line.resource)
            .collect()
    }

    /// The run as CORE-08 soak evidence, for the record. It names the fake substrate, so
    /// CORE-08 refuses a no-leak claim from it as well.
    pub fn soak_evidence(&self) -> SoakEvidence {
        let first = self.samples.first().map(|sample| sample.snapshot);
        let last = self.samples.last().map(|sample| sample.snapshot);
        let tolerance = self.policy.tolerance_per_switch();
        SoakEvidence {
            substrate: RunSubstrate::FakeTimeControlled,
            duration_seconds: self.simulated_nanos / 1_000_000_000,
            switch_or_wake_cycles: self.switches,
            recycles: self.recycles.len() as u64,
            canary_failures: self.canaries.failed,
            trends: TrackedResource::ALL
                .iter()
                .map(|resource| ResourceTrend {
                    resource: *resource,
                    first: first.map_or(0, |snapshot| snapshot.get(*resource)),
                    last: last.map_or(0, |snapshot| snapshot.get(*resource)),
                    allowed_growth: tolerance.get(*resource).saturating_mul(self.switches),
                })
                .collect(),
        }
    }

    /// Never: a fake run, however long its simulated time, is not a multi-day soak in a
    /// dedicated environment (S7: "No process or snapshot mode receives a no-leak claim
    /// from a short run"; BENCH-07).
    pub fn claim_no_leak(&self) -> Result<NoLeakClaim, BenchError> {
        Err(BenchError::NoLeakClaimFromFake {
            simulated_seconds: self.simulated_nanos / 1_000_000_000,
            switches: self.switches,
        })
    }
}

fn slope(values: &[f64]) -> f64 {
    let count = values.len() as f64;
    if values.len() < 2 {
        return 0.0;
    }
    let mean_x = (count - 1.0) / 2.0;
    let mean_y = values.iter().sum::<f64>() / count;
    let (numerator, denominator) = values.iter().enumerate().fold(
        (0.0f64, 0.0f64),
        |(numerator, denominator), (index, value)| {
            let dx = index as f64 - mean_x;
            (numerator + dx * (value - mean_y), denominator + dx * dx)
        },
    );
    numerator / denominator
}

/// BENCH-07 on a fake: `spec.cycles` A/B/A cycles on one runner, sampling every tracked
/// resource after each return to A, with an optional planned recycle. A leak shows as a
/// trend within a recycle segment; the report makes no no-leak claim.
pub fn short_repeated_switch_run(
    factory: &RunnerFactory,
    cell: SwitchCell,
    spec: &AbaSpec,
    policy: TrendPolicy,
    recycle_after_switches: Option<u64>,
) -> Result<ShortRunReport, BenchError> {
    if cell.state == TargetState::Cold {
        return Err(BenchError::ColdStateUnavailable {
            model: spec.model_b.to_string(),
        });
    }
    if let Err(reason) = compatibility(cell, &factory.profile.release, &factory.rules) {
        return Err(match reason {
            CellRefusal::Mode(refusal) => BenchError::Mode(refusal),
            _ => BenchError::WrongState {
                operation: "short repeated-switch run",
                reason: "the cell is not compatible",
            },
        });
    }
    let (mut runner, _start) = factory.started(20_000, &spec.model_a, BenchId::Bench07)?;
    prepare(&mut runner, cell.state, &spec.model_b)?;
    let started: MonotonicTime = runner.clock().now();
    let switches_before = runner.switches();
    let mut script = aba_script(
        &runner,
        cell,
        spec,
        spec.cycles,
        0,
        ReadyExecutions::None,
        recycle_after_switches,
    )?;
    script.bench = BenchId::Bench07;
    let outcome = runner.serve(&script)?;
    let back_variant = cell.variant("back-to-a")?;
    let to_b_variant = cell.variant("to-b")?;
    let serving_variant = cell.variant("a-serving")?;
    let back: BTreeSet<_> = outcome
        .records
        .iter()
        .filter(|record| record.attempt.variant == back_variant)
        .map(|record| record.attempt.operation.clone())
        .collect();
    let samples: Vec<ResourceSample> = outcome
        .samples
        .iter()
        .filter(|sample| back.contains(&sample.operation))
        .zip(0u64..)
        .map(|(sample, cycle)| ResourceSample {
            cycle,
            at: sample.at,
            segment: sample.recycles_before,
            snapshot: sample.snapshot,
        })
        .collect();
    let trends = trend_lines(&samples, &policy, 2)?;
    let to_b_records: Vec<RunRecord> = outcome
        .records
        .iter()
        .filter(|record| record.attempt.variant == to_b_variant)
        .cloned()
        .collect();
    let clock_values: Vec<f64> = to_b_records
        .iter()
        .filter(|record| record.is_success())
        .filter_map(|record| match record.clock_reading() {
            Ok(ClockReading::Switching(clock)) => {
                Some(clock.last_output_to_first_output.elapsed_nanos() as f64)
            }
            _ => None,
        })
        .collect();
    let back_records: Vec<RunRecord> = outcome
        .records
        .iter()
        .filter(|record| record.attempt.variant == back_variant)
        .cloned()
        .collect();
    Ok(ShortRunReport {
        cell,
        switches: runner.switches().saturating_sub(switches_before),
        simulated_nanos: runner
            .clock()
            .now()
            .saturating_duration_since(started)
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX),
        samples,
        trends,
        recycles: outcome.recycles.clone(),
        canaries: outcome.canaries,
        a_serving: AttemptLedger::from_records(of_variant(
            std::slice::from_ref(&outcome),
            &serving_variant,
        ))?,
        to_b: AttemptLedger::from_records(to_b_records)?,
        back_to_a: AttemptLedger::from_records(back_records)?,
        switch_clock_drift_nanos_per_cycle: slope(&clock_values),
        policy,
    })
}
