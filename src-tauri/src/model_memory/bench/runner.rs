//! The fake runner (S10 line 183; rollout T12): the four baseline modes over
//! continuous-batching serving, with injected faults, driven by a
//! [`ManualClock`] with seeded variation.
//!
//! It is a discrete-event simulation: it works out when each event happens, moves the
//! manual clock to that time and records the event through a CORE-08
//! [`EventRecorder`], so every timestamp comes from the clock and the clock never moves
//! back. Every attempt becomes a [`RunRecord`]; a recycle becomes a stage record.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::corpus::RenderedRequest;
use super::faults::{
    FaultClass, FaultKind, FaultRecord, RecycleCause, RecycleCost, RecycleEvent, ScheduledFault,
};
use super::profile::{seconds, ModelSpec, RunnerMode, RunnerProfile, NANOS_PER_SECOND};
use super::resources::{CanaryTally, ResourceSnapshot};
use super::rng::SeededRng;
use super::BenchError;
use crate::foundation::evidence::{BackendModeRules, Optimization};
use crate::foundation::ids::{
    digest, Clock, Digest, DigestBuilder, ExecutionId, ManualClock, MonotonicTime, OperationId,
};
use crate::foundation::report::{
    ArrivalMode, AttemptIdentity, AttemptRole, BenchId, BuildIdentity, CacheTier,
    ClientDescription, ClientPlacement, ClockId, ColdProvenance, CpuDescription, EngineIdentity,
    EventKind, EventRecorder, FailureKind, GpuDescription, HostDescription, IntervalKind, Label,
    LaunchDescription, LoadDescription, Measured, ModelAtArrival, ModelIdentity, ModelRevision,
    NonNegative, NotMeasuredReason, Offload, Outcome, Precision, PrefillMode, RunMeasurements,
    RunRecord, RunSubstrate, Sampling, Scenario, SchemaVersion, StartState, StartTemperature,
    SwitchMode, Workload,
};
use crate::model_memory::math::overlap::{
    first_token, no_stall, Dependency, DependencyKind, GroupRequirement, GroupTiming, NoStall,
};

/// The fake runner's version, part of its S8 build identity.
pub const FAKE_RUNNER_VERSION: &str = "1";

/// Domain of the plan identity written into every record's build identity (S8).
pub const PLAN_DIGEST_DOMAIN: &str = "yougori/bench/plan/v1";

const MODEL_DIGEST_DOMAIN: &str = "yougori/bench/fake-model/v1";
const RESPONSE_DIGEST_DOMAIN: &str = "yougori/bench/fake-response/v1";
const CLOCK_LABEL: &str = "fake-manual-clock";
const LICENSE: &str = "LicenseRef-yougori-synthetic";

/// The CORE-08 clock every event of the fake runners is stamped on.
pub fn clock_id() -> Result<ClockId, BenchError> {
    Ok(ClockId::new(label(CLOCK_LABEL)?))
}

/// Where a model's weights are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Residency {
    Resident,
    /// Offloaded to pinned host memory by a version-supported sleep; the process lives.
    Asleep,
    NotLoaded,
}

/// The host copy of a model's weights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCopy {
    /// Never read on this host.
    None,
    PageCache,
    /// A zero-copy preload in pinned host memory.
    Preloaded,
}

/// BENCH-02 cache, weight, KV and graph status of one model at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelStatus {
    pub residency: Residency,
    pub host_copy: HostCopy,
    pub kv_allocated: bool,
    pub graphs_captured: bool,
}

/// What a response comparison rests on (S13 FAST-01: "Temperature zero does not
/// establish token identity").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityBasis {
    /// The fake declares that the same request always yields the same response.
    DeclaredDeterministicFake,
    /// Greedy sampling alone, which is not enough to claim identical tokens.
    TemperatureZeroOnly,
}

/// Whether two responses are the same tokens; refused when the basis cannot establish it.
pub fn same_response(
    expected: &Digest,
    actual: &Digest,
    basis: IdentityBasis,
) -> Result<bool, BenchError> {
    match basis {
        IdentityBasis::DeclaredDeterministicFake => Ok(expected == actual),
        IdentityBasis::TemperatureZeroOnly => Err(BenchError::TokenIdentityNotEstablished),
    }
}

/// One request of a script.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestPlan {
    /// The case variant its record belongs to.
    pub variant: Label,
    pub model: Label,
    pub request: RenderedRequest,
    pub max_output_tokens: u32,
    /// The deadline on the scenario's primary interval (S8).
    pub deadline_nanos: u64,
    /// When the client gives up, after arrival.
    pub timeout_nanos: u64,
    /// Time after the previous request of the same user ends; for a switch, the
    /// controlled gap S8 discloses.
    pub gap_before_nanos: u64,
    /// Measure this request on the S8 switching clock from the previous request's last
    /// output.
    pub switch_from_previous: bool,
    pub burst: u32,
    /// Compare the response with the expected one: a state-corruption canary (S10).
    pub check_response: bool,
}

/// Retries are separate results linked to their first attempt (S8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_nanos: u64,
}

impl RetryPolicy {
    pub const NONE: Self = Self {
        max_retries: 0,
        backoff_nanos: 0,
    };
}

/// One client stream: its requests in order, each sent after the previous one ends.
#[derive(Clone, Debug, PartialEq)]
pub struct UserScript {
    pub start_at: MonotonicTime,
    pub requests: Vec<RequestPlan>,
    pub retry: RetryPolicy,
}

/// A run: its case, its load description and its users.
#[derive(Clone, Debug, PartialEq)]
pub struct Script {
    pub bench: BenchId,
    pub load: LoadDescription,
    pub users: Vec<UserScript>,
    /// Recycle once this many switches have passed, as a planned and recorded recovery
    /// event; users wait for it.
    pub recycle_after_switches: Option<u64>,
}

/// How a load overlapped the first step (GPU §2.6).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoadOverlap {
    pub execute_while_load: bool,
    /// Whether execution waited for loading after the first layer group.
    pub no_stall: NoStall,
    pub first_token_after_load_start_nanos: u64,
}

/// What the runner saw for one attempt beyond its record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AttemptStatus {
    pub model_at_arrival: ModelStatus,
    pub model_at_first_token: Option<ModelStatus>,
    pub switch: Option<SwitchMode>,
    pub overlap: Option<LoadOverlap>,
    /// The state-corruption canary, for requests that check their response.
    pub canary: Option<CanaryVerdict>,
}

/// The tracked resources right after an attempt ended.
#[derive(Clone, Debug, PartialEq)]
pub struct AttemptSample {
    pub operation: OperationId,
    pub at: MonotonicTime,
    pub snapshot: ResourceSnapshot,
    pub recycles_before: u32,
}

/// The first arrival, the end of the first user's last request (the steady window's
/// end) and the last end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunWindow {
    pub first_arrival: MonotonicTime,
    pub steady_end: MonotonicTime,
    pub last_end: MonotonicTime,
}

/// Everything a run produced.
#[derive(Clone, Debug, PartialEq)]
pub struct ServeOutcome {
    /// Every attempt, in the order it ended.
    pub records: Vec<RunRecord>,
    pub statuses: BTreeMap<OperationId, AttemptStatus>,
    pub samples: Vec<AttemptSample>,
    pub canaries: CanaryTally,
    pub window: Option<RunWindow>,
    /// Recycles during this run.
    pub recycles: Vec<RecycleEvent>,
    pub peak: ResourceSnapshot,
}

struct ModelSlot {
    spec: ModelSpec,
    residency: Residency,
    host_copy: HostCopy,
    ever_read: bool,
}

/// A state-corruption canary's result (S10). Without a declared deterministic fake the
/// response cannot be compared, which is never a pass (S13 FAST-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanaryVerdict {
    Passed,
    Failed,
    NotComparable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Queued,
    Transition,
    Active,
    /// The engine finished but the completion event was lost; the client waits.
    AwaitingTimeout,
    Done,
}

struct Attempt {
    user: usize,
    plan: usize,
    role: AttemptRole,
    operation: OperationId,
    recorder: Option<EventRecorder<Arc<ManualClock>>>,
    arrival: u64,
    timeout_at: u64,
    /// When the previous request's last output was recorded, for a switch.
    switch_from: Option<u64>,
    canary: Option<CanaryVerdict>,
    state: StartState,
    phase: Phase,
    stall_fault: Option<usize>,
    lost_fault: Option<usize>,
    warm_prefix_missed: bool,
    prefix_hit: bool,
    generated: u64,
    uncached_tokens: u64,
    kv_reserved_bytes: u64,
    first_token: Option<u64>,
    last_token: Option<u64>,
    batch_tokens_after_first: u64,
    prefill_nanos: u64,
    peak: ResourceSnapshot,
    transferred_bytes: u64,
    storage_read_bytes: u64,
    status: AttemptStatus,
}

struct UserState {
    next: usize,
    next_arrival: Option<u64>,
    retry: Option<(OperationId, u32)>,
    /// The next switch attempt, its model-A final output already recorded at the time.
    prepared: Option<(OperationId, EventRecorder<Arc<ManualClock>>, u64)>,
    last_end: Option<u64>,
    live: bool,
}

/// The parts of a CORE-08 stage record (§2.1 boundaries).
struct StageParts {
    bench: BenchId,
    variant: Label,
    operation: OperationId,
    primary: IntervalKind,
    load: LoadDescription,
    recorder: EventRecorder<Arc<ManualClock>>,
    outcome: Outcome,
    peak: ResourceSnapshot,
    end: ResourceSnapshot,
    transferred_bytes: u64,
    storage_read_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Park {
    Sleep,
    Unload,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Demand {
    Dispatch,
    Wake,
    Load,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Move {
    Park { model: Label, park: Park },
    DemandStarted,
    Ready,
}

struct Transition {
    target: Label,
    demand: Demand,
    waiting: Vec<usize>,
    moves: VecDeque<(u64, Move)>,
    first_step_end: u64,
    overlap: Option<LoadOverlap>,
    transferred_bytes: u64,
    storage_read_bytes: u64,
    starts_process: bool,
    switch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecycleMove {
    RuntimeInitialized,
    WeightsUsable { model: Label },
    EngineReady { model: Label },
    Restored { model: Label, residency: Residency },
    Completed,
}

struct Recycle {
    cause: RecycleCause,
    started_at: u64,
    operation: OperationId,
    recorder: EventRecorder<Arc<ManualClock>>,
    moves: VecDeque<(u64, RecycleMove)>,
    before: ResourceSnapshot,
    peak: ResourceSnapshot,
    cost: RecycleCost,
    fault: Option<usize>,
    bench: BenchId,
    load: LoadDescription,
}

enum Activity {
    Idle,
    Step { ends_at: u64 },
    Transition(Box<Transition>),
    Recycle(Box<Recycle>),
}

struct Run<'a> {
    script: &'a Script,
    attempts: Vec<Attempt>,
    users: Vec<UserState>,
    queue: VecDeque<usize>,
    active: Vec<usize>,
    activity: Activity,
    stalled_until: u64,
    hold_until: u64,
    out: ServeOutcome,
}

/// The fake runner: one profile, one manual clock, one seeded generator.
pub struct FakeRunner {
    profile: RunnerProfile,
    rules: BackendModeRules,
    clock: Arc<ManualClock>,
    clock_id: ClockId,
    rng: SeededRng,
    seed: u64,
    execution: ExecutionId,
    build: BuildIdentity,
    launch: LaunchDescription,
    host: HostDescription,
    models: BTreeMap<Label, ModelSlot>,
    serving: Option<Label>,
    engine_up: bool,
    leaked: ResourceSnapshot,
    switches: u64,
    switches_since_recycle: u64,
    kv_in_use_bytes: u64,
    prefix_cache: BTreeSet<(Label, Digest)>,
    pending_faults: Vec<usize>,
    armed: Vec<usize>,
    fault_log: Vec<FaultRecord>,
    recycles: Vec<RecycleEvent>,
    next_operation: u64,
}

fn label(value: &str) -> Result<Label, BenchError> {
    Ok(Label::new(value)?)
}

fn failed(class: FaultClass) -> Result<Outcome, BenchError> {
    failure(class.failure, class.component, class.code)
}

fn failure(failure: FailureKind, component: &str, code: &str) -> Result<Outcome, BenchError> {
    Ok(Outcome::Failed {
        failure,
        component: label(component)?,
        code: label(code)?,
    })
}

fn add(left: u64, right: u64) -> Result<u64, BenchError> {
    left.checked_add(right).ok_or(BenchError::Overflow)
}

fn nanos_of(seconds: f64) -> Result<u64, BenchError> {
    let nanos = (seconds * NANOS_PER_SECOND as f64).round();
    if nanos.is_finite() && nanos >= 0.0 && nanos <= u64::MAX as f64 {
        Ok(nanos as u64)
    } else {
        Err(BenchError::Overflow)
    }
}

fn rate(count: u64, nanos: u64) -> Result<Measured<NonNegative>, BenchError> {
    if nanos == 0 {
        return Ok(Measured::not_measured(NotMeasuredReason::ZeroElapsedTime));
    }
    Ok(Measured::measured(NonNegative::new(
        count as f64 / seconds(nanos),
    )?))
}

/// The S8 switch label of a start state: hot dispatch, wake, warm reload or cold process
/// start.
pub fn switch_mode_of(state: &StartState) -> SwitchMode {
    match (state.temperature, state.model_at_arrival) {
        (StartTemperature::Hot, _) => SwitchMode::HotDispatch,
        (_, ModelAtArrival::Asleep) => SwitchMode::Wake,
        (StartTemperature::Cold, _) => SwitchMode::ColdProcessStart,
        _ => SwitchMode::WarmReload,
    }
}

impl FakeRunner {
    /// A fresh runner: no process, every model unread. Refuses an invalid profile and a
    /// mode whose backend modes the release does not record (S7 "version-supported
    /// sleep"; CORE-01 rules).
    pub fn new(
        profile: RunnerProfile,
        rules: BackendModeRules,
        clock: Arc<ManualClock>,
        seed: u64,
        execution: ExecutionId,
    ) -> Result<Self, BenchError> {
        profile.validate()?;
        rules.check(&profile.release, &profile.mode.backend_modes())?;
        let runner_build = profile.build_digest()?;
        let build = BuildIdentity {
            plan: digest(
                PLAN_DIGEST_DOMAIN,
                &[b"combined-gpu-memory-and-vm-sandbox-plan", b"T12"],
            ),
            runner_build,
            runner_version: label(FAKE_RUNNER_VERSION)?,
        };
        let launch = LaunchDescription {
            image: runner_build,
            backend: label(&format!(
                "simulated-{}-{}",
                profile.release.backend.tag(),
                profile.release.version.as_str()
            ))?,
        };
        let host = HostDescription {
            os: label("simulated")?,
            os_version: label("fake-time-controlled")?,
            cpu: CpuDescription {
                model: label("simulated")?,
                logical_cores: 1,
            },
            host_memory_bytes: profile.host.host_memory_bytes,
            gpus: Measured::measured(vec![GpuDescription {
                model: label("simulated-gpu")?,
                memory_bytes: profile.host.vram_capacity_bytes,
            }]),
            gpu_driver: Measured::not_measured(NotMeasuredReason::NotApplicable),
            gpu_power_clock: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            power_source: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            displays_on_gpu: Measured::not_measured(NotMeasuredReason::NotApplicable),
        };
        let models = profile
            .models
            .iter()
            .map(|spec| {
                (
                    spec.name.clone(),
                    ModelSlot {
                        spec: spec.clone(),
                        residency: Residency::NotLoaded,
                        host_copy: HostCopy::None,
                        ever_read: false,
                    },
                )
            })
            .collect();
        Ok(Self {
            profile,
            rules,
            clock,
            clock_id: clock_id()?,
            rng: SeededRng::new(seed),
            seed,
            execution,
            build,
            launch,
            host,
            models,
            serving: None,
            engine_up: false,
            leaked: ResourceSnapshot::ZERO,
            switches: 0,
            switches_since_recycle: 0,
            kv_in_use_bytes: 0,
            prefix_cache: BTreeSet::new(),
            pending_faults: Vec::new(),
            armed: Vec::new(),
            fault_log: Vec::new(),
            recycles: Vec::new(),
            next_operation: 0,
        })
    }

    pub fn profile(&self) -> &RunnerProfile {
        &self.profile
    }

    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.clock
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Switches since the runner was made.
    pub fn switches(&self) -> u64 {
        self.switches
    }

    /// The model whose requests the engine batches now.
    pub fn serving(&self) -> Option<&Label> {
        self.serving.as_ref()
    }

    /// The raw data of every injected fault (S8).
    pub fn fault_log(&self) -> &[FaultRecord] {
        &self.fault_log
    }

    /// Every recycle since the runner was made (S10).
    pub fn recycles(&self) -> &[RecycleEvent] {
        &self.recycles
    }

    fn now(&self) -> u64 {
        self.clock.now().as_nanos()
    }

    fn advance_to(&self, at: u64) -> Result<(), BenchError> {
        if self.now() > at {
            return Err(BenchError::ClockAhead);
        }
        self.clock.advance_to(MonotonicTime::from_nanos(at));
        Ok(())
    }

    fn advance_by(&self, nanos: u64) -> Result<(), BenchError> {
        self.advance_to(add(self.now(), nanos)?)
    }

    fn vary(&mut self, nanos: u64) -> u64 {
        self.rng.vary_nanos(nanos, self.profile.variation)
    }

    fn slot(&self, model: &Label) -> Result<&ModelSlot, BenchError> {
        self.models
            .get(model)
            .ok_or_else(|| BenchError::UnknownModel {
                model: model.to_string(),
            })
    }

    fn slot_mut(&mut self, model: &Label) -> Result<&mut ModelSlot, BenchError> {
        self.models
            .get_mut(model)
            .ok_or_else(|| BenchError::UnknownModel {
                model: model.to_string(),
            })
    }

    fn next_operation_id(&mut self) -> Result<OperationId, BenchError> {
        self.next_operation = add(self.next_operation, 1)?;
        OperationId::new(format!("op-{:016x}-{}", self.seed, self.next_operation)).map_err(|_| {
            BenchError::InvalidParameter {
                field: "operation",
                reason: "not a valid operation id",
            }
        })
    }

    fn recorder(&self, operation: OperationId) -> EventRecorder<Arc<ManualClock>> {
        EventRecorder::new(operation, self.clock_id.clone(), Arc::clone(&self.clock))
    }

    fn corrupted(&self) -> bool {
        matches!(self.profile.corrupt_state_after_switches, Some(after) if self.switches_since_recycle >= after)
    }

    fn processes(&self) -> u64 {
        match self.profile.mode {
            RunnerMode::VerifiedReload => u64::from(self.engine_up),
            _ => self
                .models
                .values()
                .filter(|slot| slot.residency != Residency::NotLoaded)
                .count() as u64,
        }
    }

    /// Every S10 resource now: per-process footprints, resident weights, graphs,
    /// communicators and allocations, KV in use, offloaded and preloaded pinned memory,
    /// and whatever a leaky fake left behind.
    pub fn snapshot(&self) -> ResourceSnapshot {
        let footprint = &self.profile.footprint;
        let processes = self.processes();
        let mut snapshot = ResourceSnapshot {
            vram_bytes: processes
                .saturating_mul(footprint.context_vram_bytes)
                .saturating_add(self.kv_in_use_bytes),
            rss_bytes: processes.saturating_mul(footprint.rss_bytes),
            file_descriptors: processes.saturating_mul(footprint.file_descriptors),
            gpu_contexts: processes,
            ..ResourceSnapshot::ZERO
        };
        for slot in self.models.values() {
            let spec = &slot.spec;
            match slot.residency {
                Residency::Resident => {
                    snapshot.vram_bytes = snapshot.vram_bytes.saturating_add(spec.weights_bytes);
                    snapshot.cuda_graphs = snapshot.cuda_graphs.saturating_add(spec.cuda_graphs);
                    snapshot.communicators =
                        snapshot.communicators.saturating_add(spec.communicators);
                    snapshot.allocation_references = snapshot
                        .allocation_references
                        .saturating_add(spec.weight_allocations)
                        .saturating_add(footprint.kv_pool_allocations);
                }
                Residency::Asleep => {
                    snapshot.pinned_host_bytes = snapshot
                        .pinned_host_bytes
                        .saturating_add(spec.weights_bytes);
                    snapshot.communicators =
                        snapshot.communicators.saturating_add(spec.communicators);
                }
                Residency::NotLoaded => {}
            }
            if slot.host_copy == HostCopy::Preloaded {
                snapshot.pinned_host_bytes = snapshot
                    .pinned_host_bytes
                    .saturating_add(spec.weights_bytes);
            }
        }
        snapshot.saturating_add(&self.leaked)
    }

    /// BENCH-02 status of `model`.
    pub fn status(&self, model: &Label) -> Result<ModelStatus, BenchError> {
        let slot = self.slot(model)?;
        let resident = slot.residency == Residency::Resident;
        Ok(ModelStatus {
            residency: slot.residency,
            host_copy: slot.host_copy,
            kv_allocated: resident,
            graphs_captured: resident && slot.spec.cuda_graphs > 0,
        })
    }

    /// S8: a cold baseline comes from a fresh fake. A model this runner ever read is not
    /// cold, and nothing here flushes a cache to pretend it is.
    pub fn require_cold(&self, model: &Label) -> Result<(), BenchError> {
        if self.slot(model)?.ever_read {
            return Err(BenchError::ColdStateUnavailable {
                model: model.to_string(),
            });
        }
        Ok(())
    }

    fn check_vram(&self, extra_bytes: u64) -> Result<(), BenchError> {
        let required = self.snapshot().vram_bytes.saturating_add(extra_bytes);
        if required > self.profile.host.vram_capacity_bytes {
            return Err(BenchError::Capacity {
                resource: "vram",
                required_bytes: required,
                available_bytes: self.profile.host.vram_capacity_bytes,
            });
        }
        Ok(())
    }

    fn check_pinned(&self, extra_bytes: u64) -> Result<(), BenchError> {
        let required = self
            .snapshot()
            .pinned_host_bytes
            .saturating_add(extra_bytes);
        if required > self.profile.host.pinned_host_capacity_bytes {
            return Err(BenchError::Capacity {
                resource: "pinned-host-memory",
                required_bytes: required,
                available_bytes: self.profile.host.pinned_host_capacity_bytes,
            });
        }
        Ok(())
    }

    fn load_nanos(slot: &ModelSlot) -> u64 {
        match slot.host_copy {
            HostCopy::None => slot.spec.timings.cold_load_nanos,
            HostCopy::PageCache | HostCopy::Preloaded => slot.spec.timings.warm_load_nanos,
        }
    }

    fn mark_loaded(slot: &mut ModelSlot) {
        slot.residency = Residency::Resident;
        slot.ever_read = true;
        if slot.host_copy == HostCopy::None {
            slot.host_copy = HostCopy::PageCache;
        }
    }

    /// Starts `model` on a runner with nothing loaded: process launch, a verified load
    /// and graph capture. Setup, not a measured attempt; its §2.1 stages are recorded.
    pub fn start(&mut self, model: &Label, bench: BenchId) -> Result<RunRecord, BenchError> {
        let slot = self.slot(model)?;
        if slot.residency != Residency::NotLoaded || self.serving.is_some() {
            return Err(BenchError::WrongState {
                operation: "start",
                reason: "start is for a runner with nothing serving",
            });
        }
        let weights = slot.spec.weights_bytes;
        let cold = slot.host_copy == HostCopy::None;
        let load = Self::load_nanos(slot);
        let capture = slot.spec.timings.graph_capture_nanos;
        let launches = self.profile.mode != RunnerMode::VerifiedReload || !self.engine_up;
        let context = if launches {
            self.profile.footprint.context_vram_bytes
        } else {
            0
        };
        self.check_vram(weights.saturating_add(context))?;
        let operation = self.next_operation_id()?;
        let mut recorder = self.recorder(operation.clone());
        let before = self.snapshot();
        recorder.record(EventKind::ActivationRequested);
        if launches {
            recorder.record(EventKind::ProcessLaunched);
            let startup = self.vary(self.profile.runner.engine_startup_nanos);
            self.advance_by(startup)?;
            recorder.record(EventKind::RuntimeInitialized);
            if self.profile.mode == RunnerMode::VerifiedReload {
                self.engine_up = true;
            }
        }
        recorder.record(EventKind::PlacementRequested);
        let load = self.vary(load);
        self.advance_by(load)?;
        Self::mark_loaded(self.slot_mut(model)?);
        recorder.record(EventKind::WeightsUsable);
        let capture = self.vary(capture);
        self.advance_by(capture)?;
        recorder.record(EventKind::EngineReadyForShape);
        self.serving = Some(model.clone());
        let after = self.snapshot();
        let record = self.stage_record(StageParts {
            bench,
            variant: label(&format!("start-{model}"))?,
            operation,
            primary: IntervalKind::ReadyLatency,
            load: LoadDescription {
                concurrent_requests: 0,
                arrival: ArrivalMode::Sequential,
            },
            recorder,
            outcome: Outcome::Succeeded,
            peak: before.max(&after),
            end: after,
            transferred_bytes: weights,
            storage_read_bytes: if cold { weights } else { 0 },
        })?;
        record.validate()?;
        Ok(record)
    }

    /// Reads `model` into the host page cache: the "warm" state. Returns the preparation
    /// time in nanoseconds.
    pub fn warm_host_copy(&mut self, model: &Label) -> Result<u64, BenchError> {
        let slot = self.slot(model)?;
        if slot.residency != Residency::NotLoaded || slot.host_copy != HostCopy::None {
            return Err(BenchError::WrongState {
                operation: "warm host copy",
                reason: "the model already has a host copy or is loaded",
            });
        }
        let nanos = self.vary(slot.spec.timings.host_read_nanos);
        self.advance_by(nanos)?;
        let slot = self.slot_mut(model)?;
        slot.host_copy = HostCopy::PageCache;
        slot.ever_read = true;
        Ok(nanos)
    }

    /// Preloads `model` zero-copy into pinned host memory, only on a release that
    /// supports it with this runner's own modes: on vLLM 0.31.0 zero-copy preloaded
    /// weights cannot use sleep weight offloading (S7).
    pub fn preload(&mut self, model: &Label) -> Result<u64, BenchError> {
        let mut modes = self.profile.mode.backend_modes();
        modes.insert(Optimization::ZeroCopyPreload);
        self.rules.check(&self.profile.release, &modes)?;
        let slot = self.slot(model)?;
        if slot.residency != Residency::NotLoaded || slot.host_copy == HostCopy::Preloaded {
            return Err(BenchError::WrongState {
                operation: "preload",
                reason: "the model is loaded or already preloaded",
            });
        }
        let (weights, read) = (slot.spec.weights_bytes, slot.spec.timings.host_read_nanos);
        self.check_pinned(weights)?;
        let nanos = self.vary(read);
        self.advance_by(nanos)?;
        let slot = self.slot_mut(model)?;
        slot.host_copy = HostCopy::Preloaded;
        slot.ever_read = true;
        Ok(nanos)
    }

    /// Loads `model` in its own resident process beside the serving one (retained
    /// process mode).
    pub fn retain(&mut self, model: &Label) -> Result<u64, BenchError> {
        if self.profile.mode != RunnerMode::RetainedProcess {
            return Err(BenchError::WrongState {
                operation: "retain",
                reason: "only the retained process mode keeps several models resident",
            });
        }
        self.load_beside(model, false)
    }

    /// Loads `model` in its own process and puts it to sleep (version-supported sleep).
    pub fn prepare_asleep(&mut self, model: &Label) -> Result<u64, BenchError> {
        if self.profile.mode != RunnerMode::VersionSupportedSleep {
            return Err(BenchError::WrongState {
                operation: "prepare asleep",
                reason: "only the version-supported sleep mode sleeps a model",
            });
        }
        self.load_beside(model, true)
    }

    fn load_beside(&mut self, model: &Label, sleep: bool) -> Result<u64, BenchError> {
        let slot = self.slot(model)?;
        if slot.residency != Residency::NotLoaded {
            return Err(BenchError::WrongState {
                operation: "load beside",
                reason: "the model is already loaded",
            });
        }
        let weights = slot.spec.weights_bytes;
        let load = Self::load_nanos(slot);
        let capture = slot.spec.timings.graph_capture_nanos;
        let sleep_nanos = slot.spec.timings.sleep_nanos;
        self.check_vram(weights.saturating_add(self.profile.footprint.context_vram_bytes))?;
        if sleep {
            self.check_pinned(weights)?;
        }
        let mut total = 0u64;
        for nanos in [self.profile.runner.engine_startup_nanos, load, capture] {
            let nanos = self.vary(nanos);
            self.advance_by(nanos)?;
            total = add(total, nanos)?;
        }
        Self::mark_loaded(self.slot_mut(model)?);
        if sleep {
            let nanos = self.vary(sleep_nanos);
            self.advance_by(nanos)?;
            total = add(total, nanos)?;
            self.slot_mut(model)?.residency = Residency::Asleep;
        }
        Ok(total)
    }

    /// Schedules a fault on the fake clock; never in the past.
    pub fn inject(&mut self, fault: ScheduledFault) -> Result<(), BenchError> {
        if fault.at.as_nanos() < self.now() {
            return Err(BenchError::FaultInThePast);
        }
        self.fault_log.push(FaultRecord {
            kind: fault.kind,
            scheduled_at: fault.at,
            triggered_at: None,
            affected: Vec::new(),
            recycle: None,
        });
        self.pending_faults.push(self.fault_log.len() - 1);
        Ok(())
    }

    /// A planned recycle now, outside a run: a recovery event with its own latency and
    /// cost (S10).
    pub fn recycle(&mut self, bench: BenchId) -> Result<RecycleEvent, BenchError> {
        let script = Script {
            bench,
            load: LoadDescription {
                concurrent_requests: 0,
                arrival: ArrivalMode::Sequential,
            },
            users: Vec::new(),
            recycle_after_switches: None,
        };
        let mut run = Run::new(&script, self.now());
        self.start_recycle(&mut run, RecycleCause::Scheduled, None)?;
        self.run_loop(&mut run)?;
        run.out.recycles.pop().ok_or(BenchError::WrongState {
            operation: "recycle",
            reason: "the recycle did not complete",
        })
    }

    /// Refuses scripts the record schema could not describe honestly: a switch without a
    /// previous request, a retried switch, and several users over several models, where a
    /// request's state on arrival could change before it is served (S8 "cache and sleep
    /// state on arrival").
    fn check_script(&self, script: &Script) -> Result<(), BenchError> {
        let models: BTreeSet<&Label> = script
            .users
            .iter()
            .flat_map(|user| user.requests.iter().map(|plan| &plan.model))
            .collect();
        if script.users.len() > 1 && models.len() > 1 {
            return Err(BenchError::InvalidParameter {
                field: "users",
                reason: "several users share one model; switching scripts have one user",
            });
        }
        for user in &script.users {
            for (index, plan) in user.requests.iter().enumerate() {
                self.slot(&plan.model)?;
                if plan.max_output_tokens == 0 {
                    return Err(BenchError::InvalidParameter {
                        field: "max_output_tokens",
                        reason: "at least one token",
                    });
                }
                if plan.switch_from_previous && index == 0 {
                    return Err(BenchError::InvalidParameter {
                        field: "switch_from_previous",
                        reason: "a switch needs a previous request",
                    });
                }
                if plan.switch_from_previous && user.retry.max_retries > 0 {
                    return Err(BenchError::InvalidParameter {
                        field: "retry",
                        reason:
                            "a retried switch would lose its switch clock; switches are not retried",
                    });
                }
            }
        }
        Ok(())
    }

    /// Runs `script` until every user is done and the engine is idle, and returns every
    /// attempt's record. Failed attempts stay in the records (S8).
    pub fn serve(&mut self, script: &Script) -> Result<ServeOutcome, BenchError> {
        self.check_script(script)?;
        let mut run = Run::new(script, self.now());
        self.run_loop(&mut run)?;
        let window = run.window();
        let mut out = run.out;
        out.window = window;
        Ok(out)
    }

    fn run_loop(&mut self, run: &mut Run) -> Result<(), BenchError> {
        while let Some(at) = self.next_time(run)? {
            self.advance_to(at)?;
            self.fire_faults(run, at)?;
            self.fire_activity(run, at)?;
            self.fire_timeouts(run, at)?;
            self.fire_arrivals(run, at)?;
            self.schedule(run, at)?;
            self.track_peaks(run);
        }
        Ok(())
    }

    fn has_work(&self, run: &Run) -> bool {
        run.users
            .iter()
            .any(|user| user.next_arrival.is_some() || user.live)
            || !matches!(run.activity, Activity::Idle)
    }

    fn next_time(&self, run: &Run) -> Result<Option<u64>, BenchError> {
        if !self.has_work(run) {
            return Ok(None);
        }
        let mut candidates: Vec<u64> = Vec::new();
        candidates.extend(
            self.pending_faults
                .iter()
                .filter_map(|index| self.fault_log.get(*index))
                .map(|fault| fault.scheduled_at.as_nanos()),
        );
        match &run.activity {
            Activity::Idle => {
                if !run.queue.is_empty() || !run.active.is_empty() {
                    candidates.push(run.stalled_until.max(self.now()));
                }
            }
            Activity::Step { ends_at } => candidates.push(*ends_at),
            Activity::Transition(transition) => {
                candidates.push(
                    transition
                        .moves
                        .front()
                        .map_or(transition.first_step_end, |(at, _)| *at),
                );
            }
            Activity::Recycle(recycle) => {
                if let Some((at, _)) = recycle.moves.front() {
                    candidates.push(*at);
                }
            }
        }
        for user in &run.users {
            if let Some(arrival) = user.next_arrival {
                candidates.push(arrival.max(run.hold_until));
            }
        }
        candidates.extend(
            run.attempts
                .iter()
                .filter(|attempt| attempt.phase != Phase::Done)
                .map(|attempt| attempt.timeout_at),
        );
        match candidates.into_iter().min() {
            Some(at) => Ok(Some(at.max(self.now()))),
            None => Err(BenchError::WrongState {
                operation: "serve",
                reason: "the run stalled with work left",
            }),
        }
    }

    fn fire_faults(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        loop {
            let due = self.pending_faults.iter().position(|index| {
                self.fault_log
                    .get(*index)
                    .is_some_and(|fault| fault.scheduled_at.as_nanos() <= at)
            });
            let Some(position) = due else {
                return Ok(());
            };
            let index = self.pending_faults.remove(position);
            let Some(kind) = self.fault_log.get(index).map(|fault| fault.kind) else {
                continue;
            };
            match kind {
                FaultKind::Crash => self.crash(run, at, index)?,
                FaultKind::StalledProvider { stall_nanos } => {
                    self.stall(run, at, stall_nanos, index)?
                }
                FaultKind::DiskFull | FaultKind::OutOfMemory | FaultKind::LostEvent => {
                    self.armed.push(index);
                }
            }
        }
    }

    /// The first armed fault of `kinds`, consumed.
    fn take_armed(&mut self, matches: impl Fn(FaultKind) -> bool, at: u64) -> Option<usize> {
        let position = self.armed.iter().position(|index| {
            self.fault_log
                .get(*index)
                .is_some_and(|fault| matches(fault.kind))
        })?;
        let index = self.armed.remove(position);
        if let Some(fault) = self.fault_log.get_mut(index) {
            fault.triggered_at = Some(MonotonicTime::from_nanos(at));
        }
        Some(index)
    }

    fn note_affected(&mut self, fault: usize, operation: &OperationId) {
        if let Some(record) = self.fault_log.get_mut(fault) {
            record.affected.push(operation.clone());
        }
    }

    fn crash(&mut self, run: &mut Run, at: u64, fault: usize) -> Result<(), BenchError> {
        if let Some(record) = self.fault_log.get_mut(fault) {
            record.triggered_at = Some(MonotonicTime::from_nanos(at));
        }
        if let Activity::Recycle(recycle) = std::mem::replace(&mut run.activity, Activity::Idle) {
            // A crash during a recycle ends that recycle unfinished; it stays recorded.
            self.finish_recycle(run, *recycle, at, false)?;
        }
        let live: Vec<usize> = (0..run.attempts.len())
            .filter(|index| run.attempts[*index].phase != Phase::Done)
            .collect();
        let mut lost_tokens = 0u64;
        for index in &live {
            lost_tokens = lost_tokens.saturating_add(run.attempts[*index].generated);
            let operation = run.attempts[*index].operation.clone();
            self.note_affected(fault, &operation);
            self.end_attempt(run, *index, failed(FaultKind::Crash.classification())?, at)?;
        }
        self.start_recycle(run, RecycleCause::Crash, Some(fault))?;
        if let Activity::Recycle(recycle) = &mut run.activity {
            recycle.cost.failed_attempts = live.len() as u64;
            recycle.cost.lost_output_tokens = lost_tokens;
        }
        Ok(())
    }

    fn stall(
        &mut self,
        run: &mut Run,
        at: u64,
        nanos: u64,
        fault: usize,
    ) -> Result<(), BenchError> {
        if let Some(record) = self.fault_log.get_mut(fault) {
            record.triggered_at = Some(MonotonicTime::from_nanos(at));
        }
        for attempt in run
            .attempts
            .iter_mut()
            .filter(|attempt| attempt.phase != Phase::Done)
        {
            attempt.stall_fault = Some(fault);
        }
        let shift = |time: &mut u64| -> Result<(), BenchError> {
            *time = add(*time, nanos)?;
            Ok(())
        };
        match &mut run.activity {
            Activity::Idle => {}
            Activity::Step { ends_at } => shift(ends_at)?,
            Activity::Transition(transition) => {
                for (time, _) in transition.moves.iter_mut() {
                    shift(time)?;
                }
                shift(&mut transition.first_step_end)?;
            }
            Activity::Recycle(recycle) => {
                for (time, _) in recycle.moves.iter_mut() {
                    shift(time)?;
                }
            }
        }
        run.stalled_until = run.stalled_until.max(add(at, nanos)?);
        Ok(())
    }

    fn fire_activity(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        loop {
            let due = match &run.activity {
                Activity::Idle => false,
                Activity::Step { ends_at } => *ends_at <= at,
                Activity::Transition(transition) => transition
                    .moves
                    .front()
                    .map_or(transition.first_step_end <= at, |(time, _)| *time <= at),
                Activity::Recycle(recycle) => {
                    recycle.moves.front().is_some_and(|(time, _)| *time <= at)
                }
            };
            if !due {
                return Ok(());
            }
            match std::mem::replace(&mut run.activity, Activity::Idle) {
                Activity::Idle => return Ok(()),
                Activity::Step { .. } => self.end_step(run, at)?,
                Activity::Transition(mut transition) => match transition.moves.pop_front() {
                    Some((_, next)) => {
                        if let Some(transition) = self.apply_move(run, transition, next, at)? {
                            run.activity = Activity::Transition(transition);
                        }
                    }
                    None => self.end_step(run, at)?,
                },
                Activity::Recycle(mut recycle) => {
                    if let Some((_, next)) = recycle.moves.pop_front() {
                        self.apply_recycle_move(run, recycle, next, at)?;
                    }
                }
            }
        }
    }

    fn fire_timeouts(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        let due: Vec<usize> = (0..run.attempts.len())
            .filter(|index| {
                let attempt = &run.attempts[*index];
                attempt.phase != Phase::Done && attempt.timeout_at <= at
            })
            .collect();
        for index in due {
            let attempt = &run.attempts[index];
            let operation = attempt.operation.clone();
            let outcome = if let Some(fault) = attempt.lost_fault {
                self.note_affected(fault, &operation);
                failed(FaultKind::LostEvent.classification())?
            } else if let Some(fault) = attempt.stall_fault {
                self.note_affected(fault, &operation);
                failed(FaultKind::StalledProvider { stall_nanos: 0 }.classification())?
            } else {
                failure(FailureKind::Timeout, "client", "timeout")?
            };
            self.end_attempt(run, index, outcome, at)?;
        }
        Ok(())
    }

    fn fire_arrivals(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        for user in 0..run.users.len() {
            let due = run.users[user]
                .next_arrival
                .is_some_and(|arrival| arrival.max(run.hold_until) <= at);
            if due {
                run.users[user].next_arrival = None;
                self.arrive(run, user, at)?;
            }
        }
        Ok(())
    }

    fn arrival_state(&self, plan: &RequestPlan) -> Result<(StartState, bool, bool), BenchError> {
        let slot = self.slot(&plan.model)?;
        let prefix_hit = self.profile.serving.prefix_caching
            && slot.residency == Residency::Resident
            && self
                .prefix_cache
                .contains(&(plan.model.clone(), plan.request.prefix_digest()));
        let declared_warm = plan.request.prefill() == PrefillMode::WarmPrefix;
        let prefill = if declared_warm && prefix_hit {
            PrefillMode::WarmPrefix
        } else {
            PrefillMode::Fresh
        };
        let state = match (slot.residency, slot.host_copy) {
            (Residency::Resident, _) => StartState {
                temperature: StartTemperature::Hot,
                model_at_arrival: ModelAtArrival::ReadyToServe,
                cache_tier: CacheTier::GpuMemory,
                prefill,
                cold_provenance: ColdProvenance::NotCold,
            },
            (Residency::Asleep, _) => StartState {
                temperature: StartTemperature::Warm,
                model_at_arrival: ModelAtArrival::Asleep,
                cache_tier: CacheTier::HostMemory,
                prefill: PrefillMode::Fresh,
                cold_provenance: ColdProvenance::NotCold,
            },
            (Residency::NotLoaded, HostCopy::PageCache | HostCopy::Preloaded) => StartState {
                temperature: StartTemperature::Warm,
                model_at_arrival: ModelAtArrival::NotLoaded,
                cache_tier: CacheTier::HostMemory,
                prefill: PrefillMode::Fresh,
                cold_provenance: ColdProvenance::NotCold,
            },
            (Residency::NotLoaded, HostCopy::None) => StartState {
                temperature: StartTemperature::Cold,
                model_at_arrival: ModelAtArrival::NotLoaded,
                cache_tier: CacheTier::NoReusableState,
                prefill: PrefillMode::Fresh,
                cold_provenance: ColdProvenance::DisposableEnvironment,
            },
        };
        Ok((state, prefix_hit, declared_warm && !prefix_hit))
    }

    fn arrive(&mut self, run: &mut Run, user: usize, at: u64) -> Result<(), BenchError> {
        let script = run.script;
        let plan_index = run.users[user].next;
        let plan = &script.users[user].requests[plan_index];
        let retry = run.users[user].retry.take();
        let (operation, mut recorder, switch_from) = match (run.users[user].prepared.take(), &retry)
        {
            (Some((operation, recorder, from)), None) => (operation, recorder, Some(from)),
            _ => {
                let operation = self.next_operation_id()?;
                let recorder = self.recorder(operation.clone());
                (operation, recorder, None)
            }
        };
        let role = match retry {
            Some((first_attempt, retry_number)) => AttemptRole::Retry {
                first_attempt,
                retry_number,
            },
            None => AttemptRole::Initial,
        };
        let (state, prefix_hit, warm_prefix_missed) = self.arrival_state(plan)?;
        let switch = (plan.switch_from_previous && role == AttemptRole::Initial)
            .then(|| switch_mode_of(&state));
        recorder.record(EventKind::RequestAccepted);
        let index = run.attempts.len();
        let stalled = at < run.stalled_until;
        run.attempts.push(Attempt {
            user,
            plan: plan_index,
            role,
            operation,
            recorder: Some(recorder),
            arrival: at,
            timeout_at: add(at, plan.timeout_nanos)?,
            switch_from: switch.and(switch_from),
            canary: None,
            state,
            phase: Phase::Queued,
            stall_fault: None,
            lost_fault: None,
            warm_prefix_missed,
            prefix_hit,
            generated: 0,
            uncached_tokens: plan.request.input_tokens(),
            kv_reserved_bytes: 0,
            first_token: None,
            last_token: None,
            batch_tokens_after_first: 0,
            prefill_nanos: 0,
            peak: self.snapshot(),
            transferred_bytes: 0,
            storage_read_bytes: 0,
            status: AttemptStatus {
                model_at_arrival: self.status(&plan.model)?,
                model_at_first_token: None,
                switch,
                overlap: None,
                canary: None,
            },
        });
        if stalled {
            run.attempts[index].stall_fault = self
                .fault_log
                .iter()
                .rposition(|fault| matches!(fault.kind, FaultKind::StalledProvider { .. }));
        }
        run.users[user].live = true;
        if let Activity::Recycle(recycle) = &mut run.activity {
            if recycle.cause == RecycleCause::Crash {
                recycle.cost.rejected_attempts = recycle.cost.rejected_attempts.saturating_add(1);
                return self.end_attempt(
                    run,
                    index,
                    failure(FailureKind::Rejected, "runner", "recycling")?,
                    at,
                );
            }
        }
        if run.queue.len() >= self.profile.serving.max_queue_depth as usize {
            return self.end_attempt(
                run,
                index,
                failure(FailureKind::Rejected, "runner", "queue-full")?,
                at,
            );
        }
        run.queue.push_back(index);
        Ok(())
    }

    fn plan<'a>(run: &Run<'a>, index: usize) -> &'a RequestPlan {
        let script = run.script;
        let attempt = &run.attempts[index];
        &script.users[attempt.user].requests[attempt.plan]
    }

    fn kv_bytes(&self, plan: &RequestPlan) -> Result<u64, BenchError> {
        let spec = &self.slot(&plan.model)?.spec;
        plan.request
            .input_tokens()
            .checked_add(u64::from(plan.max_output_tokens))
            .and_then(|tokens| tokens.checked_mul(spec.kv_bytes_per_token))
            .ok_or(BenchError::Overflow)
    }

    /// Admits `index` into the batch: reserves its KV and decides its prefill.
    fn join_batch(&mut self, run: &mut Run, index: usize) -> Result<(), BenchError> {
        let plan = Self::plan(run, index);
        let reserve = self.kv_bytes(plan)?;
        self.kv_in_use_bytes = self.kv_in_use_bytes.saturating_add(reserve);
        let attempt = &mut run.attempts[index];
        attempt.kv_reserved_bytes = reserve;
        attempt.uncached_tokens = if attempt.prefix_hit {
            plan.request
                .input_tokens()
                .saturating_sub(plan.request.prefix_tokens())
        } else {
            plan.request.input_tokens()
        };
        attempt.prefill_nanos = attempt
            .uncached_tokens
            .saturating_mul(self.profile.serving.prefill_nanos_per_token);
        attempt.phase = Phase::Active;
        if self.profile.serving.prefix_caching {
            self.prefix_cache
                .insert((plan.model.clone(), plan.request.prefix_digest()));
        }
        run.active.push(index);
        Ok(())
    }

    fn step_nanos(&mut self, run: &Run, new: &[usize]) -> u64 {
        let serving = &self.profile.serving;
        let batch = run.active.len() as u64;
        let prefill = new
            .iter()
            .map(|index| run.attempts[*index].prefill_nanos)
            .fold(0u64, u64::saturating_add);
        let context: u64 = run
            .active
            .iter()
            .map(|index| {
                let attempt = &run.attempts[*index];
                Self::plan(run, *index)
                    .request
                    .input_tokens()
                    .saturating_add(attempt.generated)
            })
            .fold(0u64, u64::saturating_add);
        let nanos = serving
            .decode_step_base_nanos
            .saturating_add(serving.decode_step_per_sequence_nanos.saturating_mul(batch))
            .saturating_add(prefill)
            .saturating_add(
                (u128::from(serving.decode_nanos_per_kibitoken_context) * u128::from(context)
                    / 1024)
                    .try_into()
                    .unwrap_or(u64::MAX),
            );
        self.vary(nanos)
    }

    fn schedule(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        if !matches!(run.activity, Activity::Idle) || at < run.stalled_until {
            return Ok(());
        }
        let ready = self
            .serving
            .as_ref()
            .and_then(|model| self.models.get(model))
            .is_some_and(|slot| slot.residency == Residency::Resident);
        let mut new = Vec::new();
        while let Some(&head) = run.queue.front() {
            let plan = Self::plan(run, head);
            if !ready
                || Some(&plan.model) != self.serving.as_ref()
                || run.active.len() >= self.profile.serving.max_num_seqs as usize
            {
                break;
            }
            let reserve = self.kv_bytes(plan)?;
            let alone = self.snapshot().vram_bytes.saturating_add(reserve);
            if alone > self.profile.host.vram_capacity_bytes {
                if run.active.is_empty() && new.is_empty() {
                    run.queue.pop_front();
                    self.end_attempt(
                        run,
                        head,
                        failure(FailureKind::Rejected, "runner", "context-exceeds-capacity")?,
                        at,
                    )?;
                    continue;
                }
                break;
            }
            run.queue.pop_front();
            if let Some(attempt) = run.attempts.get_mut(head) {
                if let Some(recorder) = attempt.recorder.as_mut() {
                    recorder.record(EventKind::RequestDequeued);
                }
            }
            if let Some(fault) = self.take_armed(|kind| kind == FaultKind::OutOfMemory, at) {
                let operation = run.attempts[head].operation.clone();
                self.note_affected(fault, &operation);
                self.end_attempt(
                    run,
                    head,
                    failed(FaultKind::OutOfMemory.classification())?,
                    at,
                )?;
                continue;
            }
            self.join_batch(run, head)?;
            new.push(head);
        }
        if !run.active.is_empty() {
            let nanos = self.step_nanos(run, &new);
            run.activity = Activity::Step {
                ends_at: add(at, nanos)?,
            };
            return Ok(());
        }
        if let Some(&head) = run.queue.front() {
            let target = Self::plan(run, head).model.clone();
            return self.start_transition(run, target, at);
        }
        if let Some(after) = run.script.recycle_after_switches {
            if self.switches_since_recycle >= after && after > 0 {
                self.start_recycle(run, RecycleCause::Scheduled, None)?;
            }
        }
        Ok(())
    }

    fn end_step(&mut self, run: &mut Run, at: u64) -> Result<(), BenchError> {
        let batch = run.active.clone();
        let size = batch.len() as u64;
        let mut finished = Vec::new();
        for index in batch {
            let status = self.status(&Self::plan(run, index).model)?;
            let attempt = &mut run.attempts[index];
            if attempt.phase != Phase::Active {
                continue;
            }
            if let Some(recorder) = attempt.recorder.as_mut() {
                recorder.record(EventKind::TokenEmitted);
            }
            attempt.generated += 1;
            if attempt.first_token.is_none() {
                attempt.first_token = Some(at);
                attempt.status.model_at_first_token = Some(status);
            } else {
                attempt.batch_tokens_after_first =
                    attempt.batch_tokens_after_first.saturating_add(size);
            }
            attempt.last_token = Some(at);
            if attempt.generated >= u64::from(Self::plan(run, index).max_output_tokens) {
                finished.push(index);
            }
        }
        for index in finished {
            self.complete(run, index, at)?;
        }
        Ok(())
    }

    fn release_kv(&mut self, run: &mut Run, index: usize) {
        let attempt = &mut run.attempts[index];
        self.kv_in_use_bytes = self
            .kv_in_use_bytes
            .saturating_sub(attempt.kv_reserved_bytes);
        attempt.kv_reserved_bytes = 0;
        run.active.retain(|active| *active != index);
    }

    fn complete(&mut self, run: &mut Run, index: usize, at: u64) -> Result<(), BenchError> {
        self.release_kv(run, index);
        if let Some(fault) = self.take_armed(|kind| kind == FaultKind::LostEvent, at) {
            let attempt = &mut run.attempts[index];
            attempt.lost_fault = Some(fault);
            attempt.phase = Phase::AwaitingTimeout;
            return Ok(());
        }
        let plan = Self::plan(run, index);
        let verdict = if plan.check_response {
            Some(self.canary(plan)?)
        } else {
            None
        };
        let attempt = &mut run.attempts[index];
        if let Some(recorder) = attempt.recorder.as_mut() {
            recorder.record(EventKind::RequestCompleted);
        }
        attempt.canary = verdict;
        // The deadline applies to the scenario's primary interval (S8): the switch clock
        // for a switch, request latency otherwise.
        let primary = match attempt.switch_from {
            Some(from) => attempt.first_token.unwrap_or(at).saturating_sub(from),
            None => at.saturating_sub(attempt.arrival),
        };
        let stall_fault = attempt.stall_fault;
        let operation = attempt.operation.clone();
        let outcome = if attempt.warm_prefix_missed {
            failure(FailureKind::InvalidResult, "bench", "warm-prefix-miss")?
        } else if verdict == Some(CanaryVerdict::Failed) {
            failure(FailureKind::InvalidResult, "canary", "state-corruption")?
        } else if primary > plan.deadline_nanos {
            match stall_fault {
                Some(fault) => {
                    self.note_affected(fault, &operation);
                    failure(FailureKind::DeadlineFailure, "provider", "stalled")?
                }
                None => failure(FailureKind::DeadlineFailure, "client", "deadline")?,
            }
        } else {
            Outcome::Succeeded
        };
        self.end_attempt(run, index, outcome, at)
    }

    /// The state-corruption canary (S10): the response is compared with the expected one
    /// only when the fake declares deterministic outputs; temperature zero alone makes it
    /// "not comparable" (S13 FAST-01).
    fn canary(&mut self, plan: &RequestPlan) -> Result<CanaryVerdict, BenchError> {
        let weights = self.model_digest(&plan.model, "weights")?;
        let expected = Self::response_digest(&weights, plan, &[]);
        let (basis, actual) = if !self.profile.deterministic_outputs {
            let draw = self.rng.next_u64().to_be_bytes();
            (
                IdentityBasis::TemperatureZeroOnly,
                Self::response_digest(&weights, plan, &draw),
            )
        } else if self.corrupted() {
            (
                IdentityBasis::DeclaredDeterministicFake,
                Self::response_digest(&weights, plan, b"corrupted-state"),
            )
        } else {
            (IdentityBasis::DeclaredDeterministicFake, expected)
        };
        match same_response(&expected, &actual, basis) {
            Ok(true) => Ok(CanaryVerdict::Passed),
            Ok(false) => Ok(CanaryVerdict::Failed),
            Err(BenchError::TokenIdentityNotEstablished) => Ok(CanaryVerdict::NotComparable),
            Err(other) => Err(other),
        }
    }

    fn response_digest(weights: &Digest, plan: &RequestPlan, extra: &[u8]) -> Digest {
        DigestBuilder::new(RESPONSE_DIGEST_DOMAIN)
            .digest(weights)
            .digest(&plan.request.task_digest())
            .u64(u64::from(plan.max_output_tokens))
            .bytes(extra)
            .finish()
    }

    fn model_digest(&self, model: &Label, part: &str) -> Result<Digest, BenchError> {
        let spec = &self.slot(model)?.spec;
        Ok(DigestBuilder::new(MODEL_DIGEST_DOMAIN)
            .str(part)
            .str(spec.name.as_str())
            .u64(spec.weights_bytes)
            .finish())
    }

    fn track_peaks(&self, run: &mut Run) {
        let snapshot = self.snapshot();
        run.out.peak = run.out.peak.max(&snapshot);
        for attempt in run
            .attempts
            .iter_mut()
            .filter(|attempt| attempt.phase != Phase::Done)
        {
            attempt.peak = attempt.peak.max(&snapshot);
        }
        if let Activity::Recycle(recycle) = &mut run.activity {
            recycle.peak = recycle.peak.max(&snapshot);
        }
    }

    /// Ends `index` with `outcome`, builds its record and moves its user on.
    fn end_attempt(
        &mut self,
        run: &mut Run,
        index: usize,
        outcome: Outcome,
        at: u64,
    ) -> Result<(), BenchError> {
        self.release_kv(run, index);
        run.queue.retain(|queued| *queued != index);
        if let Activity::Transition(transition) = &mut run.activity {
            transition.waiting.retain(|waiting| *waiting != index);
        }
        if run.attempts[index].phase == Phase::Done {
            return Ok(());
        }
        run.attempts[index].phase = Phase::Done;
        let end = self.snapshot();
        let script = run.script;
        let attempt = &mut run.attempts[index];
        attempt.peak = attempt.peak.max(&end);
        let plan = &script.users[attempt.user].requests[attempt.plan];
        let recorder = attempt.recorder.take().ok_or(BenchError::WrongState {
            operation: "end attempt",
            reason: "the attempt has no recorder",
        })?;
        let verdict = attempt.canary;
        let retryable = matches!(
            &outcome,
            Outcome::Failed { failure, .. } if matches!(
                failure,
                FailureKind::Rejected
                    | FailureKind::Timeout
                    | FailureKind::EarlyTermination
                    | FailureKind::CommandFailure
            )
        );
        let scenario = match attempt.status.switch {
            Some(mode) => Scenario::Switching {
                mode,
                controlled_gap_nanos: plan.gap_before_nanos,
            },
            None => Scenario::Serving,
        };
        let operation = attempt.operation.clone();
        let role = attempt.role.clone();
        let mut status = attempt.status;
        status.canary = verdict;
        let measurements = self.measurements(attempt, &end)?;
        let record = RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench: script.bench,
                variant: plan.variant.clone(),
                execution: self.execution.clone(),
                operation: operation.clone(),
                role: role.clone(),
                burst: plan.burst,
                deadline_nanos: Measured::measured(plan.deadline_nanos),
            },
            scenario,
            substrate: RunSubstrate::FakeTimeControlled,
            build: self.build.clone(),
            execution_category: self.profile.category,
            model: Measured::measured(self.model_identity(&plan.model)?),
            precision: Measured::measured(self.precision(&plan.model)?),
            engine: Measured::measured(EngineIdentity {
                name: label("yougori-fake-runner")?,
                version: label(FAKE_RUNNER_VERSION)?,
            }),
            host: self.host.clone(),
            workload: Measured::measured(Workload {
                fixture: plan.request.fixture().clone(),
                family: plan.request.family(),
                input_tokens: plan.request.input_tokens(),
                max_output_tokens: u64::from(plan.max_output_tokens),
                sampling: Sampling {
                    temperature: NonNegative::ZERO,
                    top_p: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    top_k: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    seed: Measured::measured(self.seed),
                },
                tool_schema: plan.request.tool_schema().clone(),
                paired: plan.request.paired(),
                cold_test_nonce: plan.request.nonce().clone(),
            }),
            client: ClientDescription {
                name: label("yougori-fake-load-generator")?,
                version: label(FAKE_RUNNER_VERSION)?,
                region: label("same-host")?,
                placement: ClientPlacement::SameHost,
            },
            load: script.load.clone(),
            state: Measured::measured(attempt.state),
            launch: self.launch.clone(),
            price: Measured::not_measured(NotMeasuredReason::NotApplicable),
            measurements,
            events: recorder.into_events(),
            outcome,
        };
        record.validate()?;
        run.out.statuses.insert(operation.clone(), status);
        run.out.samples.push(AttemptSample {
            operation: operation.clone(),
            at: MonotonicTime::from_nanos(at),
            snapshot: end,
            recycles_before: u32::try_from(self.recycles.len()).unwrap_or(u32::MAX),
        });
        let canaries = &mut run.out.canaries;
        match verdict {
            Some(CanaryVerdict::Passed) => canaries.passed += 1,
            Some(CanaryVerdict::Failed) => canaries.failed += 1,
            Some(CanaryVerdict::NotComparable) => canaries.not_comparable += 1,
            None => {}
        }
        run.out.records.push(record);
        self.advance_user(run, index, retryable, operation, role, at)
    }

    fn advance_user(
        &mut self,
        run: &mut Run,
        index: usize,
        retryable: bool,
        operation: OperationId,
        role: AttemptRole,
        at: u64,
    ) -> Result<(), BenchError> {
        let script = run.script;
        let user_index = run.attempts[index].user;
        let user_script = &script.users[user_index];
        let user = &mut run.users[user_index];
        user.live = false;
        user.last_end = Some(at);
        let retries_used = match &role {
            AttemptRole::Initial => 0,
            AttemptRole::Retry { retry_number, .. } => *retry_number,
        };
        if retryable && retries_used < user_script.retry.max_retries {
            let first = match role {
                AttemptRole::Initial => operation,
                AttemptRole::Retry { first_attempt, .. } => first_attempt,
            };
            user.retry = Some((first, retries_used + 1));
            user.next_arrival = Some(add(at, user_script.retry.backoff_nanos)?);
            return Ok(());
        }
        user.next += 1;
        if let Some(next) = user_script.requests.get(user.next) {
            user.next_arrival = Some(add(at, next.gap_before_nanos)?);
            if next.switch_from_previous {
                let operation = self.next_operation_id()?;
                let mut recorder = self.recorder(operation.clone());
                let from = recorder.record(EventKind::ModelAFinalOutput).as_nanos();
                run.users[user_index].prepared = Some((operation, recorder, from));
            }
        }
        Ok(())
    }

    fn measurements(
        &self,
        attempt: &Attempt,
        end: &ResourceSnapshot,
    ) -> Result<RunMeasurements, BenchError> {
        let prefill_tokens_per_second = match attempt.first_token {
            None => Measured::not_measured(NotMeasuredReason::RunEndedFirst),
            Some(_) if attempt.uncached_tokens == 0 => {
                Measured::not_measured(NotMeasuredReason::NotApplicable)
            }
            Some(_) => rate(attempt.uncached_tokens, attempt.prefill_nanos)?,
        };
        let aggregate_decode_tokens_per_second = match (attempt.first_token, attempt.last_token) {
            (Some(first), Some(last)) if last > first => {
                rate(attempt.batch_tokens_after_first, last - first)?
            }
            _ => Measured::not_measured(NotMeasuredReason::InsufficientTokens),
        };
        Ok(RunMeasurements {
            output_tokens: Measured::measured(attempt.generated),
            prefill_tokens_per_second,
            aggregate_decode_tokens_per_second,
            speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
            peak_gpu_memory_bytes: Measured::measured(attempt.peak.vram_bytes),
            retained_gpu_memory_bytes: Measured::measured(end.vram_bytes),
            peak_host_memory_bytes: Measured::measured(attempt.peak.rss_bytes),
            retained_host_memory_bytes: Measured::measured(end.rss_bytes),
            peak_pinned_host_memory_bytes: Measured::measured(attempt.peak.pinned_host_bytes),
            transferred_bytes: Measured::measured(attempt.transferred_bytes),
            storage_read_bytes: Measured::measured(attempt.storage_read_bytes),
            energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            offload: Measured::measured(Offload::NoOffload),
            first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
            owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
            reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
        })
    }

    fn model_identity(&self, model: &Label) -> Result<ModelIdentity, BenchError> {
        Ok(ModelIdentity {
            revision: ModelRevision::Tag {
                name: label(&format!("synthetic-{model}"))?,
            },
            licenses: vec![label(LICENSE)?],
            weights: self.model_digest(model, "weights")?,
            tokenizer: self.model_digest(model, "tokenizer")?,
            chat_template: self.model_digest(model, "chat-template")?,
        })
    }

    fn precision(&self, model: &Label) -> Result<Precision, BenchError> {
        let spec = &self.slot(model)?.spec;
        Ok(Precision {
            weight_dtype: spec.weight_dtype.clone(),
            quantization: spec.quantization.clone(),
            kv_cache_dtype: spec.kv_cache_dtype.clone(),
        })
    }

    /// The first step after a load, by the GPU §2.6 recurrence: with execute while load
    /// each layer group computes once its own bytes arrive; otherwise every group waits
    /// for all weights and graph capture.
    fn load_first_step(
        &self,
        spec: &ModelSpec,
        startup: u64,
        load: u64,
        capture: u64,
        step: u64,
    ) -> Result<(u64, LoadOverlap), BenchError> {
        let groups = u64::from(spec.layer_groups.max(1));
        let ewl = self.profile.execute_while_load;
        let all_ready = add(add(startup, load)?, capture)?;
        let per_group = seconds(step) / groups as f64;
        let layers: Vec<GroupRequirement> = (1..=groups)
            .map(|group| {
                let usable = if ewl {
                    let part = u128::from(load) * u128::from(group) / u128::from(groups);
                    startup.saturating_add(u64::try_from(part).unwrap_or(u64::MAX))
                } else {
                    all_ready
                };
                GroupRequirement {
                    weights_usable_at_seconds: seconds(usable),
                    compute_seconds: per_group,
                    dependencies: if capture > 0 {
                        vec![Dependency {
                            kind: DependencyKind::GraphCapture,
                            usable_at_seconds: seconds(all_ready),
                        }]
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect();
        let head = GroupRequirement {
            weights_usable_at_seconds: seconds(add(startup, load)?),
            compute_seconds: 0.0,
            dependencies: Vec::new(),
        };
        let first = first_token(&layers, &head)?;
        let timings: Vec<GroupTiming> = layers
            .iter()
            .map(|group| GroupTiming {
                usable_at_seconds: group.weights_usable_at_seconds,
                compute_seconds: group.compute_seconds,
            })
            .collect();
        let offset = nanos_of(first.first_token_seconds)?;
        Ok((
            offset,
            LoadOverlap {
                execute_while_load: ewl,
                no_stall: no_stall(&timings)?,
                first_token_after_load_start_nanos: offset,
            },
        ))
    }

    fn start_transition(
        &mut self,
        run: &mut Run,
        target: Label,
        at: u64,
    ) -> Result<(), BenchError> {
        let mut waiting = Vec::new();
        while let Some(&head) = run.queue.front() {
            if Self::plan(run, head).model != target
                || waiting.len() >= self.profile.serving.max_num_seqs as usize
            {
                break;
            }
            run.queue.pop_front();
            let attempt = &mut run.attempts[head];
            if let Some(recorder) = attempt.recorder.as_mut() {
                recorder.record(EventKind::RequestDequeued);
            }
            attempt.phase = Phase::Transition;
            waiting.push(head);
        }
        let (residency, host_copy, spec) = {
            let slot = self.slot(&target)?;
            (slot.residency, slot.host_copy, slot.spec.clone())
        };
        let mode = self.profile.mode;
        let parked = self
            .serving
            .clone()
            .filter(|serving| *serving != target)
            .filter(|serving| {
                self.models
                    .get(serving)
                    .is_some_and(|slot| slot.residency == Residency::Resident)
            });
        let mut moves = VecDeque::new();
        let mut time = at;
        if let Some(parked) = &parked {
            let timings = &self.slot(parked)?.spec.timings;
            let park = match mode {
                RunnerMode::RetainedProcess => None,
                RunnerMode::VersionSupportedSleep => Some((Park::Sleep, timings.sleep_nanos)),
                RunnerMode::VerifiedReload => Some((Park::Unload, timings.unload_nanos)),
                RunnerMode::FullProcessRestart => {
                    Some((Park::Exit, self.profile.runner.process_exit_nanos))
                }
            };
            if let Some((park, nanos)) = park {
                time = add(time, self.vary(nanos))?;
                moves.push_back((
                    time,
                    Move::Park {
                        model: parked.clone(),
                        park,
                    },
                ));
            }
        }
        let new: Vec<usize> = waiting.clone();
        for index in &new {
            let plan = Self::plan(run, *index);
            let attempt = &mut run.attempts[*index];
            attempt.uncached_tokens = if attempt.prefix_hit {
                plan.request
                    .input_tokens()
                    .saturating_sub(plan.request.prefix_tokens())
            } else {
                plan.request.input_tokens()
            };
            attempt.prefill_nanos = attempt
                .uncached_tokens
                .saturating_mul(self.profile.serving.prefill_nanos_per_token);
        }
        let step = {
            let saved = std::mem::replace(&mut run.active, new.clone());
            let nanos = self.step_nanos(run, &new);
            run.active = saved;
            nanos
        };
        let mut transferred_bytes = 0;
        let mut storage_read_bytes = 0;
        let mut overlap = None;
        let mut starts_process = false;
        let (demand, first_step_end) = match residency {
            Residency::Resident => {
                let ready = add(time, self.vary(self.profile.runner.hot_dispatch_nanos))?;
                moves.push_back((ready, Move::Ready));
                (Demand::Dispatch, add(ready, step)?)
            }
            Residency::Asleep => {
                moves.push_back((time, Move::DemandStarted));
                let ready = add(time, self.vary(spec.timings.wake_nanos))?;
                moves.push_back((ready, Move::Ready));
                transferred_bytes = spec.weights_bytes;
                (Demand::Wake, add(ready, step)?)
            }
            Residency::NotLoaded => {
                if mode == RunnerMode::VerifiedReload && host_copy == HostCopy::None {
                    return Err(BenchError::NoSwitchLabel);
                }
                starts_process = mode != RunnerMode::VerifiedReload || !self.engine_up;
                let startup = if starts_process {
                    self.vary(self.profile.runner.engine_startup_nanos)
                } else {
                    0
                };
                let load = match host_copy {
                    HostCopy::None => spec.timings.cold_load_nanos,
                    _ => spec.timings.warm_load_nanos,
                };
                let load = self.vary(load);
                let capture = self.vary(spec.timings.graph_capture_nanos);
                moves.push_back((time, Move::DemandStarted));
                let ready = add(time, add(add(startup, load)?, capture)?)?;
                moves.push_back((ready, Move::Ready));
                let (offset, load_overlap) =
                    self.load_first_step(&spec, startup, load, capture, step)?;
                overlap = Some(load_overlap);
                transferred_bytes = spec.weights_bytes;
                if host_copy == HostCopy::None {
                    storage_read_bytes = spec.weights_bytes;
                }
                (Demand::Load, add(time, offset)?.max(add(ready, 1)?))
            }
        };
        let switch = self
            .serving
            .as_ref()
            .is_some_and(|serving| *serving != target);
        run.activity = Activity::Transition(Box::new(Transition {
            target,
            demand,
            waiting,
            moves,
            first_step_end,
            overlap,
            transferred_bytes,
            storage_read_bytes,
            starts_process,
            switch,
        }));
        Ok(())
    }

    fn fail_transition(
        &mut self,
        run: &mut Run,
        transition: &Transition,
        outcome: Outcome,
        fault: Option<usize>,
        at: u64,
    ) -> Result<(), BenchError> {
        for index in transition.waiting.clone() {
            if let Some(fault) = fault {
                let operation = run.attempts[index].operation.clone();
                self.note_affected(fault, &operation);
            }
            self.end_attempt(run, index, outcome.clone(), at)?;
        }
        if self.serving.as_ref() == Some(&transition.target) {
            self.serving = None;
        }
        Ok(())
    }

    fn apply_move(
        &mut self,
        run: &mut Run,
        mut transition: Box<Transition>,
        next: Move,
        at: u64,
    ) -> Result<Option<Box<Transition>>, BenchError> {
        match next {
            Move::Park { model, park } => {
                let slot = self.slot_mut(&model)?;
                match park {
                    Park::Sleep => slot.residency = Residency::Asleep,
                    Park::Unload | Park::Exit => {
                        slot.residency = Residency::NotLoaded;
                        if slot.host_copy == HostCopy::None {
                            slot.host_copy = HostCopy::PageCache;
                        }
                    }
                }
                self.prefix_cache.retain(|(cached, _)| *cached != model);
                if self.serving.as_ref() == Some(&model) {
                    self.serving = None;
                }
                Ok(Some(transition))
            }
            Move::DemandStarted => {
                for index in &transition.waiting {
                    if let Some(recorder) = run.attempts[*index].recorder.as_mut() {
                        recorder.record(match transition.demand {
                            Demand::Wake => EventKind::WakeStarted,
                            _ => EventKind::LoadStarted,
                        });
                    }
                }
                let spec = self.slot(&transition.target)?.spec.clone();
                let loads = transition.demand == Demand::Load;
                let disk = if loads {
                    self.take_armed(|kind| kind == FaultKind::DiskFull, at)
                } else {
                    None
                };
                if let Some(fault) = disk {
                    self.fail_transition(
                        run,
                        &transition,
                        failed(FaultKind::DiskFull.classification())?,
                        Some(fault),
                        at,
                    )?;
                    return Ok(None);
                }
                if let Some(fault) = self.take_armed(|kind| kind == FaultKind::OutOfMemory, at) {
                    self.fail_transition(
                        run,
                        &transition,
                        failed(FaultKind::OutOfMemory.classification())?,
                        Some(fault),
                        at,
                    )?;
                    return Ok(None);
                }
                let context = if transition.starts_process {
                    self.profile.footprint.context_vram_bytes
                } else {
                    0
                };
                if self
                    .check_vram(spec.weights_bytes.saturating_add(context))
                    .is_err()
                {
                    self.fail_transition(
                        run,
                        &transition,
                        failure(FailureKind::CommandFailure, "gpu-memory", "out-of-memory")?,
                        None,
                        at,
                    )?;
                    return Ok(None);
                }
                if loads
                    && transition.starts_process
                    && self.profile.mode == RunnerMode::VerifiedReload
                {
                    self.engine_up = true;
                }
                Ok(Some(transition))
            }
            Move::Ready => {
                Self::mark_loaded(self.slot_mut(&transition.target)?);
                for index in &transition.waiting {
                    let attempt = &mut run.attempts[*index];
                    if let Some(recorder) = attempt.recorder.as_mut() {
                        match transition.demand {
                            Demand::Wake => {
                                recorder.record(EventKind::WakeCompleted);
                            }
                            Demand::Load => {
                                recorder.record(EventKind::LoadCompleted);
                            }
                            Demand::Dispatch => {}
                        }
                    }
                    attempt.transferred_bytes = transition.transferred_bytes;
                    attempt.storage_read_bytes = transition.storage_read_bytes;
                    attempt.status.overlap = transition.overlap;
                }
                if transition.switch {
                    self.switches = self.switches.saturating_add(1);
                    self.switches_since_recycle = self.switches_since_recycle.saturating_add(1);
                    self.leaked = self.leaked.saturating_add(&self.profile.leak_per_switch);
                }
                self.serving = Some(transition.target.clone());
                for index in transition.waiting.clone() {
                    self.join_batch(run, index)?;
                }
                if run.active.is_empty() {
                    return Ok(None);
                }
                transition.first_step_end = transition.first_step_end.max(add(at, 1)?);
                Ok(Some(transition))
            }
        }
    }

    fn start_recycle(
        &mut self,
        run: &mut Run,
        cause: RecycleCause,
        fault: Option<usize>,
    ) -> Result<(), BenchError> {
        let at = self.now();
        let before = self.snapshot();
        let mut layout: Vec<(Label, Residency)> = Vec::new();
        if let Some(serving) = &self.serving {
            layout.push((serving.clone(), Residency::Resident));
        }
        for (name, slot) in &self.models {
            if slot.residency != Residency::NotLoaded && Some(name) != self.serving.as_ref() {
                layout.push((name.clone(), slot.residency));
            }
        }
        // Every process is gone: weights stay in the page cache, preloads stay pinned.
        for slot in self.models.values_mut() {
            if slot.residency != Residency::NotLoaded {
                slot.residency = Residency::NotLoaded;
                if slot.host_copy == HostCopy::None {
                    slot.host_copy = HostCopy::PageCache;
                }
            }
        }
        self.engine_up = false;
        self.serving = None;
        self.leaked = ResourceSnapshot::ZERO;
        self.switches_since_recycle = 0;
        self.kv_in_use_bytes = 0;
        self.prefix_cache.clear();
        let operation = self.next_operation_id()?;
        let mut recorder = self.recorder(operation.clone());
        recorder.record(EventKind::RecycleStarted);
        let mut moves = VecDeque::new();
        let mut time = at;
        let mut cost = RecycleCost::default();
        for (position, (model, residency)) in layout.iter().enumerate() {
            let slot = self.slot(model)?;
            let load = Self::load_nanos(slot);
            let weights = slot.spec.weights_bytes;
            let cold = slot.host_copy == HostCopy::None;
            let (capture, sleep) = (
                slot.spec.timings.graph_capture_nanos,
                slot.spec.timings.sleep_nanos,
            );
            cost.reloaded_bytes = cost.reloaded_bytes.saturating_add(weights);
            if cold {
                cost.storage_read_bytes = cost.storage_read_bytes.saturating_add(weights);
            }
            let startup = self.vary(self.profile.runner.engine_startup_nanos);
            let load = self.vary(load);
            let capture = self.vary(capture);
            if position == 0 {
                recorder.record(EventKind::ActivationRequested);
                recorder.record(EventKind::ProcessLaunched);
                time = add(time, startup)?;
                moves.push_back((time, RecycleMove::RuntimeInitialized));
                time = add(time, load)?;
                moves.push_back((
                    time,
                    RecycleMove::WeightsUsable {
                        model: model.clone(),
                    },
                ));
                time = add(time, capture)?;
                moves.push_back((
                    time,
                    RecycleMove::EngineReady {
                        model: model.clone(),
                    },
                ));
            } else {
                time = add(time, add(add(startup, load)?, capture)?)?;
                if *residency == Residency::Asleep {
                    time = add(time, self.vary(sleep))?;
                }
                moves.push_back((
                    time,
                    RecycleMove::Restored {
                        model: model.clone(),
                        residency: *residency,
                    },
                ));
            }
        }
        moves.push_back((time, RecycleMove::Completed));
        if cause == RecycleCause::Scheduled {
            run.hold_until = run.hold_until.max(time);
        }
        run.activity = Activity::Recycle(Box::new(Recycle {
            cause,
            started_at: at,
            operation,
            recorder,
            moves,
            before,
            peak: before,
            cost,
            fault,
            bench: run.script.bench,
            load: run.script.load.clone(),
        }));
        Ok(())
    }

    fn apply_recycle_move(
        &mut self,
        run: &mut Run,
        mut recycle: Box<Recycle>,
        next: RecycleMove,
        at: u64,
    ) -> Result<(), BenchError> {
        match next {
            RecycleMove::RuntimeInitialized => {
                if self.profile.mode == RunnerMode::VerifiedReload {
                    self.engine_up = true;
                }
                recycle.recorder.record(EventKind::RuntimeInitialized);
                recycle.recorder.record(EventKind::PlacementRequested);
                for kind in [FaultKind::DiskFull, FaultKind::OutOfMemory] {
                    if let Some(fault) = self.take_armed(|armed| armed == kind, at) {
                        if let Some(record) = self.fault_log.get_mut(fault) {
                            record.recycle = Some(self.recycles.len());
                        }
                        return self.finish_recycle(run, *recycle, at, false);
                    }
                }
                run.activity = Activity::Recycle(recycle);
                Ok(())
            }
            RecycleMove::WeightsUsable { model } => {
                Self::mark_loaded(self.slot_mut(&model)?);
                recycle.recorder.record(EventKind::WeightsUsable);
                run.activity = Activity::Recycle(recycle);
                Ok(())
            }
            RecycleMove::EngineReady { model } => {
                recycle.recorder.record(EventKind::EngineReadyForShape);
                self.serving = Some(model);
                run.activity = Activity::Recycle(recycle);
                Ok(())
            }
            RecycleMove::Restored { model, residency } => {
                let slot = self.slot_mut(&model)?;
                Self::mark_loaded(slot);
                slot.residency = residency;
                run.activity = Activity::Recycle(recycle);
                Ok(())
            }
            RecycleMove::Completed => {
                recycle.recorder.record(EventKind::RecycleCompleted);
                self.finish_recycle(run, *recycle, at, true)
            }
        }
    }

    fn finish_recycle(
        &mut self,
        run: &mut Run,
        recycle: Recycle,
        at: u64,
        completed: bool,
    ) -> Result<(), BenchError> {
        let after = self.snapshot();
        let mut cost = recycle.cost;
        cost.downtime_nanos = at.saturating_sub(recycle.started_at);
        let outcome = if completed {
            Outcome::Succeeded
        } else {
            failure(FailureKind::CommandFailure, "runner", "recycle-failed")?
        };
        let variant = match recycle.cause {
            RecycleCause::Crash => "recycle-after-crash",
            RecycleCause::Scheduled => "recycle-scheduled",
        };
        let record = self.stage_record(StageParts {
            bench: recycle.bench,
            variant: label(variant)?,
            operation: recycle.operation,
            primary: IntervalKind::Recycle,
            load: recycle.load,
            recorder: recycle.recorder,
            outcome,
            peak: recycle.peak.max(&after),
            end: after,
            transferred_bytes: cost.reloaded_bytes,
            storage_read_bytes: cost.storage_read_bytes,
        })?;
        record.validate()?;
        let event = RecycleEvent {
            cause: recycle.cause,
            started_at: MonotonicTime::from_nanos(recycle.started_at),
            completed_at: MonotonicTime::from_nanos(at),
            latency_nanos: cost.downtime_nanos,
            cost,
            before: recycle.before,
            after,
            record,
        };
        if let Some(fault) = recycle.fault {
            if let Some(entry) = self.fault_log.get_mut(fault) {
                entry.recycle = Some(self.recycles.len());
            }
        }
        self.recycles.push(event.clone());
        run.out.recycles.push(event);
        Ok(())
    }

    /// A §2.1 stage record: a start or a recycle.
    fn stage_record(&self, parts: StageParts) -> Result<RunRecord, BenchError> {
        let StageParts {
            bench,
            variant,
            operation,
            primary,
            load,
            recorder,
            outcome,
            peak,
            end,
            transferred_bytes,
            storage_read_bytes,
        } = parts;
        Ok(RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench,
                variant,
                execution: self.execution.clone(),
                operation,
                role: AttemptRole::Initial,
                burst: 0,
                deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            scenario: Scenario::Stages { primary },
            substrate: RunSubstrate::FakeTimeControlled,
            build: self.build.clone(),
            execution_category: self.profile.category,
            model: Measured::not_measured(NotMeasuredReason::NotApplicable),
            precision: Measured::not_measured(NotMeasuredReason::NotApplicable),
            engine: Measured::measured(EngineIdentity {
                name: label("yougori-fake-runner")?,
                version: label(FAKE_RUNNER_VERSION)?,
            }),
            host: self.host.clone(),
            workload: Measured::not_measured(NotMeasuredReason::NotApplicable),
            client: ClientDescription {
                name: label("yougori-fake-load-generator")?,
                version: label(FAKE_RUNNER_VERSION)?,
                region: label("same-host")?,
                placement: ClientPlacement::SameHost,
            },
            load,
            state: Measured::not_measured(NotMeasuredReason::NotApplicable),
            launch: self.launch.clone(),
            price: Measured::not_measured(NotMeasuredReason::NotApplicable),
            measurements: RunMeasurements {
                output_tokens: Measured::not_measured(NotMeasuredReason::NotApplicable),
                prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotApplicable),
                aggregate_decode_tokens_per_second: Measured::not_measured(
                    NotMeasuredReason::NotApplicable,
                ),
                speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
                peak_gpu_memory_bytes: Measured::measured(peak.vram_bytes),
                retained_gpu_memory_bytes: Measured::measured(end.vram_bytes),
                peak_host_memory_bytes: Measured::measured(peak.rss_bytes),
                retained_host_memory_bytes: Measured::measured(end.rss_bytes),
                peak_pinned_host_memory_bytes: Measured::measured(peak.pinned_host_bytes),
                transferred_bytes: Measured::measured(transferred_bytes),
                storage_read_bytes: Measured::measured(storage_read_bytes),
                energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                offload: Measured::not_measured(NotMeasuredReason::NotApplicable),
                first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
                owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
                reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            events: recorder.into_events(),
            outcome,
        })
    }
}

impl<'a> Run<'a> {
    fn new(script: &'a Script, now: u64) -> Self {
        let users = script
            .users
            .iter()
            .map(|user| UserState {
                next: 0,
                next_arrival: (!user.requests.is_empty())
                    .then(|| user.start_at.as_nanos().max(now)),
                retry: None,
                prepared: None,
                last_end: None,
                live: false,
            })
            .collect();
        Self {
            script,
            attempts: Vec::new(),
            users,
            queue: VecDeque::new(),
            active: Vec::new(),
            activity: Activity::Idle,
            stalled_until: 0,
            hold_until: 0,
            out: ServeOutcome {
                records: Vec::new(),
                statuses: BTreeMap::new(),
                samples: Vec::new(),
                canaries: CanaryTally::default(),
                window: None,
                recycles: Vec::new(),
                peak: ResourceSnapshot::ZERO,
            },
        }
    }

    fn window(&self) -> Option<RunWindow> {
        let first_arrival = self.attempts.iter().map(|attempt| attempt.arrival).min()?;
        let steady_end = self.users.iter().filter_map(|user| user.last_end).min()?;
        let last_end = self.users.iter().filter_map(|user| user.last_end).max()?;
        Some(RunWindow {
            first_arrival: MonotonicTime::from_nanos(first_arrival),
            steady_end: MonotonicTime::from_nanos(steady_end),
            last_end: MonotonicTime::from_nanos(last_end),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::{ClockReading, NoncePlacement};
    use crate::model_memory::bench::corpus::{render_fresh, ColdTestNonce, Corpus};
    use crate::model_memory::bench::test_support::{
        label, one_user, plan, profile, runner, MILLIS,
    };

    /// The synthetic profile without context cost, so step times are exact.
    fn exact(mode: RunnerMode) -> RunnerProfile {
        let mut profile = profile(mode);
        profile.serving.decode_nanos_per_kibitoken_context = 0;
        profile
    }

    /// One sequence's step: base, one sequence and the prefill of `tokens` new tokens.
    fn step(tokens: u64) -> u64 {
        10 * MILLIS + 200_000 + tokens * 20_000
    }

    /// Runs A, then B and A again as switches with a 250 ms controlled gap.
    fn aba(mode: RunnerMode, prepare: impl FnOnce(&mut FakeRunner)) -> Vec<RunRecord> {
        let mut runner = runner(exact(mode), 7);
        runner.start(&label("model-a"), BenchId::Bench02).unwrap();
        prepare(&mut runner);
        let mut to_b = plan("to-b", "model-b", 2, 4);
        to_b.switch_from_previous = true;
        to_b.gap_before_nanos = 250 * MILLIS;
        let mut back = plan("back-to-a", "model-a", 3, 4);
        back.switch_from_previous = true;
        back.gap_before_nanos = 250 * MILLIS;
        let script = one_user(
            &runner,
            BenchId::Bench02,
            vec![plan("a", "model-a", 1, 4), to_b, back],
        );
        runner.serve(&script).unwrap().records
    }

    /// (mode, B accepted to first B token, A's last output to first B token).
    fn clocks(record: &RunRecord) -> (SwitchMode, u64, u64, u64) {
        match record.clock_reading().unwrap() {
            ClockReading::Switching(clock) => (
                clock.mode,
                clock.request.time_to_first_token.elapsed_nanos(),
                clock.last_output_to_first_output.elapsed_nanos(),
                clock.measured_gap.elapsed_nanos(),
            ),
            other => panic!("not a switching reading: {other:?}"),
        }
    }

    #[test]
    fn a_hot_request_reads_the_serving_clock() {
        let mut runner = runner(exact(RunnerMode::VerifiedReload), 1);
        runner.start(&label("model-a"), BenchId::Bench01).unwrap();
        let request = plan("hot", "model-a", 1, 4);
        let tokens = request.request.input_tokens();
        let script = one_user(&runner, BenchId::Bench01, vec![request]);
        let out = runner.serve(&script).unwrap();
        let record = &out.records[0];
        assert!(record.is_success());
        let ttft = record.interval(IntervalKind::TimeToFirstToken).unwrap();
        assert_eq!(ttft.elapsed_nanos(), step(tokens));
        assert_eq!(
            record
                .interval(IntervalKind::QueueWait)
                .unwrap()
                .elapsed_nanos(),
            0
        );
        assert_eq!(
            record
                .interval(IntervalKind::RequestLatency)
                .unwrap()
                .elapsed_nanos(),
            step(tokens) + 3 * step(0)
        );
        assert_eq!(record.measurements.output_tokens, Measured::measured(4));
        assert_eq!(record.substrate, RunSubstrate::FakeTimeControlled);
        assert_eq!(
            record.state.value().map(|state| state.temperature),
            Some(StartTemperature::Hot)
        );
    }

    /// A mode, how to prepare B, and each switch's label and time to ready.
    type SwitchCase = (
        RunnerMode,
        Box<dyn FnOnce(&mut FakeRunner)>,
        SwitchMode,
        u64,
        SwitchMode,
        u64,
    );

    #[test]
    fn both_switch_clocks_are_exact_in_every_mode() {
        let tokens = plan("x", "model-a", 1, 1).request.input_tokens();
        let gap = 250 * MILLIS;
        let cases: Vec<SwitchCase> = vec![
            (
                RunnerMode::RetainedProcess,
                Box::new(|runner: &mut FakeRunner| {
                    runner.retain(&label("model-b")).unwrap();
                }),
                SwitchMode::HotDispatch,
                2 * MILLIS,
                SwitchMode::HotDispatch,
                2 * MILLIS,
            ),
            (
                RunnerMode::VersionSupportedSleep,
                Box::new(|runner: &mut FakeRunner| {
                    runner.prepare_asleep(&label("model-b")).unwrap();
                }),
                SwitchMode::Wake,
                (350 + 250) * MILLIS,
                SwitchMode::Wake,
                (250 + 350) * MILLIS,
            ),
            (
                RunnerMode::VerifiedReload,
                Box::new(|runner: &mut FakeRunner| {
                    runner.warm_host_copy(&label("model-b")).unwrap();
                }),
                SwitchMode::WarmReload,
                (50 + 300 + 250) * MILLIS,
                SwitchMode::WarmReload,
                (40 + 400 + 300) * MILLIS,
            ),
            (
                RunnerMode::FullProcessRestart,
                Box::new(|_: &mut FakeRunner| {}),
                SwitchMode::ColdProcessStart,
                (100 + 2_000 + 1_000 + 250) * MILLIS,
                SwitchMode::WarmReload,
                (100 + 2_000 + 400 + 300) * MILLIS,
            ),
        ];
        for (mode, prepare, to_b_mode, to_b_ready, back_mode, back_ready) in cases {
            let records = aba(mode, prepare);
            assert_eq!(records.len(), 3, "{mode:?}");
            assert!(records.iter().all(RunRecord::is_success), "{mode:?}");
            assert_eq!(records[0].scenario, Scenario::Serving);
            let first_token = step(tokens);
            assert_eq!(
                clocks(&records[1]),
                (
                    to_b_mode,
                    to_b_ready + first_token,
                    gap + to_b_ready + first_token,
                    gap
                ),
                "{mode:?} to B"
            );
            assert_eq!(
                clocks(&records[2]),
                (
                    back_mode,
                    back_ready + first_token,
                    gap + back_ready + first_token,
                    gap
                ),
                "{mode:?} back to A"
            );
            assert_eq!(
                records[1].scenario,
                Scenario::Switching {
                    mode: to_b_mode,
                    controlled_gap_nanos: gap
                }
            );
        }
    }

    #[test]
    fn a_planned_recycle_is_recorded_with_its_latency_and_cost() {
        let mut runner = runner(exact(RunnerMode::VerifiedReload), 31);
        runner.start(&label("model-a"), BenchId::Bench07).unwrap();
        let event = runner.recycle(BenchId::Bench07).unwrap();
        assert_eq!(event.cause, RecycleCause::Scheduled);
        // Engine startup, a load from the page cache and graph capture.
        assert_eq!(event.latency_nanos, (2_000 + 400 + 300) * MILLIS);
        assert_eq!(event.cost.reloaded_bytes, 8_000_000_000);
        assert_eq!(event.cost.storage_read_bytes, 0);
        assert!(event.record.is_success());
        assert_eq!(
            event
                .record
                .interval(IntervalKind::EngineStartup)
                .unwrap()
                .elapsed_nanos(),
            2_000 * MILLIS
        );
        assert_eq!(runner.serving(), Some(&label("model-a")));
        assert_eq!(runner.recycles().len(), 1);
    }

    #[test]
    fn admission_refuses_beyond_the_queue_and_beyond_memory() {
        let mut narrow = exact(RunnerMode::VerifiedReload);
        narrow.serving.max_num_seqs = 1;
        narrow.serving.max_queue_depth = 2;
        let mut narrow = runner(narrow, 32);
        narrow.start(&label("model-a"), BenchId::Bench01).unwrap();
        let now = narrow.clock().now();
        let users = (0..5)
            .map(|user| UserScript {
                start_at: now,
                requests: vec![plan("admission", "model-a", 40 + user, 4)],
                retry: RetryPolicy::NONE,
            })
            .collect();
        let script = Script {
            bench: BenchId::Bench01,
            load: LoadDescription {
                concurrent_requests: 5,
                arrival: ArrivalMode::Burst { size: 5 },
            },
            users,
            recycle_after_switches: None,
        };
        let out = narrow.serve(&script).unwrap();
        let ledger =
            crate::foundation::report::AttemptLedger::from_records(out.records.clone()).unwrap();
        assert_eq!(ledger.failures().rejected, 3);
        assert_eq!(ledger.success_rate().unwrap().attempts(), 5);
        for record in out.records.iter().filter(|record| !record.is_success()) {
            assert!(matches!(
                &record.outcome,
                Outcome::Failed { component, code, .. }
                    if component.as_str() == "runner" && code.as_str() == "queue-full"
            ));
        }

        // A request whose KV cannot fit even alone is refused, naming why.
        let mut tight = exact(RunnerMode::VerifiedReload);
        tight.host.vram_capacity_bytes = 12_000_000_000;
        let mut tight = runner(tight, 33);
        tight.start(&label("model-a"), BenchId::Bench01).unwrap();
        let corpus = Corpus::fast01().unwrap();
        let mut request = plan("too-long", "model-a", 1, 4);
        request.request = render_fresh(
            corpus.get("fast01-long-context-32000").unwrap(),
            ColdTestNonce::new(5, NoncePlacement::PromptPrefix),
        )
        .unwrap();
        let out = tight
            .serve(&one_user(&tight, BenchId::Bench01, vec![request]))
            .unwrap();
        assert!(matches!(
            &out.records[0].outcome,
            Outcome::Failed { failure: FailureKind::Rejected, code, .. }
                if code.as_str() == "context-exceeds-capacity"
        ));
    }

    #[test]
    fn a_script_the_record_could_not_describe_is_refused() {
        let mut runner = runner(exact(RunnerMode::VerifiedReload), 34);
        runner.start(&label("model-a"), BenchId::Bench01).unwrap();
        let mut switch_first = plan("x", "model-b", 1, 4);
        switch_first.switch_from_previous = true;
        assert!(runner
            .serve(&one_user(&runner, BenchId::Bench02, vec![switch_first]))
            .is_err());
        let now = runner.clock().now();
        let mixed = Script {
            bench: BenchId::Bench01,
            load: LoadDescription {
                concurrent_requests: 2,
                arrival: ArrivalMode::Sequential,
            },
            users: ["model-a", "model-b"]
                .iter()
                .map(|model| UserScript {
                    start_at: now,
                    requests: vec![plan("x", model, 2, 4)],
                    retry: RetryPolicy::NONE,
                })
                .collect(),
            recycle_after_switches: None,
        };
        assert!(runner.serve(&mixed).is_err());
        assert_eq!(
            runner.inject(ScheduledFault {
                at: MonotonicTime::ZERO,
                kind: FaultKind::Crash,
            }),
            Err(BenchError::FaultInThePast)
        );
        // A sleep-mode runner needs a release that records sleep.
        let mut old = exact(RunnerMode::VersionSupportedSleep);
        old.release = crate::model_memory::bench::test_support::release("0.29.0");
        assert!(matches!(
            FakeRunner::new(
                old,
                crate::model_memory::bench::test_support::rules(),
                crate::model_memory::bench::test_support::clock(),
                1,
                crate::model_memory::bench::test_support::execution()
            ),
            Err(BenchError::Mode(_))
        ));
    }
}
