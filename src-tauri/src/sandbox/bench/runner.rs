//! The fake time-controlled runner (S12 G0 line 383; S7 line 296; S8 lines 317 and 321;
//! S10 line 351; VM-W49 line 2672).
//!
//! The runner is a discrete-event simulation over the real lifecycle supervisor. Each
//! attempt is a create: a launch of a new execution, or a checkout of a stopped sandbox
//! out of a warm pool. The supervisor runs the CORE-04 launch transaction against the
//! CORE-03 ledger and the backend port at the instant the create is initiated; the fake
//! timing then says when the guest's first command comes, and the runner moves the
//! manual clock there and asks the supervisor for the first command. The lifecycle's own
//! first-command time must equal the runner's, or the run stops.
//!
//! Every initial attempt ends in exactly one CORE-08 record on the fake substrate:
//! a success, a deadline failure, a timeout (on the first command or in the ledger's
//! queue), a rejection by type, a command failure, an early termination or a duplicate
//! identity. A create the ledger queues waits until a stop frees capacity, and its clock
//! keeps running from the original create; asking the ledger again for a queued create
//! is the same attempt, not a retry.
//!
//! A rejected create is created again only under the plan's explicit
//! [`RetryPolicy`](super::retry::RetryPolicy): after the policy's delay, the same sandbox
//! is created as a retry, its own attempt with its own record, linked to its first
//! attempt through CORE-08's retry role (S8 line 321). A sequential plan starts its next
//! first attempt once the retries of the last one are over. Retries draw their fake
//! timing from a second stream of the seed, so a first attempt's draws do not depend on
//! the policy.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::time::Duration;

use super::host::FakeVmHost;
use super::plan::{ArrivalPattern, Bench05Plan, BenchHost, ReplenishmentSchedule, RunSpec};
use super::pool::ReplenishmentCharge;
use super::report::{AttemptSummary, BurstWindow, RejectionKind, VmRunReport};
use super::retry::{NoRetry, RetryDecision, RetryOutcomes, RetryPolicy, RetrySummary};
use super::timing::{FakeVmTiming, FaultPlan, InjectedFault, SeededRng};
use super::BenchError;
use crate::foundation::coordination::{CapacityPort, RetryProspect, SandboxState, VmInstanceId};
use crate::foundation::ids::{
    validate_identifier, ExecutionCategory, ExecutionId, MonotonicTime, OperationId,
    SandboxBootGeneration,
};
use crate::foundation::report::{
    AttemptIdentity, AttemptRole, ClockId, EventKind, FailureKind, Label, Measured,
    NotMeasuredReason, Outcome, RecordedEvent, RunMeasurements, RunRecord, RunSubstrate, Scenario,
    SchemaVersion,
};
use crate::sandbox::lifecycle::{
    Acknowledgment, BootPath, LaunchReceipt, RevocationCause, SupervisorError, WarmPool,
};

use super::host::RecordTemplate;

/// What a runner is configured with.
#[derive(Clone, Debug, PartialEq)]
pub struct RunnerConfig {
    /// The parent execution of the benchmark run, on every record.
    pub run: ExecutionId,
    /// Prefixes the executions and operations the runner names; unique per host.
    pub prefix: String,
    /// The one clock every event is stamped on: the first-command clock of every mode.
    pub clock: ClockId,
    pub template: RecordTemplate,
    pub timing: FakeVmTiming,
}

/// Mixed into the seed for the retries' stream of the fake timing's variation.
const RETRY_STREAM: u64 = 0xD1B5_4A32_D192_ED03;

/// Where the creates of a run come from.
pub(crate) enum CreateSource<'p> {
    /// New executions, launched cold.
    Launch,
    /// Stopped sandboxes checked out of a warm pool (BENCH-06).
    Checkout(PoolSource<'p>),
}

/// A warm pool and the stopped sandboxes checked out of it.
pub(crate) struct PoolSource<'p> {
    pub pool: &'p mut WarmPool,
    /// One stopped sandbox per attempt of a burst, reused in every burst.
    pub slots: Vec<ExecutionId>,
    /// Clones prepared at the start of every burst.
    pub initial_clones: u32,
    pub replenishment: Option<ReplenishmentSchedule>,
    pub charge: ReplenishmentCharge,
}

/// How a booting attempt resolves, decided when its boot starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resolution {
    FirstCommand,
    CommandFails,
    ExitsEarly,
    DuplicateIdentity,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Scheduled,
    Queued,
    Booting {
        started: MonotonicTime,
        resolution: Resolution,
    },
    /// The first command came; the VM is held until its release.
    Up,
    Done,
}

/// What links a retry to its first attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RetryLink {
    /// The first attempt's position in the run's attempts.
    first: usize,
    first_operation: OperationId,
    number: u32,
    /// The rejection of the attempt the retry follows.
    after: RejectionKind,
}

struct Attempt {
    summary: AttemptSummary,
    created_at: MonotonicTime,
    resolved_at: Option<MonotonicTime>,
    events: Vec<RecordedEvent>,
    phase: Phase,
    outcome: Option<Outcome>,
    /// Set on a retry.
    retry: Option<RetryLink>,
    /// The ledger's prospect when it refused the create.
    prospect: Option<RetryProspect>,
}

impl Attempt {
    fn scheduled(
        index: u32,
        burst: u32,
        execution: ExecutionId,
        operation: OperationId,
        injected: Option<InjectedFault>,
        created_at: MonotonicTime,
        retry: Option<RetryLink>,
    ) -> Self {
        Self {
            summary: AttemptSummary {
                index,
                burst,
                execution,
                operation,
                injected,
                boot: None,
                vm: None,
                path: None,
                decision: None,
                failed_clone_cleaned_up: false,
                queued_nanos: None,
                first_command_nanos: None,
                failure: None,
                rejection: None,
                limiting_resource: None,
                supervisor_refusal: None,
            },
            created_at,
            resolved_at: None,
            events: Vec::new(),
            phase: Phase::Scheduled,
            outcome: None,
            retry,
            prospect: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Create(usize),
    Acknowledge(usize),
    Resolve(usize),
    QueueTimeout(usize),
    Release(usize),
    Replenish,
}

/// Steps in time order; steps at one instant run in the order they were scheduled.
#[derive(Default)]
struct Agenda {
    steps: BTreeMap<(u64, u64), Step>,
    next: u64,
}

impl Agenda {
    fn at(&mut self, time: MonotonicTime, step: Step) {
        self.steps.insert((time.as_nanos(), self.next), step);
        self.next = self.next.saturating_add(1);
    }

    fn pop(&mut self) -> Option<(MonotonicTime, Step)> {
        self.steps
            .pop_first()
            .map(|((nanos, _), step)| (MonotonicTime::from_nanos(nanos), step))
    }
}

#[derive(Default)]
struct RunState {
    /// First attempts, each burst's together, with each burst's retries after them.
    attempts: Vec<Attempt>,
    agenda: Agenda,
    waitlist: VecDeque<usize>,
    seen_vms: BTreeSet<VmInstanceId>,
    /// The current burst's first attempts.
    burst: Range<usize>,
    boot_calls: u64,
    faults: FaultPlan,
    not_retried: BTreeMap<NoRetry, u64>,
}

impl RunState {
    /// Every first attempt of the current burst and every retry scheduled so far is over.
    fn burst_done(&self) -> bool {
        self.attempts[self.burst.start..]
            .iter()
            .all(|attempt| attempt.phase == Phase::Done)
    }
}

fn after(time: MonotonicTime, nanos: u64) -> Result<MonotonicTime, BenchError> {
    time.checked_add(Duration::from_nanos(nanos))
        .ok_or(BenchError::Overflow)
}

fn nanos_between(earlier: MonotonicTime, later: MonotonicTime) -> u64 {
    later.as_nanos().saturating_sub(earlier.as_nanos())
}

fn duration_nanos(duration: Duration) -> Result<u64, BenchError> {
    u64::try_from(duration.as_nanos()).map_err(|_| BenchError::Overflow)
}

fn not_applicable<T>() -> Measured<T> {
    Measured::not_measured(NotMeasuredReason::NotApplicable)
}

/// The fake substrate has no instrument for host memory, transfers or energy.
fn no_instrument<T>() -> Measured<T> {
    Measured::not_measured(NotMeasuredReason::InstrumentUnavailable)
}

fn failed(failure: FailureKind, component: &str, code: &str) -> Result<Outcome, BenchError> {
    Ok(Outcome::Failed {
        failure,
        component: Label::new(component)?,
        code: Label::new(code)?,
    })
}

/// The fake, time-controlled runner over a [`FakeVmHost`].
pub struct FakeVmRunner<'h, H: FakeVmHost> {
    host: &'h mut H,
    config: RunnerConfig,
    rng: SeededRng,
    /// The retries' own stream of the variation.
    retry_rng: SeededRng,
    next_name: u64,
}

impl<'h, H: FakeVmHost> FakeVmRunner<'h, H> {
    /// A runner over `host`; refuses an invalid timing or prefix.
    pub fn new(host: &'h mut H, config: RunnerConfig) -> Result<Self, BenchError> {
        config.timing.check()?;
        validate_identifier(&config.prefix)?;
        let rng = SeededRng::new(config.timing.seed);
        let retry_rng = SeededRng::new(config.timing.seed ^ RETRY_STREAM);
        Ok(Self {
            host,
            config,
            rng,
            retry_rng,
            next_name: 0,
        })
    }

    pub fn config(&self) -> &RunnerConfig {
        &self.config
    }

    pub fn host(&mut self) -> &mut H {
        &mut *self.host
    }

    /// Runs a BENCH-05 plan. A plan that needs an authorized, sized host is refused
    /// before anything starts (S11 line 369).
    pub fn run_bench05(
        &mut self,
        plan: &Bench05Plan,
        faults: &FaultPlan,
    ) -> Result<VmRunReport, BenchError> {
        plan.spec().admit(&BenchHost::FakeTimeControlled)?;
        self.run(plan.spec(), &mut CreateSource::Launch, faults)
    }

    /// A new execution named after the runner's prefix and `role`.
    pub(crate) fn fresh_execution(&mut self, role: &str) -> Result<ExecutionId, BenchError> {
        self.next_name = self.next_name.saturating_add(1);
        Ok(ExecutionId::new(format!(
            "{}-{role}-{}",
            self.config.prefix, self.next_name
        ))?)
    }

    fn fresh_operation(&mut self) -> Result<OperationId, BenchError> {
        self.next_name = self.next_name.saturating_add(1);
        Ok(OperationId::new(format!(
            "op-{}-{}",
            self.config.prefix, self.next_name
        ))?)
    }

    /// Moves the manual clock to `at` and checks that the supervisor reads it.
    pub(crate) fn advance_to(&mut self, at: MonotonicTime) -> Result<(), BenchError> {
        if at > self.host.now() {
            self.host.advance_to(at);
        }
        let now = self.host.now();
        let supervisor = self.host.drive().supervisor.now();
        if now != at || supervisor != at {
            return Err(BenchError::ClockNotControlled {
                expected_nanos: at.as_nanos(),
                found_nanos: supervisor.as_nanos(),
            });
        }
        Ok(())
    }

    /// Stops `execution` through the supervisor: revocation, the channels' acknowledgment
    /// and the advance that stops the VM through its handle and releases its capacity.
    pub(crate) fn stop_execution(&mut self, execution: &ExecutionId) -> Result<(), BenchError> {
        let drive = self.host.drive();
        let supervisor = drive.supervisor;
        let mut backend = drive.backend;
        supervisor.revoke(execution, RevocationCause::UserRequested, &mut *backend)?;
        supervisor.acknowledge(execution, Acknowledgment::ChannelsClosed)?;
        supervisor.advance(execution, &mut *backend)?;
        let state = supervisor
            .coordinator()
            .sandbox(execution)
            .map(|sandbox| sandbox.state());
        if state == Some(SandboxState::Stopped) {
            Ok(())
        } else {
            Err(BenchError::StopIncomplete {
                execution: execution.clone(),
            })
        }
    }

    /// Launches `execution` cold for a setup step and requires authority.
    pub(crate) fn launch_setup(
        &mut self,
        execution: &ExecutionId,
        step: &'static str,
    ) -> Result<(), BenchError> {
        let request = self.host.request(execution)?;
        let drive = self.host.drive();
        let mut backend = drive.backend;
        let receipt = drive
            .supervisor
            .launch(request, &mut *backend, drive.registry)?;
        match receipt {
            LaunchReceipt::AuthorityActive { .. } => Ok(()),
            _ => Err(BenchError::SetupFailed {
                step,
                execution: execution.clone(),
            }),
        }
    }

    /// Runs `spec`: every burst from the same starting state, with a quiet gap between
    /// bursts, every VM stopped before the next burst starts.
    pub(crate) fn run(
        &mut self,
        spec: &RunSpec,
        source: &mut CreateSource<'_>,
        faults: &FaultPlan,
    ) -> Result<VmRunReport, BenchError> {
        let mut state = RunState {
            faults: faults.clone(),
            ..RunState::default()
        };
        let mut windows = Vec::new();
        let limits = spec.limits();
        for burst in 0..spec.bursts() {
            let now = self.host.now();
            let start = if burst == 0 {
                now
            } else {
                after(now, limits.burst_gap_nanos)?
            };
            self.advance_to(start)?;
            if burst > 0 {
                self.host.drive().supervisor.begin_burst();
            }
            if let CreateSource::Checkout(pool) = source {
                self.refill(pool)?;
                if let Some(schedule) = pool.replenishment {
                    state
                        .agenda
                        .at(after(start, schedule.every_nanos)?, Step::Replenish);
                }
            }
            let first = state.attempts.len();
            for slot in 0..spec.attempts_per_burst() {
                let index = burst
                    .checked_mul(spec.attempts_per_burst())
                    .and_then(|before| before.checked_add(slot))
                    .ok_or(BenchError::Overflow)?;
                let execution = match source {
                    CreateSource::Launch => self.fresh_execution("vm")?,
                    CreateSource::Checkout(pool) => pool.slots.get(slot as usize).cloned().ok_or(
                        BenchError::InvalidParameter {
                            field: "slots",
                            reason: "one stopped sandbox per checkout of a burst",
                        },
                    )?,
                };
                let operation = self.fresh_operation()?;
                state.attempts.push(Attempt::scheduled(
                    index,
                    burst,
                    execution,
                    operation,
                    faults.get(index),
                    start,
                    None,
                ));
            }
            state.burst = first..state.attempts.len();
            match spec.arrival() {
                ArrivalPattern::Sequential => state.agenda.at(start, Step::Create(first)),
                ArrivalPattern::Burst => {
                    for index in state.burst.clone() {
                        state.agenda.at(start, Step::Create(index));
                    }
                }
                ArrivalPattern::Staggered { interval_nanos } => {
                    let mut at = start;
                    for index in state.burst.clone() {
                        state.agenda.at(at, Step::Create(index));
                        at = after(at, interval_nanos)?;
                    }
                }
            }
            while let Some((at, step)) = state.agenda.pop() {
                if step == Step::Replenish && state.burst_done() {
                    continue;
                }
                self.advance_to(at)?;
                self.step(spec, source, &mut state, step)?;
                self.retry_waitlist(spec, source, &mut state)?;
            }
            windows.push(Self::window(&state, burst)?);
        }
        self.finish(spec, state, windows)
    }

    /// The burst's window over its first attempts; its retries are not counted.
    fn window(state: &RunState, burst: u32) -> Result<BurstWindow, BenchError> {
        let attempts = &state.attempts[state.burst.clone()];
        let mut first_create = u64::MAX;
        let mut last_resolution = 0u64;
        let mut successes = 0u32;
        for attempt in attempts {
            let resolved = attempt.resolved_at.ok_or(BenchError::UnresolvedAttempt {
                index: attempt.summary.index,
            })?;
            first_create = first_create.min(attempt.created_at.as_nanos());
            last_resolution = last_resolution.max(resolved.as_nanos());
            if attempt.outcome == Some(Outcome::Succeeded) {
                successes = successes.saturating_add(1);
            }
        }
        Ok(BurstWindow {
            burst,
            attempts: u32::try_from(attempts.len()).map_err(|_| BenchError::Overflow)?,
            successes,
            first_create_nanos: first_create,
            last_resolution_nanos: last_resolution,
        })
    }

    fn refill(&mut self, pool: &mut PoolSource<'_>) -> Result<(), BenchError> {
        let missing = pool.initial_clones.saturating_sub(pool.pool.available());
        let added = pool.pool.replenish(missing);
        pool.charge.add(
            u64::from(added),
            self.config.timing.prepare_nanos(u64::from(added))?,
        )
    }

    fn step(
        &mut self,
        spec: &RunSpec,
        source: &mut CreateSource<'_>,
        state: &mut RunState,
        step: Step,
    ) -> Result<(), BenchError> {
        match step {
            Step::Create(index) => {
                state.attempts[index].created_at = self.host.now();
                self.launch_attempt(spec, source, state, index)
            }
            Step::Acknowledge(index) => {
                let now = self.host.now();
                let attempt = &mut state.attempts[index];
                if let Phase::Booting { .. } = attempt.phase {
                    self.push_event(attempt, now, EventKind::VmApiAcknowledged);
                }
                Ok(())
            }
            Step::Resolve(index) => self.resolve(spec, state, index),
            Step::QueueTimeout(index) => self.queue_timeout(spec, state, index),
            Step::Release(index) => {
                if state.attempts[index].phase == Phase::Up {
                    let execution = state.attempts[index].summary.execution.clone();
                    self.stop_execution(&execution)?;
                    self.finished(spec, state, index)?;
                }
                Ok(())
            }
            Step::Replenish => {
                if let CreateSource::Checkout(pool) = source {
                    if let Some(schedule) = pool.replenishment {
                        let added = pool.pool.replenish(schedule.clones);
                        pool.charge.add(
                            u64::from(added),
                            self.config.timing.prepare_nanos(u64::from(added))?,
                        )?;
                        let next = after(self.host.now(), schedule.every_nanos)?;
                        state.agenda.at(next, Step::Replenish);
                    }
                }
                Ok(())
            }
        }
    }

    fn push_event(&self, attempt: &mut Attempt, at: MonotonicTime, event: EventKind) {
        let sequence = attempt.events.len() as u64;
        attempt.events.push(RecordedEvent {
            operation: attempt.summary.operation.clone(),
            clock: self.config.clock.clone(),
            sequence,
            at_nanos: at,
            event,
        });
    }

    /// Launches or checks out the attempt's sandbox now: a first attempt, a retry, or
    /// either again while the ledger queues it.
    fn launch_attempt(
        &mut self,
        spec: &RunSpec,
        source: &mut CreateSource<'_>,
        state: &mut RunState,
        index: usize,
    ) -> Result<(), BenchError> {
        let execution = state.attempts[index].summary.execution.clone();
        let refuse =
            state.attempts[index].summary.injected == Some(InjectedFault::BackendRefusesCreate);
        let request = self.host.request(&execution)?;
        if refuse {
            self.host.refuse_creates(true);
        }
        let result = {
            let drive = self.host.drive();
            let mut backend = drive.backend;
            match source {
                CreateSource::Launch => drive
                    .supervisor
                    .launch(request, &mut *backend, drive.registry)
                    .map(|receipt| (receipt, None, false)),
                CreateSource::Checkout(pool) => drive
                    .supervisor
                    .checkout(request, &mut *pool.pool, &mut *backend, drive.registry)
                    .map(|checkout| {
                        (
                            checkout.launch,
                            Some(checkout.decision),
                            checkout.failed_clone_cleaned_up,
                        )
                    }),
            }
        };
        if refuse {
            self.host.refuse_creates(false);
        }
        match result {
            Ok((receipt, decision, cleaned)) => {
                state.boot_calls = state.boot_calls.saturating_add(1);
                let attempt = &mut state.attempts[index];
                if decision.is_some() {
                    attempt.summary.decision = decision;
                }
                attempt.summary.failed_clone_cleaned_up |= cleaned;
                match receipt {
                    LaunchReceipt::AuthorityActive { boot, path, .. } => {
                        self.begin_boot(spec, state, index, boot, path)
                    }
                    LaunchReceipt::Queued { .. } => {
                        if attempt.phase != Phase::Queued {
                            attempt.phase = Phase::Queued;
                            let timeout_at =
                                after(attempt.created_at, spec.limits().timeout_nanos)?;
                            state.waitlist.push_back(index);
                            state.agenda.at(timeout_at, Step::QueueTimeout(index));
                        }
                        Ok(())
                    }
                    LaunchReceipt::RolledBack { failure, .. } => {
                        attempt.prospect = RetryPolicy::prospect(&failure);
                        self.reject(
                            spec,
                            state,
                            index,
                            RejectionKind::of_failure(&failure),
                            RejectionKind::limiting_resource(&failure),
                            None,
                        )
                    }
                    LaunchReceipt::RollbackStalled { failure, .. } => self.reject(
                        spec,
                        state,
                        index,
                        RejectionKind::RollbackStalled,
                        RejectionKind::limiting_resource(&failure),
                        None,
                    ),
                }
            }
            Err(error) => self.reject(
                spec,
                state,
                index,
                RejectionKind::Supervisor,
                None,
                Some(error),
            ),
        }
    }

    /// The boot generation the coordinator holds for `execution`, or the first.
    fn current_boot(&mut self, execution: &ExecutionId) -> SandboxBootGeneration {
        self.host
            .drive()
            .supervisor
            .coordinator()
            .sandbox(execution)
            .map(|sandbox| sandbox.generations().boot)
            .unwrap_or(SandboxBootGeneration::FIRST)
    }

    /// Authority is active: the boot starts now, and its resolution is decided by the
    /// fake timing and any injected fault.
    fn begin_boot(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
        boot: SandboxBootGeneration,
        path: BootPath,
    ) -> Result<(), BenchError> {
        let now = self.host.now();
        let limits = spec.limits();
        let booting = state
            .attempts
            .iter()
            .filter(|attempt| matches!(attempt.phase, Phase::Booting { .. }))
            .count() as u64;
        let rng = if state.attempts[index].retry.is_some() {
            &mut self.retry_rng
        } else {
            &mut self.rng
        };
        let mut duration = self.config.timing.first_command_nanos(path, booting, rng)?;
        let execution = state.attempts[index].summary.execution.clone();
        let vm = self
            .host
            .drive()
            .supervisor
            .coordinator()
            .sandbox(&execution)
            .and_then(|sandbox| sandbox.vm());
        let attempt = &mut state.attempts[index];
        let injected = attempt.summary.injected;
        if let Some(InjectedFault::SlowFirstCommand { extra_nanos }) = injected {
            duration = duration
                .checked_add(extra_nanos)
                .ok_or(BenchError::Overflow)?;
        }
        if attempt.phase == Phase::Queued {
            attempt.summary.queued_nanos = Some(nanos_between(attempt.created_at, now));
        }
        attempt.summary.boot = Some(boot);
        attempt.summary.path = Some(path);
        attempt.summary.vm = vm;
        let created_at = attempt.created_at;
        self.push_event(
            attempt,
            created_at,
            EventKind::VmCreateInitiated {
                guest: execution,
                boot,
            },
        );
        let timeout_at = after(created_at, limits.timeout_nanos)?;
        let command_at = after(now, duration)?;
        let exit_at = match injected {
            Some(InjectedFault::VmExitsEarly { after_nanos }) => Some(after(now, after_nanos)?),
            _ => None,
        };
        let (resolution, resolve_at) = match exit_at
            .filter(|exit| *exit < command_at && *exit < timeout_at)
        {
            Some(exit) => (Resolution::ExitsEarly, exit),
            None if command_at > timeout_at => (Resolution::Timeout, timeout_at),
            None => match injected {
                Some(InjectedFault::GuestCommandFails) => (Resolution::CommandFails, command_at),
                Some(InjectedFault::DuplicateGuestIdentity) => {
                    (Resolution::DuplicateIdentity, command_at)
                }
                _ => (Resolution::FirstCommand, command_at),
            },
        };
        attempt.phase = Phase::Booting {
            started: now,
            resolution,
        };
        let ack_at = after(now, self.config.timing.api_ack_nanos)?;
        if ack_at <= resolve_at {
            state.agenda.at(ack_at, Step::Acknowledge(index));
        }
        state.agenda.at(resolve_at, Step::Resolve(index));
        Ok(())
    }

    fn resolve(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
    ) -> Result<(), BenchError> {
        let Phase::Booting {
            started,
            resolution,
        } = state.attempts[index].phase
        else {
            return Ok(());
        };
        let (kind, component, code) = match resolution {
            Resolution::FirstCommand => return self.first_command(spec, state, index, started),
            Resolution::CommandFails => {
                (FailureKind::CommandFailure, "guest", "first-command-failed")
            }
            Resolution::ExitsEarly => (
                FailureKind::EarlyTermination,
                "backend",
                "vm-exited-before-first-command",
            ),
            Resolution::DuplicateIdentity => (
                FailureKind::DuplicateIdentity,
                "guest",
                "duplicate-guest-identity",
            ),
            Resolution::Timeout => (FailureKind::Timeout, "harness", "first-command-timeout"),
        };
        self.fail_and_stop(spec, state, index, kind, component, code)
    }

    /// The first command came: the lifecycle and the record must agree on its time.
    fn first_command(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
        started: MonotonicTime,
    ) -> Result<(), BenchError> {
        let now = self.host.now();
        let execution = state.attempts[index].summary.execution.clone();
        let lifecycle = self.host.drive().supervisor.first_command(&execution);
        let elapsed = match lifecycle {
            Ok(elapsed) => duration_nanos(elapsed)?,
            Err(error) => {
                state.attempts[index].summary.supervisor_refusal = Some(error);
                return self.fail_and_stop(
                    spec,
                    state,
                    index,
                    FailureKind::CommandFailure,
                    "supervisor",
                    "first-command-refused",
                );
            }
        };
        let harness = nanos_between(started, now);
        if elapsed != harness {
            return Err(BenchError::ClockDisagreement {
                execution,
                lifecycle_nanos: elapsed,
                harness_nanos: harness,
            });
        }
        let attempt = &mut state.attempts[index];
        let boot = attempt.summary.boot.unwrap_or(SandboxBootGeneration::FIRST);
        self.push_event(
            attempt,
            now,
            EventKind::GuestCommandSucceeded {
                guest: execution,
                boot,
            },
        );
        let total = nanos_between(attempt.created_at, now);
        attempt.summary.first_command_nanos = Some(total);
        let duplicate = attempt
            .summary
            .vm
            .is_some_and(|vm| !state.seen_vms.insert(vm));
        let outcome = if duplicate {
            failed(
                FailureKind::DuplicateIdentity,
                "lifecycle",
                "vm-identity-reused",
            )?
        } else if total > spec.limits().deadline_nanos {
            failed(
                FailureKind::DeadlineFailure,
                "harness",
                "first-command-after-deadline",
            )?
        } else {
            Outcome::Succeeded
        };
        attempt.summary.failure = match &outcome {
            Outcome::Failed { failure, .. } => Some(*failure),
            Outcome::Succeeded => None,
        };
        attempt.outcome = Some(outcome);
        attempt.resolved_at = Some(now);
        attempt.phase = Phase::Up;
        state
            .agenda
            .at(after(now, spec.limits().hold_nanos)?, Step::Release(index));
        Ok(())
    }

    /// The attempt failed while its VM existed: record the failure, stop the VM.
    fn fail_and_stop(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
        kind: FailureKind,
        component: &str,
        code: &str,
    ) -> Result<(), BenchError> {
        let now = self.host.now();
        let attempt = &mut state.attempts[index];
        attempt.outcome = Some(failed(kind, component, code)?);
        attempt.summary.failure = Some(kind);
        attempt.resolved_at = Some(now);
        let execution = attempt.summary.execution.clone();
        self.stop_execution(&execution)?;
        self.finished(spec, state, index)
    }

    /// The create was refused: no VM exists and no authority was exposed.
    fn reject(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
        kind: RejectionKind,
        limiting_resource: Option<crate::foundation::coordination::ResourceKind>,
        refusal: Option<SupervisorError>,
    ) -> Result<(), BenchError> {
        let now = self.host.now();
        let execution = state.attempts[index].summary.execution.clone();
        let boot = self.current_boot(&execution);
        let attempt = &mut state.attempts[index];
        if attempt.phase == Phase::Queued {
            attempt.summary.queued_nanos = Some(nanos_between(attempt.created_at, now));
        }
        let created_at = attempt.created_at;
        self.push_event(
            attempt,
            created_at,
            EventKind::VmCreateInitiated {
                guest: execution,
                boot,
            },
        );
        attempt.outcome = Some(failed(
            FailureKind::Rejected,
            kind.component(),
            kind.code(),
        )?);
        attempt.summary.failure = Some(FailureKind::Rejected);
        attempt.summary.rejection = Some(kind);
        attempt.summary.limiting_resource = limiting_resource;
        attempt.summary.supervisor_refusal = refusal;
        attempt.resolved_at = Some(now);
        state.waitlist.retain(|queued| *queued != index);
        self.finished(spec, state, index)
    }

    /// A queued create reached its timeout: withdraw it from the ledger's queue.
    fn queue_timeout(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
    ) -> Result<(), BenchError> {
        if state.attempts[index].phase != Phase::Queued {
            return Ok(());
        }
        let now = self.host.now();
        let execution = state.attempts[index].summary.execution.clone();
        self.host
            .drive()
            .supervisor
            .coordinator_mut()
            .capacity_mut()
            .cancel_execution(&execution)?;
        let boot = self.current_boot(&execution);
        let attempt = &mut state.attempts[index];
        attempt.summary.queued_nanos = Some(nanos_between(attempt.created_at, now));
        let created_at = attempt.created_at;
        self.push_event(
            attempt,
            created_at,
            EventKind::VmCreateInitiated {
                guest: execution,
                boot,
            },
        );
        attempt.outcome = Some(failed(
            FailureKind::Timeout,
            "ledger",
            "queued-past-timeout",
        )?);
        attempt.summary.failure = Some(FailureKind::Timeout);
        attempt.resolved_at = Some(now);
        state.waitlist.retain(|queued| *queued != index);
        self.finished(spec, state, index)
    }

    /// The attempt is over and its VM, if any, stopped. A rejection the plan's policy
    /// retries schedules its retry; otherwise a sequential plan starts its next first
    /// attempt now.
    fn finished(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
    ) -> Result<(), BenchError> {
        state.attempts[index].phase = Phase::Done;
        if self.schedule_retry(spec, state, index)? {
            return Ok(());
        }
        if spec.arrival() == ArrivalPattern::Sequential {
            let first = state.attempts[index]
                .retry
                .as_ref()
                .map_or(index, |link| link.first);
            let next = first + 1;
            if state.burst.contains(&next) && state.attempts[next].phase == Phase::Scheduled {
                state.agenda.at(self.host.now(), Step::Create(next));
            }
        }
        Ok(())
    }

    /// Schedules a retry of the rejected attempt at `index` when the plan's policy names
    /// its rejection, the ledger does not rule progress out and the first attempt has
    /// retries left: the same sandbox, a new operation, the policy's delay after the
    /// refusal. Every other rejection is counted with the reason it was not retried.
    fn schedule_retry(
        &mut self,
        spec: &RunSpec,
        state: &mut RunState,
        index: usize,
    ) -> Result<bool, BenchError> {
        let attempt = &state.attempts[index];
        let Some(kind) = attempt.summary.rejection else {
            return Ok(false);
        };
        let used = attempt.retry.as_ref().map_or(0, |link| link.number);
        let retry_number = match spec.retries().decide(kind, attempt.prospect, used) {
            RetryDecision::Retry { retry_number } => retry_number,
            RetryDecision::Stop { reason } => {
                *state.not_retried.entry(reason).or_insert(0) += 1;
                return Ok(false);
            }
        };
        let (first, first_operation) = match &attempt.retry {
            Some(link) => (link.first, link.first_operation.clone()),
            None => (index, attempt.summary.operation.clone()),
        };
        let refused_at = attempt.resolved_at.unwrap_or_else(|| self.host.now());
        let at = after(refused_at, spec.retries().delay_nanos())?;
        let (number, burst, execution) = {
            let origin = &state.attempts[first].summary;
            (origin.index, origin.burst, origin.execution.clone())
        };
        let operation = self.fresh_operation()?;
        let injected = state.faults.retry_fault(number, retry_number);
        let retry = state.attempts.len();
        state.attempts.push(Attempt::scheduled(
            number,
            burst,
            execution,
            operation,
            injected,
            at,
            Some(RetryLink {
                first,
                first_operation,
                number: retry_number,
                after: kind,
            }),
        ));
        state.agenda.at(at, Step::Create(retry));
        Ok(true)
    }

    /// Retries every queued create, oldest first, until none makes progress: a stop may
    /// have freed the capacity they wait for.
    fn retry_waitlist(
        &mut self,
        spec: &RunSpec,
        source: &mut CreateSource<'_>,
        state: &mut RunState,
    ) -> Result<(), BenchError> {
        loop {
            let queued: Vec<usize> = state.waitlist.iter().copied().collect();
            let mut progressed = false;
            for index in queued {
                if state.attempts[index].phase != Phase::Queued {
                    continue;
                }
                self.launch_attempt(spec, source, state, index)?;
                if state.attempts[index].phase != Phase::Queued {
                    state.waitlist.retain(|waiting| *waiting != index);
                    progressed = true;
                }
            }
            if !progressed {
                return Ok(());
            }
        }
    }

    fn record(&self, spec: &RunSpec, attempt: Attempt) -> Result<RunRecord, BenchError> {
        let outcome = attempt.outcome.ok_or(BenchError::UnresolvedAttempt {
            index: attempt.summary.index,
        })?;
        let template = &self.config.template;
        let role = match &attempt.retry {
            None => AttemptRole::Initial,
            Some(link) => AttemptRole::Retry {
                first_attempt: link.first_operation.clone(),
                retry_number: link.number,
            },
        };
        Ok(RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench: spec.bench(),
                variant: spec.variant().clone(),
                execution: self.config.run.clone(),
                operation: attempt.summary.operation.clone(),
                role,
                burst: attempt.summary.burst,
                deadline_nanos: Measured::measured(spec.limits().deadline_nanos),
            },
            scenario: Scenario::VmProvisioning,
            substrate: RunSubstrate::FakeTimeControlled,
            build: template.build.clone(),
            execution_category: ExecutionCategory::VmSandbox,
            model: not_applicable(),
            precision: not_applicable(),
            engine: not_applicable(),
            host: template.host.clone(),
            workload: not_applicable(),
            client: template.client.clone(),
            load: spec.load(),
            state: not_applicable(),
            launch: template.launch.clone(),
            price: not_applicable(),
            measurements: RunMeasurements {
                output_tokens: not_applicable(),
                prefill_tokens_per_second: not_applicable(),
                aggregate_decode_tokens_per_second: not_applicable(),
                speculative: not_applicable(),
                peak_gpu_memory_bytes: not_applicable(),
                retained_gpu_memory_bytes: not_applicable(),
                peak_host_memory_bytes: no_instrument(),
                retained_host_memory_bytes: no_instrument(),
                peak_pinned_host_memory_bytes: not_applicable(),
                transferred_bytes: no_instrument(),
                storage_read_bytes: no_instrument(),
                energy_joules: no_instrument(),
                offload: not_applicable(),
                first_run: not_applicable(),
                owner_return: not_applicable(),
                reasoning: not_applicable(),
            },
            events: attempt.events,
            outcome,
        })
    }

    /// The report: the first attempts' records in order, then the retries' in the order
    /// created, so every retry follows its first attempt in the ledger.
    fn finish(
        &mut self,
        spec: &RunSpec,
        state: RunState,
        windows: Vec<BurstWindow>,
    ) -> Result<VmRunReport, BenchError> {
        let (firsts, retried): (Vec<Attempt>, Vec<Attempt>) = state
            .attempts
            .into_iter()
            .partition(|attempt| attempt.retry.is_none());
        let boots: BTreeSet<(ExecutionId, SandboxBootGeneration)> = firsts
            .iter()
            .filter(|attempt| attempt.summary.first_command_nanos.is_some())
            .filter_map(|attempt| {
                attempt
                    .summary
                    .boot
                    .map(|boot| (attempt.summary.execution.clone(), boot))
            })
            .collect();
        let lifecycle = self
            .host
            .drive()
            .supervisor
            .measurements()
            .first_commands()
            .iter()
            .filter(|sample| boots.contains(&(sample.execution.clone(), sample.boot)))
            .cloned()
            .collect();
        let mut summaries = Vec::with_capacity(firsts.len());
        let mut records = Vec::with_capacity(firsts.len().saturating_add(retried.len()));
        for attempt in firsts {
            summaries.push(attempt.summary.clone());
            records.push(self.record(spec, attempt)?);
        }
        let mut retries = Vec::with_capacity(retried.len());
        for attempt in retried {
            if let Some(link) = &attempt.retry {
                retries.push(RetrySummary {
                    first_attempt: attempt.summary.index,
                    first_operation: link.first_operation.clone(),
                    retry_number: link.number,
                    after: link.after,
                    attempt: attempt.summary.clone(),
                });
            }
            records.push(self.record(spec, attempt)?);
        }
        VmRunReport::assemble(
            spec,
            records,
            summaries,
            RetryOutcomes {
                retries,
                not_retried: state.not_retried,
            },
            windows,
            state.boot_calls,
            lifecycle,
        )
    }
}
