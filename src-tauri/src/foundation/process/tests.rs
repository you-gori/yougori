//! Tests of the host process handle, the termination proof and the coordinator adapters
//! (S04). The only processes they start are this test executable again, running
//! [`helper_process`]: it sleeps, exits, or starts one more copy of itself that sleeps.
//! Every one runs inside a job that kills what is left in it when its holder drops, so
//! nothing outlives the test, and no network is touched.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU32;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

use super::*;
use crate::foundation::coordination::{
    BootRequest, CapacityPort, CapacityRefusal, Compensation, CoordinationError, Coordinator,
    GpuDemand, LaunchFailure, LaunchOutcome, LaunchPlan, LeaseKind, LeaseState, LeaseTerms,
    LedgerCapacity, ModelGenerations, ModelId, ObservedVm, PerimeterId, PortFailure, PortOperation,
    Readiness, ReadinessReport, RecoveryReport, ReleaseOutcome, ReservationKey,
    ReservationPriority, ReservationPurpose, ReservationRequest, ResourceKind, RestoredVmReport,
    RevocationMilestone, RevocationStatus, SandboxGenerations, SandboxPort, SandboxRecovery,
    SandboxState, SnapshotId, SnapshotManifest, StallCause, TerminationStalled, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, ArtifactVerification, Backend, BackendRelease, Capability, ClockSession,
    ConfigurationFingerprint, HostSubject, Observation, ProbeRegistry, Residency, RuntimeOffer,
    RuntimeRequirement, RuntimeSettings, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionCategory, ExecutionId, GpuAllocationGeneration, GpuDeviceKey, LeaseId,
    ManualClock, ModelActivationGeneration, MonotonicTime, OperationId, PolicyEpoch,
    SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{
    CapacityDeclaration, CloseReason, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};

/// The environment variable that makes the test executable a helper process, and its
/// mode.
const HELPER: &str = "YG_PROCESS_HELPER";

/// How long a helper may take to start, exit or die: generous, since it is a whole test
/// executable starting up.
const PATIENT: Duration = Duration::from_secs(20);

const GIB: u64 = 1 << 30;
const HOUR: Duration = Duration::from_secs(3600);

/// What a helper process does, by its mode; an ordinary test run, without the variable,
/// does nothing. `sleep` sleeps 30 seconds; `exit:N` exits with N at once; `grandchild`
/// starts a sleeping copy of itself and exits with 0; `breakaway` tries to start a copy
/// that breaks away from the job and exits with 0 when refused, or with 3 after ending the
/// copy when not.
#[test]
fn helper_process() {
    let Ok(mode) = std::env::var(HELPER) else {
        return;
    };
    let code = match mode.as_str() {
        "sleep" => {
            thread::sleep(Duration::from_secs(30));
            0
        }
        "grandchild" => match helper_command("sleep").spawn() {
            Ok(_) => 0,
            Err(_) => 2,
        },
        "breakaway" => {
            let mut command = helper_command("sleep");
            command.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
            match command.spawn() {
                Err(_) => 0,
                Ok(mut escaped) => {
                    let _ = escaped.kill();
                    let _ = escaped.wait();
                    3
                }
            }
        }
        other if other.starts_with("whpx:") => {
            // The WHPX capability as a token variant sees it (restricted::tests diagnostic).
            let (code, note) =
                super::restricted::tests::whpx_capability_as(&other["whpx:".len()..]);
            eprintln!("{note}");
            code
        }
        other => other
            .strip_prefix("exit:")
            .and_then(|code| code.parse().ok())
            .unwrap_or(99),
    };
    std::process::exit(code);
}

/// This test executable, set to run only [`helper_process`] in `mode`, with no console
/// input or output.
fn helper_command(mode: &str) -> Command {
    let path = module_path!();
    let tests = path.split_once("::").map_or(path, |(_, rest)| rest);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &format!("{tests}::helper_process"),
            "--test-threads=1",
            "--quiet",
        ])
        .env(HELPER, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn model() -> ModelId {
    ModelId::new(named("yougori/test/model/v1", "chat-model"))
}

fn generations(activation: u64, gpu_allocation: u64) -> ModelGenerations {
    ModelGenerations {
        activation: ModelActivationGeneration::new(activation),
        gpu_allocation: GpuAllocationGeneration::new(gpu_allocation),
    }
}

fn vm_of(of: &ExecutionId, boot: SandboxBootGeneration) -> VmInstanceId {
    VmInstanceId::new(digest(
        "yougori/test/vm/v1",
        &[of.as_str().as_bytes(), &boot.get().to_be_bytes()],
    ))
}

fn vm_role(of: &str) -> ProcessRole {
    let execution = execution(of);
    ProcessRole::VmHost {
        vm: vm_of(&execution, SandboxBootGeneration::FIRST),
        execution,
        boot: SandboxBootGeneration::FIRST,
    }
}

fn runner_role(of: &str, generation: u64) -> ProcessRole {
    ProcessRole::ModelRunner {
        execution: execution(of),
        model: model(),
        generations: generations(generation, generation),
    }
}

fn spawn(mode: &str, role: ProcessRole) -> HostProcess {
    HostProcess::spawn(&mut helper_command(mode), role).unwrap()
}

fn kill_now() -> Escalation {
    Escalation {
        grace: Duration::ZERO,
        kill_wait: PATIENT,
    }
}

/// Polls, a bounded time, until `done` holds.
fn wait_until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Polls, a bounded time, until the process itself has ended, and returns why that is no
/// proof yet, if it is not.
fn first_ended(process: &HostProcess) -> Result<TerminationProof, NoProof> {
    let deadline = Instant::now() + PATIENT;
    loop {
        match process.check_ended() {
            Err(NoProof::StillRunning) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10))
            }
            other => return other,
        }
    }
}

#[test]
fn a_process_starts_in_its_own_job_and_is_named_by_pid_and_creation_time() {
    let process = spawn("sleep", vm_role("exe-identity"));
    let identity = process.identity();
    assert_eq!(identity.pid, process.identity().pid);
    assert_eq!(
        ProcessIdentity::holder_of(identity.pid).unwrap(),
        Some(identity)
    );
    assert_eq!(identity.check().unwrap(), IdentityCheck::Same);
    // The same PID with another creation time is another process: never this one.
    let other = ProcessIdentity {
        start_time_ticks: identity.start_time_ticks + 1,
        ..identity
    };
    assert_eq!(other.check().unwrap(), IdentityCheck::Reused);
    assert_ne!(other.digest(), identity.digest());
    assert_eq!(process.check_ended(), Err(NoProof::StillRunning));

    // It ignores the grace period, so the host kills its job and observes the end.
    let proof = process
        .terminate(Escalation {
            grace: Duration::from_millis(100),
            kill_wait: PATIENT,
        })
        .unwrap();
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    assert_eq!(proof.exit_code(), KILLED_EXIT_CODE);
    assert!(proof.job_processes() >= 1);
    assert_eq!(proof.identity(), identity);
    assert_eq!(proof.role(), &vm_role("exe-identity"));
    assert_eq!(proof.source(), SourceClass::HostProbe);

    // Once its handle is released, the PID no longer names it.
    drop(process);
    wait_until(|| identity.check().unwrap() != IdentityCheck::Same);
}

#[test]
fn an_end_is_proven_by_the_signalled_handle_its_exit_code_and_an_empty_job() {
    let process = spawn("exit:7", runner_role("exe-exit", 1));
    let proof = process.wait_ended(PATIENT).unwrap();
    assert_eq!(proof.ending(), Ending::Exited);
    assert_eq!(proof.exit_code(), 7);
    // The process, and the console host the system starts for it, both ended.
    assert!(proof.job_processes() >= 1);
    assert_eq!(proof.role(), &runner_role("exe-exit", 1));
    // Observing again gives the same proof.
    assert_eq!(process.check_ended().map(|again| again.exit_code()), Ok(7));
}

/// How many processes the job of a helper that starts nothing holds over its life: the
/// helper and what the system starts for it, such as its console host.
fn processes_of_a_lone_helper() -> u32 {
    let lone = spawn("exit:0", runner_role("exe-lone", 1));
    lone.wait_ended(PATIENT).unwrap().job_processes()
}

#[test]
fn a_child_still_alive_means_no_proof_until_the_whole_job_is_killed() {
    let lone = processes_of_a_lone_helper();
    let process = spawn("grandchild", runner_role("exe-grandchild", 1));
    // The runner exits with 0 as if all were done; the child it started still runs.
    let Err(NoProof::JobStillActive { exit_code, active }) = first_ended(&process) else {
        panic!("the runner's own exit was taken for the end of its job");
    };
    assert_eq!(exit_code, 0);
    assert!(active >= 1);
    assert!(matches!(
        process.wait_ended(Duration::from_millis(200)),
        Err(NoProof::JobStillActive { .. })
    ));
    let proof = process.terminate(kill_now()).unwrap();
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    assert_eq!(proof.exit_code(), 0);
    assert_eq!(proof.job_processes(), lone + 1);
}

#[test]
fn no_process_breaks_away_from_its_job() {
    let lone = processes_of_a_lone_helper();
    let process = spawn("breakaway", runner_role("exe-breakaway", 1));
    let proof = process.wait_ended(PATIENT).unwrap();
    // The helper exits with 0 only when its breakaway start was refused.
    assert_eq!(proof.exit_code(), 0, "a child broke away from the job");
    assert_eq!(proof.job_processes(), lone);
}

/// Closes a handle value this test process holds (one a refused adoption left).
fn close_raw(handle: u64) {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    // SAFETY: the value is a handle this test duplicated into itself and nothing took.
    drop(unsafe { OwnedHandle::from_raw_handle(handle as usize as _) });
}

/// PROVES a holder takes a process's handles only when they name that process and its own
/// job, keeps the process running after its starter's handles closed (the job stays open
/// while held), ends it through the held job and observes the end, and that ending a held
/// job again touches no process started later, whatever PID it got: nothing acts by PID.
#[test]
fn a_holder_takes_checked_handles_and_ends_only_the_held_job() {
    let vm = spawn("sleep", vm_role("held"));
    let other = spawn("sleep", vm_role("other"));
    let shared = vm.share_with_this_process().unwrap();
    let foreign = other.share_with_this_process().unwrap();
    // Named as another process: refused, nothing taken.
    // SAFETY: both values were duplicated into this test process for this holder.
    let refused = unsafe { AdoptedLifetime::adopt(shared, other.identity()) };
    assert!(matches!(refused, Err(AdoptRefusal::OtherProcess { .. })), "{refused:?}");
    // The job of another process: refused.
    let mixed = SharedHandles {
        job: foreign.job,
        process: shared.process,
    };
    // SAFETY: as above.
    let refused = unsafe { AdoptedLifetime::adopt(mixed, vm.identity()) };
    assert!(matches!(refused, Err(AdoptRefusal::NotInJob)), "{refused:?}");
    close_raw(foreign.job);
    close_raw(foreign.process);
    // SAFETY: as above; this time the values name the process and its job.
    let held = unsafe { AdoptedLifetime::adopt(shared, vm.identity()) }.unwrap();
    assert_eq!(held.identity(), vm.identity());
    assert!(held.ended().is_none());
    // The starter lets go: its job and process handles close. Held, the job stays open
    // and the process runs on.
    let identity = vm.identity();
    drop(vm);
    thread::sleep(Duration::from_millis(500));
    assert!(held.ended().is_none(), "the held process runs on after its starter let go");
    assert_eq!(ProcessIdentity::holder_of(identity.pid).unwrap(), Some(identity));
    let ended = held.terminate(PATIENT).unwrap();
    assert_eq!(ended.kill_rounds, 1);
    assert_eq!(ended.exit_code, Some(KILLED_EXIT_CODE));
    assert!(held.ended().is_some());
    // Ending the held job again touches nothing else: a process started afterwards runs on.
    let later = spawn("sleep", vm_role("later"));
    let again = held.terminate(PATIENT).unwrap();
    assert_eq!(again.kill_rounds, 0, "an ended job is observed, not killed again");
    assert!(later.check_ended().is_err(), "a later process runs on");
    drop(held);
    other.terminate(kill_now()).unwrap();
    later.terminate(kill_now()).unwrap();
}

/// PROVES a process that exited does not run, although its process object (and so a holder
/// of its PID) remains while a handle to it stays open; one that runs, runs.
#[test]
fn an_exited_process_does_not_run_while_a_handle_keeps_its_object() {
    let process = spawn("sleep", vm_role("running"));
    let identity = process.identity();
    assert!(identity.running().unwrap());
    process.terminate(kill_now()).unwrap();
    // The held process keeps its object: the PID still has its holder.
    assert_eq!(ProcessIdentity::holder_of(identity.pid).unwrap(), Some(identity));
    assert!(!identity.running().unwrap());
    drop(process);
}

/// PROVES the platform's cleanup when every holder is gone: once the starter's and the
/// holder's handles have both closed, the job's kill-on-close ends the process
/// (`SupervisorDeathFallback::OsJobCleanup`).
#[test]
fn a_process_ends_once_its_starter_and_its_holder_both_let_go() {
    let vm = spawn("sleep", vm_role("both"));
    let identity = vm.identity();
    let shared = vm.share_with_this_process().unwrap();
    // SAFETY: duplicated into this test process for this holder.
    let held = unsafe { AdoptedLifetime::adopt(shared, identity) }.unwrap();
    drop(vm);
    thread::sleep(Duration::from_millis(300));
    assert!(held.ended().is_none());
    drop(held);
    wait_until(|| ProcessIdentity::holder_of(identity.pid).unwrap() != Some(identity));
}

#[test]
fn a_jobs_usage_counts_its_processes_and_never_falls() {
    let process = spawn("grandchild", vm_role("exe-usage"));
    // The runner exits with 0 once it has started its child; the child still runs.
    let Err(NoProof::JobStillActive { exit_code: 0, .. }) = first_ended(&process) else {
        panic!("the runner did not leave its child running in the job");
    };
    let running = process.usage().unwrap();
    assert!(running.total_processes >= 2, "{running:?}");
    assert!(running.active_processes >= 1, "{running:?}");
    assert!(running.peak_committed_bytes > 0, "{running:?}");
    thread::sleep(Duration::from_millis(50));
    let later = process.usage().unwrap();
    assert!(later.cpu_time_ticks >= running.cpu_time_ticks, "{later:?}");
    assert!(
        later.peak_committed_bytes >= running.peak_committed_bytes,
        "{later:?}"
    );
    assert!(
        later.total_processes >= running.total_processes,
        "{later:?}"
    );

    // Killed and proven ended: the held job handle still reads, with nothing left in it.
    let proof = process.terminate(kill_now()).unwrap();
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    let ended = process.usage().unwrap();
    assert_eq!(ended.active_processes, 0, "{ended:?}");
    assert_eq!(ended.total_processes, proof.job_processes());
    assert!(ended.cpu_time_ticks >= later.cpu_time_ticks, "{ended:?}");
    assert!(
        ended.peak_committed_bytes >= later.peak_committed_bytes,
        "{ended:?}"
    );
}

#[test]
fn identities_and_roles_read_back_strictly() {
    let identity = ProcessIdentity {
        pid: 4242,
        start_time_ticks: 133_000_000_000_000_000,
    };
    let text = serde_json::to_string(&identity).unwrap();
    assert_eq!(
        serde_json::from_str::<ProcessIdentity>(&text).unwrap(),
        identity
    );
    assert!(serde_json::from_str::<ProcessIdentity>(
        r#"{"pid":4242,"start_time_ticks":1,"handle":"forged"}"#
    )
    .is_err());
    for role in [vm_role("exe-serde"), runner_role("exe-serde", 3)] {
        let text = serde_json::to_string(&role).unwrap();
        assert_eq!(serde_json::from_str::<ProcessRole>(&text).unwrap(), role);
        let widened = text.replacen('{', r#"{"pid":1,"#, 1);
        assert!(serde_json::from_str::<ProcessRole>(&widened).is_err());
    }
    assert_eq!(
        vm_role("exe-serde").authority(),
        ProcessAuthority::VmLifecycle
    );
    assert_eq!(
        runner_role("exe-serde", 3).authority(),
        ProcessAuthority::ModelActivation
    );
}

#[test]
fn vm_processes_hold_each_vm_host_process_once_and_no_runner() {
    let mut processes = VmProcesses::new(kill_now());
    let runner = spawn("exit:0", runner_role("exe-bind", 1));
    let role = runner.role().clone();
    assert_eq!(
        processes.bind(runner),
        Err(BindRefusal::NotAVmHost { role })
    );
    let vm = processes
        .bind(spawn("exit:0", vm_role("exe-bind")))
        .unwrap();
    assert_eq!(
        processes.bind(spawn("exit:0", vm_role("exe-bind"))),
        Err(BindRefusal::AlreadyBound { vm })
    );
    wait_until(|| {
        processes.refresh();
        processes.proof(&vm).is_some()
    });
    assert!(processes.process(&vm).is_none());
    assert_eq!(
        processes.bind(spawn("exit:0", vm_role("exe-bind"))),
        Err(BindRefusal::AlreadyBound { vm })
    );
}

// --- The coordinator over a VM backend whose VMs are helper processes ---

type TestClock = Arc<ManualClock>;
type TestCapacity = LedgerCapacity<TestClock>;
type TestCoordinator = Coordinator<TestClock, TestCapacity>;

fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: named("yougori/test/machine/v1", "host"),
        device: named("yougori/test/device/v1", "gpu0"),
    }
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(named("yougori/test/configuration/v1", "launch"))
}

/// The CORE-03 ledger of the test host: RAM and one GPU, observed by the host, with the
/// tenant budgeted for all of it.
fn host_capacity(clock: &TestClock) -> TestCapacity {
    let config = LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: Duration::from_secs(60),
        },
        grant_ttl: Duration::from_secs(300),
        unmanaged_usage_max_age: HOUR,
    };
    let host = HostSubject {
        machine: named("yougori/test/machine/v1", "host"),
    };
    let mut ledger = Ledger::new(Arc::clone(clock), host, config);
    for (key, total) in [
        (ResourceKey::Host(HostResource::Ram), 64 * GIB),
        (ResourceKey::vram(device()), 48 * GIB),
    ] {
        ledger
            .declare_capacity(
                key,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), key, total).unwrap();
    }
    LedgerCapacity::new(ledger)
}

fn sandbox_key(of: &ExecutionId) -> ReservationKey {
    ReservationKey::derive(
        of,
        &ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::FIRST,
        },
    )
}

/// Whether the ledger closed a reservation on a host observation of its release.
fn closed_on_host_observation(capacity: &TestCapacity) -> bool {
    capacity.ledger().closed_records().iter().any(|record| {
        record.close_reason()
            == Some(CloseReason::ReleaseObserved {
                source: SourceClass::HostProbe,
            })
    })
}

/// A VM backend whose every VM is a helper process it starts and binds, in the mode
/// `modes` gives next (`sleep` once they run out; `unbound` starts no process). Its own
/// stop does not end the process, so the host kills it; its own list is what it believes.
struct HelperVms {
    processes: VmProcesses,
    modes: VecDeque<&'static str>,
    listed: BTreeMap<VmInstanceId, ObservedVm>,
    stops: Vec<VmInstanceId>,
}

impl HelperVms {
    fn new(modes: &[&'static str]) -> Self {
        Self {
            processes: VmProcesses::new(Escalation {
                grace: Duration::from_millis(50),
                kill_wait: PATIENT,
            }),
            modes: modes.iter().copied().collect(),
            listed: BTreeMap::new(),
            stops: Vec::new(),
        }
    }
}

impl SandboxPort for HelperVms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        let boot = request.generations.boot;
        let vm = vm_of(&request.execution, boot);
        let mode = self.modes.pop_front().unwrap_or("sleep");
        if mode != "unbound" {
            let role = ProcessRole::VmHost {
                execution: request.execution.clone(),
                vm,
                boot,
            };
            let failure = |detail: String| PortFailure {
                operation: PortOperation::CreateVm,
                detail,
            };
            let process = HostProcess::spawn(&mut helper_command(mode), role)
                .map_err(|error| failure(error.to_string()))?;
            self.processes
                .bind(process)
                .map_err(|refusal| failure(refusal.to_string()))?;
        }
        self.listed.insert(
            vm,
            ObservedVm {
                vm,
                execution: request.execution.clone(),
                boot,
            },
        );
        Ok(vm)
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "restore is not supported".to_owned(),
        })
    }

    fn observe_readiness(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness: Readiness::Ready,
        }
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        RestoredVmReport {
            vm: *vm,
            boot,
            snapshot: SnapshotId::new(named("yougori/test/snapshot/v1", "none")),
            guest_identity: named("yougori/test/guest/v1", "none"),
            actions: Default::default(),
            attached_volumes: Default::default(),
            policy: PolicyEpoch::FIRST,
            image_profile: named("yougori/test/image/v1", "none"),
            presented_epochs: Default::default(),
            source: SourceClass::GuestReport,
        }
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.stops.push(*vm);
        self.listed.remove(vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(self.listed.values().cloned().collect())
    }
}

impl ProcessBackedVms for HelperVms {
    fn vm_processes(&mut self) -> &mut VmProcesses {
        &mut self.processes
    }
}

/// A coordinator over the real ledger, with host evidence that the test runtime is a VM
/// sandbox.
struct World {
    clock: TestClock,
    registry: ProbeRegistry<TestClock>,
    category: Arc<FakeProbe>,
    runtime: RuntimeSubject,
    coordinator: TestCoordinator,
}

impl World {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(100_000_000_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let coordinator = Coordinator::new(Arc::clone(&clock), session(1), host_capacity(&clock));
        Self {
            clock,
            registry,
            category,
            runtime: RuntimeSubject {
                category: ExecutionCategory::VmSandbox,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: named("yougori/test/instance/v1", "vm-host-1"),
            },
            coordinator,
        }
    }

    /// The runtime, admitted on fresh host evidence.
    fn admit(&mut self) -> AdmittedRuntime {
        let subject = Subject::Runtime(self.runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer =
            RuntimeOffer::observe(&self.registry, self.runtime.clone(), HOUR, configuration())
                .unwrap();
        RuntimeRequirement::VmSandbox.admit(&offer).unwrap()
    }

    fn launch(&mut self, of: &ExecutionId, backend: &mut HelperVms) -> LaunchOutcome {
        let plan = LaunchPlan {
            execution: of.clone(),
            tenant: tenant(),
            runtime: self.admit(),
            demand: BTreeMap::from([
                (ResourceKind::HostMemoryBytes, 4 * GIB),
                (ResourceKind::GpuMemoryBytes { device: device() }, 8 * GIB),
            ]),
            priority: ReservationPriority::Foreground,
            authority_lifetime: Duration::from_secs(600),
            readiness_max_age: Duration::from_secs(5),
            runtime_evidence_max_age: HOUR,
        };
        self.coordinator
            .launch(plan, &mut ObservedTermination::new(backend), &self.registry)
            .unwrap()
    }

    fn launched(&mut self, of: &ExecutionId, backend: &mut HelperVms) -> VmInstanceId {
        let outcome = self.launch(of, backend);
        assert!(
            matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
            "{outcome:?}"
        );
        vm_of(of, SandboxBootGeneration::FIRST)
    }

    /// Recovers from what the coordinator persisted, on a new clock session, with the
    /// capacity port it used.
    fn recover(&mut self, backend: &mut HelperVms) -> RecoveryReport {
        let persisted = self.coordinator.persist();
        let unused = Coordinator::new(
            Arc::clone(&self.clock),
            session(99),
            host_capacity(&self.clock),
        );
        let crashed = std::mem::replace(&mut self.coordinator, unused);
        let (recovered, report) = Coordinator::recover(
            persisted,
            Arc::clone(&self.clock),
            session(2),
            crashed.into_capacity(),
            &mut ObservedTermination::new(backend),
        )
        .unwrap();
        self.coordinator = recovered;
        report
    }

    fn holds(&self, of: &ExecutionId) -> bool {
        self.coordinator
            .capacity()
            .record(&sandbox_key(of))
            .is_some()
    }
}

#[test]
fn a_revocation_completes_only_on_the_host_proof_that_the_vm_process_ended() {
    let mut world = World::new();
    let of = execution("exe-revoked");
    let mut backend = HelperVms::new(&["sleep"]);
    let vm = world.launched(&of, &mut backend);
    let identity = backend.processes.process(&vm).unwrap().identity();
    assert!(world.holds(&of));

    world.coordinator.revoke(&of).unwrap();
    let status = world
        .coordinator
        .advance_revocation(&of, &mut ObservedTermination::new(&mut backend))
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    // The backend was asked first; its stop ended nothing, so the host killed the job and
    // observed the end.
    assert_eq!(backend.stops, vec![vm]);
    let proof = backend.processes.proof(&vm).unwrap();
    assert_eq!(proof.identity(), identity);
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    let revocation = world.coordinator.revocation(&of).unwrap();
    assert!(revocation
        .milestone(RevocationMilestone::VmStopped)
        .is_some());
    assert_eq!(
        world.coordinator.sandbox(&of).unwrap().state(),
        SandboxState::Stopped
    );
    assert!(!world.holds(&of));
    assert!(closed_on_host_observation(world.coordinator.capacity()));
}

#[test]
fn a_vm_whose_process_the_host_no_longer_holds_never_stops_nor_frees_its_reservation() {
    let mut world = World::new();
    let of = execution("exe-lost");
    let mut first = HelperVms::new(&["sleep"]);
    let vm = world.launched(&of, &mut first);
    let identity = first.processes.process(&vm).unwrap().identity();

    // The handles are lost, as when their holder ends: the job closes and kills the VM
    // process. The backend that comes back still lists the VM, without its handle.
    let mut second = HelperVms::new(&[]);
    second.listed = first.listed.clone();
    drop(first);
    wait_until(|| identity.check().unwrap() != IdentityCheck::Same);

    let report = world.recover(&mut second);
    assert!(
        matches!(
            report.sandboxes.get(&of),
            Some(SandboxRecovery::VmKeptWithoutAuthority { vm: kept, .. }) if *kept == vm
        ),
        "{report:?}"
    );
    let error = world
        .coordinator
        .terminate(&of, &mut ObservedTermination::new(&mut second))
        .unwrap_err();
    assert!(
        matches!(
            &error,
            CoordinationError::Stalled {
                stall: TerminationStalled {
                    cause: StallCause::Port { failure },
                    ..
                }
            } if failure.operation == PortOperation::TerminateVm
        ),
        "{error:?}"
    );
    // Nothing still possibly in use is reported free.
    assert!(world.holds(&of));
}

#[test]
fn recovery_frees_a_vm_only_once_the_host_saw_its_process_end() {
    let mut world = World::new();
    let (ended, alive) = (execution("exe-ended"), execution("exe-alive"));
    let mut backend = HelperVms::new(&["sleep", "sleep"]);
    let ended_vm = world.launched(&ended, &mut backend);
    let alive_vm = world.launched(&alive, &mut backend);

    // The first VM's process ended, here through its handle behind the table's back, yet
    // the backend still lists the VM; the backend lost track of the second, whose process
    // still runs.
    backend
        .processes
        .process(&ended_vm)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    backend.listed.remove(&alive_vm);

    let report = world.recover(&mut backend);
    assert!(
        matches!(
            report.sandboxes.get(&ended),
            Some(SandboxRecovery::VmLost { .. })
        ),
        "{report:?}"
    );
    assert_eq!(
        backend.processes.proof(&ended_vm).unwrap().ending(),
        Ending::Exited
    );
    assert!(!world.holds(&ended));
    assert!(
        matches!(
            report.sandboxes.get(&alive),
            Some(SandboxRecovery::VmKeptWithoutAuthority { vm, .. }) if *vm == alive_vm
        ),
        "{report:?}"
    );
    assert!(world.holds(&alive));

    // Ending it later frees it, on the proof.
    let compensations = world
        .coordinator
        .terminate(&alive, &mut ObservedTermination::new(&mut backend))
        .unwrap();
    assert!(compensations.contains(&Compensation::TerminateVm { vm: alive_vm }));
    assert_eq!(
        backend.processes.proof(&alive_vm).unwrap().ending(),
        Ending::Killed { rounds: 1 }
    );
    assert!(!world.holds(&alive));
}

#[test]
fn a_vm_without_a_held_process_never_becomes_ready() {
    let mut world = World::new();
    let of = execution("exe-unbound");
    let mut backend = HelperVms::new(&["unbound"]);
    match world.launch(&of, &mut backend) {
        LaunchOutcome::RollbackStalled {
            failure: LaunchFailure::NotReady { .. },
            stall:
                TerminationStalled {
                    cause: StallCause::Port { failure },
                    ..
                },
        } => assert_eq!(failure.operation, PortOperation::TerminateVm),
        other => panic!("{other:?}"),
    }
    assert!(world.holds(&of));
}

#[test]
fn a_vm_whose_process_ended_is_not_ready_whatever_its_backend_says() {
    let of = execution("exe-crashed");
    let mut backend = HelperVms::new(&["sleep"]);
    let request = BootRequest {
        execution: of.clone(),
        tenant: tenant(),
        generations: SandboxGenerations::FIRST,
        reservation: sandbox_key(&of),
    };
    let boot = SandboxBootGeneration::FIRST;
    let mut port = ObservedTermination::new(&mut backend);
    let perimeter = port.prepare_perimeter(&request).unwrap();
    let vm = port.create_vm(&request, &perimeter).unwrap();
    assert_eq!(
        port.observe_readiness(&vm, boot).readiness,
        Readiness::Ready
    );

    // The VM's process ends behind the table's back, as a crash would; the backend's own
    // check still says ready.
    backend
        .processes
        .process(&vm)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    let report = ObservedTermination::new(&mut backend).observe_readiness(&vm, boot);
    assert!(
        matches!(report.readiness, Readiness::NotReady { .. }),
        "{report:?}"
    );
    assert_eq!(report.source, SourceClass::HostProbe);
    assert!(backend.processes.process(&vm).is_none());
    assert!(backend.processes.proof(&vm).is_some());
}

fn cancelling(coordinator: &TestCoordinator, lease: LeaseId) -> bool {
    matches!(
        coordinator.lease_record(lease).unwrap().state(),
        LeaseState::Cancelling { .. }
    )
}

#[test]
fn leases_settle_only_on_the_proof_of_the_bound_process_that_held_them() {
    let mut world = World::new();
    let of = execution("exe-leases");
    let mut backend = HelperVms::new(&["sleep"]);
    let vm = world.launched(&of, &mut backend);
    world.coordinator.start_running(&of).unwrap();

    // A model serves under the VM, with one request admitted to it; the VM has child work.
    let grant = world.coordinator.sandbox(&of).unwrap().authority().unwrap();
    let settings = RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::new(),
        authority: grant,
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        },
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
    };
    let handle = world
        .coordinator
        .begin_activation(
            &of,
            model(),
            settings,
            GpuDemand {
                device: device(),
                memory_bytes: 2 * GIB,
            },
        )
        .unwrap();
    world
        .coordinator
        .complete_activation(&of, model(), handle.generations.activation)
        .unwrap();
    let terms = LeaseTerms {
        term: Duration::from_secs(600),
        max_lifetime: Duration::from_secs(600),
        cancel_within: Duration::from_secs(300),
    };
    let request = world
        .coordinator
        .admit_request(&of, model(), OperationId::new("op-request").unwrap(), terms)
        .unwrap()
        .id();
    let child = world
        .coordinator
        .start_child_work(
            &of,
            OperationId::new("op-guest-work").unwrap(),
            LeaseKind::ChildWork,
            terms,
        )
        .unwrap()
        .id();
    world.coordinator.revoke(&of).unwrap();
    let status = world
        .coordinator
        .advance_revocation(&of, &mut ObservedTermination::new(&mut backend))
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::WaitingForLeases { .. }),
        "{status:?}"
    );

    // The VM's process ended, as the host observed through the handle it holds.
    let vm_proof = backend
        .processes
        .process(&vm)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    // It never settles the model's request, issued under the same execution and boot: the
    // runner holds that. A lease named twice is refused too. Nothing closes.
    assert_eq!(
        settle_leases(
            &mut world.coordinator,
            &backend.processes,
            &vm_proof,
            &[child, request]
        ),
        Err(SettleRefusal::LeaseNotOfProcess { lease: request })
    );
    assert_eq!(
        settle_leases(
            &mut world.coordinator,
            &backend.processes,
            &vm_proof,
            &[child, child]
        ),
        Err(SettleRefusal::DuplicateLease { lease: child })
    );
    // Another process started for the same VM role is not the one the table holds.
    let stray_proof = spawn("exit:0", vm_role("exe-leases"))
        .wait_ended(PATIENT)
        .unwrap();
    assert_eq!(
        settle_leases(
            &mut world.coordinator,
            &backend.processes,
            &stray_proof,
            &[child]
        ),
        Err(SettleRefusal::NotTheBoundProcess {
            identity: stray_proof.identity()
        })
    );
    assert!(cancelling(&world.coordinator, child));
    assert!(cancelling(&world.coordinator, request));

    assert_eq!(
        settle_leases(
            &mut world.coordinator,
            &backend.processes,
            &vm_proof,
            &[child]
        ),
        Ok(vec![child])
    );
    assert!(matches!(
        world.coordinator.lease_record(child).unwrap().state(),
        LeaseState::Cancelled { .. }
    ));

    // The model's runner, bound to its activation: its proof never settles the VM's child
    // work, is not bound in the VM table, and settles its own request.
    let runner_role = ProcessRole::ModelRunner {
        execution: of.clone(),
        model: model(),
        generations: handle.generations,
    };
    let mut runners = RunnerProcesses::new();
    runners.bind(spawn("sleep", runner_role.clone())).unwrap();
    let runner_proof = runners
        .process(&runner_role)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    assert_eq!(
        settle_leases(&mut world.coordinator, &runners, &runner_proof, &[child]),
        Err(SettleRefusal::LeaseNotOfProcess { lease: child })
    );
    assert_eq!(
        settle_leases(
            &mut world.coordinator,
            &backend.processes,
            &runner_proof,
            &[request]
        ),
        Err(SettleRefusal::NotTheBoundProcess {
            identity: runner_proof.identity()
        })
    );
    assert!(cancelling(&world.coordinator, request));
    assert_eq!(
        settle_leases(&mut world.coordinator, &runners, &runner_proof, &[request]),
        Ok(vec![request])
    );

    let status = world
        .coordinator
        .advance_revocation(&of, &mut ObservedTermination::new(&mut backend))
        .unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert!(world
        .coordinator
        .revocation(&of)
        .unwrap()
        .uncertain()
        .is_empty());
}

#[test]
fn a_replacement_runner_never_settles_the_old_runners_reservations() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(100_000_000_000)));
    let mut capacity = host_capacity(&clock);
    let of = execution("exe-runner");
    let (old, new) = (generations(1, 1), generations(2, 2));
    let keys = |generations: ModelGenerations| {
        [
            ReservationPurpose::ModelGpu {
                model: model(),
                gpu_allocation: generations.gpu_allocation,
            },
            ReservationPurpose::ModelHost {
                model: model(),
                activation: generations.activation,
            },
        ]
        .map(|purpose| (ReservationKey::derive(&of, &purpose), purpose))
    };
    for (key, purpose) in keys(old).into_iter().chain(keys(new)) {
        let resource = match purpose {
            ReservationPurpose::ModelGpu { .. } => {
                ResourceKind::GpuMemoryBytes { device: device() }
            }
            _ => ResourceKind::HostMemoryBytes,
        };
        let request = ReservationRequest {
            key,
            tenant: tenant(),
            execution: of.clone(),
            purpose,
            priority: ReservationPriority::Foreground,
            parent: None,
            demand: BTreeMap::from([(resource, 8 * GIB)]),
        };
        capacity.reserve(&request).unwrap();
        capacity.begin_create(&key).unwrap();
    }
    let old_keys = keys(old).map(|(key, _)| key);
    let new_keys = keys(new).map(|(key, _)| key);
    let runner_of = |generations| ProcessRole::ModelRunner {
        execution: of.clone(),
        model: model(),
        generations,
    };
    let (old_role, new_role) = (runner_of(old), runner_of(new));
    let mut runners = RunnerProcesses::new();
    runners.bind(spawn("sleep", old_role.clone())).unwrap();
    runners.bind(spawn("exit:0", new_role.clone())).unwrap();
    // A second process for the old runner's role, as a retry would start, is not bound
    // while the old one runs; a VM host process is no runner at all.
    assert_eq!(
        runners.bind(spawn("exit:0", old_role.clone())),
        Err(BindRefusal::RunnerStillRunning {
            role: old_role.clone()
        })
    );
    assert_eq!(
        runners.bind(spawn("exit:0", vm_role("exe-runner"))),
        Err(BindRefusal::NotAModelRunner {
            role: vm_role("exe-runner")
        })
    );

    // The replacement's word that the old runner is gone is a report, not the host's
    // observation: the ledger keeps the old host-level grant counted.
    assert_eq!(capacity.release(&old_keys[0]), Ok(ReleaseOutcome::Pending));
    assert!(matches!(
        capacity.confirm_release(&old_keys[0], SourceClass::GuestReport),
        Err(CapacityRefusal::SourceTooWeak { .. })
    ));

    // A stray process started for the old runner's generations ends: it is not the bound
    // runner, so its end frees nothing the live one uses.
    let stray_proof = spawn("exit:0", old_role.clone())
        .wait_ended(PATIENT)
        .unwrap();
    assert_eq!(
        release_runner_reservations(&mut capacity, &runners, &stray_proof),
        Err(SettleRefusal::NotTheBoundProcess {
            identity: stray_proof.identity()
        })
    );
    assert!(old_keys.iter().all(|key| capacity.record(key).is_some()));

    // The replacement's own proof settles only its own reservations.
    let replacement_proof = runners
        .process(&new_role)
        .unwrap()
        .wait_ended(PATIENT)
        .unwrap();
    let settled = release_runner_reservations(&mut capacity, &runners, &replacement_proof).unwrap();
    assert_eq!(
        settled,
        new_keys
            .iter()
            .map(|key| (*key, ReleaseOutcome::Released))
            .collect::<Vec<_>>()
    );
    assert!(old_keys.iter().all(|key| capacity.record(key).is_some()));

    // A VM host process's end never settles a runner's grant.
    let vm_process = spawn("exit:0", vm_role("exe-runner"));
    let vm_proof = vm_process.wait_ended(PATIENT).unwrap();
    assert_eq!(
        release_runner_reservations(&mut capacity, &runners, &vm_proof),
        Err(SettleRefusal::OtherAuthority {
            expected: ProcessAuthority::ModelActivation,
            role: vm_role("exe-runner"),
        })
    );
    assert!(old_keys.iter().all(|key| capacity.record(key).is_some()));

    // Only the host's proof of the bound old runner's own end frees them.
    let old_runner = runners.process(&old_role).unwrap();
    assert_eq!(old_runner.check_ended(), Err(NoProof::StillRunning));
    let old_proof = old_runner.terminate(kill_now()).unwrap();
    let settled = release_runner_reservations(&mut capacity, &runners, &old_proof).unwrap();
    assert_eq!(
        settled,
        old_keys
            .iter()
            .map(|key| (*key, ReleaseOutcome::Released))
            .collect::<Vec<_>>()
    );
    assert!(old_keys.iter().all(|key| capacity.record(key).is_none()));
    assert!(closed_on_host_observation(&capacity));

    // Once the old runner was seen to end, its role may be bound again, and then the old
    // proof binds no more.
    runners.bind(spawn("exit:0", old_role.clone())).unwrap();
    assert_eq!(
        release_runner_reservations(&mut capacity, &runners, &old_proof),
        Err(SettleRefusal::NotTheBoundProcess {
            identity: old_proof.identity()
        })
    );
}

mod exit_release;
