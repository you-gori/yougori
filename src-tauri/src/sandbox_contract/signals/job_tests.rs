//! The job readings: CPU, memory and process counts of a VM's host process from its job's
//! accounting, checked over fake snapshots, fed through V14's sustained windows and
//! responder, and read from real helper processes on Windows (VM part §8.2; VM-W43; M17C).
//! The only processes started are this test executable again, running
//! [`job_helper_process`], each inside the kill-on-close job PX1 gives it; every test
//! ends them.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::{ModelGenerations, ModelId, VmInstanceId};
use crate::foundation::evidence::HypervisorKind;
use crate::foundation::ids::{
    digest, Clock, GpuAllocationGeneration, ManualClock, ModelActivationGeneration, MonotonicTime,
    SandboxBootGeneration,
};
use crate::foundation::process::{HostCall, JobUsage, ProcessError, ProcessIdentity, ProcessRole};
use crate::sandbox_contract::files::SandboxClass;
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, MonitoredResource, Reading, ResourceMonitor, ResourceObservation,
    ResponseAction, SeriesKey, SignalAssessment, SignalClass, SignalSource, SustainedWindow,
};

/// Job CPU time ticks in one second of one core.
const TICKS_PER_SECOND: u64 = 10_000_000;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The process every fake snapshot is of, unless a test says otherwise.
const PROCESS: ProcessIdentity = ProcessIdentity {
    pid: 4242,
    start_time_ticks: 133_000_000_000_000_000,
};

/// The host process of boot `boot` of sandbox `sandbox`'s VM.
fn vm_role(sandbox: &str, boot: u64) -> ProcessRole {
    ProcessRole::VmHost {
        execution: execution(sandbox),
        vm: VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[sandbox.as_bytes(), &boot.to_be_bytes()],
        )),
        boot: SandboxBootGeneration::new(boot),
    }
}

/// The runner of a model activation under sandbox `sandbox`'s execution.
fn runner_role(sandbox: &str) -> ProcessRole {
    ProcessRole::ModelRunner {
        execution: execution(sandbox),
        model: ModelId::new(digest("yougori/test/model/v1", &[b"chat-model"])),
        generations: ModelGenerations {
            activation: ModelActivationGeneration::FIRST,
            gpu_allocation: GpuAllocationGeneration::FIRST,
        },
    }
}

fn usage(cpu_time_ticks: u64, active: u32, total: u32, peak: u64) -> JobUsage {
    JobUsage {
        cpu_time_ticks,
        active_processes: active,
        total_processes: total,
        peak_committed_bytes: peak,
    }
}

/// A fake snapshot of [`PROCESS`] as `role`, on WHPX, at the clock's time.
fn snapshot(
    role: ProcessRole,
    usage: Result<JobUsage, ProcessError>,
    now: &ManualClock,
) -> JobSnapshot {
    JobSnapshot {
        identity: PROCESS,
        role,
        hypervisor: HypervisorKind::Whpx,
        usage,
        at: now.now(),
        session: host_session(),
    }
}

/// A fake snapshot of the host process of sandbox `exe-a`'s first boot, its job having
/// spent `cpu_time_ticks` and holding two processes and a 512 MiB peak.
fn vm_snapshot(cpu_time_ticks: u64, now: &ManualClock) -> JobSnapshot {
    snapshot(
        vm_role("exe-a", 1),
        Ok(usage(cpu_time_ticks, 2, 2, 512 * MIB)),
        now,
    )
}

/// A job read that failed.
fn unreadable() -> Result<JobUsage, ProcessError> {
    Err(ProcessError::HostCall {
        call: HostCall::ReadJobUsage,
        os_error: 5,
    })
}

/// Checks the parts every reading shares: the sandbox, the class, the host observer, V14's
/// series subject, the snapshot's time and session, no grant, and V14's acceptance.
fn assert_reading(
    reading: &ResourceReading,
    sandbox: &str,
    resource: MonitoredResource,
    observer: HostObserver,
    snapshot: &JobSnapshot,
) {
    let draft = reading.draft().unwrap();
    assert_eq!(draft.sandbox, execution(sandbox));
    assert_eq!(draft.class, SignalClass::Resource { resource });
    assert_eq!(draft.source, SignalSource::HostObserved { observer });
    assert_eq!(draft.subject, SeriesKey::subject(resource));
    assert_eq!(draft.observed_at, snapshot.at());
    assert_eq!(draft.session, snapshot.session());
    assert_eq!(draft.violated_grant, None);
    assert!(matches!(draft.reading, Reading::Amount { .. }));
    signal(draft.clone());
}

/// The reason each of the three readings gives no reading of `snapshot`, CPU over the
/// snapshot and a copy a second later.
fn refusals(snapshot: &JobSnapshot) -> [Option<Ordinary>; 3] {
    let mut later = snapshot.clone();
    later.at = later.at.saturating_add(SECOND);
    [
        cpu_reading(snapshot, &later).ordinary(),
        memory_reading(snapshot).ordinary(),
        process_count_reading(snapshot).ordinary(),
    ]
}

// ---------------------------------------------------------------------------------------
// The arithmetic and the refusals

#[test]
fn a_cpu_reading_is_the_jobs_cpu_time_over_the_host_clock_interval_in_millicores() {
    let now = clock();
    let earlier = vm_snapshot(0, &now);
    // Three seconds of one core's time in two seconds: one and a half cores.
    now.advance(2 * SECOND);
    let later = vm_snapshot(3 * TICKS_PER_SECOND, &now);
    let reading = cpu_reading(&earlier, &later);
    assert_eq!(reading.amount(), Some(1_500));
    assert_reading(
        &reading,
        "exe-a",
        MonitoredResource::CpuMillicores,
        HostObserver::HypervisorCounters,
        &later,
    );
    // Rounded down: a tick of CPU time in a second is far below a millicore.
    let start = vm_snapshot(0, &now);
    now.advance(SECOND);
    assert_eq!(cpu_reading(&start, &vm_snapshot(1, &now)).amount(), Some(0));
    // Exactly the minimum window reads; one second of one core is a thousand millicores.
    assert_eq!(MIN_CPU_WINDOW, SECOND);
    let start = vm_snapshot(0, &now);
    now.advance(MIN_CPU_WINDOW);
    let full = vm_snapshot(TICKS_PER_SECOND, &now);
    assert_eq!(cpu_reading(&start, &full).amount(), Some(1_000));
    // The largest counter step over the shortest window reads exactly, without wrapping.
    let largest = vm_snapshot(u64::MAX, &now);
    let start = {
        let mut start = vm_snapshot(0, &now);
        start.at = MonotonicTime::from_nanos(now.now().as_nanos() - 1_000_000_000);
        start
    };
    assert_eq!(
        cpu_reading(&start, &largest).amount(),
        Some(u64::MAX / 10_000)
    );
}

#[test]
fn a_cpu_reading_refuses_another_process_or_boot_a_backward_clock_a_short_window_and_a_falling_counter(
) {
    let now = clock();
    let earlier = vm_snapshot(TICKS_PER_SECOND, &now);
    now.advance(2 * SECOND);
    let later = vm_snapshot(3 * TICKS_PER_SECOND, &now);
    assert!(cpu_reading(&earlier, &later).amount().is_some());
    let refused = |earlier: &JobSnapshot, later: &JobSnapshot| {
        let reading = cpu_reading(earlier, later);
        assert_eq!(reading.draft(), None);
        reading.ordinary().unwrap()
    };

    // Another process: another PID, or the same PID with another creation time.
    for identity in [
        ProcessIdentity {
            pid: PROCESS.pid + 1,
            ..PROCESS
        },
        ProcessIdentity {
            start_time_ticks: PROCESS.start_time_ticks + 1,
            ..PROCESS
        },
    ] {
        let mut other = later.clone();
        other.identity = identity;
        assert_eq!(refused(&earlier, &other), Ordinary::HostConfiguration);
    }
    // Another boot of the same sandbox's VM, or another sandbox's.
    for role in [vm_role("exe-a", 2), vm_role("exe-b", 1)] {
        let mut other = later.clone();
        other.role = role;
        assert_eq!(refused(&earlier, &other), Ordinary::HostConfiguration);
    }
    // A clock that went backwards, or did not move.
    assert_eq!(refused(&later, &earlier), Ordinary::HostConfiguration);
    assert_eq!(refused(&later, &later), Ordinary::HostConfiguration);
    // Closer together than the minimum window.
    let mut soon = earlier.clone();
    soon.at = earlier
        .at
        .saturating_add(MIN_CPU_WINDOW - Duration::from_millis(1));
    soon.usage = Ok(usage(2 * TICKS_PER_SECOND, 2, 2, 512 * MIB));
    assert_eq!(refused(&earlier, &soon), Ordinary::HostConfiguration);
    // Another clock session: the interval cannot be known.
    let mut restarted = later.clone();
    restarted.session = session(2);
    assert_eq!(refused(&earlier, &restarted), Ordinary::NotCurrent);
    // A counter that went down is not this job's accounting.
    let mut fallen = later.clone();
    fallen.usage = Ok(usage(TICKS_PER_SECOND - 1, 2, 2, 512 * MIB));
    assert_eq!(refused(&earlier, &fallen), Ordinary::HostFault);
    let mut fewer = later.clone();
    fewer.usage = Ok(usage(3 * TICKS_PER_SECOND, 1, 1, 512 * MIB));
    assert_eq!(refused(&earlier, &fewer), Ordinary::HostFault);
    // A job that could not be read, at either end.
    let mut failed = later.clone();
    failed.usage = unreadable();
    assert_eq!(refused(&earlier, &failed), Ordinary::HostFault);
    let mut failed_first = earlier.clone();
    failed_first.usage = unreadable();
    assert_eq!(refused(&failed_first, &later), Ordinary::HostFault);
}

#[test]
fn memory_is_the_jobs_peak_commit_and_the_process_count_its_active_processes() {
    let now = clock();
    let job = snapshot(
        vm_role("exe-a", 1),
        Ok(usage(TICKS_PER_SECOND, 3, 5, 2 * GIB)),
        &now,
    );
    let memory = memory_reading(&job);
    assert_eq!(memory.amount(), Some(2 * GIB));
    assert_reading(
        &memory,
        "exe-a",
        MonitoredResource::MemoryBytes,
        HostObserver::HypervisorCounters,
        &job,
    );
    // The processes in the job now, not the ones it ever held.
    let processes = process_count_reading(&job);
    assert_eq!(processes.amount(), Some(3));
    assert_reading(
        &processes,
        "exe-a",
        MonitoredResource::ProcessCount,
        HostObserver::Supervisor,
        &job,
    );
    // A job whose processes all ended holds none: a count of zero is a reading.
    let ended = snapshot(vm_role("exe-a", 1), Ok(usage(1, 0, 5, 2 * GIB)), &now);
    assert_eq!(process_count_reading(&ended).amount(), Some(0));
    // A job that could not be read makes no reading.
    let failed = snapshot(vm_role("exe-a", 1), unreadable(), &now);
    assert_eq!(
        refusals(&failed),
        [Some(Ordinary::HostFault); 3],
        "{failed:?}"
    );
}

#[test]
fn the_sandbox_is_the_vm_host_roles_and_any_other_role_is_refused() {
    let now = clock();
    // The draft names the execution of the process's role; no caller names one.
    let earlier = snapshot(vm_role("exe-b", 4), Ok(usage(0, 1, 1, 64 * MIB)), &now);
    now.advance(SECOND);
    let later = snapshot(
        vm_role("exe-b", 4),
        Ok(usage(TICKS_PER_SECOND / 2, 1, 1, 64 * MIB)),
        &now,
    );
    for reading in [
        cpu_reading(&earlier, &later),
        memory_reading(&later),
        process_count_reading(&later),
    ] {
        assert_eq!(reading.draft().unwrap().sandbox, execution("exe-b"));
    }
    // A model runner's job is the model activations', not a sandbox's.
    let runner = snapshot(runner_role("exe-a"), Ok(usage(0, 1, 1, 64 * MIB)), &now);
    assert_eq!(refusals(&runner), [Some(Ordinary::HostConfiguration); 3]);
    // Nor does a runner's snapshot pair with a VM host's.
    let mut runner_later = runner.clone();
    runner_later.at = later.at.saturating_add(SECOND);
    assert_eq!(
        cpu_reading(&later, &runner_later).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
    assert_eq!(
        cpu_reading(&runner, &later).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
}

#[test]
fn an_hcs_backed_vm_gives_no_reading_and_only_a_whpx_host_process_is_read() {
    for hypervisor in HypervisorKind::ALL {
        let expected = match hypervisor {
            HypervisorKind::Whpx => JobCoverage::WholeVm,
            HypervisorKind::Hcs => JobCoverage::HcsWorkerOutsideJob,
            HypervisorKind::Kvm | HypervisorKind::Hvf | HypervisorKind::Vz => {
                JobCoverage::NotJobAccounted
            }
        };
        assert_eq!(JobCoverage::of(hypervisor), expected, "{hypervisor:?}");
    }
    assert_eq!(JobCoverage::WholeVm.refusal(), None);
    let now = clock();
    let on = |hypervisor: HypervisorKind| {
        let mut job = vm_snapshot(TICKS_PER_SECOND, &now);
        job.hypervisor = hypervisor;
        job
    };
    // The HCS worker that runs the VM is not in the job: the counts would read low.
    let hcs = on(HypervisorKind::Hcs);
    assert_eq!(hcs.coverage(), JobCoverage::HcsWorkerOutsideJob);
    assert_eq!(refusals(&hcs), [Some(Ordinary::NothingObserved); 3]);
    // A hypervisor whose host is not a Windows job is a host configuration error here.
    for hypervisor in [HypervisorKind::Kvm, HypervisorKind::Hvf, HypervisorKind::Vz] {
        assert_eq!(
            refusals(&on(hypervisor)),
            [Some(Ordinary::HostConfiguration); 3]
        );
    }
    // Two snapshots of one process must name one hypervisor.
    let whpx = on(HypervisorKind::Whpx);
    let mut hcs_later = hcs.clone();
    hcs_later.at = whpx.at.saturating_add(SECOND);
    assert_eq!(
        cpu_reading(&whpx, &hcs_later).ordinary(),
        Some(Ordinary::NothingObserved)
    );
}

#[test]
fn cpu_memory_and_process_count_are_measured_and_packets_per_second_stays_open() {
    for (resource, observer) in [
        (MonitoredResource::CpuMillicores, CPU_OBSERVER),
        (MonitoredResource::MemoryBytes, MEMORY_OBSERVER),
        (MonitoredResource::ProcessCount, PROCESS_COUNT_OBSERVER),
    ] {
        assert!(MEASURED_RESOURCES.contains(&(resource, observer)));
        assert!(resource.host_observers().contains(&observer));
    }
    assert_eq!(CPU_OBSERVER, HostObserver::HypervisorCounters);
    assert_eq!(MEMORY_OBSERVER, HostObserver::HypervisorCounters);
    assert_eq!(PROCESS_COUNT_OBSERVER, HostObserver::Supervisor);
    assert_eq!(OPEN_RESOURCES, [MonitoredResource::PacketsPerSecond]);
}

// ---------------------------------------------------------------------------------------
// Through V14's monitor and responder

/// A monitor on the host session judging `resource` over `window`.
fn monitor(resource: MonitoredResource, window: SustainedWindow) -> ResourceMonitor {
    ResourceMonitor::new(
        host_session(),
        &uncertain(),
        BTreeMap::from([(resource, window)]),
        16,
    )
    .unwrap()
}

fn feed(
    monitor: &mut ResourceMonitor,
    reading: ResourceReading,
    now: &ManualClock,
) -> ResourceObservation {
    monitor
        .observe(&signal(reading.into_draft().unwrap()), now)
        .unwrap()
}

fn triggered(observation: ResourceObservation) -> SignalAssessment {
    match observation {
        ResourceObservation::Triggered { assessment, .. } => assessment,
        other => panic!("expected a trigger, got {other:?}"),
    }
}

fn held(observation: &ResourceObservation) -> bool {
    matches!(observation, ResourceObservation::Held { .. })
}

/// The V14 response to a resource assessment about task sandbox `exe-a`.
fn respond(
    assessment: &SignalAssessment,
    now: &ManualClock,
) -> crate::sandbox_contract::response::ResponseRecord {
    let mut responder = responder_with(now, &[("exe-a", SandboxClass::Task, &[])]);
    responded(responder.respond_to(assessment).unwrap())
}

#[test]
fn sustained_cpu_from_job_snapshots_notifies_the_user_and_clears() {
    let now = clock();
    let resource = MonitoredResource::CpuMillicores;
    let mut monitor = monitor(
        resource,
        SustainedWindow {
            high_mark: 1_500,
            low_mark: 500,
            sustain_seconds: 3,
            clear_seconds: 3,
            max_sample_gap_seconds: 1,
        },
    );
    let mut spent = 0;
    let mut earlier = vm_snapshot(spent, &now);
    let mut sample = |cores: u64, now: &ManualClock| {
        spent += cores * TICKS_PER_SECOND;
        now.advance(SECOND);
        let later = vm_snapshot(spent, now);
        let reading = cpu_reading(&earlier, &later);
        assert_eq!(reading.amount(), Some(cores * 1_000));
        earlier = later;
        reading
    };
    // Two busy cores for three seconds: over the high mark for the whole sustain window.
    for _ in 0..3 {
        let observation = feed(&mut monitor, sample(2, &now), &now);
        assert!(held(&observation), "{observation:?}");
    }
    let assessment = triggered(feed(&mut monitor, sample(2, &now), &now));
    assert!(assessment.freshness().is_fresh());
    let record = respond(&assessment, &now);
    assert_eq!(
        record.decision.actions,
        BTreeSet::from([ResponseAction::NotifyUser])
    );
    assert_eq!(
        record.decision.reason,
        DecisionReason::SustainedResource {
            resource,
            observer: HostObserver::HypervisorCounters
        }
    );
    // Idle for the clear window: the incident may close.
    for _ in 0..3 {
        let observation = feed(&mut monitor, sample(0, &now), &now);
        assert!(held(&observation), "{observation:?}");
    }
    assert!(matches!(
        feed(&mut monitor, sample(0, &now), &now),
        ResourceObservation::Cleared { .. }
    ));
}

/// A reading of one snapshot.
type SnapshotReading = fn(&JobSnapshot) -> ResourceReading;

#[test]
fn sustained_memory_and_process_counts_from_job_snapshots_notify_the_user() {
    let cases: [(MonitoredResource, HostObserver, u64, u64, SnapshotReading); 2] = [
        (
            MonitoredResource::MemoryBytes,
            HostObserver::HypervisorCounters,
            GIB,
            512 * MIB,
            memory_reading,
        ),
        (
            MonitoredResource::ProcessCount,
            HostObserver::Supervisor,
            10,
            4,
            process_count_reading,
        ),
    ];
    for (resource, observer, high_mark, low_mark, read) in cases {
        let now = clock();
        let mut monitor = monitor(
            resource,
            SustainedWindow {
                high_mark,
                low_mark,
                sustain_seconds: 20,
                clear_seconds: 20,
                max_sample_gap_seconds: 10,
            },
        );
        // Two gibibytes committed at peak, twelve processes in the job.
        let job = |now: &ManualClock| {
            snapshot(
                vm_role("exe-a", 1),
                Ok(usage(TICKS_PER_SECOND, 12, 12, 2 * GIB)),
                now,
            )
        };
        for _ in 0..2 {
            let observation = feed(&mut monitor, read(&job(&now)), &now);
            assert!(held(&observation), "{resource:?}: {observation:?}");
            now.advance(10 * SECOND);
        }
        let assessment = triggered(feed(&mut monitor, read(&job(&now)), &now));
        let record = respond(&assessment, &now);
        assert_eq!(
            record.decision.actions,
            BTreeSet::from([ResponseAction::NotifyUser]),
            "{resource:?}"
        );
        assert_eq!(
            record.decision.reason,
            DecisionReason::SustainedResource { resource, observer }
        );
    }
}

// ---------------------------------------------------------------------------------------
// Real host processes (Windows)

#[cfg(windows)]
mod host {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::foundation::ids::SystemClock;
    use crate::foundation::process::{Escalation, HostProcess, TerminationProof};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    /// The environment variable that makes the test executable a helper process, and its
    /// mode.
    const HELPER: &str = "YG_JOB_HELPER";

    /// The file whose appearance makes a working helper start its child.
    const TRIGGER: &str = "YG_JOB_HELPER_TRIGGER";

    /// What a working helper allocates and touches.
    const ALLOCATION: u64 = 64 * MIB;

    /// How long a working helper spins.
    const SPIN: Duration = Duration::from_millis(300);

    /// How long a helper sleeps, and how long one waits for its trigger.
    const HELPER_LIFE: Duration = Duration::from_secs(30);

    /// How long a helper may take to start, work or die: generous, since it is a whole
    /// test executable starting up.
    const PATIENT: Duration = Duration::from_secs(20);

    /// What a helper process does, by its mode; an ordinary test run, without the
    /// variable, does nothing. `work` spins for [`SPIN`], allocates and touches
    /// [`ALLOCATION`] bytes, waits for the file [`TRIGGER`] names, then starts one
    /// sleeping copy of itself and sleeps; `sleep` sleeps; `exit` exits with 0 at once.
    #[test]
    fn job_helper_process() {
        let Ok(mode) = std::env::var(HELPER) else {
            return;
        };
        match mode.as_str() {
            "work" => {
                let started = Instant::now();
                let mut spins = 0_u64;
                while started.elapsed() < SPIN {
                    spins = std::hint::black_box(spins.wrapping_add(1));
                }
                let held = vec![1_u8; usize::try_from(ALLOCATION).unwrap()];
                std::hint::black_box(&held);
                let trigger = std::env::var(TRIGGER).unwrap_or_default();
                let deadline = Instant::now() + HELPER_LIFE;
                while !Path::new(&trigger).exists() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                let code = match helper_command("sleep").spawn() {
                    Ok(_) => 0,
                    Err(_) => 2,
                };
                thread::sleep(HELPER_LIFE);
                drop(held);
                std::process::exit(code);
            }
            "sleep" => {
                thread::sleep(HELPER_LIFE);
                std::process::exit(0);
            }
            "exit" => std::process::exit(0),
            _ => std::process::exit(99),
        }
    }

    /// This test executable, set to run only [`job_helper_process`] in `mode`, with no
    /// console input or output.
    fn helper_command(mode: &str) -> Command {
        let path = module_path!();
        let tests = path.split_once("::").map_or(path, |(_, rest)| rest);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                &format!("{tests}::job_helper_process"),
                "--test-threads=1",
                "--quiet",
            ])
            .env(HELPER, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// Ends `process` and every process of its job and returns the host's proof.
    fn end(process: &HostProcess) -> TerminationProof {
        process
            .terminate(Escalation {
                grace: Duration::ZERO,
                kill_wait: PATIENT,
            })
            .unwrap()
    }

    /// The console hosts (`conhost.exe`) the process `pid` started: Windows starts one for
    /// a console program created without a window, inside the program's job.
    fn console_hosts_of(pid: u32) -> u64 {
        // SAFETY: a process snapshot of the whole system takes no pointer.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        // SAFETY: the snapshot handle was just returned, open and owned by nobody else.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap(),
            ..PROCESSENTRY32W::default()
        };
        let mut hosts = 0;
        // SAFETY: the snapshot handle is open and `entry` is live with its size set.
        let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
        while more {
            let name = &entry.szExeFile;
            let length = name
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(name.len());
            if entry.th32ParentProcessID == pid
                && String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("conhost.exe")
            {
                hosts += 1;
            }
            // SAFETY: as for Process32FirstW.
            more = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
        }
        hosts
    }

    /// Reads `process`'s job until `done` holds of the snapshot, a bounded time.
    fn read_until(
        process: &HostProcess,
        clock: &SystemClock,
        mut done: impl FnMut(&JobSnapshot) -> bool,
    ) -> JobSnapshot {
        let deadline = Instant::now() + PATIENT;
        loop {
            let snapshot = JobSnapshot::read(process, HypervisorKind::Whpx, clock, host_session());
            if done(&snapshot) {
                return snapshot;
            }
            assert!(Instant::now() < deadline, "timed out: {snapshot:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_vm_host_process_job_reads_its_cpu_its_memory_and_its_processes() {
        let host_clock = SystemClock::new();
        let triggers = tempfile::tempdir().unwrap();
        let trigger = triggers.path().join("start-child");
        let mut command = helper_command("work");
        command.env(TRIGGER, &trigger);
        let process = HostProcess::spawn(&mut command, vm_role("exe-a", 1)).unwrap();

        let first = JobSnapshot::read(&process, HypervisorKind::Whpx, &host_clock, host_session());
        assert!(first.usage().is_ok(), "{first:?}");
        // Once it has spun and allocated, and the minimum window has passed.
        let worked = read_until(&process, &host_clock, |snapshot| {
            snapshot.usage().unwrap().peak_committed_bytes >= ALLOCATION
                && snapshot.at().saturating_duration_since(first.at()) >= MIN_CPU_WINDOW
        });
        assert_eq!(worked.identity(), process.identity());
        assert_eq!(worked.role(), &vm_role("exe-a", 1));

        let cpu = cpu_reading(&first, &worked);
        assert!(cpu.amount().unwrap() > 0, "{cpu:?}");
        assert_reading(
            &cpu,
            "exe-a",
            MonitoredResource::CpuMillicores,
            HostObserver::HypervisorCounters,
            &worked,
        );
        let memory = memory_reading(&worked);
        assert!(memory.amount().unwrap() >= ALLOCATION, "{memory:?}");
        assert_reading(
            &memory,
            "exe-a",
            MonitoredResource::MemoryBytes,
            HostObserver::HypervisorCounters,
            &worked,
        );
        let alone = process_count_reading(&worked);
        assert_reading(
            &alone,
            "exe-a",
            MonitoredResource::ProcessCount,
            HostObserver::Supervisor,
            &worked,
        );
        // The helper itself, and the console host Windows started for it in its job.
        let consoles = console_hosts_of(process.identity().pid);
        assert!(consoles <= 1, "{consoles} console hosts");
        let alone = alone.amount().unwrap();
        assert_eq!(alone, 1 + consoles, "{worked:?}");

        // The helper starts a child, which stays in the job.
        std::fs::write(&trigger, b"go").unwrap();
        let with_child = read_until(&process, &host_clock, |snapshot| {
            u64::from(snapshot.usage().unwrap().active_processes) > alone
        });
        assert_eq!(process_count_reading(&with_child).amount(), Some(alone + 1));
        assert_eq!(
            with_child.usage().unwrap().total_processes,
            worked.usage().unwrap().total_processes + 1
        );

        // Ended: the job holds no process, and its counts stay readable.
        assert!(u64::from(end(&process).job_processes()) > alone);
        let ended = JobSnapshot::read(&process, HypervisorKind::Whpx, &host_clock, host_session());
        assert_eq!(process_count_reading(&ended).amount(), Some(0));
        assert!(memory_reading(&ended).amount().unwrap() >= ALLOCATION);
    }

    #[test]
    fn a_model_runner_process_job_gives_no_reading() {
        let host_clock = SystemClock::new();
        let process =
            HostProcess::spawn(&mut helper_command("exit"), runner_role("exe-a")).unwrap();
        let proof = process.wait_ended(PATIENT).unwrap();
        assert_eq!(proof.exit_code(), 0);
        let snapshot =
            JobSnapshot::read(&process, HypervisorKind::Whpx, &host_clock, host_session());
        // The job was read; the role alone refuses it.
        assert!(snapshot.usage().is_ok(), "{snapshot:?}");
        assert_eq!(refusals(&snapshot), [Some(Ordinary::HostConfiguration); 3]);
    }
}
