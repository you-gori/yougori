//! The QEMU backend on scripted host, QMP and layout ports, with a real CORE-01 registry
//! and a real CORE-03 ledger on a manual clock. Nothing here starts a process, opens a
//! socket or reads a file: the ports record what they are asked and answer from a script.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tests::{
    fixture_for, linux, observe_hypervisor, path, strings, windows, Fixture, TestClock, GIB, MINUTE,
};
use super::*;
use crate::foundation::coordination::{SnapshotId, SnapshotManifest, SnapshotOrigin, VmInstanceId};
use crate::foundation::evidence::{HypervisorKind, OsKind, UnknownReason};
use crate::foundation::ids::{digest, Digest, ExecutionId, SandboxBootGeneration};
use crate::foundation::ledger::Ledger;
use crate::foundation::process::{NoProof, ProcessError, ProcessIdentity, ProcessRole};
use crate::sandbox::backend::{
    vm_handle, Accelerator, Architecture, BackendIdentity, BackendKind, BackendOperation,
    BackendRefusal, BuildId, CheckFailure, ConfigurationCheck, ConfigurationComparison,
    ConfinementControl, Emulator, Facet, FactSource, Feature, GuestAssertions, HardwareFailure,
    HostBuild, HostFact, HostInterfaceListing, LaunchRefusal, LaunchRequest, LeftBehind,
    Persistence, ReobservationRefusal, RequiredCheck, StopOutcome, VmBackend, VmProcessState,
};

/// A proof as the scripted host gives it. CORE-04's `TerminationProof` has no public
/// constructor: only a held host process produces one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScriptedProof {
    identity: ProcessIdentity,
    role: ProcessRole,
    ended_before: bool,
}

impl TerminationEvidence for ScriptedProof {
    fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    fn role(&self) -> &ProcessRole {
        &self.role
    }
}

/// What the scripted host was asked to do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Start {
        role: ProcessRole,
        executable: HostPath,
        arguments: Vec<String>,
    },
    Terminate {
        process: ProcessIdentity,
    },
}

/// How the scripted host behaves.
#[derive(Clone, Debug, Default)]
struct HostScript {
    start_failure: Option<StartFailure>,
    /// The process listing names this executable instead of the one started.
    listed_executable: Option<String>,
    /// The process listing shows these after the plan's vector.
    extra_arguments: Vec<String>,
    /// The process listing shows the second argument wherever the plan has the first.
    replaced_argument: Option<(&'static str, &'static str)>,
    /// Changes what the host queries from the token and Job.
    windows: Option<fn(&mut WindowsObservedState)>,
    no_windows_observation: bool,
    /// Changes what the host reads of the process on Linux.
    linux: Option<fn(&mut LinuxObservedState)>,
    no_linux_observation: bool,
    /// The process exits with this code right after it starts.
    exits_at_start: Option<u32>,
    /// The host does not observe the end on termination.
    no_proof: Option<NoProof>,
    /// The proof names another process.
    proof_of_another_process: bool,
    host_build_unreadable: bool,
}

#[derive(Debug)]
struct ScriptedProcess {
    role: ProcessRole,
    command_line: Vec<String>,
    windows: Option<WindowsObservedState>,
    linux: Option<LinuxObservedState>,
    exit_code: Option<u32>,
}

#[derive(Debug)]
struct ScriptedHost {
    os: OsKind,
    script: HostScript,
    next_pid: u32,
    processes: BTreeMap<ProcessIdentity, ScriptedProcess>,
    calls: Vec<Call>,
}

impl ScriptedHost {
    fn new(os: OsKind) -> Self {
        Self {
            os,
            script: HostScript::default(),
            next_pid: 4000,
            processes: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    fn starts(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| matches!(call, Call::Start { .. }))
            .count()
    }

    fn exit(&mut self, process: &ProcessIdentity, code: u32) {
        if let Some(held) = self.processes.get_mut(process) {
            held.exit_code = Some(code);
        }
    }
}

/// The token, Job, handles and mitigations the host would query from a process confined
/// exactly as planned.
fn confined_as(expected: &WindowsHostRestrictions) -> WindowsObservedState {
    let handles = expected.inherited_handles();
    WindowsObservedState {
        token_restricted: true,
        restricting_sids: expected.token().restricting_sids.clone(),
        privileges: expected.token().retained_privileges.clone(),
        administrators: GroupState::DenyOnly,
        integrity_rid: expected.integrity().rid(),
        job: Some(ObservedJob {
            limits: expected.job().limits.clone(),
            active_process_limit: expected.job().active_process_limit,
            job_memory_limit_bytes: expected.job().job_memory_limit_bytes,
            ui_restrictions: expected.job().ui_restrictions.clone(),
        }),
        inherited_handles: vec![handles.stdin, handles.stdout, handles.stderr],
        mitigations: expected.mitigations().clone(),
    }
}

/// What the host would read of a process confined exactly as planned on Linux.
fn linux_confined_as(expected: &LinuxHostRestrictions) -> LinuxObservedState {
    use crate::sandbox::firecracker::{IdQuad, ProcStatus, SeccompMode};
    let ids = IdQuad {
        real: 61000,
        effective: 61000,
        saved: 61000,
        filesystem: 61000,
    };
    LinuxObservedState {
        status: ProcStatus {
            pid: 4000,
            uid: ids,
            gid: ids,
            namespace_pids: vec![4000],
            cap_permitted: 0,
            cap_effective: 0,
            cap_ambient: 0,
            no_new_privs: true,
            seccomp: SeccompMode::Filter,
        },
        cgroup: "/yougori/p-1-1".to_owned(),
        memory_max: Some(expected.memory_limit_bytes),
        pids_max: Some(u64::from(expected.max_tasks)),
        network_interfaces: ["lo".to_owned()].into_iter().collect(),
        host_uid: 0,
    }
}

impl QemuHost for ScriptedHost {
    type Proof = ScriptedProof;

    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure> {
        self.calls.push(Call::Start {
            role: role.clone(),
            executable: executable.clone(),
            arguments: plan.profile().argv(),
        });
        if let Some(failure) = &self.script.start_failure {
            return Err(failure.clone());
        }
        let identity = ProcessIdentity {
            pid: self.next_pid,
            start_time_ticks: 133_000_000_000 + u64::from(self.next_pid),
        };
        self.next_pid += 1;
        let mut command_line = vec![self
            .script
            .listed_executable
            .clone()
            .unwrap_or_else(|| executable.as_str().to_owned())];
        command_line.extend(plan.profile().argv());
        command_line.extend(self.script.extra_arguments.iter().cloned());
        let command_line = rewritten(&command_line, self.script.replaced_argument, &[]);
        let windows = plan
            .windows()
            .filter(|_| !self.script.no_windows_observation)
            .map(|expected| {
                let mut state = confined_as(expected);
                if let Some(change) = self.script.windows {
                    change(&mut state);
                }
                state
            });
        let linux = plan
            .linux()
            .filter(|_| !self.script.no_linux_observation)
            .map(|expected| {
                let mut state = linux_confined_as(expected);
                if let Some(change) = self.script.linux {
                    change(&mut state);
                }
                state
            });
        self.processes.insert(
            identity,
            ScriptedProcess {
                role: role.clone(),
                command_line,
                windows,
                linux,
                exit_code: self.script.exits_at_start,
            },
        );
        Ok(identity)
    }

    fn state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        let held = self
            .processes
            .get(process)
            .ok_or(ObserveFailure::NotHeld { process: *process })?;
        Ok(match held.exit_code {
            Some(exit_code) => ProcessState::Ended { exit_code },
            None => ProcessState::Running,
        })
    }

    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure> {
        let state = self.state(process)?;
        let held = self
            .processes
            .get(process)
            .ok_or(ObserveFailure::NotHeld { process: *process })?;
        Ok(ProcessInspection {
            state,
            command_line: held.command_line.clone(),
            windows: held.windows.clone(),
            linux: held.linux.clone(),
        })
    }

    fn host_build(&self) -> Result<HostBuild, ObserveFailure> {
        if self.script.host_build_unreadable {
            return Err(ObserveFailure::Unreadable {
                detail: "the build number could not be read".to_owned(),
            });
        }
        Ok(HostBuild {
            os: self.os,
            build: BuildId::new("26100.1234").unwrap(),
            architecture: Architecture::X86_64,
        })
    }

    fn terminate(&mut self, process: &ProcessIdentity) -> Result<ScriptedProof, NoProof> {
        self.calls.push(Call::Terminate { process: *process });
        if let Some(no_proof) = &self.script.no_proof {
            return Err(no_proof.clone());
        }
        let held = self
            .processes
            .get_mut(process)
            .ok_or(NoProof::StillRunning)?;
        let ended_before = held.exit_code.is_some();
        held.exit_code.get_or_insert(1);
        let identity = if self.script.proof_of_another_process {
            ProcessIdentity {
                pid: process.pid,
                start_time_ticks: process.start_time_ticks + 1,
            }
        } else {
            *process
        };
        Ok(ScriptedProof {
            identity,
            role: held.role.clone(),
            ended_before,
        })
    }
}

#[derive(Debug)]
struct ScriptedMonitor {
    accelerator: Result<String, MonitorFailure>,
    status: Result<RunState, MonitorFailure>,
    /// Every socket QMP was used on.
    asked: RefCell<Vec<HostPath>>,
    quits: Vec<HostPath>,
}

impl ScriptedMonitor {
    fn reporting(accelerator: &str) -> Self {
        Self {
            accelerator: Ok(accelerator.to_owned()),
            status: Ok(RunState::Running),
            asked: RefCell::new(Vec::new()),
            quits: Vec::new(),
        }
    }
}

impl QemuMonitor for ScriptedMonitor {
    fn accelerator(&self, socket: &HostPath) -> Result<String, MonitorFailure> {
        self.asked.borrow_mut().push(socket.clone());
        self.accelerator.clone()
    }

    fn status(&self, socket: &HostPath) -> Result<RunState, MonitorFailure> {
        self.asked.borrow_mut().push(socket.clone());
        self.status.clone()
    }

    fn quit(&mut self, socket: &HostPath) -> Result<(), MonitorFailure> {
        self.quits.push(socket.clone());
        Ok(())
    }
}

/// The fixture's inputs, with a private directory per VM.
#[derive(Debug)]
struct ScriptedLayout {
    base: QemuLaunchInputs,
    guest_image: Digest,
    refusal: Option<LayoutRefusal>,
    lookups: Cell<u32>,
}

impl LaunchLayout for ScriptedLayout {
    fn inputs(
        &self,
        _request: &LaunchRequest,
        vm: VmInstanceId,
    ) -> Result<HostInputs, LayoutRefusal> {
        self.lookups.set(self.lookups.get() + 1);
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        let hex = vm.digest().to_hex();
        let short = &hex[..16];
        let mut inputs = self.base.clone();
        inputs.control = PrivateDirectory::new(path(
            inputs.platform.os,
            &format!("/run/yougori/{short}"),
            &format!(r"C:\Yougori\vm\{short}"),
        ))
        .map_err(|error| LayoutRefusal::Unavailable {
            detail: error.to_string(),
        })?;
        Ok(HostInputs {
            inputs,
            guest_image: self.guest_image,
        })
    }
}

/// Arguments appended to the process listing, and the finding they must produce.
type ArgvCase = (&'static [&'static str], fn(&ArgvFinding) -> bool);

/// A change to the observed token or Job, and the finding it must produce.
type WindowsCase = (fn(&mut WindowsObservedState), WindowsFinding);

type TestBackend<'a> =
    QemuBackend<ScriptedHost, ScriptedMonitor, ScriptedLayout, &'a Ledger<TestClock>>;

fn executable(os: OsKind) -> HostPath {
    path(
        os,
        "/opt/yougori/qemu/bin/qemu-system-x86_64",
        r"C:\Program Files\Yougori\qemu\qemu-system-x86_64.exe",
    )
}

/// A backend for the fixture's build whose QMP reports `accelerator`.
fn scripted_backend<'a>(fixture: &'a Fixture, accelerator: &str) -> TestBackend<'a> {
    backend_on(fixture, &fixture.host.ledger, accelerator)
}

/// [`scripted_backend`] over `ledger` alone, so the fixture's registry stays writable.
fn backend_on<'a>(
    fixture: &Fixture,
    ledger: &'a Ledger<TestClock>,
    accelerator: &str,
) -> TestBackend<'a> {
    backend_with(fixture, ledger, accelerator, golden_for(fixture))
}

/// The release's golden file of the fixture's launch: the golden file of its plan's
/// profile, or, when the fixture's launch is refused before a plan exists, of a launch on
/// the same platform.
fn golden_for(fixture: &Fixture) -> GoldenFile {
    let platform = fixture.inputs.platform;
    let profile = match fixture.plan() {
        Ok(plan) => plan.profile().clone(),
        Err(_) => fixture_for("exe-golden", platform.os, platform.architecture).profile(),
    };
    GoldenFile::of(&profile, &fixture.backend).unwrap()
}

/// [`backend_on`] with `golden` as the release's golden file.
fn backend_with<'a>(
    fixture: &Fixture,
    ledger: &'a Ledger<TestClock>,
    accelerator: &str,
    golden: GoldenFile,
) -> TestBackend<'a> {
    let os = fixture.inputs.platform.os;
    QemuBackend::new(
        fixture.backend.clone(),
        QemuSettings {
            executable: executable(os),
            fresh_for: Duration::from_secs(600),
            golden,
        },
        ScriptedHost::new(os),
        ScriptedMonitor::reporting(accelerator),
        ScriptedLayout {
            base: fixture.inputs.clone(),
            guest_image: fixture.request.pinned.guest_image,
            refusal: None,
            lookups: Cell::new(0),
        },
        ledger,
    )
}

/// A process listing with the second argument of `replaced` wherever it has the first, and
/// `extra` appended.
fn rewritten(listing: &[String], replaced: Option<(&str, &str)>, extra: &[&str]) -> Vec<String> {
    let mut rewritten: Vec<String> = listing
        .iter()
        .map(|argument| match replaced {
            Some((planned, observed)) if argument == planned => observed.to_owned(),
            _ => argument.clone(),
        })
        .collect();
    rewritten.extend(strings(extra));
    rewritten
}

/// The guest memory the fixture plans, doubled in the process listing.
const MORE_MEMORY: (&str, &str) = ("2048M", "4096M");
/// A 9p share of a host directory.
const NINE_P_SHARE: [&str; 2] = [
    "-virtfs",
    r"local,path=C:\Users,mount_tag=host,security_model=none",
];
/// QMP on a TCP listener.
const QMP_LISTENER: [&str; 2] = ["-qmp", "tcp:127.0.0.1:4444,server=on,wait=off"];

fn handle(request: &LaunchRequest) -> VmInstanceId {
    vm_handle(
        BackendKind::Qemu,
        &request.execution,
        request.generations.boot,
    )
}

fn role(request: &LaunchRequest) -> ProcessRole {
    ProcessRole::VmHost {
        execution: request.execution.clone(),
        vm: handle(request),
        boot: request.generations.boot,
    }
}

/// The plan the backend runs for `request`, built the same way.
fn plan_of(fixture: &Fixture, backend: &TestBackend, request: &LaunchRequest) -> QemuLaunchPlan {
    let inputs = backend
        .layout()
        .inputs(request, handle(request))
        .unwrap()
        .inputs;
    plan_launch(
        request,
        &fixture.backend,
        &fixture.host.registry,
        &fixture.host.ledger,
        inputs,
    )
    .unwrap()
}

/// The launch was refused after QEMU started once: QEMU was asked to quit unless its
/// process had ended, the host proved the end of exactly that process, and nothing of it
/// is held, listed or queryable.
fn assert_stopped(backend: &TestBackend, request: &LaunchRequest) {
    let vm = handle(request);
    assert_eq!(backend.host().starts(), 1, "started once, never retried");
    let process = *backend.host().processes.keys().next().unwrap();
    assert_eq!(
        backend.host().calls.last(),
        Some(&Call::Terminate { process })
    );
    let proof = backend.termination(&vm).unwrap();
    assert_eq!(proof.identity, process);
    assert_eq!(proof.role, role(request));
    if !proof.ended_before {
        assert_eq!(backend.monitor().quits.len(), 1);
    }
    assert!(backend.running().is_empty());
    assert_eq!(backend.process_of(&vm), None);
    assert_eq!(
        backend.actual_accelerator(&vm),
        Err(BackendRefusal::NoSuchVm { vm })
    );
}

#[test]
fn a_whpx_launch_seals_a_record_naming_the_observed_accelerator() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let request = &fixture.request;
    let launched = backend.launch(request, &fixture.host.registry).unwrap();
    let vm = handle(request);
    assert_eq!(launched.vm, vm);

    let record = &launched.record;
    assert_eq!(
        *record.accelerator().value(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx
        }
    );
    assert_eq!(record.accelerator().source(), FactSource::HostObserved);
    assert_eq!(record.backend(), backend.identity());
    assert_eq!(record.reservation(), request.reservation);
    assert_eq!(record.vm(), vm);
    assert!(record.checks().iter().all(RequiredCheck::is_satisfied));
    assert_eq!(record.checks().len(), Facet::ALL.len());
    let observed = record.host_observed();
    let windows_controls: BTreeSet<ConfinementControl> = [
        ConfinementControl::ProcessIdentity,
        ConfinementControl::FilesystemLimits,
        ConfinementControl::OsRestrictions,
        ConfinementControl::ResourceControls,
    ]
    .into_iter()
    .collect();
    assert_eq!(observed.confinement.value(), Some(&windows_controls));
    assert_eq!(
        observed.guest_image.value(),
        Some(&request.pinned.guest_image)
    );
    assert_eq!(
        observed.host.value().map(|host| host.os),
        Some(OsKind::Windows)
    );
    assert_eq!(
        observed.persistence.value(),
        Some(&Persistence::EphemeralTask)
    );
    assert_eq!(record.guest_asserted(), &GuestAssertions::none());
    assert!(record
        .fact_sources()
        .iter()
        .all(|(_, source)| source.is_host()));
    assert_eq!(record.assert_current(fixture.host.registry.now()), Ok(()));

    // One process, started with exactly the plan's vector as the host process of this
    // boot, and bound to the handle by its CORE-04 identity.
    let plan = plan_of(&fixture, &backend, request);
    let process = backend.process_of(&vm).unwrap();
    assert_eq!(
        backend.host().calls,
        vec![Call::Start {
            role: role(request),
            executable: executable(OsKind::Windows),
            arguments: plan.profile().argv(),
        }]
    );
    assert_eq!(backend.host().processes[&process].role, role(request));
    // QMP was used only on the launch's private socket and never asked to quit.
    let socket = plan.profile().control().qmp_socket().clone();
    assert!(backend
        .monitor()
        .asked
        .borrow()
        .iter()
        .all(|asked| *asked == socket));
    assert!(backend.monitor().quits.is_empty());

    assert_eq!(backend.running(), vec![vm]);
    assert_eq!(
        backend.actual_accelerator(&vm).unwrap(),
        *record.accelerator()
    );
    assert_eq!(backend.confinement_evidence(&vm).unwrap(), *observed);
    assert_eq!(backend.features(), &qemu_features());
    assert_eq!(backend.identity().kind, BackendKind::Qemu);
}

#[test]
fn a_repeated_launch_of_a_running_boot_is_the_same_vm_and_a_boot_is_used_once() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let registry = &fixture.host.registry;
    let first = backend.launch(&fixture.request, registry).unwrap();
    let again = backend.launch(&fixture.request, registry).unwrap();
    assert_eq!(again, first);
    assert_eq!(backend.host().starts(), 1);

    let mut changed = fixture.request.clone();
    changed.contract = digest("yougori/test/contract/v1", &[b"other"]);
    assert_eq!(
        backend.launch(&changed, registry),
        Err(LaunchRefusal::BootGenerationUsed {
            execution: changed.execution.clone(),
            boot: changed.generations.boot,
        })
    );

    let mut next = fixture.request.clone();
    next.generations.boot = SandboxBootGeneration::new(2);
    let second = backend.launch(&next, registry).unwrap();
    assert_ne!(second.vm, first.vm);
    assert_ne!(
        backend.process_of(&second.vm),
        backend.process_of(&first.vm)
    );
    assert_eq!(backend.running(), {
        let mut both = vec![first.vm, second.vm];
        both.sort();
        both
    });

    // A stopped boot is not launched again.
    assert_eq!(backend.stop(&first.vm), Ok(StopOutcome::Stopped));
    assert!(matches!(
        backend.launch(&fixture.request, registry),
        Err(LaunchRefusal::BootGenerationUsed { .. })
    ));
}

#[test]
fn tcg_or_another_accelerator_is_refused_and_the_vm_is_stopped() {
    let tcg = Accelerator::Emulation {
        emulator: Emulator::Tcg,
    };
    let kvm = Accelerator::Hardware {
        hypervisor: HypervisorKind::Kvm,
    };
    for (reported, expected) in [
        (
            Ok("tcg"),
            LaunchRefusal::NotHardwareVirtualized { observed: tcg },
        ),
        (
            Ok("kvm"),
            LaunchRefusal::UnexpectedAccelerator {
                expected: HypervisorKind::Whpx,
                observed: kvm,
            },
        ),
        (
            Ok("nvmm"),
            LaunchRefusal::AcceleratorNotObserved {
                reason: UnknownReason::InconsistentReport,
            },
        ),
        (
            Err(MonitorFailure::Protocol {
                detail: "CommandNotFound".to_owned(),
            }),
            LaunchRefusal::AcceleratorNotObserved {
                reason: UnknownReason::Inconclusive,
            },
        ),
    ] {
        let fixture = windows();
        let mut backend = scripted_backend(&fixture, "whpx");
        backend.monitor_mut().accelerator = reported.map(str::to_owned);
        let refusal = backend
            .launch(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        assert_eq!(refusal, expected);
        assert_stopped(&backend, &fixture.request);
        // The boot was used; nothing retries it, in emulation or otherwise.
        assert!(matches!(
            backend.launch(&fixture.request, &fixture.host.registry),
            Err(LaunchRefusal::BootGenerationUsed { .. })
        ));
        assert_eq!(backend.host().starts(), 1);
    }
}

#[test]
fn a_tcg_argument_in_the_process_listing_is_refused() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.extra_arguments = vec!["-accel".to_owned(), "tcg".to_owned()];
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    let QemuRefusal::Arguments { refusal: argv } = &refusal else {
        panic!("{refusal:?}");
    };
    assert!(argv.names_tcg());
    assert_eq!(
        refusal.launch_refusal(),
        LaunchRefusal::NotHardwareVirtualized {
            observed: Accelerator::Emulation {
                emulator: Emulator::Tcg
            }
        }
    );
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn a_precheck_refusal_starts_and_looks_up_nothing() {
    let mut unavailable = windows();
    unavailable.host.observe(HypervisorKind::Whpx, false);
    let mut pinned_elsewhere = windows();
    pinned_elsewhere.request.pinned.backend = digest("yougori/test/backend/v1", &[b"other"]);
    let mut with_display = windows();
    with_display.request.device_profile.devices.display = true;

    for (fixture, expected) in [
        (&unavailable, None),
        (
            &pinned_elsewhere,
            Some(LaunchRefusal::BackendArtifactMismatch {
                pinned: pinned_elsewhere.request.pinned.backend,
                actual: pinned_elsewhere.backend.artifact,
            }),
        ),
        (
            &with_display,
            Some(LaunchRefusal::Unsupported {
                feature: Feature::Display,
            }),
        ),
    ] {
        let mut backend = scripted_backend(fixture, "whpx");
        let refusal = backend
            .launch(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        match expected {
            Some(expected) => assert_eq!(refusal, expected),
            None => assert!(matches!(refusal, LaunchRefusal::Evidence { .. })),
        }
        assert_eq!(backend.layout().lookups.get(), 0);
        assert!(backend.host().calls.is_empty());
        assert!(backend.monitor().asked.borrow().is_empty());
        assert!(backend.running().is_empty());
    }

    // A refusal before anything started leaves the boot unused.
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let mut elsewhere = fixture.request.clone();
    elsewhere.pinned.backend = digest("yougori/test/backend/v1", &[b"other"]);
    assert!(matches!(
        backend.launch(&elsewhere, &fixture.host.registry),
        Err(LaunchRefusal::BackendArtifactMismatch { .. })
    ));
    assert!(backend
        .launch(&fixture.request, &fixture.host.registry)
        .is_ok());
}

#[test]
fn a_layout_or_profile_refusal_starts_nothing() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let image = fixture.request.pinned.guest_image;
    backend.layout_mut().refusal = Some(LayoutRefusal::ImageNotAvailable { image });
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        QemuRefusal::Layout {
            refusal: LayoutRefusal::ImageNotAvailable { image }
        }
    );
    assert!(matches!(
        refusal.launch_refusal(),
        LaunchRefusal::LayoutRefused { backend: BackendKind::Qemu, detail }
            if detail.ends_with("is not available on this host")
    ));
    assert!(refusal
        .launch_refusal()
        .to_string()
        .contains("so nothing was started"));
    assert!(backend.host().calls.is_empty());

    let mut fixture = windows();
    fixture
        .request
        .required
        .confinement
        .insert(ConfinementControl::AccountIdentity);
    let mut backend = scripted_backend(&fixture, "whpx");
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        QemuRefusal::Profile {
            refusal: Box::new(ProfileRefusal::ConfinementNotProvided {
                missing: [ConfinementControl::AccountIdentity].into_iter().collect()
            })
        }
    );
    assert!(matches!(
        refusal.launch_refusal(),
        LaunchRefusal::ProfileRefused { backend: BackendKind::Qemu, detail }
            if detail.contains("does not apply the required confinement")
    ));
    assert!(backend.host().calls.is_empty());
}

#[test]
fn an_observed_vector_that_differs_from_the_plan_is_refused_and_the_vm_is_stopped() {
    let share = |finding: &ArgvFinding| {
        matches!(
            finding,
            ArgvFinding::ShareDevice {
                kind: ShareKind::NineP,
                ..
            }
        )
    };
    let listener = |finding: &ArgvFinding| {
        matches!(
            finding,
            ArgvFinding::ManagementListener {
                interface: ManagementInterface::Qmp,
                ..
            }
        )
    };
    let cases: [ArgvCase; 2] = [
        (
            &[
                "-virtfs",
                r"local,path=C:\Users,mount_tag=host,security_model=none",
            ],
            share,
        ),
        (&["-qmp", "tcp:127.0.0.1:4444,server=on,wait=off"], listener),
    ];
    for (extra, expected) in cases {
        let fixture = windows();
        let mut backend = scripted_backend(&fixture, "whpx");
        backend.host_mut().script.extra_arguments = extra
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        let refusal = backend
            .launch_qemu(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        let QemuRefusal::Arguments { refusal: argv } = &refusal else {
            panic!("{extra:?}: {refusal:?}");
        };
        assert!(argv.findings().iter().any(expected), "{extra:?}: {argv:?}");
        assert!(!argv.names_tcg());
        let LaunchRefusal::ConfigurationNotApproved {
            backend: BackendKind::Qemu,
            checks,
            findings,
        } = refusal.launch_refusal()
        else {
            panic!("{extra:?}: not stated as a configuration that is not approved");
        };
        assert_eq!(
            checks,
            BTreeSet::from([
                ConfigurationCheck::GoldenConfiguration,
                ConfigurationCheck::HostInterfaces
            ])
        );
        assert_eq!(findings.len(), argv.findings().len());
        assert_stopped(&backend, &fixture.request);
    }

    // Another executable with the plan's vector is not the pinned build.
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.listed_executable =
        Some(r"C:\Users\someone\qemu-system-x86_64.exe".to_owned());
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    assert!(matches!(refusal, QemuRefusal::OtherExecutable { .. }));
    assert!(matches!(
        refusal.launch_refusal(),
        LaunchRefusal::ConfigurationNotApproved { checks, findings, .. }
            if checks == BTreeSet::from([ConfigurationCheck::GoldenConfiguration])
                && findings.len() == 1
    ));
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn a_missing_windows_restriction_is_refused_and_the_vm_is_stopped() {
    let cases: [WindowsCase; 3] = [
        (
            |state| {
                if let Some(job) = &mut state.job {
                    job.limits.remove(&JobLimit::JobMemory);
                }
            },
            WindowsFinding::JobLimitMissing {
                limit: JobLimit::JobMemory,
            },
        ),
        (
            |state| state.token_restricted = false,
            WindowsFinding::TokenNotRestricted,
        ),
        (|state| state.job = None, WindowsFinding::NotInJob),
    ];
    for (change, finding) in cases {
        let fixture = windows();
        let mut backend = scripted_backend(&fixture, "whpx");
        backend.host_mut().script.windows = Some(change);
        let refusal = backend
            .launch_qemu(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        assert_eq!(
            refusal,
            QemuRefusal::RestrictionsNotInEffect {
                findings: vec![finding]
            }
        );
        assert!(refusal
            .to_string()
            .starts_with("1 of the launch's Windows restrictions is not in effect: "));
        assert_stopped(&backend, &fixture.request);
    }

    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.no_windows_observation = true;
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::RestrictionsNotObserved)
    );
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn stop_is_proven_and_idempotent() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let vm = launched.vm;
    let process = backend.process_of(&vm).unwrap();
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::Stopped));
    let socket = launched_socket(&fixture, &backend);
    assert_eq!(backend.monitor().quits, vec![socket]);
    assert_eq!(
        backend.host().calls.last(),
        Some(&Call::Terminate { process })
    );
    let proof = backend.termination(&vm).unwrap().clone();
    assert_eq!(proof.identity, process);
    assert_eq!(proof.role, role(&fixture.request));
    assert!(!proof.ended_before);
    assert!(backend.running().is_empty());
    assert_eq!(backend.process_of(&vm), None);

    // Again: already gone, with the same proof, and nothing asked of the host.
    let calls = backend.host().calls.len();
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
    assert_eq!(backend.host().calls.len(), calls);
    assert_eq!(backend.termination(&vm), Some(&proof));
    assert_eq!(
        backend.confinement_evidence(&vm),
        Err(BackendRefusal::NoSuchVm { vm })
    );

    // A handle this backend never held is not claimed stopped.
    let unknown = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"unknown"]));
    assert_eq!(
        backend.stop(&unknown),
        Err(BackendRefusal::NoSuchVm { vm: unknown })
    );
}

/// The QMP socket of the fixture's first launch.
fn launched_socket(fixture: &Fixture, backend: &TestBackend) -> HostPath {
    plan_of(fixture, backend, &fixture.request)
        .profile()
        .control()
        .qmp_socket()
        .clone()
}

#[test]
fn a_vm_whose_process_ended_is_not_running_and_its_stop_is_already_gone() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let vm = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap()
        .vm;
    let process = backend.process_of(&vm).unwrap();
    // The guest shut down: QEMU exited on its own.
    backend.host_mut().exit(&process, 0);
    assert!(backend.running().is_empty());
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
    assert!(backend.monitor().quits.is_empty());
    let proof = backend.termination(&vm).unwrap();
    assert!(proof.ended_before);
    assert_eq!(proof.identity, process);
}

#[test]
fn a_stop_without_the_hosts_proof_of_that_process_is_not_a_stop() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let vm = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap()
        .vm;
    backend.host_mut().script.no_proof = Some(NoProof::JobStillActive {
        exit_code: 0,
        active: 1,
    });
    let Err(BackendRefusal::Failed { operation, detail }) = backend.stop(&vm) else {
        panic!("a stop without proof succeeded");
    };
    assert_eq!(operation, BackendOperation::Stop);
    assert!(
        detail.contains("1 process(es) of its job still run"),
        "{detail}"
    );
    assert_eq!(backend.running(), vec![vm]);
    assert!(backend.process_of(&vm).is_some());
    assert!(backend.termination(&vm).is_none());

    backend.host_mut().script.no_proof = None;
    backend.host_mut().script.proof_of_another_process = true;
    let Err(BackendRefusal::Failed { detail, .. }) = backend.stop(&vm) else {
        panic!("a proof of another process was accepted");
    };
    assert!(
        detail.contains("not of the process held for the VM"),
        "{detail}"
    );
    assert!(backend.termination(&vm).is_none());

    backend.host_mut().script.proof_of_another_process = false;
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
    assert!(backend.running().is_empty());
}

#[test]
fn a_refused_launch_whose_vm_cannot_be_shown_stopped_stays_listed() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "tcg");
    backend.host_mut().script.no_proof = Some(NoProof::StillRunning);
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    let tcg = LaunchRefusal::NotHardwareVirtualized {
        observed: Accelerator::Emulation {
            emulator: Emulator::Tcg,
        },
    };
    let vm = handle(&fixture.request);
    assert_eq!(
        refusal,
        QemuRefusal::NotStopped {
            vm,
            refusal: Box::new(QemuRefusal::Launch {
                refusal: Box::new(tcg.clone())
            }),
            problem: EndNotProven::NoProof {
                no_proof: NoProof::StillRunning
            },
        }
    );
    // The contract hears what may remain, never that nothing is left.
    let stated = refusal.launch_refusal();
    let LaunchRefusal::CleanupIncomplete {
        vm: left_vm,
        refusal: cause,
        left,
    } = &stated
    else {
        panic!("{stated:?}");
    };
    assert_eq!(*left_vm, vm);
    assert_eq!(**cause, tcg);
    assert_eq!(stated.cause(), &tcg);
    assert_eq!(
        left.iter().map(LeftBehind::tag).collect::<Vec<_>>(),
        ["process", "host_resource"]
    );
    assert!(refusal
        .to_string()
        .contains("stays listed until a stop succeeds"));
    assert_eq!(
        backend.reobserve(&vm, &fixture.host.registry),
        Err(ReobservationRefusal::NotAdmitted { vm })
    );

    assert_eq!(backend.running(), vec![vm]);
    assert!(matches!(
        backend.actual_accelerator(&vm),
        Err(BackendRefusal::Failed {
            operation: BackendOperation::Query,
            ..
        })
    ));
    assert!(matches!(
        backend.launch(&fixture.request, &fixture.host.registry),
        Err(LaunchRefusal::BootGenerationUsed { .. })
    ));

    // The process still runs, so stopping it now is a stop, with the proof.
    backend.host_mut().script.no_proof = None;
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::Stopped));
    let process = *backend.host().processes.keys().next().unwrap();
    assert_eq!(
        backend.termination(&vm).map(|proof| proof.identity),
        Some(process)
    );
    assert!(backend.running().is_empty());
    assert_eq!(backend.host().starts(), 1);
}

#[test]
fn reservation_amounts_from_the_ledger_cover_the_plan() {
    // The guest memory beyond the 4 GiB reserved: refused before anything starts.
    let mut fixture = windows();
    fixture.inputs.resources = GuestResources::new(2, 6 * GIB).unwrap();
    let mut backend = scripted_backend(&fixture, "whpx");
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::Profile {
            refusal: Box::new(ProfileRefusal::MemoryExceedsReservation {
                memory_bytes: 6 * GIB,
                reserved_bytes: 4 * GIB,
            })
        })
    );
    assert!(backend.host().calls.is_empty());

    // A reservation of another execution: refused before anything starts.
    let mut fixture = windows();
    let other = ExecutionId::new("exe-other").unwrap();
    fixture.request.reservation = fixture.host.reserve(&other, 4 * GIB);
    let mut backend = scripted_backend(&fixture, "whpx");
    let Err(QemuRefusal::Profile { refusal }) =
        backend.launch_qemu(&fixture.request, &fixture.host.registry)
    else {
        panic!("a reservation of another execution was used");
    };
    assert!(matches!(
        *refusal,
        ProfileRefusal::ReservationOfOtherExecution { .. }
    ));
    assert!(backend.host().calls.is_empty());

    // All of the reservation: the plan's Job holds QEMU to the reserved RAM, and the
    // record binds the reservation.
    let mut fixture = windows();
    fixture.inputs.resources = GuestResources::new(2, 4 * GIB).unwrap();
    let mut backend = scripted_backend(&fixture, "whpx");
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let plan = plan_of(&fixture, &backend, &fixture.request);
    assert_eq!(plan.reserved_ram_bytes(), 4 * GIB);
    assert_eq!(
        plan.windows().unwrap().job().job_memory_limit_bytes,
        4 * GIB
    );
    assert_eq!(launched.record.reservation(), fixture.request.reservation);

    // A Job whose memory limit is above the reservation is refused.
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.windows = Some(|state| {
        if let Some(job) = &mut state.job {
            job.job_memory_limit_bytes = 8 * GIB;
        }
    });
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::RestrictionsNotInEffect {
            findings: vec![WindowsFinding::JobMemoryLimit {
                expected_bytes: 4 * GIB,
                observed_bytes: 8 * GIB,
            }]
        })
    );
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn a_hardware_failure_at_start_is_refused_without_emulation() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let detail = "WHPX: No accelerator found, hr=c0350000".to_owned();
    backend.host_mut().script.start_failure = Some(StartFailure::HardwareVirtualization {
        detail: detail.clone(),
    });
    assert_eq!(
        backend.launch(&fixture.request, &fixture.host.registry),
        Err(LaunchRefusal::HardwareVirtualizationFailed {
            failure: HardwareFailure {
                hypervisor: HypervisorKind::Whpx,
                detail,
            }
        })
    );
    assert_eq!(backend.host().starts(), 1);
    assert!(backend.running().is_empty());

    // The port left nothing behind, so the boot is not used.
    backend.host_mut().script.start_failure = Some(StartFailure::Process {
        error: ProcessError::NotInJob,
    });
    let refusal = backend
        .launch_qemu(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        QemuRefusal::Start {
            failure: StartFailure::Process {
                error: ProcessError::NotInJob
            }
        }
    );
    assert!(matches!(
        refusal.launch_refusal(),
        LaunchRefusal::CreateFailed { .. }
    ));
    backend.host_mut().script.start_failure = None;
    assert!(backend
        .launch(&fixture.request, &fixture.host.registry)
        .is_ok());
}

#[test]
fn a_vm_that_ends_or_does_not_run_before_admission_is_refused() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.exits_at_start = Some(1);
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::Ended { exit_code: 1 })
    );
    assert!(backend.monitor().quits.is_empty());
    assert_stopped(&backend, &fixture.request);

    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.monitor_mut().status = Ok(RunState::NotRunning {
        status: "paused".to_owned(),
    });
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::NotRunning {
            status: "paused".to_owned()
        })
    );
    assert_stopped(&backend, &fixture.request);

    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let failure = MonitorFailure::Unreachable {
        detail: "the socket refused the connection".to_owned(),
    };
    backend.monitor_mut().status = Err(failure.clone());
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::Monitor { failure })
    );
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn admission_judges_the_booted_image_and_the_host_build() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let other = digest("yougori/test/image/v1", &[b"other"]);
    backend.layout_mut().guest_image = other;
    let refusal = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    let failed = refusal.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].facet(), Facet::Evidence);
    assert_eq!(
        failed[0].failure(),
        Some(&CheckFailure::ArtifactMismatch {
            pinned: fixture.request.pinned.guest_image,
            observed: other,
        })
    );
    assert_stopped(&backend, &fixture.request);

    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    backend.host_mut().script.host_build_unreadable = true;
    let refusal = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap_err();
    let failed = refusal.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].failure(),
        Some(&CheckFailure::NotObserved {
            reason: UnknownReason::Inconclusive
        })
    );
    assert_stopped(&backend, &fixture.request);
}

#[test]
fn declared_volumes_are_the_observed_persistence() {
    let data = digest("yougori/test/volume/v1", &[b"data"]);
    let volumes: BTreeSet<Digest> = [data].into_iter().collect();
    for persistence in [
        Persistence::DeclaredDataVolumes {
            volumes: volumes.clone(),
        },
        Persistence::ControlledServiceRenewal {
            volumes: volumes.clone(),
        },
    ] {
        let mut fixture = windows();
        fixture.request.required.persistence = persistence.clone();
        fixture.inputs.volumes = [(
            data,
            path(OsKind::Windows, "", r"C:\Yougori\volumes\data.img"),
        )]
        .into_iter()
        .collect();
        let mut backend = scripted_backend(&fixture, "whpx");
        let launched = backend
            .launch(&fixture.request, &fixture.host.registry)
            .unwrap();
        assert_eq!(
            launched.record.host_observed().persistence.value(),
            Some(&persistence)
        );
    }
}

/// PROVES a Linux launch is admitted on the confinement the host observed of the QEMU
/// process (an account of its own, no new privileges, no capability, seccomp in filter
/// mode, its own cgroup with the planned limits, only `lo`), which its record carries as the
/// five Linux controls.
#[test]
fn a_linux_launch_is_admitted_on_its_observed_confinement() {
    let fixture = linux();
    let mut backend = scripted_backend(&fixture, "kvm");
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let confinement = launched.record.host_observed().confinement.value().cloned();
    assert_eq!(confinement, Some(LINUX_CONTROLS.into_iter().collect()));
}

/// PROVES a Linux launch whose QEMU process shows any restriction missing is refused with
/// that finding and stopped, and one the host could not read is refused as not observed.
#[test]
fn a_linux_launch_whose_restriction_is_missing_is_refused() {
    use crate::sandbox::firecracker::SeccompMode;
    let cases: Vec<(fn(&mut LinuxObservedState), LinuxFinding)> = vec![
        (
            |state| {
                state.status.uid = crate::sandbox::firecracker::IdQuad {
                    real: 0,
                    effective: 0,
                    saved: 0,
                    filesystem: 0,
                }
            },
            LinuxFinding::RunsAsRoot,
        ),
        (|state| state.status.no_new_privs = false, LinuxFinding::NewPrivilegesAllowed),
        (
            |state| state.status.seccomp = SeccompMode::Disabled,
            LinuxFinding::NoSeccompFilter {
                mode: SeccompMode::Disabled,
            },
        ),
        (
            |state| state.cgroup = "/".to_owned(),
            LinuxFinding::NoGroupOfItsOwn {
                cgroup: "/".to_owned(),
            },
        ),
        (
            |state| {
                state.network_interfaces.insert("eth0".to_owned());
            },
            LinuxFinding::NetworkInterfaces {
                found: ["eth0".to_owned()].into_iter().collect(),
            },
        ),
    ];
    for (change, finding) in cases {
        let fixture = linux();
        let mut backend = scripted_backend(&fixture, "kvm");
        backend.host_mut().script.linux = Some(change);
        let refusal = backend
            .launch_qemu(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        assert_eq!(
            refusal,
            QemuRefusal::LinuxRestrictionsNotInEffect {
                findings: vec![finding]
            }
        );
        assert!(refusal
            .to_string()
            .starts_with("1 of the launch's Linux restrictions is not in effect: "));
        assert_stopped(&backend, &fixture.request);
    }
    let fixture = linux();
    let mut backend = scripted_backend(&fixture, "kvm");
    backend.host_mut().script.no_linux_observation = true;
    assert_eq!(
        backend.launch_qemu(&fixture.request, &fixture.host.registry),
        Err(QemuRefusal::RestrictionsNotObserved)
    );
    assert_stopped(&backend, &fixture.request);
    let _ = (fixture_for, CheckFailure::NotObserved { reason: UnknownReason::NotTested }, Facet::HypervisorConfinement);
}

#[test]
fn snapshot_and_restore_are_refused_by_name() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let vm = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap()
        .vm;
    assert!(!backend.features().supports(Feature::Snapshot));
    assert!(!backend.features().supports(Feature::Restore));
    assert!(!backend.features().supports(Feature::DeveloperEmulation));
    assert_eq!(
        backend.snapshot(&vm, SnapshotOrigin::PreTenantGolden),
        Err(BackendRefusal::Unsupported {
            feature: Feature::Snapshot
        })
    );
    let manifest = SnapshotManifest {
        snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"s"])),
        origin: SnapshotOrigin::PreTenantGolden,
        image_profile: fixture.request.pinned.guest_image,
        contents: BTreeSet::new(),
        source_vm: vm,
        guest_identity: digest("yougori/test/guest/v1", &[b"g"]),
    };
    let mut next = fixture.request.clone();
    next.generations.boot = SandboxBootGeneration::new(2);
    assert_eq!(
        backend
            .restore(&next, &manifest, &fixture.host.registry)
            .unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::Restore
        }
    );
    assert_eq!(backend.host().starts(), 1);
}

#[test]
fn refusals_serialize_and_explain_themselves() {
    let refusal = QemuRefusal::RestrictionsNotInEffect {
        findings: vec![WindowsFinding::NotInJob, WindowsFinding::TokenNotRestricted],
    };
    let json = serde_json::to_value(&refusal).unwrap();
    assert_eq!(json["kind"], "restrictions_not_in_effect");
    assert_eq!(json["findings"][0]["finding"], "not_in_job");
    assert_eq!(
        refusal.to_string(),
        "2 of the launch's Windows restrictions are not in effect: the process is in no job \
         object; the token is not restricted"
    );
    assert_eq!(
        refusal.launch_refusal(),
        LaunchRefusal::ConfinementNotInEffect {
            backend: BackendKind::Qemu,
            observed: true,
            findings: vec![
                "the process is in no job object".to_owned(),
                "the token is not restricted".to_owned()
            ],
        }
    );

    let not_stopped = QemuRefusal::NotStopped {
        vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm"])),
        refusal: Box::new(QemuRefusal::Ended { exit_code: 3 }),
        problem: EndNotProven::OtherProcess {
            proven: ProcessIdentity {
                pid: 7,
                start_time_ticks: 9,
            },
            role: ProcessRole::VmHost {
                execution: ExecutionId::new("exe-1").unwrap(),
                vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm"])),
                boot: SandboxBootGeneration::FIRST,
            },
        },
    };
    let json = serde_json::to_value(&not_stopped).unwrap();
    assert_eq!(json["kind"], "not_stopped");
    assert_eq!(json["refusal"]["kind"], "ended");
    assert_eq!(json["problem"]["problem"], "other_process");
    // Another process's proof is a proof of no end of this one: the process may remain.
    assert!(matches!(
        not_stopped.launch_refusal(),
        LaunchRefusal::CleanupIncomplete { refusal, left, .. }
            if matches!(*refusal, LaunchRefusal::ProcessNotRunning {
                state: VmProcessState::Exited { exit_code: 3 },
                ..
            }) && left.len() == 1
    ));
    assert!(not_stopped
        .to_string()
        .starts_with("QEMU exited with code 3 before the launch was admitted; "));
    for failure in [
        StartFailure::Prepare {
            detail: "access denied".to_owned(),
        },
        StartFailure::HardwareVirtualization {
            detail: "x".to_owned(),
        },
    ] {
        assert!(!failure.to_string().is_empty());
    }
    assert!(MonitorFailure::Unreachable {
        detail: "refused".to_owned()
    }
    .to_string()
    .starts_with("QMP could not be reached"));
    assert!(LayoutRefusal::VolumeNotAvailable {
        volume: digest("yougori/test/volume/v1", &[b"v"])
    }
    .to_string()
    .contains("is not available on this host"));
}

#[test]
fn every_qemu_refusal_is_stated_by_what_the_host_observed() {
    let process = ProcessIdentity {
        pid: 7,
        start_time_ticks: 9,
    };
    let cases = [
        (QemuRefusal::Ended { exit_code: 1 }, "process_not_running"),
        (
            QemuRefusal::NotRunning {
                status: "internal-error".to_owned(),
            },
            "process_not_running",
        ),
        (
            QemuRefusal::NotObserved {
                failure: ObserveFailure::NotHeld { process },
            },
            "process_not_running",
        ),
        (
            QemuRefusal::NotObserved {
                failure: ObserveFailure::Unreadable {
                    detail: "access denied".to_owned(),
                },
            },
            "backend_specific",
        ),
        (
            QemuRefusal::Listing {
                error: ObservedArgv::from_process_listing(&[]).unwrap_err(),
            },
            "backend_specific",
        ),
        (
            QemuRefusal::Monitor {
                failure: MonitorFailure::Protocol {
                    detail: "no return".to_owned(),
                },
            },
            "backend_specific",
        ),
        (
            QemuRefusal::RestrictionsNotObserved,
            "confinement_not_in_effect",
        ),
        (
            QemuRefusal::Start {
                failure: StartFailure::Prepare {
                    detail: "access denied".to_owned(),
                },
            },
            "create_failed",
        ),
    ];
    for (refusal, kind) in cases {
        let stated = refusal.launch_refusal();
        assert_eq!(
            serde_json::to_value(&stated).unwrap()["kind"],
            kind,
            "{refusal:?}"
        );
        assert_eq!(stated.left_behind(), None, "{refusal:?}");
    }
    assert_eq!(
        QemuRefusal::Ended { exit_code: 1 }.launch_refusal(),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Qemu,
            state: VmProcessState::Exited { exit_code: 1 },
        }
    );
    assert_eq!(
        QemuRefusal::NotObserved {
            failure: ObserveFailure::NotHeld { process },
        }
        .launch_refusal(),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Qemu,
            state: VmProcessState::Gone,
        }
    );
    assert_eq!(
        QemuRefusal::RestrictionsNotObserved.launch_refusal(),
        LaunchRefusal::ConfinementNotInEffect {
            backend: BackendKind::Qemu,
            observed: false,
            findings: Vec::new(),
        }
    );
}

#[test]
fn a_running_vm_is_observed_again_through_the_same_ports() {
    let mut fixture = windows();
    let mut backend = backend_on(&fixture, &fixture.host.ledger, "whpx");
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let vm = launched.vm;
    let record = &launched.record;
    let process = backend.process_of(&vm).unwrap();

    // Once the launch-time facts are stale, the host observes the VM again; nothing is
    // started, asked to quit or ended.
    fixture.host.clock.advance(MINUTE + Duration::from_secs(1));
    assert!(record.assert_current(fixture.host.registry.now()).is_err());
    observe_hypervisor(
        &fixture.host.probe,
        &mut fixture.host.registry,
        HypervisorKind::Whpx,
        true,
    );
    let lookups = backend.layout().lookups.get();
    let again = backend.reobserve(&vm, &fixture.host.registry).unwrap();
    assert_eq!(backend.layout().lookups.get(), lookups + 1);
    assert_eq!(
        record.assert_current_with(fixture.host.registry.now(), &again),
        Ok(())
    );
    assert_eq!(again.record(), record.identity());
    assert_eq!(
        again.host_observed().confinement.value(),
        record.host_observed().confinement.value()
    );
    assert_eq!(
        again
            .accelerator()
            .observation()
            .map(|observed| observed.observed_at()),
        Some(fixture.host.registry.now().at())
    );
    assert_eq!(backend.host().starts(), 1);
    assert_eq!(backend.host().calls.len(), 1);
    assert!(backend.monitor().quits.is_empty());

    // The image store now verifies another image at the root path, or cannot be read:
    // the evidence facet fails on the record's check.
    let pinned = fixture.request.pinned.guest_image;
    backend.layout_mut().guest_image = digest("yougori/test/image/v1", &[b"other"]);
    let other = backend.reobserve(&vm, &fixture.host.registry).unwrap();
    let refusal = record
        .assert_current_with(fixture.host.registry.now(), &other)
        .unwrap_err();
    assert!(
        matches!(
            &refusal,
            ReobservationRefusal::Refused { refusal }
                if refusal.failed_checks().iter().map(|check| check.facet()).eq([Facet::Evidence])
        ),
        "{refusal:?}"
    );
    backend.layout_mut().guest_image = pinned;
    backend.layout_mut().refusal = Some(LayoutRefusal::Unavailable {
        detail: "the image store is locked".to_owned(),
    });
    let unread = backend.reobserve(&vm, &fixture.host.registry).unwrap();
    assert_eq!(
        unread.host_observed().guest_image,
        HostFact::unavailable(UnknownReason::Unreachable)
    );
    assert!(record
        .assert_current_with(fixture.host.registry.now(), &unread)
        .is_err());
    backend.layout_mut().refusal = None;

    // Restrictions no longer in effect, an argument added to the running process, a VM
    // QEMU reports paused and a process that exited are refused as at launch.
    let refused = |backend: &mut TestBackend, fixture: &Fixture| match backend
        .reobserve(&vm, &fixture.host.registry)
    {
        Err(ReobservationRefusal::Refused { refusal }) => *refusal,
        other => panic!("{other:?}"),
    };
    backend
        .host_mut()
        .processes
        .get_mut(&process)
        .and_then(|held| held.windows.as_mut())
        .unwrap()
        .token_restricted = false;
    assert!(matches!(
        refused(&mut backend, &fixture),
        LaunchRefusal::ConfinementNotInEffect { observed: true, findings, .. }
            if findings == ["the token is not restricted"]
    ));
    backend
        .host_mut()
        .processes
        .get_mut(&process)
        .and_then(|held| held.windows.as_mut())
        .unwrap()
        .token_restricted = true;

    let listing = backend.host().processes[&process].command_line.clone();
    backend
        .host_mut()
        .processes
        .get_mut(&process)
        .unwrap()
        .command_line
        .extend([
            "-qmp".to_owned(),
            "tcp:127.0.0.1:4444,server=on,wait=off".to_owned(),
        ]);
    assert!(matches!(
        refused(&mut backend, &fixture),
        LaunchRefusal::ConfigurationNotApproved { checks, .. }
            if checks.contains(&ConfigurationCheck::HostInterfaces)
    ));
    backend
        .host_mut()
        .processes
        .get_mut(&process)
        .unwrap()
        .command_line = listing;

    backend.monitor_mut().status = Ok(RunState::NotRunning {
        status: "paused".to_owned(),
    });
    assert_eq!(
        refused(&mut backend, &fixture),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Qemu,
            state: VmProcessState::NotRunning {
                status: "paused".to_owned()
            },
        }
    );
    backend.monitor_mut().status = Ok(RunState::Running);
    assert!(backend.reobserve(&vm, &fixture.host.registry).is_ok());

    backend.host_mut().exit(&process, 0);
    assert_eq!(
        refused(&mut backend, &fixture),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Qemu,
            state: VmProcessState::Exited { exit_code: 0 },
        }
    );
    // Observing again never ends anything.
    assert_eq!(backend.host().calls.len(), 1);
    assert_eq!(backend.process_of(&vm), Some(process));

    // A handle this backend never held, and a stopped VM, are not observed.
    let unknown = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"unknown"]));
    assert_eq!(
        backend.reobserve(&unknown, &fixture.host.registry),
        Err(ReobservationRefusal::NoSuchVm { vm: unknown })
    );
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
    assert_eq!(
        backend.reobserve(&vm, &fixture.host.registry),
        Err(ReobservationRefusal::NoSuchVm { vm })
    );
}

// ---- the configuration facts of VM-CP-02 and VM-CP-03 (§17 lines 3152 and 3153) ----

#[test]
fn a_matching_golden_file_seals_the_configuration_facts() {
    let fixture = windows();
    let mut backend = scripted_backend(&fixture, "whpx");
    let golden = backend.settings().golden.clone();
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let record = &launched.record;
    let comparison = record.configuration_comparison().unwrap();
    assert_eq!(
        *comparison.value(),
        ConfigurationComparison {
            golden: golden.digest,
            observed: golden.digest,
            network_device: false,
            console: false,
            balloon: false,
            undeclared_pci_transport: false,
        }
    );
    assert!(comparison.value().approved());
    assert_eq!(comparison.source(), FactSource::HostObserved);
    assert_eq!(comparison.observed_at(), record.recorded_at());
    assert_eq!(comparison.configuration(), record.configuration());
    let listing = record.interface_listing().unwrap();
    assert_eq!(*listing.value(), HostInterfaceListing::clean());
    assert_eq!(listing.observed_at(), record.recorded_at());
    assert!(record.gpu_assignments().is_empty());
    assert_eq!(record.assert_current(fixture.host.registry.now()), Ok(()));
    let json = serde_json::to_value(record).unwrap();
    assert_eq!(
        json["configuration_comparison"]["value"]["observed"],
        golden.digest.to_hex()
    );
    assert_eq!(json["interface_listing"]["value"]["share_device"], false);

    // One golden file covers every launch of the profile: the per-launch values of
    // another boot are roles in it.
    let plan = plan_of(&fixture, &backend, &fixture.request);
    assert_ne!(plan.profile().argv(), fixture.profile().argv());
    assert_eq!(
        GoldenFile::of(plan.profile(), &fixture.backend)
            .unwrap()
            .digest,
        golden.digest
    );
}

#[test]
fn a_golden_file_that_does_not_approve_the_plan_starts_nothing() {
    let fixture = windows();
    let approved = golden_for(&fixture);
    let newer = BackendIdentity::new(
        BackendKind::Qemu,
        "9.2.1",
        fixture.backend.artifact,
        HypervisorKind::Whpx,
    )
    .unwrap();
    let mut tampered = approved.clone();
    tampered.arguments.push("-S".to_owned());
    let mut other_vector = tampered.clone();
    other_vector.digest = golden_digest(
        other_vector.backend_kind,
        &other_vector.backend_version,
        other_vector.os,
        other_vector.architecture,
        other_vector.profile,
        &other_vector.arguments,
    );
    let cases: [(GoldenFile, fn(&QemuRefusal) -> bool); 4] = [
        (
            GoldenFile::of(&fixture.profile(), &newer).unwrap(),
            |refusal| {
                matches!(
                    refusal,
                    QemuRefusal::Golden {
                        refusal: GoldenRefusal::OtherBackendVersion { .. }
                    }
                )
            },
        ),
        (tampered, |refusal| {
            matches!(
                refusal,
                QemuRefusal::Golden {
                    refusal: GoldenRefusal::DigestMismatch { .. }
                }
            )
        }),
        (golden_for(&linux()), |refusal| {
            matches!(
                refusal,
                QemuRefusal::Golden {
                    refusal: GoldenRefusal::OtherProfile { .. }
                }
            )
        }),
        (other_vector, |refusal| {
            matches!(
                refusal,
                QemuRefusal::NotGolden { comparison }
                    if comparison.differences
                        == [ArgumentDifference::Missing { argument: "-S".to_owned() }]
            )
        }),
    ];
    for (golden, expected) in cases {
        let mut backend = backend_with(&fixture, &fixture.host.ledger, "whpx", golden);
        let refusal = backend
            .launch_qemu(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        assert!(expected(&refusal), "{refusal:?}");
        assert!(refusal.to_string().ends_with("; nothing was started"));
        let stated = refusal.launch_refusal();
        assert!(
            matches!(
                &stated,
                LaunchRefusal::ProfileRefused { backend: BackendKind::Qemu, detail }
                    if detail.contains("golden file")
            ),
            "{stated:?}"
        );
        assert!(stated.to_string().contains("so nothing was started"));
        assert!(backend.host().calls.is_empty());
        assert!(backend.monitor().asked.borrow().is_empty());
        assert!(backend.running().is_empty());
    }

    // The release's file of this build and profile launches the same request.
    let mut backend = backend_with(&fixture, &fixture.host.ledger, "whpx", approved);
    assert!(backend
        .launch(&fixture.request, &fixture.host.registry)
        .is_ok());
}

#[test]
fn a_changed_argv_an_extra_share_device_or_a_listener_refuses_with_the_existing_refusals() {
    let golden = BTreeSet::from([ConfigurationCheck::GoldenConfiguration]);
    let both = BTreeSet::from([
        ConfigurationCheck::GoldenConfiguration,
        ConfigurationCheck::HostInterfaces,
    ]);
    let cases: [(Option<(&'static str, &'static str)>, &[&str], _); 3] = [
        (Some(MORE_MEMORY), &[], golden),
        (None, &NINE_P_SHARE, both.clone()),
        (None, &QMP_LISTENER, both),
    ];
    for (replaced, extra, failed) in cases {
        let fixture = windows();
        let mut backend = scripted_backend(&fixture, "whpx");
        backend.host_mut().script.replaced_argument = replaced;
        backend.host_mut().script.extra_arguments = strings(extra);
        let refusal = backend
            .launch_qemu(&fixture.request, &fixture.host.registry)
            .unwrap_err();
        assert!(
            matches!(&refusal, QemuRefusal::Arguments { .. }),
            "{refusal:?}"
        );
        assert!(
            matches!(
                refusal.launch_refusal(),
                LaunchRefusal::ConfigurationNotApproved { backend: BackendKind::Qemu, checks, .. }
                    if checks == failed
            ),
            "{refusal:?}"
        );
        assert_stopped(&backend, &fixture.request);
    }
}

#[test]
fn a_reobservation_makes_the_configuration_facts_again_and_finds_a_changed_configuration() {
    let mut fixture = windows();
    let mut backend = backend_on(&fixture, &fixture.host.ledger, "whpx");
    let launched = backend
        .launch(&fixture.request, &fixture.host.registry)
        .unwrap();
    let vm = launched.vm;
    let record = &launched.record;
    let process = backend.process_of(&vm).unwrap();

    fixture.host.clock.advance(MINUTE + Duration::from_secs(1));
    assert!(record.assert_current(fixture.host.registry.now()).is_err());
    observe_hypervisor(
        &fixture.host.probe,
        &mut fixture.host.registry,
        HypervisorKind::Whpx,
        true,
    );
    let again = backend.reobserve(&vm, &fixture.host.registry).unwrap();
    let now = fixture.host.registry.now();
    let comparison = again.configuration_comparison().unwrap();
    assert_eq!(
        comparison.value(),
        record.configuration_comparison().unwrap().value()
    );
    assert_eq!(comparison.observed_at(), now.at());
    let listing = again.interface_listing().unwrap();
    assert_eq!(*listing.value(), HostInterfaceListing::clean());
    assert_eq!(listing.observed_at(), now.at());
    assert_eq!(record.assert_current_with(now, &again), Ok(()));
    let json = serde_json::to_value(&again).unwrap();
    assert_eq!(
        json["configuration_comparison"]["value"]["golden"],
        backend.settings().golden.digest.to_hex()
    );

    // A changed argument in the running process, or a share device added to it, is found
    // again and refused as at launch; the VM is left running and listed.
    let planned = backend.host().processes[&process].command_line.clone();
    let cases: [(Option<(&'static str, &'static str)>, &[&str], bool); 2] =
        [(Some(MORE_MEMORY), &[], false), (None, &NINE_P_SHARE, true)];
    for (replaced, extra, interfaces) in cases {
        backend
            .host_mut()
            .processes
            .get_mut(&process)
            .unwrap()
            .command_line = rewritten(&planned, replaced, extra);
        match backend.reobserve(&vm, &fixture.host.registry) {
            Err(ReobservationRefusal::Refused { refusal }) => assert!(
                matches!(
                    &*refusal,
                    LaunchRefusal::ConfigurationNotApproved { checks, .. }
                        if checks.contains(&ConfigurationCheck::GoldenConfiguration)
                            && checks.contains(&ConfigurationCheck::HostInterfaces) == interfaces
                ),
                "{refusal:?}"
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(backend.running(), vec![vm]);
    }
    backend
        .host_mut()
        .processes
        .get_mut(&process)
        .unwrap()
        .command_line = planned;
    let restored = backend.reobserve(&vm, &fixture.host.registry).unwrap();
    assert_eq!(
        record.assert_current_with(fixture.host.registry.now(), &restored),
        Ok(())
    );
}

// ---- the enums read back (tracker E01Y follow-up, ST1) ----

/// Reads `T` as serde reads a field of an internally tagged enum: buffered.
#[derive(Deserialize)]
#[serde(tag = "wrap", rename_all = "snake_case")]
enum Buffered<T> {
    Inner { value: T },
}

/// The JSON pointer of every string and of every object in `value`.
fn pointers(value: &Value, at: &str, strings: &mut Vec<String>, objects: &mut Vec<String>) {
    match value {
        Value::String(_) => strings.push(at.to_owned()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                pointers(item, &format!("{at}/{index}"), strings, objects);
            }
        }
        Value::Object(fields) => {
            objects.push(at.to_owned());
            for (key, field) in fields {
                let key = key.replace('~', "~0").replace('/', "~1");
                pointers(field, &format!("{at}/{key}"), strings, objects);
            }
        }
        _ => {}
    }
}

/// ST1's table checks on a type read back whose enums are all unit-only: `sample` writes
/// back unchanged; any string in it, each variant name included, swapped for the variant
/// index 0 is refused, read straight from JSON, from a JSON value and buffered as the
/// field of a tagged enum; and a key repeated in any one object is refused.
fn assert_reads_strictly<T: Serialize + DeserializeOwned>(sample: &T) {
    let json = serde_json::to_value(sample).unwrap();
    let reads = |value: &Value| {
        let buffered = serde_json::json!({ "wrap": "inner", "value": value });
        [
            serde_json::from_str::<T>(&value.to_string()).is_ok(),
            serde_json::from_value::<T>(value.clone()).is_ok(),
            serde_json::from_value::<Buffered<T>>(buffered)
                .map(|Buffered::Inner { value }| value)
                .is_ok(),
        ]
    };
    let back: T = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
    assert_eq!(reads(&json), [true; 3], "{json}");
    let (mut strings, mut objects) = (Vec::new(), Vec::new());
    pointers(&json, "", &mut strings, &mut objects);
    assert!(!strings.is_empty(), "{json}");
    for pointer in strings {
        let mut swapped = json.clone();
        if let Some(string) = swapped.pointer_mut(&pointer) {
            *string = Value::from(0);
        }
        assert_eq!(reads(&swapped), [false; 3], "{pointer} of {json}");
    }
    let text = json.to_string();
    for pointer in objects {
        let Some(object) = json.pointer(&pointer) else {
            continue;
        };
        let Some((key, field)) = object.as_object().and_then(|fields| fields.iter().next()) else {
            continue;
        };
        let written = object.to_string();
        let repeated = format!("{{{}:{field},{}", Value::from(key.as_str()), &written[1..]);
        assert!(
            serde_json::from_str::<T>(&text.replacen(&written, &repeated, 1)).is_err(),
            "{pointer} of {json}"
        );
    }
}

#[test]
fn the_enums_read_back_are_unit_only_and_read_strictly() {
    // ST1 converts the internally and adjacently tagged enums read back. Every tagged enum
    // of this module is written only (refusals, findings, port states); the inputs it
    // reads back (the release's golden file and the host's query of the Windows process)
    // hold unit-only enums, whose variant name serde never takes as an index, so none
    // needs converting.
    assert_reads_strictly(&golden_for(&windows()));
    assert_reads_strictly(&golden_for(&linux()));
    let fixture = windows();
    let backend = scripted_backend(&fixture, "whpx");
    let plan = plan_of(&fixture, &backend, &fixture.request);
    let confined = confined_as(plan.windows().unwrap());
    assert_reads_strictly(&confined);
    let unconfined = WindowsObservedState {
        token_restricted: false,
        administrators: GroupState::Enabled,
        job: None,
        ..confined.clone()
    };
    assert_reads_strictly(&unconfined);
    assert_reads_strictly(&WindowsObservedState {
        administrators: GroupState::Absent,
        ..confined
    });
}
