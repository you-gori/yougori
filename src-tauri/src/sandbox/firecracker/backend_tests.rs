//! Backend tests on a scripted host (`scripted.rs`) and a real CORE-01 registry on a
//! manual clock: a launch that succeeds, refusals with the launcher's own cleanup, the
//! precheck before any privileged operation, the launch session's order, stop with the
//! host's proof, reconciliation, jail identities, and the refusals by name.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::backend::{FirecrackerBackend, FirecrackerSettings, JailStop, SettingsError};
use super::fixtures::{self, Scenario};
use super::golden::{ForbiddenItem, GoldenFile, VERSION_KEY};
use super::jail::{CleanupOutcome, Jail, JailEnd, StepError};
use super::jailer::CgroupFile;
use super::launcher::{Authorized, LauncherRefusal, PrivilegedOperation};
use super::linux_state::StateItem;
use super::names::{HostPath, JailIdentity};
use super::plan::{LaunchPlan, PlanInputs, PlanRefusal};
use super::ports::ProcessObservation;
use super::profile::FirecrackerProfile;
use super::refusal::{FirecrackerRefusal, LaunchFailure};
use super::scripted::{Event, Machine, ScriptedApi, ScriptedHost, ScriptedLauncher, FIRST_PID};
use super::status::fixtures::UNJAILED;
use crate::foundation::coordination::{
    SandboxGenerations, SnapshotId, SnapshotManifest, SnapshotOrigin, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidenceRefusal, HypervisorKind, HypervisorSubject,
    Observation, ProbeRegistry, SourceClass, Subject, SupportDetail, UnknownReason,
};
use crate::foundation::ids::{digest, ExecutionId, ManualClock, SandboxBootGeneration};
use crate::foundation::ledger::{Ledger, ReservationId};
use crate::foundation::process::{Ending, IdentityCheck, ProcessIdentity, ProcessRole};
use crate::sandbox::backend::{
    vm_handle, Accelerator, BackendKind, BackendOperation, BackendRefusal, ConfigurationCheck,
    ConfigurationComparison, ConfinementControl, Facet, FactName, FactSource, Feature,
    HostInterfaceListing, LaunchRefusal, LaunchRequest, Launched, LeftBehind, ObservationProblem,
    ReobservationRefusal, StopOutcome, VmBackend, VmProcessState,
};
use crate::sandbox::trust::ComponentVersion;

/// A change to what the host observes about a process.
type Tamper = fn(&mut ProcessObservation);

type Backend =
    FirecrackerBackend<ScriptedLauncher, ScriptedApi, ScriptedHost, Ledger<Arc<ManualClock>>>;

/// The first identity of the fixture host's jail range.
fn first_identity() -> JailIdentity {
    JailIdentity {
        uid: 64000,
        gid: 64000,
    }
}

fn hypervisor() -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: fixtures::machine(),
        hypervisor: HypervisorKind::Kvm,
    })
}

/// The host's CORE-01 registry with one hypervisor probe, on a manual clock.
struct Evidence {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    probe: Arc<FakeProbe>,
}

impl Evidence {
    /// A registry whose probe has not run.
    fn unobserved() -> Self {
        let clock = Arc::new(ManualClock::default());
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::new(
            Capability::HypervisorAvailable,
            SourceClass::HostProbe,
        ));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        Self {
            clock,
            registry,
            probe,
        }
    }

    /// A registry whose probe found KVM available under `configuration`.
    fn kvm(configuration: ConfigurationFingerprint) -> Self {
        let mut evidence = Self::unobserved();
        evidence.observe(configuration);
        evidence
    }

    /// The probe finds KVM available under `configuration` now, fresh for ten minutes.
    fn observe(&mut self, configuration: ConfigurationFingerprint) {
        self.probe.respond(
            &hypervisor(),
            Observation::supported(
                configuration,
                Duration::from_secs(600),
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm,
                },
            ),
        );
        self.registry
            .refresh(Capability::HypervisorAvailable, &hypervisor())
            .unwrap();
    }
}

/// A backend over a scripted host, the request of its fixture scenario and the plan the
/// backend builds for that request.
struct Setup {
    machine: Machine,
    backend: Backend,
    evidence: Evidence,
    request: LaunchRequest,
    plan: LaunchPlan,
}

fn setup_adjusted(
    profile: FirecrackerProfile,
    adjust: impl FnOnce(&mut FirecrackerSettings),
) -> Setup {
    let scenario = Scenario::new(profile);
    let plan = LaunchPlan::build(&PlanInputs {
        identity: first_identity(),
        ..scenario.inputs()
    })
    .unwrap();
    let golden = GoldenFile::parse(&GoldenFile::from_plan(&plan).canonical_text()).unwrap();
    let configuration = scenario.request.configuration;
    let machine = Machine::new(configuration, fixtures::VERSION);
    let (launcher, api, host) = machine.ports();
    let Scenario {
        ledger,
        request,
        profile,
        configuration: pinned,
        host: jail_host,
        ..
    } = scenario;
    let mut settings = FirecrackerSettings {
        profile,
        configuration: pinned,
        host: jail_host,
        golden,
        fresh_for: Duration::from_secs(600),
    };
    adjust(&mut settings);
    let backend = FirecrackerBackend::new(settings, launcher, api, host, ledger).unwrap();
    Setup {
        machine,
        backend,
        evidence: Evidence::kvm(configuration),
        request,
        plan,
    }
}

fn scripted() -> Setup {
    setup_adjusted(fixtures::profile(), |_| {})
}

impl Setup {
    fn launch(&mut self) -> Result<Launched, LaunchFailure> {
        self.backend
            .launch_jailed(&self.request, &self.evidence.registry)
    }

    fn launch_request(&mut self, request: &LaunchRequest) -> Result<Launched, LaunchFailure> {
        self.backend.launch_jailed(request, &self.evidence.registry)
    }

    /// A request of `execution` for boot `boot`, with its own granted reservation.
    fn request_for(&mut self, execution: &str, boot: u64) -> LaunchRequest {
        let execution = ExecutionId::new(execution).unwrap();
        let demand = fixtures::demand(&self.backend.settings().profile);
        let reservation = fixtures::reserve(
            self.backend.reservations_mut(),
            execution.clone(),
            fixtures::tenant(),
            demand,
        );
        LaunchRequest {
            execution,
            generations: SandboxGenerations {
                boot: SandboxBootGeneration::new(boot),
                ..SandboxGenerations::FIRST
            },
            reservation,
            ..self.request.clone()
        }
    }

    /// The plan's cleanup operations, in order.
    fn cleanup_operations(&self) -> Vec<PrivilegedOperation> {
        self.plan
            .launcher()
            .cleanup()
            .iter()
            .map(|step| step.operation.clone())
            .collect()
    }

    /// Launches with `tamper` applied to every process observation; returns the refusal.
    fn refused_with(&mut self, tamper: Tamper) -> LaunchFailure {
        self.machine.script().tamper = Some(tamper);
        self.launch().unwrap_err()
    }
}

fn outcomes(failure: &LaunchFailure) -> Vec<(&'static str, CleanupOutcome)> {
    failure
        .cleanup
        .as_ref()
        .unwrap()
        .steps
        .iter()
        .map(|step| (step.op, step.outcome.clone()))
        .collect()
}

fn all_performed() -> Vec<(&'static str, CleanupOutcome)> {
    [
        "terminate_jail",
        "remove_cgroup",
        "remove_jail",
        "remove_network_namespace",
    ]
    .into_iter()
    .map(|op| (op, CleanupOutcome::Performed))
    .collect()
}

fn failed_items(failure: &LaunchFailure) -> Vec<StateItem> {
    let FirecrackerRefusal::StateDiffers { report } = &failure.refusal else {
        panic!("not a VM-CP-04 refusal: {failure}");
    };
    report.failed().iter().map(|check| check.item).collect()
}

#[test]
fn a_scripted_host_where_everything_succeeds_seals_a_record_with_kvm_observed() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    let request = setup.request.clone();
    let vm = vm_handle(
        BackendKind::Firecracker,
        &request.execution,
        request.generations.boot,
    );
    assert_eq!(launched.vm, vm);
    let record = &launched.record;
    assert_eq!(record.vm(), vm);
    assert_eq!(record.backend(), setup.backend.identity());
    assert_eq!(record.backend().kind, BackendKind::Firecracker);
    assert_eq!(record.backend().hypervisor, HypervisorKind::Kvm);
    assert_eq!(
        *record.accelerator().value(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Kvm
        }
    );
    assert_eq!(record.accelerator().source(), FactSource::HostObserved);
    let observed = record.host_observed();
    assert_eq!(
        observed.confinement.value(),
        Some(&ConfinementControl::all())
    );
    assert_eq!(
        observed.guest_image.value(),
        Some(&request.pinned.guest_image)
    );
    assert!(record.checks().iter().all(|check| check.is_satisfied()));
    assert!(record
        .fact_sources()
        .iter()
        .all(|(_, source)| source.is_host()));

    // The launcher saw exactly the plan's setup, in order, each as the step the session
    // authorized; the API saw exactly the plan's sequence over the jail's own socket.
    let setup_operations = setup.plan.launcher().setup().to_vec();
    assert_eq!(setup.machine.operations(), setup_operations);
    let steps: Vec<Authorized> = setup
        .machine
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Launcher { step, jail, .. } => {
                assert_eq!(&jail, setup.plan.jail_id());
                Some(step)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        steps,
        (0..setup_operations.len())
            .map(|step| Authorized::Setup { step })
            .collect::<Vec<_>>()
    );
    let calls: Vec<String> = setup
        .plan
        .api()
        .calls()
        .into_iter()
        .map(|call| call.path)
        .collect();
    assert_eq!(setup.machine.api_paths(), calls);
    let socket = format!(
        "{}/run/firecracker.socket",
        setup.plan.jailer().chroot_dir().unwrap()
    );
    for event in setup.machine.events() {
        if let Event::Api { socket: used, .. } | Event::Describe { socket: used } = event {
            assert_eq!(used.as_str(), socket);
        }
    }

    // The handle is bound to the jail and the process's identity.
    let process = setup.machine.alive()[0];
    assert_eq!(process.pid, FIRST_PID);
    let bound = setup.backend.bound(&vm).unwrap();
    assert_eq!(bound.jail, *setup.plan.jail_id());
    assert_eq!(bound.identity, first_identity());
    assert_eq!(bound.process, process);
    assert_eq!(
        bound.role,
        ProcessRole::VmHost {
            execution: request.execution.clone(),
            vm,
            boot: request.generations.boot,
        }
    );
    assert_eq!(setup.backend.running(), vec![vm]);
    assert_eq!(
        setup.backend.actual_accelerator(&vm).unwrap(),
        *record.accelerator()
    );
    assert_eq!(setup.backend.confinement_evidence(&vm).unwrap(), *observed);

    // A repeated launch of the running boot is the same object and does nothing.
    setup.machine.forget_events();
    assert_eq!(setup.launch().unwrap(), launched);
    assert_eq!(
        VmBackend::launch(&mut setup.backend, &request, &setup.evidence.registry).unwrap(),
        launched
    );
    assert!(setup.machine.events().is_empty());
    assert!(setup.backend.uncleaned().is_empty());
}

#[test]
fn an_api_refusal_mid_sequence_cleans_up_only_what_this_launch_created() {
    let mut setup = scripted();
    let other_request = setup.request_for("exe-fc-2", 1);
    let other = setup.launch_request(&other_request).unwrap();
    let other_process = setup.backend.bound(&other.vm).unwrap().process;
    let other_cgroups = setup.machine.cgroups();
    setup.machine.forget_events();

    setup.machine.script().refuse_path = Some("/boot-source".to_owned());
    let failure = setup.launch().unwrap_err();
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::ApiRefused {
            path: "/boot-source".to_owned(),
            status: 400,
            fault_message: Some("scripted refusal".to_owned()),
        }
    );
    // Nothing after the refused call was sent.
    assert_eq!(
        setup.machine.api_paths(),
        ["/logger", "/metrics", "/machine-config", "/boot-source"]
    );
    // After its setup, the launcher performed exactly this launch's cleanup, in order.
    let operations = setup.machine.operations();
    let setup_count = setup.plan.launcher().setup().len();
    assert_eq!(operations[setup_count..], setup.cleanup_operations()[..]);
    let cleanup_steps: Vec<Authorized> = setup.machine.events()[..]
        .iter()
        .filter_map(|event| match event {
            Event::Launcher { step, .. } => Some(*step),
            _ => None,
        })
        .skip(setup_count)
        .collect();
    assert_eq!(
        cleanup_steps,
        (0..4)
            .map(|step| Authorized::Cleanup { step })
            .collect::<Vec<_>>()
    );
    let report = failure.cleanup.as_ref().unwrap();
    assert!(report.complete());
    assert_eq!(outcomes(&failure), all_performed());
    let proof = report.proof().unwrap();
    assert_eq!(proof.jail(), setup.plan.jail_id());
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    assert_eq!(proof.found(), Some(IdentityCheck::Gone));
    assert_eq!(proof.source(), SourceClass::HostProbe);
    assert_ne!(proof.process(), Some(other_process));

    // The other launch's jail is untouched.
    assert_eq!(setup.machine.alive(), vec![other_process]);
    assert_eq!(setup.machine.cgroups(), other_cgroups);
    assert_eq!(setup.backend.running(), vec![other.vm]);
    assert!(setup.backend.uncleaned().is_empty());

    // Through the contract, the refusal is stated as Firecracker's own; nothing is left,
    // so the same boot may be launched again.
    let LaunchRefusal::BackendSpecific {
        backend: BackendKind::Firecracker,
        detail,
    } = failure.to_launch_refusal()
    else {
        panic!("not stated as a Firecracker refusal");
    };
    assert!(detail.contains("Firecracker refused /boot-source with status 400"));
    assert!(failure
        .to_string()
        .ends_with("everything the launch created was removed"));
    setup.machine.script().refuse_path = None;
    assert!(setup.launch().is_ok());
}

#[test]
fn a_launcher_failure_before_the_jailer_removes_only_the_jail_and_its_namespace() {
    let mut setup = scripted();
    setup.machine.script().fail_op = Some("stage_artifact");
    let failure = setup.launch().unwrap_err();
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::LauncherFailed {
            op: "stage_artifact",
            detail: "scripted failure of stage_artifact".to_owned(),
        }
    );
    assert_eq!(
        setup.machine.operation_tags(),
        [
            "create_network_namespace",
            "create_directory",
            "create_directory",
            "stage_artifact",
            "remove_jail",
            "remove_network_namespace",
        ]
    );
    assert_eq!(
        outcomes(&failure),
        [
            ("terminate_jail", CleanupOutcome::NotCreated),
            ("remove_cgroup", CleanupOutcome::NotCreated),
            ("remove_jail", CleanupOutcome::Performed),
            ("remove_network_namespace", CleanupOutcome::Performed),
        ]
    );
    let report = failure.cleanup.as_ref().unwrap();
    assert_eq!(report.end, JailEnd::NothingStarted);
    assert!(report.complete());
    assert!(setup.machine.api_paths().is_empty());
    assert!(setup.machine.namespaces().is_empty());
}

#[test]
fn a_staged_copy_that_is_not_the_pinned_artifact_is_refused() {
    let mut setup = scripted();
    let other = crate::foundation::ids::ContentKey::of(b"another root image");
    setup.machine.script().staged_root_image = Some(other);
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::StagedArtifactDiffers { role, staged, .. } = &failure.refusal else {
        panic!("not a staging refusal: {failure}");
    };
    assert_eq!(*role, super::launcher::ArtifactRole::RootImage);
    assert_eq!(*staged, other);
    assert!(!setup.machine.operation_tags().contains(&"run_jailer"));
    assert!(failure.nothing_left());
}

#[test]
fn a_failed_jailer_is_ended_through_its_cgroup_and_removed() {
    let mut setup = scripted();
    setup.machine.script().jailer_code = 1;
    let failure = setup.launch().unwrap_err();
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::JailerFailed { code: 1 }
    );
    assert_eq!(outcomes(&failure), all_performed());
    let proof = failure.cleanup.as_ref().unwrap().proof().unwrap();
    assert_eq!(proof.process(), None);
    assert!(setup.machine.cgroups().is_empty());
    assert!(setup.machine.api_paths().is_empty());
}

#[test]
fn a_jail_cgroup_without_exactly_one_process_is_refused() {
    let mut setup = scripted();
    setup.machine.script().second_process = true;
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::JailProcesses { found } = &failure.refusal else {
        panic!("not a process count refusal: {failure}");
    };
    assert_eq!(found.len(), 2);
    assert!(setup.machine.alive().is_empty());
    assert!(failure.nothing_left());
    assert!(setup.machine.api_paths().is_empty());
}

#[test]
fn an_unjailed_process_is_refused_with_every_difference_and_cleaned_up() {
    let mut setup = scripted();
    let failure = setup.refused_with(|observation| {
        observation.status = UNJAILED.to_owned();
        observation.network_interfaces = ["lo", "eth0", "wlan0"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        observation.cgroup = "0::/user.slice/user-1000.slice/session-2.scope\n".to_owned();
        observation.cgroup_files = [("memory.max".to_owned(), "max".to_owned())]
            .into_iter()
            .collect();
        observation
            .descriptors
            .extend((0..400).map(|index| format!("socket:[{index}]")));
    });
    assert_eq!(
        failed_items(&failure),
        [
            StateItem::Uid,
            StateItem::Gid,
            StateItem::Capabilities,
            StateItem::NoNewPrivs,
            StateItem::Seccomp,
            StateItem::PidNamespace,
            StateItem::NetworkInterfaces,
            StateItem::Cgroup,
            StateItem::CgroupLimit {
                file: CgroupFile::CpuMax
            },
            StateItem::CgroupLimit {
                file: CgroupFile::MemoryMax
            },
            StateItem::CgroupLimit {
                file: CgroupFile::PidsMax
            },
            StateItem::OpenDescriptors,
        ]
    );
    assert_eq!(outcomes(&failure), all_performed());
    assert!(setup.backend.running().is_empty());
    let LaunchRefusal::ConfinementNotInEffect {
        backend: BackendKind::Firecracker,
        observed: true,
        findings,
    } = failure.to_launch_refusal()
    else {
        panic!("not stated as confinement not in effect");
    };
    assert!(findings
        .iter()
        .any(|finding| finding.contains("seccomp mode: expected 2, observed 0 (fail)")));
}

#[test]
fn a_wrongly_confined_process_is_refused_by_the_item_that_differs() {
    let cases: [(Tamper, StateItem); 5] = [
        (
            |observation| {
                observation.status = observation.status.replace("Seccomp:\t2", "Seccomp:\t0");
            },
            StateItem::Seccomp,
        ),
        (
            |observation| {
                observation.status = observation
                    .status
                    .replace("NoNewPrivs:\t1", "NoNewPrivs:\t0");
            },
            StateItem::NoNewPrivs,
        ),
        (
            |observation| {
                observation.network_interfaces.insert("eth0".to_owned());
            },
            StateItem::NetworkInterfaces,
        ),
        (
            |observation| {
                observation.cgroup_files.remove("memory.max");
            },
            StateItem::CgroupLimit {
                file: CgroupFile::MemoryMax,
            },
        ),
        (
            |observation| {
                observation
                    .descriptors
                    .extend((0..200).map(|index| format!("socket:[{index}]")));
            },
            StateItem::OpenDescriptors,
        ),
    ];
    for (tamper, item) in cases {
        let mut setup = scripted();
        let failure = setup.refused_with(tamper);
        assert_eq!(failed_items(&failure), [item]);
        assert_eq!(outcomes(&failure), all_performed());
    }

    let mut setup = scripted();
    let failure = setup.refused_with(|observation| observation.root = "/".to_owned());
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::NotChrooted {
            expected: setup.plan.jailer().chroot_dir().unwrap(),
            observed: "/".to_owned(),
        }
    );
    assert!(failure.nothing_left());

    let mut setup = scripted();
    let failure = setup.refused_with(|observation| {
        observation.status = observation.status.replace("Pid:\t48211", "Pid:\t1");
    });
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::StatusOfAnotherProcess {
            process: ProcessIdentity {
                pid: FIRST_PID,
                start_time_ticks: 900_000 + u64::from(FIRST_PID),
            },
            pid: 1,
        }
    );

    let mut setup = scripted();
    let failure = setup.refused_with(|observation| {
        observation.cgroup = "0::/a\n1:cpu:/b\n".to_owned();
    });
    assert!(matches!(
        failure.refusal,
        FirecrackerRefusal::CgroupUnreadable { .. }
    ));

    let mut setup = scripted();
    let failure = setup.refused_with(|observation| observation.status.push_str("Pid:\t9\n"));
    assert!(matches!(
        failure.refusal,
        FirecrackerRefusal::StatusUnreadable { .. }
    ));
    assert!(failure.nothing_left());
}

#[test]
fn without_a_kvm_vm_descriptor_the_accelerator_is_not_observed_and_nothing_is_emulated() {
    let mut setup = scripted();
    setup.machine.script().kvm = false;
    let failure = setup.launch().unwrap_err();
    let expected = LaunchRefusal::AcceleratorNotObserved {
        reason: UnknownReason::Inconclusive,
    };
    assert_eq!(
        failure.refusal,
        FirecrackerRefusal::Admission {
            refusal: expected.clone()
        }
    );
    assert_eq!(outcomes(&failure), all_performed());
    assert_eq!(failure.to_launch_refusal(), expected);
    assert!(setup.backend.running().is_empty());
}

#[test]
fn a_running_configuration_other_than_the_golden_file_is_refused() {
    let mut setup = scripted();
    setup.machine.script().vmm_version = "1.10.0".to_owned();
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::ConfigurationNotGolden { check } = &failure.refusal else {
        panic!("not a golden refusal: {failure}");
    };
    assert_eq!(check.diff.changed.len(), 1);
    assert_eq!(check.diff.changed[0].key, VERSION_KEY);
    assert!(failure.nothing_left());

    let mut setup = scripted();
    setup.machine.script().rewrite = Some(|call| {
        if call.path == "/machine-config" {
            call.body["smt"] = true.into();
        }
    });
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::ConfigurationNotGolden { check } = &failure.refusal else {
        panic!("not a golden refusal: {failure}");
    };
    assert_eq!(check.diff.changed[0].key, "PUT /machine-config /smt");
    assert!(failure.nothing_left());

    let mut setup = scripted();
    setup.machine.script().rewrite = Some(|call| {
        if call.path == "/boot-source" {
            call.body["boot_args"] = "console=ttyS0 reboot=k".into();
        }
    });
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::ConfigurationNotGolden { check } = &failure.refusal else {
        panic!("not a golden refusal: {failure}");
    };
    assert!(check
        .forbidden
        .contains(&super::golden::ForbiddenItem::Console));

    let mut setup = scripted();
    setup.machine.script().instance_state = "Not started".to_owned();
    let failure = setup.launch().unwrap_err();
    assert!(matches!(
        &failure.refusal,
        FirecrackerRefusal::InstanceMismatch { expected_id, .. } if expected_id == setup.plan.jail_id()
    ));
    assert!(failure.nothing_left());
}

#[test]
fn a_matching_golden_file_seals_the_configuration_facts_in_the_record() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    let record = &launched.record;
    let now = setup.evidence.registry.now();

    // VM-CP-02: the running configuration is the golden file's, so both digests are the
    // golden file's, and it has none of the devices the row names.
    let golden = setup.backend.settings().golden.digest();
    assert_eq!(golden, GoldenFile::from_plan(&setup.plan).digest());
    let comparison = record.configuration_comparison().unwrap();
    assert_eq!(
        *comparison.value(),
        ConfigurationComparison {
            golden,
            observed: golden,
            network_device: false,
            console: false,
            balloon: false,
            undeclared_pci_transport: false,
        }
    );
    // VM-CP-03: the API socket in the jail's socket directory, no share device, listener
    // or port forward.
    let listing = record.interface_listing().unwrap();
    assert_eq!(*listing.value(), HostInterfaceListing::clean());
    assert!(record.gpu_assignments().is_empty());

    // Both are the host's own observations, made with the launch facts under the
    // request's configuration, and current while the record is.
    for (source, clock, observed_at, fresh_for, configuration) in [
        (
            comparison.source(),
            comparison.clock(),
            comparison.observed_at(),
            comparison.fresh_for(),
            comparison.configuration(),
        ),
        (
            listing.source(),
            listing.clock(),
            listing.observed_at(),
            listing.fresh_for(),
            listing.configuration(),
        ),
    ] {
        assert_eq!(source, FactSource::HostObserved);
        assert_eq!(clock, record.clock());
        assert_eq!(observed_at, record.accelerator().observed_at());
        assert_eq!(fresh_for, setup.backend.settings().fresh_for);
        assert_eq!(configuration, setup.request.configuration);
    }
    assert_eq!(record.assert_current(now), Ok(()));
}

#[test]
fn an_extra_device_or_a_listener_in_the_running_configuration_is_refused_and_seals_nothing() {
    type Rewrite = fn(&mut super::api::ApiCall);
    // An extra device in place of the entropy device, or a listener: the metadata
    // service, or the link's vsock socket moved out of the jail's socket directory.
    let cases: [(Rewrite, &str, Option<ForbiddenItem>); 4] = [
        (
            |call| {
                if call.path == "/entropy" {
                    call.path = "/balloon".to_owned();
                    call.body = serde_json::json!({ "amount_mib": 0, "deflate_on_oom": false });
                }
            },
            "PUT /balloon /amount_mib",
            Some(ForbiddenItem::Balloon),
        ),
        (
            |call| {
                if call.path == "/entropy" {
                    call.path = "/network-interfaces/eth0".to_owned();
                    call.body = serde_json::json!({ "iface_id": "eth0", "host_dev_name": "tap0" });
                }
            },
            "PUT /network-interfaces/eth0 /iface_id",
            Some(ForbiddenItem::UndeclaredNetworkInterface {
                iface_id: "eth0".to_owned(),
            }),
        ),
        (
            |call| {
                if call.path == "/entropy" {
                    call.path = "/mmds/config".to_owned();
                    call.body = serde_json::json!({ "network_interfaces": ["eth0"] });
                }
            },
            "PUT /mmds/config /network_interfaces/0",
            Some(ForbiddenItem::MetadataService),
        ),
        (
            |call| {
                if call.path == "/vsock" {
                    call.body["uds_path"] = "/tmp/link.sock".into();
                }
            },
            "PUT /vsock /uds_path",
            None,
        ),
    ];
    for (rewrite, key, item) in cases {
        let mut setup = scripted();
        setup.machine.script().rewrite = Some(rewrite);
        let failure = setup.launch().unwrap_err();
        let FirecrackerRefusal::ConfigurationNotGolden { check } = &failure.refusal else {
            panic!("not a golden refusal: {failure}");
        };
        let reported = check
            .diff
            .unexpected
            .iter()
            .map(|entry| entry.key.as_str())
            .chain(check.diff.changed.iter().map(|entry| entry.key.as_str()));
        assert!(reported.into_iter().any(|found| found == key), "{key}");
        assert_eq!(check.forbidden.iter().next(), item.as_ref(), "{key}");
        assert!(matches!(
            failure.to_launch_refusal(),
            LaunchRefusal::ConfigurationNotApproved { checks, .. }
                if checks == BTreeSet::from([ConfigurationCheck::GoldenConfiguration])
        ));
        // Nothing was admitted: the jail is removed and no VM runs.
        assert_eq!(outcomes(&failure), all_performed(), "{key}");
        assert!(setup.backend.running().is_empty());
        assert!(setup.backend.bound(&failure.vm).is_none());
    }
}

#[test]
fn a_precheck_or_plan_refusal_performs_no_privileged_operation() {
    // No hypervisor evidence: the contract's precheck refuses.
    let mut setup = scripted();
    setup.evidence = Evidence::unobserved();
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::Admission {
        refusal: LaunchRefusal::Evidence { refusal },
    } = &failure.refusal
    else {
        panic!("not an evidence refusal: {failure}");
    };
    assert!(matches!(refusal, EvidenceRefusal::Missing { .. }));
    assert_eq!(failure.cleanup, None);
    assert!(failure.nothing_left());
    assert!(setup.machine.events().is_empty());

    // A device the backend does not offer is refused by name.
    let mut request = setup.request.clone();
    request.device_profile.devices.display = true;
    setup.evidence = Evidence::kvm(setup.request.configuration);
    let failure = setup.launch_request(&request).unwrap_err();
    assert_eq!(
        failure.to_launch_refusal(),
        LaunchRefusal::Unsupported {
            feature: Feature::Display
        }
    );

    // An unknown reservation, and one too small for the plan.
    let mut unknown = setup.request.clone();
    unknown.reservation = serde_json::from_value::<ReservationId>(999.into()).unwrap();
    assert_eq!(
        setup.launch_request(&unknown).unwrap_err().refusal,
        FirecrackerRefusal::ReservationUnknown {
            reservation: unknown.reservation
        }
    );
    let mut small = setup.request.clone();
    small.reservation = fixtures::reserve(
        setup.backend.reservations_mut(),
        fixtures::execution(),
        fixtures::tenant(),
        crate::foundation::ledger::Amounts::new().host_ram_bytes(1 << 20),
    );
    assert!(matches!(
        setup.launch_request(&small).unwrap_err().refusal,
        FirecrackerRefusal::Plan {
            refusal: PlanRefusal::Reservation { .. }
        }
    ));

    // A plan that is not the approved golden file's.
    let network_golden = GoldenFile::from_plan(&fixtures::network_plan());
    let mut other = setup_adjusted(fixtures::profile(), |settings| {
        settings.golden = network_golden;
    });
    let failure = other.launch().unwrap_err();
    let FirecrackerRefusal::PlanNotGolden { check } = &failure.refusal else {
        panic!("not a golden refusal: {failure}");
    };
    assert!(!check.diff.missing.is_empty());
    assert!(other.machine.events().is_empty());
    assert!(setup.machine.events().is_empty());
}

#[test]
fn an_operation_out_of_order_is_refused_by_the_session_and_never_reaches_the_launcher() {
    let plan = fixtures::plan();
    let machine = Machine::new(
        fixtures::configuration().fingerprint().unwrap(),
        fixtures::VERSION,
    );
    let (mut launcher, _, _) = machine.ports();
    let role = ProcessRole::VmHost {
        execution: fixtures::execution(),
        vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm"])),
        boot: SandboxBootGeneration::FIRST,
    };
    let mut jail = Jail::new(
        &plan,
        fixtures::identity(),
        role,
        HostPath::new("/sys/fs/cgroup/yougori/firecracker/x").unwrap(),
    );
    let setup = plan.launcher().setup();
    let cleanup: Vec<PrivilegedOperation> = plan
        .launcher()
        .cleanup()
        .iter()
        .map(|step| step.operation.clone())
        .collect();
    assert_eq!(
        jail.perform(&mut launcher, &setup[9]),
        Err(StepError::Refused(LauncherRefusal::OutOfOrder {
            op: "run_jailer",
            expected: "create_network_namespace",
        }))
    );
    assert_eq!(
        jail.perform(&mut launcher, &cleanup[0]),
        Err(StepError::Refused(LauncherRefusal::NothingCreated {
            op: "terminate_jail"
        }))
    );
    assert!(machine.events().is_empty());

    assert!(jail.perform(&mut launcher, &setup[0]).is_ok());
    assert_eq!(
        jail.perform(&mut launcher, &setup[0]),
        Err(StepError::Refused(LauncherRefusal::AlreadyPerformed {
            op: "create_network_namespace"
        }))
    );
    let elsewhere = PrivilegedOperation::RemoveJail {
        jail_dir: HostPath::new("/srv/jailer").unwrap(),
    };
    assert_eq!(
        jail.perform(&mut launcher, &elsewhere),
        Err(StepError::Refused(LauncherRefusal::NotPlanned {
            op: "remove_jail"
        }))
    );
    assert_eq!(
        jail.perform(&mut launcher, &setup[2]),
        Err(StepError::Refused(LauncherRefusal::OutOfOrder {
            op: "create_directory",
            expected: "create_directory",
        }))
    );
    assert_eq!(machine.operations(), vec![setup[0].clone()]);
}

#[test]
fn stop_kills_through_the_launchs_own_cgroup_ends_on_the_hosts_proof_and_is_idempotent() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    let vm = launched.vm;
    let bound = setup.backend.bound(&vm).unwrap();
    setup.machine.forget_events();

    assert_eq!(setup.backend.stop(&vm), Ok(StopOutcome::Stopped));
    let cleanup = setup.cleanup_operations();
    assert_eq!(setup.machine.operations(), cleanup);
    let PrivilegedOperation::TerminateJail { cgroup } = &cleanup[0] else {
        panic!("the first cleanup step kills the jail");
    };
    assert_eq!(
        cgroup.as_str(),
        format!(
            "/sys/fs/cgroup/yougori/firecracker/{}",
            setup.plan.jail_id()
        )
    );
    let proof = setup.backend.termination_proof(&vm).unwrap();
    assert_eq!(proof.process(), Some(bound.process));
    assert_eq!(proof.role(), &bound.role);
    assert_eq!(proof.jail(), &bound.jail);
    assert_eq!(proof.cgroup(), cgroup);
    assert_eq!(proof.ending(), Ending::Killed { rounds: 1 });
    assert_eq!(proof.found(), Some(IdentityCheck::Gone));
    assert_eq!(proof.source(), SourceClass::HostProbe);
    assert!(setup.backend.running().is_empty());
    assert!(setup.backend.bound(&vm).is_none());
    assert!(setup.machine.cgroups().is_empty());
    assert!(setup.machine.namespaces().is_empty());
    assert!(setup.backend.uncleaned().is_empty());

    // Stopping again, or a handle the backend never had, is already gone.
    setup.machine.forget_events();
    assert_eq!(setup.backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
    let unknown = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"unknown"]));
    assert_eq!(setup.backend.stop(&unknown), Ok(StopOutcome::AlreadyGone));
    assert!(setup.machine.events().is_empty());
    assert_eq!(
        setup.backend.actual_accelerator(&vm),
        Err(BackendRefusal::NoSuchVm { vm })
    );
    assert_eq!(
        setup.backend.confinement_evidence(&vm),
        Err(BackendRefusal::NoSuchVm { vm })
    );

    // The boot generation was used; launching it again is refused before anything.
    let failure = setup.launch().unwrap_err();
    assert!(matches!(
        failure.to_launch_refusal(),
        LaunchRefusal::BootGenerationUsed { .. }
    ));
    assert!(setup.machine.events().is_empty());
}

#[test]
fn a_stop_without_an_observed_end_removes_nothing_and_never_kills_twice() {
    let mut setup = scripted();
    setup.machine.script().survive_kill = true;
    let launched = setup.launch().unwrap();
    let vm = launched.vm;
    let process = setup.backend.bound(&vm).unwrap().process;
    setup.machine.forget_events();

    let Err(BackendRefusal::Failed { operation, detail }) = setup.backend.stop(&vm) else {
        panic!("a stop without the host's proof fails");
    };
    assert_eq!(operation, BackendOperation::Stop);
    assert_eq!(detail, "a process is still in the jail's cgroup");
    assert_eq!(setup.machine.operation_tags(), ["terminate_jail"]);
    assert_eq!(setup.backend.running(), vec![vm]);
    assert!(setup.backend.termination_proof(&vm).is_none());
    let JailStop::NotStopped { cleanup } = setup.backend.stop_jail(&vm) else {
        panic!("still not stopped");
    };
    assert_eq!(
        cleanup
            .steps
            .iter()
            .map(|step| step.outcome.clone())
            .collect::<Vec<_>>(),
        [
            CleanupOutcome::Performed,
            CleanupOutcome::Withheld,
            CleanupOutcome::Withheld,
            CleanupOutcome::Withheld,
        ]
    );

    // Once the process ends, the next stop observes it and removes, without a second kill.
    setup.machine.end_process(process, false);
    setup.machine.forget_events();
    assert_eq!(setup.backend.stop(&vm), Ok(StopOutcome::Stopped));
    assert_eq!(
        setup.machine.operation_tags(),
        ["remove_cgroup", "remove_jail", "remove_network_namespace"]
    );
    assert_eq!(
        setup.backend.termination_proof(&vm).unwrap().ending(),
        Ending::Killed { rounds: 1 }
    );
}

#[test]
fn running_reconciles_with_the_host_and_a_reused_pid_is_never_signalled() {
    let mut setup = scripted();
    let first = setup.launch().unwrap().vm;
    let second_request = setup.request_for("exe-fc-2", 1);
    let second = setup.launch_request(&second_request).unwrap().vm;
    let first_process = setup.backend.bound(&first).unwrap().process;
    let second_binding = setup.backend.bound(&second).unwrap();
    assert_eq!(
        second_binding.identity,
        JailIdentity {
            uid: 64001,
            gid: 64001
        }
    );
    assert_eq!(
        setup.backend.running().into_iter().collect::<BTreeSet<_>>(),
        [first, second].into_iter().collect()
    );

    // The first VM's process ends on its own and another process takes its PID.
    setup.machine.end_process(first_process, true);
    assert_eq!(setup.backend.running(), vec![second]);
    setup.machine.forget_events();
    assert_eq!(setup.backend.reconcile(), vec![first]);
    assert_eq!(
        setup.machine.operation_tags(),
        ["remove_cgroup", "remove_jail", "remove_network_namespace"]
    );
    let proof = setup.backend.termination_proof(&first).unwrap();
    assert_eq!(proof.ending(), Ending::Exited);
    assert_eq!(proof.found(), Some(IdentityCheck::Reused));
    assert_eq!(setup.backend.running(), vec![second]);
    assert_eq!(setup.backend.bound(&second), Some(second_binding));
    assert_eq!(setup.backend.stop(&first), Ok(StopOutcome::AlreadyGone));

    // Nothing ended: reconciling does nothing.
    setup.machine.forget_events();
    assert!(setup.backend.reconcile().is_empty());
    assert!(setup.machine.events().is_empty());
}

#[test]
fn an_unobservable_jail_is_listed_kept_and_cleaned_up_once_the_host_sees_its_end() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    setup.machine.script().observation_failure = Some("procfs unreadable".to_owned());
    assert_eq!(setup.backend.running(), vec![launched.vm]);
    assert!(setup.backend.reconcile().is_empty());

    // A refused launch whose end cannot be observed keeps its jail, names and identity.
    let request = setup.request_for("exe-fc-3", 1);
    setup.machine.script().observation_failure = None;
    setup.machine.script().refuse_path = Some("/vsock".to_owned());
    setup.machine.script().survive_kill = true;
    let failure = setup.launch_request(&request).unwrap_err();
    assert!(!failure.nothing_left());
    assert_eq!(
        outcomes(&failure),
        [
            ("terminate_jail", CleanupOutcome::Performed),
            ("remove_cgroup", CleanupOutcome::Withheld),
            ("remove_jail", CleanupOutcome::Withheld),
            ("remove_network_namespace", CleanupOutcome::Withheld),
        ]
    );
    // The contract hears what may remain: the process and every withheld removal.
    let vm = vm_handle(
        BackendKind::Firecracker,
        &request.execution,
        request.generations.boot,
    );
    let stated = failure.to_launch_refusal();
    let LaunchRefusal::CleanupIncomplete {
        vm: left_vm,
        refusal,
        left,
    } = &stated
    else {
        panic!("not stated as an incomplete cleanup: {stated:?}");
    };
    assert_eq!(*left_vm, vm);
    assert!(matches!(
        **refusal,
        LaunchRefusal::BackendSpecific {
            backend: BackendKind::Firecracker,
            ..
        }
    ));
    assert_eq!(
        left[0],
        LeftBehind::Process {
            detail: "a process is still in the jail's cgroup".to_owned()
        }
    );
    assert_eq!(
        left[1..]
            .iter()
            .map(|item| match item {
                LeftBehind::HostResource { step, .. } => step.as_str(),
                LeftBehind::Process { .. } => "process",
            })
            .collect::<Vec<_>>(),
        ["remove_cgroup", "remove_jail", "remove_network_namespace"]
    );
    assert_eq!(setup.backend.uncleaned().len(), 1);
    // The refused launch's VM stays listed while its process may run; it is not observed
    // again as a launch.
    assert!(setup.backend.running().contains(&vm));
    assert_eq!(
        setup.backend.reobserve(&vm, &setup.evidence.registry),
        Err(ReobservationRefusal::NotAdmitted { vm })
    );
    setup.machine.forget_events();
    assert!(matches!(
        setup.launch_request(&request).unwrap_err().refusal,
        FirecrackerRefusal::JailNotCleanedUp { .. }
    ));
    assert!(setup.machine.events().is_empty());

    // Once its process is gone, reconciliation performs the withheld removals.
    for process in setup.machine.alive() {
        if Some(process) != setup.backend.bound(&launched.vm).map(|bound| bound.process) {
            setup.machine.end_process(process, false);
        }
    }
    assert!(setup.backend.reconcile().is_empty());
    assert_eq!(
        setup.machine.operation_tags(),
        ["remove_cgroup", "remove_jail", "remove_network_namespace"]
    );
    assert!(setup.backend.uncleaned().is_empty());
    setup.machine.script().refuse_path = None;
    setup.machine.script().survive_kill = false;
    assert!(setup.launch_request(&request).is_ok());
}

#[test]
fn a_failed_removal_keeps_the_jail_identity_held() {
    let mut setup = scripted();
    setup.machine.script().refuse_path = Some("/vsock".to_owned());
    setup.machine.script().fail_op = Some("remove_jail");
    let failure = setup.launch().unwrap_err();
    assert_eq!(
        outcomes(&failure)[2],
        (
            "remove_jail",
            CleanupOutcome::Failed {
                detail: "scripted failure of remove_jail".to_owned()
            }
        )
    );
    assert_eq!(
        outcomes(&failure)[3],
        ("remove_network_namespace", CleanupOutcome::Performed)
    );
    assert!(failure
        .to_string()
        .ends_with("cleanup is incomplete; remove_jail not done"));
    assert_eq!(
        setup.backend.uncleaned(),
        vec![setup.plan.jail_id().clone()]
    );

    // The failed removal is never sent again, and its jail identity stays held.
    setup.machine.script().refuse_path = None;
    setup.machine.script().fail_op = None;
    setup.machine.forget_events();
    assert!(setup.backend.reconcile().is_empty());
    assert!(setup.machine.events().is_empty());
    let request = setup.request_for("exe-fc-2", 1);
    let launched = setup.launch_request(&request).unwrap();
    assert_eq!(
        setup.backend.bound(&launched.vm).unwrap().identity,
        JailIdentity {
            uid: 64001,
            gid: 64001
        }
    );
}

#[test]
fn jail_identities_come_from_the_hosts_range_and_return_after_a_stop() {
    let mut setup = setup_adjusted(fixtures::profile(), |settings| {
        settings.host.jail_ids.count = 1;
    });
    let launched = setup.launch().unwrap();
    let request = setup.request_for("exe-fc-2", 1);
    setup.machine.forget_events();
    let failure = setup.launch_request(&request).unwrap_err();
    assert!(matches!(
        failure.refusal,
        FirecrackerRefusal::NoJailIdentity { .. }
    ));
    assert!(setup.machine.events().is_empty());
    assert_eq!(setup.backend.stop(&launched.vm), Ok(StopOutcome::Stopped));
    let second = setup.launch_request(&request).unwrap();
    assert_eq!(
        setup.backend.bound(&second.vm).unwrap().identity,
        first_identity()
    );
}

#[test]
fn a_declared_interface_is_refused_until_the_host_shows_which_channels_it_enforces() {
    let mut setup = setup_adjusted(fixtures::network_profile(), |_| {});
    let failure = setup.launch().unwrap_err();
    let FirecrackerRefusal::Admission {
        refusal: refusal @ LaunchRefusal::PropertiesNotSatisfied { .. },
    } = &failure.refusal
    else {
        panic!("not a properties refusal: {failure}");
    };
    let failed: Vec<Facet> = refusal
        .failed_checks()
        .iter()
        .map(|check| check.facet())
        .collect();
    assert_eq!(failed, [Facet::NetworkAuthority]);
    assert!(setup
        .machine
        .operation_tags()
        .contains(&"create_tap_device"));
    assert!(failure.nothing_left());
    assert!(setup.machine.namespaces().is_empty());
}

#[test]
fn a_host_configuration_changed_since_the_request_is_refused() {
    let mut setup = scripted();
    setup.machine.script().configuration =
        ConfigurationFingerprint::from_settings([("kvm", "changed")]).unwrap();
    let failure = setup.launch().unwrap_err();
    assert!(matches!(
        failure.refusal,
        FirecrackerRefusal::Admission {
            refusal: LaunchRefusal::ObservationNotCurrent {
                fact: FactName::Accelerator,
                problem: ObservationProblem::OtherConfiguration { .. },
            }
        }
    ));
    assert!(failure.nothing_left());
}

#[test]
fn snapshots_and_restores_are_refused_by_name() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    let request = setup.request_for("exe-fc-2", 1);
    setup.machine.forget_events();
    assert!(setup.backend.features().supported.is_empty());
    assert_eq!(
        setup
            .backend
            .snapshot(&launched.vm, SnapshotOrigin::PreTenantGolden),
        Err(BackendRefusal::Unsupported {
            feature: Feature::Snapshot
        })
    );
    let manifest = SnapshotManifest {
        snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"s"])),
        origin: SnapshotOrigin::PreTenantGolden,
        image_profile: setup.request.pinned.guest_image,
        contents: BTreeSet::new(),
        source_vm: launched.vm,
        guest_identity: digest("yougori/test/guest/v1", &[b"g"]),
    };
    assert_eq!(
        setup
            .backend
            .restore(&request, &manifest, &setup.evidence.registry)
            .unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::Restore
        }
    );
    assert!(setup.machine.events().is_empty());
    assert_eq!(setup.backend.running(), vec![launched.vm]);
}

#[test]
fn settings_must_be_valid_and_the_golden_file_of_the_pinned_version() {
    let scenario = Scenario::new(fixtures::profile());
    let plan = scenario.build().unwrap();
    let settings = |golden: GoldenFile| FirecrackerSettings {
        profile: scenario.profile.clone(),
        configuration: scenario.configuration.clone(),
        host: scenario.host.clone(),
        golden,
        fresh_for: Duration::from_secs(600),
    };
    let machine = Machine::new(scenario.request.configuration, fixtures::VERSION);
    let build = |settings: FirecrackerSettings| {
        let (launcher, api, host) = machine.ports();
        FirecrackerBackend::new(
            settings,
            launcher,
            api,
            host,
            Scenario::new(fixtures::profile()).ledger,
        )
        .map(|_| ())
    };
    let older = ComponentVersion::new("1.10.0").unwrap();
    let golden = GoldenFile::from_parts(&older, plan.api(), &plan.jailer().firecracker_args());
    assert_eq!(
        build(settings(golden)),
        Err(SettingsError::GoldenVersion {
            golden: older,
            pinned: ComponentVersion::new(fixtures::VERSION).unwrap(),
        })
    );
    let mut host_problem = settings(GoldenFile::from_plan(&plan));
    host_problem.host.firecracker = HostPath::new("/opt/vm/vmm").unwrap();
    assert!(matches!(
        build(host_problem),
        Err(SettingsError::Host { .. })
    ));
    let mut profile_problem = settings(GoldenFile::from_plan(&plan));
    profile_problem.profile.machine.vcpu_count = 0;
    assert!(matches!(
        build(profile_problem),
        Err(SettingsError::Profile { .. })
    ));
    assert_eq!(build(settings(GoldenFile::from_plan(&plan))), Ok(()));
    assert!(SettingsError::GoldenVersion {
        golden: ComponentVersion::new("1.10.0").unwrap(),
        pinned: ComponentVersion::new("1.10.1").unwrap(),
    }
    .to_string()
    .contains("golden file is of Firecracker 1.10.0"));
}

#[test]
fn refusals_serialize_with_a_tag_and_describe_themselves() {
    let mut setup = scripted();
    setup.machine.script().refuse_path = Some("/vsock".to_owned());
    let failure = setup.launch().unwrap_err();
    let json = serde_json::to_value(&failure).unwrap();
    assert_eq!(json["refusal"]["kind"], "api_refused");
    assert_eq!(json["cleanup"]["end"]["end"], "proven");
    assert_eq!(
        json["cleanup"]["steps"][0]["outcome"]["outcome"],
        "performed"
    );
    assert_eq!(json["cleanup"]["end"]["proof"]["role"]["role"], "vm_host");
    assert!(failure
        .to_string()
        .starts_with("Firecracker refused /vsock with status 400: scripted refusal"));
    let before =
        LaunchFailure::before_creation(failure.vm, FirecrackerRefusal::JailerFailed { code: 3 });
    assert_eq!(serde_json::to_value(&before).unwrap()["vm"], json["vm"]);
    assert_eq!(
        before.to_string(),
        "the jailer exited with code 3; nothing was created"
    );
}

#[test]
fn every_firecracker_refusal_is_stated_by_what_the_host_observed() {
    let setup = scripted();
    let jail = setup.plan.jail_id().clone();
    let process = ProcessIdentity {
        pid: 7,
        start_time_ticks: 9,
    };
    let info = |id: &str, state: &str| super::ports::InstanceInfo {
        id: id.to_owned(),
        state: state.to_owned(),
        vmm_version: fixtures::VERSION.to_owned(),
    };
    let cases = [
        (
            FirecrackerRefusal::ReservationUnknown {
                reservation: serde_json::from_value::<ReservationId>(9.into()).unwrap(),
            },
            "profile_refused",
        ),
        (
            FirecrackerRefusal::JailerFailed { code: 1 },
            "backend_specific",
        ),
        (
            FirecrackerRefusal::LauncherFailed {
                op: "stage_artifact",
                detail: "no space".to_owned(),
            },
            "backend_specific",
        ),
        (
            FirecrackerRefusal::JailProcesses { found: Vec::new() },
            "process_not_running",
        ),
        (
            FirecrackerRefusal::JailProcesses {
                found: vec![process, process],
            },
            "backend_specific",
        ),
        (
            FirecrackerRefusal::InstanceMismatch {
                expected_id: jail.clone(),
                info: info(jail.as_str(), "Paused"),
            },
            "process_not_running",
        ),
        (
            FirecrackerRefusal::InstanceMismatch {
                expected_id: jail.clone(),
                info: info("another-jail", "Running"),
            },
            "configuration_not_approved",
        ),
        (
            FirecrackerRefusal::ProcessNotHeld {
                process,
                found: IdentityCheck::Reused,
            },
            "process_not_running",
        ),
        (
            FirecrackerRefusal::NotChrooted {
                expected: HostPath::new("/srv/jail/root").unwrap(),
                observed: "/".to_owned(),
            },
            "confinement_not_in_effect",
        ),
    ];
    for (refusal, kind) in cases {
        let stated = refusal.launch_refusal();
        assert_eq!(
            serde_json::to_value(&stated).unwrap()["kind"],
            kind,
            "{refusal:?}"
        );
        assert!(!matches!(stated, LaunchRefusal::CreateFailed { .. }));
        // With nothing left, the launch failure states the refusal itself.
        let failure = LaunchFailure {
            vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"fc"])),
            refusal,
            cleanup: None,
        };
        assert_eq!(failure.to_launch_refusal(), stated);
    }
    assert_eq!(
        FirecrackerRefusal::InstanceMismatch {
            expected_id: jail.clone(),
            info: info(jail.as_str(), "Paused"),
        }
        .launch_refusal(),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Firecracker,
            state: VmProcessState::NotRunning {
                status: "Paused".to_owned()
            },
        }
    );
    assert!(matches!(
        FirecrackerRefusal::ProcessNotHeld {
            process,
            found: IdentityCheck::Gone,
        }
        .launch_refusal(),
        LaunchRefusal::ProcessNotRunning {
            state: VmProcessState::Gone,
            ..
        }
    ));
}

#[test]
fn a_running_jail_is_observed_again_through_the_same_ports() {
    let mut setup = scripted();
    let launched = setup.launch().unwrap();
    let vm = launched.vm;
    let record = &launched.record;
    let configuration = setup.request.configuration;

    // Past every freshness bound, the launch-time facts are stale; the host observes the
    // jail again, and only Firecracker's own description is asked for.
    setup.evidence.clock.advance(Duration::from_secs(601));
    assert!(record
        .assert_current(setup.evidence.registry.now())
        .is_err());
    setup.evidence.observe(configuration);
    setup.machine.forget_events();
    let again = setup
        .backend
        .reobserve(&vm, &setup.evidence.registry)
        .unwrap();
    assert_eq!(
        record.assert_current_with(setup.evidence.registry.now(), &again),
        Ok(())
    );
    assert_eq!(
        again
            .accelerator()
            .observation()
            .map(|observed| observed.observed_at()),
        Some(setup.evidence.registry.now().at())
    );
    assert!(!setup.machine.events().is_empty());
    assert!(setup
        .machine
        .events()
        .iter()
        .all(|event| matches!(event, Event::Describe { .. })));

    let refused = |setup: &mut Setup| match setup.backend.reobserve(&vm, &setup.evidence.registry) {
        Err(ReobservationRefusal::Refused { refusal }) => *refusal,
        other => panic!("{other:?}"),
    };
    // The jailed process lost its seccomp filter: refused as at launch.
    setup.machine.script().tamper = Some(|observation| {
        observation.status = observation.status.replace("Seccomp:\t2", "Seccomp:\t0");
    });
    assert!(matches!(
        refused(&mut setup),
        LaunchRefusal::ConfinementNotInEffect { observed: true, .. }
    ));
    // The process no longer holds the staged root image: the booted image is not
    // observed, so the evidence facet fails.
    setup.machine.script().tamper = Some(|observation| {
        observation
            .descriptors
            .retain(|target| target != super::layout::ROOT_IMAGE);
    });
    let unattached = setup
        .backend
        .reobserve(&vm, &setup.evidence.registry)
        .unwrap();
    assert_eq!(unattached.host_observed().guest_image.value(), None);
    let refusal = record
        .assert_current_with(setup.evidence.registry.now(), &unattached)
        .unwrap_err();
    assert!(
        matches!(
            &refusal,
            ReobservationRefusal::Refused { refusal }
                if refusal.failed_checks().iter().map(|check| check.facet()).eq([Facet::Evidence])
        ),
        "{refusal:?}"
    );
    setup.machine.script().tamper = None;

    // Firecracker reports another version, or the instance not running.
    setup.machine.script().vmm_version = "1.10.0".to_owned();
    assert!(matches!(
        refused(&mut setup),
        LaunchRefusal::ConfigurationNotApproved { checks, .. }
            if checks.contains(&ConfigurationCheck::GoldenConfiguration)
    ));
    setup.machine.script().vmm_version = fixtures::VERSION.to_owned();
    setup.machine.script().instance_state = "Paused".to_owned();
    assert_eq!(
        refused(&mut setup),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Firecracker,
            state: VmProcessState::NotRunning {
                status: "Paused".to_owned()
            },
        }
    );
    setup.machine.script().instance_state = "Running".to_owned();

    // The host's configuration changed: what it observes now does not apply to the
    // launch.
    setup.machine.script().configuration =
        ConfigurationFingerprint::from_settings([("host", "changed")]).unwrap();
    let changed = setup
        .backend
        .reobserve(&vm, &setup.evidence.registry)
        .unwrap();
    assert!(matches!(
        record.assert_current_with(setup.evidence.registry.now(), &changed),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::ObservationNotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            })
    ));
    setup.machine.script().configuration = configuration;

    // The process ended and another took its PID: refused, and nothing is killed.
    let process = setup.backend.bound(&vm).unwrap().process;
    setup.machine.end_process(process, true);
    setup.machine.forget_events();
    assert_eq!(
        refused(&mut setup),
        LaunchRefusal::ProcessNotRunning {
            backend: BackendKind::Firecracker,
            state: VmProcessState::Replaced,
        }
    );
    assert!(setup.machine.operation_tags().is_empty());

    let unknown = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"unknown"]));
    assert_eq!(
        setup.backend.reobserve(&unknown, &setup.evidence.registry),
        Err(ReobservationRefusal::NoSuchVm { vm: unknown })
    );
}

#[test]
fn a_refused_launchs_jail_without_an_observed_end_is_listed_and_stopped_later() {
    let mut setup = scripted();
    setup.machine.script().refuse_path = Some("/vsock".to_owned());
    setup.machine.script().survive_kill = true;
    let failure = setup.launch().unwrap_err();
    let vm = failure.vm;
    assert!(failure.to_launch_refusal().left_behind().is_some());
    assert_eq!(setup.backend.running(), vec![vm]);

    // A stop while the process survives does not stop it, and the kill is not sent again.
    setup.machine.forget_events();
    assert!(matches!(
        setup.backend.stop(&vm),
        Err(BackendRefusal::Failed {
            operation: BackendOperation::Stop,
            ..
        })
    ));
    assert!(setup.machine.operation_tags().is_empty());
    assert_eq!(setup.backend.running(), vec![vm]);

    // Once the process is gone, a stop performs the withheld removals and the VM is gone.
    for process in setup.machine.alive() {
        setup.machine.end_process(process, false);
    }
    setup.machine.forget_events();
    assert_eq!(setup.backend.stop(&vm), Ok(StopOutcome::Stopped));
    assert_eq!(
        setup.machine.operation_tags(),
        ["remove_cgroup", "remove_jail", "remove_network_namespace"]
    );
    assert!(setup.backend.running().is_empty());
    assert!(setup.backend.uncleaned().is_empty());
    assert!(setup.backend.termination_proof(&vm).is_some());
    assert_eq!(setup.backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
}
