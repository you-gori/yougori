//! Tests of check outcomes from sealed launch records: records the fake backend seals
//! through the backend contract's own admission, with a real CORE-01 registry on a manual
//! clock, and refusals of controlled negative launches as the backend returns them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::catalog::{check, CheckId, CorroboratingFact, Part, RunProfile, SourceKind};
use super::expect::{expectation, Expect, ExpectationId, Observed, Role};
use super::fakes::{boot, check_id, configuration, id, refused, vm, GuestEnd, FRESH, MAX_AGE};
use super::outcome::{
    Evidence, HostKind, ProbeOutcome, RecordAge, RecordRun, RunResult, StampOrigin,
};
use super::drill::{ConnectionDrill, DrillAttempt, DrillCase};
use super::process_scan::{ListedProcess, ProcessScan, ScanMoment};
use super::records::{
    record_coverage, record_coverage_of, record_source, ComparisonItem, ControlledFault,
    ListingItem, NegativeOutcome, RecordInputError, RecordResults, RecordSource,
};
use super::report::{BoundaryReport, HostProfile};
use super::rules::{judge, CheckRefusal, CheckStatus, Failure, InconclusiveReason, JudgeContext};
use crate::foundation::coordination::{SandboxGenerations, SnapshotManifest, SnapshotOrigin};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    BackendVersion, Capability, EvidenceRefusal, HypervisorKind, HypervisorSubject, Observation,
    OsKind, ProbeRegistry, Staleness, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionId, GpuDeviceKey, ManualClock, MonotonicTime, SandboxBootGeneration,
    TenantId,
};
use crate::foundation::ledger::ReservationId;
use crate::sandbox::backend::{
    Accelerator, Architecture, BackendFeatures, BackendKind, BuildId, ConfigurationCheck,
    ConfigurationComparison, ConfigurationFact, DeviceInventory, DeviceProfile, Emulator, FactName,
    FactSource, FakeBackend, Feature, GpuIsolation, GpuIsolationCheck, GuestScript,
    HardwareFailure, HostBuild, HostInterfaceListing, HostObserved, HostScript, LaunchRecord,
    LaunchRefusal, LaunchRequest, ObservationProblem, ObservedGpu, PinnedArtifacts,
    RequiredProperties, Scripted, UnsafeDeviceSetting, VmBackend,
};
use crate::sandbox::link::ProbeOutcome as GuestVerdict;

/// The freshness a launch asks of its host observations.
const LAUNCH_AGE: Duration = Duration::from_secs(60);

const HOST_CONFIG: &str = "host-a";

fn machine() -> Digest {
    digest("yougori/test/probes/machine/v1", &[b"m"])
}

fn image() -> Digest {
    digest("yougori/test/probes/image/v1", &[b"root"])
}

fn artifact() -> Digest {
    digest("yougori/test/probes/backend/v1", &[b"fake"])
}

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/probes/device/v1", &[b"gpu0"]),
    }
}

fn build(os: OsKind, name: &str) -> HostBuild {
    HostBuild {
        os,
        build: BuildId::new(name).unwrap(),
        architecture: Architecture::X86_64,
    }
}

fn linux() -> HostBuild {
    build(OsKind::Linux, "6.8.0-45")
}

fn hypervisor_subject(hypervisor: HypervisorKind) -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor,
    })
}

/// A host: a manual clock and a CORE-01 registry with a hypervisor probe.
struct Host {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    probe: Arc<FakeProbe>,
    hypervisor: HypervisorKind,
}

impl Host {
    /// A host whose probe found `hypervisor` available under the host configuration.
    fn new(hypervisor: HypervisorKind) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::hypervisor_availability());
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let mut host = Self {
            clock,
            registry,
            probe,
            hypervisor,
        };
        host.observe(true);
        host
    }

    /// The probe finds the hypervisor available or not, now.
    fn observe(&mut self, available: bool) {
        let config = configuration(HOST_CONFIG);
        let observation = if available {
            Observation::supported(
                config,
                FRESH,
                SupportDetail::Hypervisor {
                    hypervisor: self.hypervisor,
                },
            )
        } else {
            Observation::unsupported(config, FRESH, UnsupportedReason::HypervisorUnavailable)
        };
        let subject = hypervisor_subject(self.hypervisor);
        self.probe.respond(&subject, observation);
        self.registry
            .refresh(Capability::HypervisorAvailable, &subject)
            .unwrap();
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    fn judging(&self, os: OsKind) -> JudgeContext {
        JudgeContext {
            now: self.registry.now(),
            configuration: configuration(HOST_CONFIG),
            max_age: MAX_AGE,
            os,
        }
    }

    /// `refusal`, stamped now as the host observed it.
    fn stamped(&self, refusal: LaunchRefusal) -> NegativeOutcome {
        NegativeOutcome::Refused {
            refusal: HostObserved::stamp(
                refusal,
                self.registry.now(),
                FRESH,
                configuration(HOST_CONFIG),
            ),
        }
    }
}

/// A fake backend on `host` that launches with `hypervisor` and offers snapshots,
/// restore and GPU assignment.
fn backend_on(host: HostBuild, hypervisor: HypervisorKind) -> FakeBackend {
    FakeBackend::new(
        hypervisor,
        BackendVersion::new("0.1.0").unwrap(),
        artifact(),
        HostScript::hardware_vm(hypervisor, host, image(), configuration(HOST_CONFIG)),
    )
    .with_features(BackendFeatures::of([
        Feature::Snapshot,
        Feature::Restore,
        Feature::GpuAssignment,
    ]))
}

fn kvm_backend() -> FakeBackend {
    backend_on(linux(), HypervisorKind::Kvm)
}

fn reservation(number: u64) -> ReservationId {
    serde_json::from_value(number.into()).unwrap()
}

fn request(execution: &str, boot: u64) -> LaunchRequest {
    LaunchRequest {
        execution: ExecutionId::new(execution).unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations {
            boot: SandboxBootGeneration::new(boot),
            ..SandboxGenerations::FIRST
        },
        machine: machine(),
        configuration: configuration(HOST_CONFIG),
        contract: digest("yougori/test/probes/contract/v1", &[b"c1"]),
        pinned: PinnedArtifacts {
            guest_image: image(),
            backend: artifact(),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/probes/profile/v1", &[b"minimal"]),
            devices: Default::default(),
        },
        required: RequiredProperties::strictest(LAUNCH_AGE),
        reservation: reservation(1),
    }
}

fn gpu_request(execution: &str) -> LaunchRequest {
    let mut with_gpu = request(execution, 1);
    with_gpu.device_profile.devices.gpus.insert(gpu());
    with_gpu.required.devices.gpus.insert(gpu());
    with_gpu
}

/// The fake's script observes `gpu()` assigned with `isolation`.
fn assigned(backend: &mut FakeBackend, isolation: GpuIsolation) {
    backend.script_mut().devices = Scripted::HostObserved(DeviceInventory {
        paravirtualized_gpu: false,
            display: false,
        gpus: [ObservedGpu {
            device: gpu(),
            isolation,
        }]
        .into_iter()
        .collect(),
    });
}

fn lacking(check: GpuIsolationCheck) -> GpuIsolation {
    let mut isolation = GpuIsolation::complete();
    isolation.checks.remove(&check);
    isolation
}

fn launch(backend: &mut FakeBackend, host: &Host, request: &LaunchRequest) -> LaunchRecord {
    backend.launch(request, &host.registry).unwrap().record
}

fn refusal(backend: &mut FakeBackend, host: &Host, request: &LaunchRequest) -> LaunchRefusal {
    backend.launch(request, &host.registry).unwrap_err()
}

fn results_of(backend: &FakeBackend, host: HostBuild) -> RecordResults {
    RecordResults::new(host, backend.identity().clone())
}

fn sealed(record: LaunchRecord) -> NegativeOutcome {
    NegativeOutcome::Launched {
        record: Box::new(record),
    }
}

fn run_of(outcome: &ProbeOutcome) -> &RecordRun {
    match outcome.evidence() {
        Evidence::Record { run } => run,
        other => panic!("expected a record run, got {other:?}"),
    }
}

/// The record outcomes of `check_number`, judged at `context`.
fn status(
    outcomes: &BTreeMap<CheckId, Vec<ProbeOutcome>>,
    check_number: u8,
    context: &JudgeContext,
) -> CheckStatus {
    let row = check(check_id(check_number));
    judge(
        row,
        outcomes.get(&row.id).map(Vec::as_slice).unwrap_or(&[]),
        context,
    )
}

fn checks(outcomes: &BTreeMap<CheckId, Vec<ProbeOutcome>>) -> Vec<u8> {
    outcomes.keys().map(|check_id| check_id.number()).collect()
}

fn failed(id_name: &str, part: Part) -> CheckStatus {
    CheckStatus::Failed {
        failure: Failure::Expectation {
            id: id(id_name),
            part,
        },
    }
}

fn no_control(id_name: &str) -> CheckStatus {
    CheckStatus::Inconclusive {
        reason: InconclusiveReason::NoPositiveControl { id: id(id_name) },
    }
}

// ---------------------------------------------------------------- the coverage map

#[test]
fn the_record_coverage_names_every_check_once_and_decides_only_host_parts() {
    let numbers: Vec<u8> = record_coverage()
        .iter()
        .map(|entry| entry.check.number())
        .collect();
    assert_eq!(numbers, (1..=35).collect::<Vec<u8>>());
    let mut decided = BTreeSet::new();
    for entry in record_coverage() {
        assert_eq!(record_coverage_of(entry.check), entry);
        assert!(!entry.leaves.is_empty(), "{} gives no reason", entry.check);
        let row = check(entry.check);
        for decision in entry.decides {
            let expected = expectation(decision.expectation)
                .unwrap_or_else(|| panic!("{} is no expectation", decision.expectation));
            assert_eq!(expected.check, entry.check, "{}", decision.expectation);
            assert!(decided.insert(decision.expectation.as_str()));
            assert_eq!(record_source(decision.expectation), Some(decision.source));
            // A record is host evidence: it never decides a guest-reported part.
            assert_ne!(
                row.side.required_source(expected.part),
                Some(SourceKind::Guest),
                "{} is guest-reported",
                decision.expectation
            );
            // Each source yields the kind of observation its expectation judges.
            let fits = match decision.source {
                RecordSource::RecordedAccelerator => matches!(expected.expect, Expect::OneOf(_)),
                RecordSource::NormalLaunch => {
                    expected.expect == Expect::Succeeds && expected.role == Role::PositiveControl
                }
                RecordSource::CloneGenerations | RecordSource::CloneHandles => {
                    expected.expect == Expect::AllDistinct
                }
                RecordSource::NegativeLaunch { hypervisors, .. } => {
                    expected.expect == Expect::Refused && !hypervisors.is_empty()
                }
                RecordSource::NegativeDetection { hypervisors, .. } => {
                    expected.expect == Expect::Happens
                        && expected.role == Role::PositiveControl
                        && !hypervisors.is_empty()
                }
                RecordSource::RecordedComparison { item } => {
                    expected.expect
                        == if item == ComparisonItem::GoldenFile {
                            Expect::Matches
                        } else {
                            Expect::Absent
                        }
                }
                RecordSource::RecordedListing { item } => {
                    expected.expect
                        == if item == ListingItem::MonitorSocketPrivate {
                            Expect::Present
                        } else {
                            Expect::Absent
                        }
                }
                RecordSource::RecordedGpuOrder { .. } => expected.expect == Expect::Present,
                RecordSource::ExaminationScan => expected.expect == Expect::Absent,
                RecordSource::FallbackScan { faults } => {
                    expected.expect == Expect::Absent && !faults.is_empty()
                }
                // A drill's attempt is refused or succeeds as its case expects.
                RecordSource::DrillAttempt { case } => {
                    expected.expect
                        == if case.refusal_expected() {
                            Expect::Refused
                        } else {
                            Expect::Succeeds
                        }
                }
                RecordSource::DrillSharedState => expected.expect == Expect::Absent,
            };
            assert!(
                fits,
                "{} cannot come from {:?}",
                decision.expectation, decision.source
            );
        }
    }
    assert_eq!(
        decided,
        BTreeSet::from([
            "cp01.accelerator",
            "cp01.forced-unavailable-refused",
            "cp01.no-tcg-hypervisor",
            "cp01.normal-launch-records-accelerator",
            "cp02.golden-configuration",
            "cp02.network-device",
            "cp02.console",
            "cp02.balloon",
            "cp02.undeclared-pci-transport",
            "cp03.shared-filesystem-device",
            "cp03.management-tcp-listener",
            "cp03.qmp-socket-private",
            "cp03.old-agent-port-forward",
            "cp03.planted-share-device-detected",
            "cp21.generation-ids",
            "cp21.boot-ids",
            "cp23.root-image-byte-change",
            "cp29.expired-grant",
            "cp29.granted-port",
            "cp29.other-ports",
            "cp29.revoked-grant",
            "cp29.second-grant-passes",
            "cp29.shared-caches-and-volumes",
            "cp29.transitive-connection",
            "cp29.ungranted-connection",
            "cp31.incomplete-iommu-group",
            "cp31.display-owning-gpu",
            "cp31.reset-capability-checked",
            "cp31.acs-state-checked",
            "cp33.linux.kvm-unavailable",
            "cp33.windows.whpx-unavailable",
            "cp33.macos.framework-unavailable",
            "cp33.gpu-path-unavailable",
            "cp33.fallback-start",
        ])
    );
    assert_eq!(
        record_source(id("cp01.no-tcg-hypervisor")),
        Some(RecordSource::ExaminationScan)
    );
    assert_eq!(record_source(id("cp05.booted-root-image")), None);
    let json = serde_json::to_string(record_coverage()).unwrap();
    assert!(!json.contains("score"));
}

#[test]
fn a_refusal_counts_only_for_its_faults_reason() {
    use ControlledFault::*;
    let kvm = HypervisorKind::Kvm;
    let unsupported = LaunchRefusal::Evidence {
        refusal: EvidenceRefusal::Unsupported {
            capability: Capability::HypervisorAvailable,
            reason: UnsupportedReason::HypervisorUnavailable,
        },
    };
    let missing = LaunchRefusal::Evidence {
        refusal: EvidenceRefusal::Missing {
            capability: Capability::HypervisorAvailable,
        },
    };
    let failure = |hypervisor| LaunchRefusal::HardwareVirtualizationFailed {
        failure: HardwareFailure {
            hypervisor,
            detail: "KVM_CREATE_VM: EPERM".to_owned(),
        },
    };
    let tcg = LaunchRefusal::NotHardwareVirtualized {
        observed: Accelerator::Emulation {
            emulator: Emulator::Tcg,
        },
    };
    let unobserved = LaunchRefusal::AcceleratorNotObserved {
        reason: UnknownReason::Unreachable,
    };
    let other_hypervisor = |expected| LaunchRefusal::UnexpectedAccelerator {
        expected,
        observed: Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx,
        },
    };
    let no_gpu = LaunchRefusal::Unsupported {
        feature: Feature::GpuAssignment,
    };
    let no_display = LaunchRefusal::Unsupported {
        feature: Feature::Display,
    };
    let create = LaunchRefusal::CreateFailed {
        detail: "boom".to_owned(),
    };
    for refusal in [
        &unsupported,
        &failure(kvm),
        &tcg,
        &unobserved,
        &other_hypervisor(kvm),
    ] {
        assert!(
            HypervisorUnavailable.refused_for(refusal, kvm),
            "{refusal:?}"
        );
    }
    // A refusal for an evidence gap, another hypervisor's failure or any other reason
    // shows nothing about the hypervisor being unavailable.
    for refusal in [
        &missing,
        &failure(HypervisorKind::Whpx),
        &other_hypervisor(HypervisorKind::Whpx),
        &no_gpu,
        &create,
    ] {
        assert!(
            !HypervisorUnavailable.refused_for(refusal, kvm),
            "{refusal:?}"
        );
    }
    assert!(GpuPathUnavailable.refused_for(&no_gpu, kvm));
    assert!(!GpuPathUnavailable.refused_for(&no_display, kvm));
    // A planted share device counts only when the host interface check failed.
    let not_approved = |checks: &[ConfigurationCheck]| LaunchRefusal::ConfigurationNotApproved {
        backend: BackendKind::Qemu,
        checks: checks.iter().copied().collect(),
        findings: vec!["a share device".to_owned()],
    };
    assert!(PlantedShareDevice.refused_for(
        &not_approved(&[
            ConfigurationCheck::GoldenConfiguration,
            ConfigurationCheck::HostInterfaces
        ]),
        kvm
    ));
    assert!(!PlantedShareDevice.refused_for(
        &not_approved(&[ConfigurationCheck::GoldenConfiguration]),
        kvm
    ));
    for fault in ControlledFault::ALL {
        assert_eq!(
            fault.refused_for(&not_approved(&[ConfigurationCheck::HostInterfaces]), kvm),
            fault == PlantedShareDevice,
            "{fault:?}"
        );
    }
    assert!(!PlantedShareDevice.needs_gpu());
    for fault in [
        RootImageChanged,
        IncompleteIommuGroup,
        DisplayOwningGpu,
        PlantedShareDevice,
    ] {
        for refusal in [&unsupported, &no_gpu, &create, &tcg] {
            assert!(!fault.refused_for(refusal, kvm), "{fault:?} {refusal:?}");
        }
    }
    for fault in ControlledFault::ALL {
        assert!(!fault.to_string().is_empty());
    }
}

// ---------------------------------------------------------------- what records decide

#[test]
fn a_normal_launch_alone_decides_no_part_so_every_check_stays_not_tested() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let record = launch(&mut backend, &host, &request("exe-1", 1));
    let mut results = results_of(&backend, linux());
    results.record(record).unwrap();
    assert_eq!(results.normal_launches(), 1);
    // The accelerator and the control are decided, but VM-CP-01's process-list
    // observation and its forced-unavailable launch are not, so the part is left out.
    assert!(results.outcomes().is_empty());

    let profile = HostProfile {
        host: linux(),
        backend: BackendKind::Fake,
        profiles: BTreeSet::from([RunProfile::Strict]),
    };
    let report =
        BoundaryReport::assemble(profile, results.inputs(), &host.judging(OsKind::Linux)).unwrap();
    for entry in report.entries() {
        assert!(
            matches!(entry.status, CheckStatus::NotTested { .. }),
            "{} is {:?}",
            entry.check,
            entry.status
        );
    }
}

#[test]
fn refused_negative_launches_still_leave_parts_with_open_observations_out() {
    let mut host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    results
        .record(launch(&mut backend, &host, &request("exe-1", 1)))
        .unwrap();

    // The hypervisor made unavailable: CORE-01 says so and the precheck refuses.
    host.observe(false);
    let unavailable = refusal(&mut backend, &host, &request("exe-2", 1));
    assert!(matches!(unavailable, LaunchRefusal::Evidence { .. }));
    results
        .negative(
            ControlledFault::HypervisorUnavailable,
            host.stamped(unavailable),
        )
        .unwrap();
    host.observe(true);

    // A one-byte change in the root image: the booted digest is not the pinned one.
    backend.script_mut().guest_image =
        Scripted::HostObserved(digest("yougori/test/probes/image/v1", &[b"root+1"]));
    let changed = refusal(&mut backend, &host, &request("exe-3", 1));
    results
        .negative(ControlledFault::RootImageChanged, host.stamped(changed))
        .unwrap();
    backend.script_mut().guest_image = Scripted::HostObserved(image());

    // An incomplete IOMMU group and a display-owning GPU are refused at admission.
    assigned(
        &mut backend,
        lacking(GpuIsolationCheck::CompleteIsolationGroup),
    );
    let incomplete = refusal(&mut backend, &host, &gpu_request("exe-4"));
    assigned(
        &mut backend,
        lacking(GpuIsolationCheck::NoHostDisplayOrOtherUsers),
    );
    let display = refusal(&mut backend, &host, &gpu_request("exe-5"));
    // Each GPU refusal counts only for its own fault.
    assert_eq!(
        results.negative(
            ControlledFault::DisplayOwningGpu,
            host.stamped(incomplete.clone())
        ),
        Err(RecordInputError::NotRefusedForFault {
            fault: ControlledFault::DisplayOwningGpu
        })
    );
    results
        .negative(
            ControlledFault::IncompleteIommuGroup,
            host.stamped(incomplete),
        )
        .unwrap();
    results
        .negative(ControlledFault::DisplayOwningGpu, host.stamped(display))
        .unwrap();

    // The GPU path unavailable: a backend without GPU assignment refuses by name.
    let mut cpu_only = kvm_backend().with_features(BackendFeatures::none());
    let no_path = refusal(&mut cpu_only, &host, &gpu_request("exe-6"));
    results
        .negative(ControlledFault::GpuPathUnavailable, host.stamped(no_path))
        .unwrap();
    assert_eq!(results.negative_launches(), 5);

    // Every decided observation held, and each part still has one no record decides:
    // VM-CP-01's process list, VM-CP-23's trust-layer refusals, VM-CP-31's checks before
    // assignment and VM-CP-33's process list. Nothing is reported for them.
    let outcomes = results.outcomes();
    assert!(outcomes.is_empty(), "{:?}", checks(&outcomes));
}

#[test]
fn a_negative_launch_that_was_not_refused_fails_its_checks() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    let normal = launch(&mut backend, &host, &request("exe-1", 1));
    results.record(normal.clone()).unwrap();
    // The test build forced the hypervisor unavailable, and the backend launched anyway.
    let anyway = launch(&mut backend, &host, &request("exe-2", 1));
    results
        .negative(
            ControlledFault::HypervisorUnavailable,
            sealed(anyway.clone()),
        )
        .unwrap();

    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![1, 33]);
    let context = host.judging(OsKind::Linux);
    assert_eq!(
        status(&outcomes, 1, &context),
        failed("cp01.forced-unavailable-refused", Part::Primary)
    );
    // VM-CP-33 lists no positive control, so its failure stands.
    assert_eq!(
        status(&outcomes, 33, &context),
        failed("cp33.linux.kvm-unavailable", Part::Primary)
    );

    let cp01 = &outcomes[&check_id(1)];
    assert_eq!(cp01.len(), 1);
    assert_eq!(cp01[0].part(), Part::Primary);
    assert_eq!(cp01[0].source_kind(), Some(SourceKind::Host));
    let run = run_of(&cp01[0]);
    assert_eq!(run.backend(), backend.identity());
    assert_eq!(run.host(), &linux());
    let observations = run.observations();
    assert_eq!(
        observations.get(&id("cp01.accelerator")),
        Some(&Observed::Value {
            value: "kvm".to_owned()
        })
    );
    assert_eq!(
        observations.get(&id("cp01.forced-unavailable-refused")),
        Some(&Observed::Attempt { refused: false })
    );
    assert_eq!(
        observations.get(&id("cp01.normal-launch-records-accelerator")),
        Some(&Observed::Attempt { refused: false })
    );
    assert!(!observations.contains_key(&id("cp01.no-tcg-hypervisor")));
    // Each observation names the record and fact it was read from.
    assert_eq!(
        run.read_from(id("cp01.forced-unavailable-refused"))[0].origin(),
        StampOrigin::Record {
            record: anyway.identity(),
            fact: FactName::Accelerator
        }
    );
    assert_eq!(
        run.read_from(id("cp01.normal-launch-records-accelerator"))[0].origin(),
        StampOrigin::Record {
            record: normal.identity(),
            fact: FactName::Accelerator
        }
    );
    assert!(run.read_from(id("cp01.no-tcg-hypervisor")).is_empty());
    assert_eq!(run.records(), vec![normal.identity(), anyway.identity()]);
    assert_eq!(run.refusals(), 0);

    // The boundary report judges them like any host outcome.
    let profile = HostProfile {
        host: linux(),
        backend: BackendKind::Fake,
        profiles: BTreeSet::from([RunProfile::Strict]),
    };
    let report = BoundaryReport::assemble(profile, results.inputs(), &context).unwrap();
    assert!(matches!(
        report.entry(check_id(1)).unwrap().status,
        CheckStatus::Failed { .. }
    ));
    assert!(!report.allows_launch());
    let json = serde_json::to_value(&report).unwrap().to_string();
    assert!(!json.contains("score"));
}

#[test]
fn without_a_normal_launch_or_a_listed_control_the_check_stays_inconclusive() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    let anyway = launch(&mut backend, &host, &request("exe-1", 1));
    results
        .negative(ControlledFault::HypervisorUnavailable, sealed(anyway))
        .unwrap();
    // A sealed changed image: the host did not see the change.
    let changed = launch(&mut backend, &host, &request("exe-2", 1));
    results
        .negative(ControlledFault::RootImageChanged, sealed(changed))
        .unwrap();
    // A GPU with an incomplete group, assigned anyway.
    assigned(&mut backend, GpuIsolation::complete());
    let gpu_anyway = launch(&mut backend, &host, &gpu_request("exe-3"));
    results
        .negative(ControlledFault::IncompleteIommuGroup, sealed(gpu_anyway))
        .unwrap();

    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![1, 23, 31, 33]);
    let context = host.judging(OsKind::Linux);
    // No normal launch shows that a launch succeeds here.
    assert_eq!(
        status(&outcomes, 1, &context),
        no_control("cp01.normal-launch-records-accelerator")
    );
    // A record shows the pinned set launched, not the signed set.
    assert_eq!(
        status(&outcomes, 23, &context),
        no_control("cp23.signed-set-launches")
    );
    // nvidia-smi in the guest is not in a record.
    assert_eq!(
        status(&outcomes, 31, &context),
        no_control("cp31.qualifying-device-assigns")
    );
    assert_eq!(
        status(&outcomes, 33, &context),
        failed("cp33.linux.kvm-unavailable", Part::Primary)
    );
    // With no normal launch, VM-CP-01's run has no accelerator from a normal record either.
    let run = run_of(&outcomes[&check_id(1)][0]);
    assert_eq!(
        run.observations()
            .keys()
            .copied()
            .collect::<Vec<ExpectationId>>(),
        vec![id("cp01.forced-unavailable-refused")]
    );
}

#[test]
fn clones_restored_from_one_snapshot_decide_the_clone_identity_corroboration() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let first = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let golden = backend
        .snapshot(&first.vm, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    backend.stop(&first.vm).unwrap();
    let restore = |backend: &mut FakeBackend, golden: &SnapshotManifest, boot: u64| {
        backend
            .restore(&request("exe-1", boot), golden, &host.registry)
            .unwrap()
            .launched
            .record
    };
    let clone_a = restore(&mut backend, &golden, 2);
    let clone_b = restore(&mut backend, &golden, 3);
    let mut results = results_of(&backend, linux());
    for record in [first.record.clone(), clone_a.clone(), clone_b.clone()] {
        results.record(record).unwrap();
    }

    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![21]);
    let cp21 = &outcomes[&check_id(21)];
    let identities = Part::Corroboration {
        fact: CorroboratingFact::CloneIdentities,
    };
    assert_eq!(
        cp21.iter().map(ProbeOutcome::part).collect::<Vec<Part>>(),
        vec![identities]
    );
    let run = run_of(&cp21[0]);
    assert_eq!(
        run.observations().get(&id("cp21.boot-ids")),
        Some(&Observed::Identities {
            values: vec![clone_a.vm().digest(), clone_b.vm().digest()]
        })
    );
    assert!(matches!(
        run.observations().get(&id("cp21.generation-ids")),
        Some(Observed::Identities { values }) if values.len() == 2 && values[0] != values[1]
    ));
    assert_eq!(run.records(), vec![clone_a.identity(), clone_b.identity()]);

    // The guest-reported part is not in a record, so the check is not tested yet.
    let context = host.judging(OsKind::Linux);
    assert!(matches!(
        status(&outcomes, 21, &context),
        CheckStatus::NotTested { .. }
    ));
    // With the guest's report and the executor's refusal, the record's corroboration
    // completes the check.
    let mut guest = GuestEnd::new(vm());
    let reports = guest.report(&[
        ("cp21.canary-values", GuestVerdict::Passed),
        ("cp21.application-identifiers", GuestVerdict::Passed),
    ]);
    let primary = ProbeOutcome::guest(
        check_id(21),
        Part::Primary,
        &reports,
        vm(),
        boot(),
        host.registry.now(),
        FRESH,
        configuration(HOST_CONFIG),
    )
    .unwrap();
    let approval = ProbeOutcome::host(
        check_id(21),
        Part::Corroboration {
            fact: CorroboratingFact::PreSnapshotApprovalRefused,
        },
        HostKind::Host,
        host.registry.now(),
        FRESH,
        configuration(HOST_CONFIG),
        RunResult::Observed {
            observations: [(id("cp21.pre-snapshot-approval"), refused())]
                .into_iter()
                .collect(),
        },
    )
    .unwrap();
    let complete = [primary.clone(), cp21[0].clone(), approval.clone()];
    assert_eq!(
        judge(check(check_id(21)), &complete, &context),
        CheckStatus::Passed
    );

    // A second backend that hands a clone the same sandbox boot again: the identities
    // the host assigned are not distinct, and the corroboration fails.
    host.advance(Duration::from_secs(1));
    let mut twin = kvm_backend();
    let reused = restore(&mut twin, &golden, 2);
    assert_eq!(reused.vm(), clone_a.vm());
    results.record(reused).unwrap();
    let outcomes = results.outcomes();
    let repeated = outcomes[&check_id(21)][0].clone();
    assert_eq!(
        judge(
            check(check_id(21)),
            &[primary, repeated, approval],
            &host.judging(OsKind::Linux)
        ),
        failed("cp21.generation-ids", identities)
    );
}

// ---------------------------------------------------------------- stamps and sources

#[test]
fn outcomes_keep_the_records_own_stamps_and_go_stale_with_them() {
    let host = Host::new(HypervisorKind::Kvm);
    let before = host.judging(OsKind::Linux);
    host.advance(Duration::from_secs(5));
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    let normal = launch(&mut backend, &host, &request("exe-1", 1));
    let anyway = launch(&mut backend, &host, &request("exe-2", 1));
    results.record(normal.clone()).unwrap();
    results
        .negative(ControlledFault::HypervisorUnavailable, sealed(anyway))
        .unwrap();
    let observed_at = normal.accelerator().observed_at();

    // Built later, the outcome still carries the record's stamp, never a fresher one.
    host.advance(Duration::from_secs(30));
    let outcomes = results.outcomes();
    let run = run_of(&outcomes[&check_id(1)][0]);
    let stamp = run.read_from(id("cp01.accelerator"))[0];
    assert_eq!(stamp.observed_at(), observed_at);
    assert_eq!(stamp.clock(), normal.accelerator().clock());
    assert_eq!(stamp.fresh_for(), normal.accelerator().fresh_for());
    assert_eq!(stamp.configuration(), configuration(HOST_CONFIG));
    assert_eq!(stamp.source(), FactSource::HostObserved);
    assert!(stamp.observed_at() < host.registry.now().at());
    assert_eq!(
        run.age_at(host.registry.now()),
        RecordAge::Observed {
            age: Duration::from_secs(30)
        }
    );
    let context = host.judging(OsKind::Linux);
    assert!(matches!(
        status(&outcomes, 1, &context),
        CheckStatus::Failed { .. }
    ));

    // Under another configuration, the stamps no longer apply.
    let reconfigured = JudgeContext {
        configuration: configuration("host-b"),
        ..context
    };
    assert!(matches!(
        status(&outcomes, 1, &reconfigured),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            }
        }
    ));
    // Read before the records existed, they are dated after the reader's time.
    assert_eq!(run.age_at(before.now), RecordAge::ObservedAfterNow);
    assert!(matches!(
        status(&outcomes, 1, &before),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::Stale {
                    staleness: Staleness::ObservedAfterNow
                },
                ..
            }
        }
    ));
    // On another clock session, such as after a restart, their age is unknown.
    let restarted = ProbeRegistry::new(Arc::clone(&host.clock));
    assert_eq!(run.age_at(restarted.now()), RecordAge::OtherClock);
    let other_clock = JudgeContext {
        now: restarted.now(),
        ..context
    };
    assert!(matches!(
        status(&outcomes, 1, &other_clock),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::Stale {
                    staleness: Staleness::OtherClock
                },
                ..
            }
        }
    ));
    // Past the reader's maximum age, they are stale.
    host.advance(MAX_AGE - Duration::from_secs(29));
    assert_eq!(
        status(&outcomes, 1, &host.judging(OsKind::Linux)),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                part: Part::Primary,
                problem: ObservationProblem::Stale {
                    staleness: Staleness::TooOld {
                        age: MAX_AGE + Duration::from_secs(1),
                        limit: MAX_AGE,
                    }
                },
            }
        }
    );
}

#[test]
fn a_refusal_is_dated_when_the_host_observed_it() {
    let mut host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    let anyway = launch(&mut backend, &host, &request("exe-1", 1));
    results
        .negative(ControlledFault::RootImageChanged, sealed(anyway))
        .unwrap();
    host.observe(false);
    let unavailable = refusal(&mut backend, &host, &request("exe-2", 1));
    let stamped = host.stamped(unavailable);
    let NegativeOutcome::Refused { refusal: observed } = &stamped else {
        panic!("a refusal");
    };
    let refused_at = observed.observed_at();
    results
        .negative(ControlledFault::HypervisorUnavailable, stamped.clone())
        .unwrap();
    host.advance(Duration::from_secs(10));
    // VM-CP-23 is decided by the sealed changed image; VM-CP-33's refusal is not enough on
    // its own, and VM-CP-01 has a refusal but no failure.
    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![23]);
    // A changed image sealed together with a refused unavailable hypervisor: VM-CP-01 and
    // VM-CP-33 stay open, and the refusal keeps its own stamp when a run reads it.
    let mut both = results.clone();
    let mut other = kvm_backend();
    host.observe(true);
    let second = launch(&mut other, &host, &request("exe-3", 1));
    both.negative(ControlledFault::HypervisorUnavailable, sealed(second))
        .unwrap();
    let outcomes = both.outcomes();
    let run = run_of(&outcomes[&check_id(33)][0]);
    // The last failing reading is used, so a failure is never hidden by an earlier pass.
    assert_eq!(
        run.observations().get(&id("cp33.linux.kvm-unavailable")),
        Some(&Observed::Attempt { refused: false })
    );
    let mut refused_only = results_of(&backend, linux());
    refused_only
        .negative(ControlledFault::HypervisorUnavailable, stamped)
        .unwrap();
    let mut gpu_backend = kvm_backend();
    assigned(&mut gpu_backend, GpuIsolation::complete());
    let gpu_anyway = launch(&mut gpu_backend, &host, &gpu_request("exe-4"));
    refused_only
        .negative(ControlledFault::GpuPathUnavailable, sealed(gpu_anyway))
        .unwrap();
    let outcomes = refused_only.outcomes();
    let run = run_of(&outcomes[&check_id(33)][0]);
    let stamp = run.read_from(id("cp33.linux.kvm-unavailable"))[0];
    assert_eq!(
        stamp.origin(),
        StampOrigin::Refusal {
            fault: ControlledFault::HypervisorUnavailable
        }
    );
    assert_eq!(stamp.observed_at(), refused_at);
    assert_eq!(run.refusals(), 1);
    assert_eq!(
        status(&outcomes, 33, &host.judging(OsKind::Linux)),
        failed("cp33.gpu-path-unavailable", Part::Primary)
    );
}

#[test]
fn a_records_guest_assertions_are_never_read() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    // The guest claims another accelerator and an assigned GPU; the host observes KVM
    // and no GPU.
    backend.script_mut().guest = GuestScript {
        accelerator: Some(Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx,
        }),
        devices: Some(DeviceInventory {
            paravirtualized_gpu: false,
            display: false,
            gpus: [ObservedGpu {
                device: gpu(),
                isolation: GpuIsolation::complete(),
            }]
            .into_iter()
            .collect(),
        }),
        ..GuestScript::default()
    };
    let normal = launch(&mut backend, &host, &request("exe-1", 1));
    let anyway = launch(&mut backend, &host, &request("exe-2", 1));
    let plain = launch(&mut backend, &host, &request("exe-3", 1));
    assert!(normal.guest_asserted().accelerator.is_some());
    let mut results = results_of(&backend, linux());
    results.record(normal).unwrap();
    results
        .negative(ControlledFault::HypervisorUnavailable, sealed(anyway))
        .unwrap();
    // A GPU fault needs a launch with a GPU; the guest's claim of one is not one.
    assert_eq!(
        results.negative(ControlledFault::IncompleteIommuGroup, sealed(plain.clone())),
        Err(RecordInputError::FaultNotExercised {
            fault: ControlledFault::IncompleteIommuGroup,
            record: plain.identity(),
        })
    );

    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![1, 33]);
    assert_eq!(
        run_of(&outcomes[&check_id(1)][0])
            .observations()
            .get(&id("cp01.accelerator")),
        Some(&Observed::Value {
            value: "kvm".to_owned()
        })
    );
    let json = serde_json::to_string(&outcomes.values().flatten().collect::<Vec<_>>()).unwrap();
    assert!(!json.contains("whpx"));
    assert!(!json.contains("guest"));
    for outcome in outcomes.values().flatten() {
        assert_eq!(outcome.source_kind(), Some(SourceKind::Host));
        for stamp in run_of(outcome).stamps() {
            assert!(stamp.source().is_host());
        }
    }
}

#[test]
fn records_of_another_backend_build_or_host_or_given_twice_are_refused() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let record = launch(&mut backend, &host, &request("exe-1", 1));

    let mut other_build = FakeBackend::new(
        HypervisorKind::Kvm,
        BackendVersion::new("0.2.0").unwrap(),
        artifact(),
        HostScript::hardware_vm(
            HypervisorKind::Kvm,
            linux(),
            image(),
            configuration(HOST_CONFIG),
        ),
    );
    let foreign = launch(&mut other_build, &host, &request("exe-2", 1));
    let mut results = results_of(&backend, linux());
    assert_eq!(
        results.record(foreign.clone()),
        Err(RecordInputError::OtherBackend {
            record: foreign.identity()
        })
    );
    assert_eq!(
        results.negative(
            ControlledFault::HypervisorUnavailable,
            sealed(foreign.clone())
        ),
        Err(RecordInputError::OtherBackend {
            record: foreign.identity()
        })
    );

    let mut upgraded = results_of(&backend, build(OsKind::Linux, "6.11.0-9"));
    assert_eq!(
        upgraded.record(record.clone()),
        Err(RecordInputError::OtherHost {
            record: record.identity()
        })
    );

    results.record(record.clone()).unwrap();
    assert_eq!(
        results.record(record.clone()),
        Err(RecordInputError::Duplicate {
            record: record.identity()
        })
    );
    assert_eq!(
        results.negative(
            ControlledFault::HypervisorUnavailable,
            sealed(record.clone())
        ),
        Err(RecordInputError::Duplicate {
            record: record.identity()
        })
    );

    // A controlled launch refused for another reason shows nothing about its fault.
    let mut mispinned = request("exe-3", 1);
    mispinned.pinned.backend = digest("yougori/test/probes/backend/v1", &[b"other"]);
    let wrong = refusal(&mut backend, &host, &mispinned);
    assert!(matches!(
        wrong,
        LaunchRefusal::BackendArtifactMismatch { .. }
    ));
    for fault in ControlledFault::ALL {
        let error = results
            .negative(fault, host.stamped(wrong.clone()))
            .unwrap_err();
        assert_eq!(error, RecordInputError::NotRefusedForFault { fault });
        assert!(error.to_string().contains("another reason"));
    }
    assert_eq!(results.normal_launches(), 1);
    assert_eq!(results.negative_launches(), 0);
    for error in [
        RecordInputError::OtherBackend {
            record: record.identity(),
        },
        RecordInputError::OtherHost {
            record: record.identity(),
        },
        RecordInputError::Duplicate {
            record: record.identity(),
        },
    ] {
        assert!(error.to_string().contains(&record.identity().to_string()));
        assert!(serde_json::to_value(&error).unwrap()["error"].is_string());
    }
}

#[test]
fn an_accelerator_outside_vm_cp_01s_list_fails_and_vm_cp_33_names_its_hypervisors() {
    // Host Compute Service is a Windows hypervisor interface the VM-CP-01 list does not
    // name (an open decision, M04): its records fail the accelerator observation.
    let windows = build(OsKind::Windows, "26100.1");
    let host = Host::new(HypervisorKind::Hcs);
    let mut backend = backend_on(windows.clone(), HypervisorKind::Hcs);
    let mut results = results_of(&backend, windows.clone());
    results
        .record(launch(&mut backend, &host, &request("exe-1", 1)))
        .unwrap();
    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![1]);
    let context = host.judging(OsKind::Windows);
    assert_eq!(
        status(&outcomes, 1, &context),
        failed("cp01.accelerator", Part::Primary)
    );

    // VM-CP-33's Windows observation names WHPX: an HCS launch that was not refused
    // fails VM-CP-01 but decides nothing of VM-CP-33.
    results
        .negative(
            ControlledFault::HypervisorUnavailable,
            sealed(launch(&mut backend, &host, &request("exe-2", 1))),
        )
        .unwrap();
    assert_eq!(checks(&results.outcomes()), vec![1]);

    // A WHPX backend on the same host does decide it.
    let whpx_host = Host::new(HypervisorKind::Whpx);
    let mut whpx = backend_on(windows.clone(), HypervisorKind::Whpx);
    let mut whpx_results = results_of(&whpx, windows);
    whpx_results
        .negative(
            ControlledFault::HypervisorUnavailable,
            sealed(launch(&mut whpx, &whpx_host, &request("exe-1", 1))),
        )
        .unwrap();
    let outcomes = whpx_results.outcomes();
    assert_eq!(checks(&outcomes), vec![1, 33]);
    assert_eq!(
        status(&outcomes, 33, &whpx_host.judging(OsKind::Windows)),
        failed("cp33.windows.whpx-unavailable", Part::Primary)
    );
}

#[test]
fn record_inputs_name_every_part_with_its_own_check() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    results
        .negative(
            ControlledFault::HypervisorUnavailable,
            sealed(launch(&mut backend, &host, &request("exe-1", 1))),
        )
        .unwrap();
    let inputs = results.inputs();
    let outcomes = results.outcomes();
    assert_eq!(inputs.len(), outcomes.len());
    for (check_id, outcomes) in &outcomes {
        for outcome in outcomes {
            assert_eq!(outcome.check(), *check_id);
            assert!(check(*check_id).parts().contains(&outcome.part()));
            for observed in run_of(outcome).observations().keys() {
                let entry = expectation(*observed).unwrap();
                assert_eq!((entry.check, entry.part), (*check_id, outcome.part()));
            }
        }
    }
    let json = serde_json::to_value(&outcomes[&check_id(1)][0]).unwrap();
    assert_eq!(json["evidence"]["evidence"], "record");
    assert_eq!(json["evidence"]["run"]["backend"]["kind"], "fake");
    let stamp = &json["evidence"]["run"]["read_from"]["cp01.forced-unavailable-refused"][0];
    assert_eq!(stamp["origin"]["from"], "record");
    assert!(stamp["origin"]["record"].is_string());
    assert_eq!(stamp["origin"]["fact"], "accelerator");
    assert_eq!(stamp["source"], "host_observed");
}

// ---------------------------------------------------------------- configuration facts

fn golden(name: &[u8]) -> Digest {
    digest("yougori/test/probes/golden/v1", &[name])
}

fn approved() -> ConfigurationComparison {
    ConfigurationComparison {
        golden: golden(b"approved"),
        observed: golden(b"approved"),
        network_device: false,
        console: false,
        balloon: false,
        undeclared_pci_transport: false,
    }
}

/// A fake on Linux whose host passes its golden comparison and its listing check to
/// admission, both clean.
fn configured_backend() -> FakeBackend {
    let mut backend = kvm_backend();
    backend.script_mut().configuration_comparison = Some(approved());
    backend.script_mut().interface_listing = Some(HostInterfaceListing::clean());
    backend
}

/// The host's checks of `gpu()` before assignment, made now.
fn checked_now(host: &Host, isolation: GpuIsolation) -> HostObserved<ObservedGpu> {
    HostObserved::stamp(
        ObservedGpu {
            device: gpu(),
            isolation,
        },
        host.registry.now(),
        FRESH,
        configuration(HOST_CONFIG),
    )
}

fn linux_strict() -> HostProfile {
    HostProfile {
        host: linux(),
        backend: BackendKind::Fake,
        profiles: BTreeSet::from([RunProfile::Strict]),
    }
}

#[test]
fn records_with_configuration_facts_decide_vm_cp_02_and_vm_cp_03() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = configured_backend();
    let record = launch(&mut backend, &host, &request("exe-1", 1));
    let mut results = results_of(&backend, linux());
    results.record(record.clone()).unwrap();
    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![2, 3]);
    let context = host.judging(OsKind::Linux);
    // VM-CP-02 lists no positive control, so its observations decide it.
    assert_eq!(status(&outcomes, 2, &context), CheckStatus::Passed);
    // VM-CP-03's control is a test launch with a share device added on purpose.
    assert_eq!(
        status(&outcomes, 3, &context),
        no_control("cp03.planted-share-device-detected")
    );

    let run = run_of(&outcomes[&check_id(2)][0]);
    assert_eq!(
        run.observations().get(&id("cp02.golden-configuration")),
        Some(&Observed::Comparison {
            observed: golden(b"approved"),
            reference: golden(b"approved"),
        })
    );
    for name in [
        "cp02.network-device",
        "cp02.console",
        "cp02.balloon",
        "cp02.undeclared-pci-transport",
    ] {
        assert_eq!(
            run.observations().get(&id(name)),
            Some(&Observed::Presence { present: false }),
            "{name}"
        );
    }
    let stamp = run.read_from(id("cp02.golden-configuration"))[0];
    assert_eq!(
        stamp.origin(),
        StampOrigin::RecordConfiguration {
            record: record.identity(),
            fact: ConfigurationFact::Comparison,
        }
    );
    let comparison = record.configuration_comparison().unwrap();
    assert_eq!(stamp.observed_at(), comparison.observed_at());
    assert_eq!(stamp.clock(), comparison.clock());
    assert_eq!(stamp.fresh_for(), comparison.fresh_for());
    assert_eq!(run.records(), vec![record.identity()]);
    let listing = run_of(&outcomes[&check_id(3)][0]);
    assert_eq!(
        listing.observations().get(&id("cp03.qmp-socket-private")),
        Some(&Observed::Presence { present: true })
    );
    assert_eq!(
        listing
            .observations()
            .get(&id("cp03.shared-filesystem-device")),
        Some(&Observed::Presence { present: false })
    );
    assert_eq!(
        listing.read_from(id("cp03.qmp-socket-private"))[0].origin(),
        StampOrigin::RecordConfiguration {
            record: record.identity(),
            fact: ConfigurationFact::Listing,
        }
    );
    assert!(!listing
        .observations()
        .contains_key(&id("cp03.planted-share-device-detected")));

    // The control: the backend refused a launch with a share device added on purpose as
    // failing the host interface check.
    let mut planted = configured_backend();
    planted.script_mut().interface_listing = Some(HostInterfaceListing {
        share_device: true,
        ..HostInterfaceListing::clean()
    });
    let detected = refusal(&mut planted, &host, &request("exe-2", 1));
    assert!(matches!(
        &detected,
        LaunchRefusal::ConfigurationNotApproved { checks, .. }
            if checks.contains(&ConfigurationCheck::HostInterfaces)
    ));
    let mut with_control = results.clone();
    with_control
        .negative(ControlledFault::PlantedShareDevice, host.stamped(detected))
        .unwrap();
    let outcomes = with_control.outcomes();
    assert_eq!(status(&outcomes, 3, &context), CheckStatus::Passed);
    let run = run_of(&outcomes[&check_id(3)][0]);
    assert_eq!(
        run.observations()
            .get(&id("cp03.planted-share-device-detected")),
        Some(&Observed::Event { happened: true })
    );
    assert_eq!(run.refusals(), 1);
    let report = BoundaryReport::assemble(linux_strict(), with_control.inputs(), &context).unwrap();
    assert!(report.entry(check_id(2)).unwrap().status.passed());
    assert!(report.entry(check_id(3)).unwrap().status.passed());

    // A configuration refused only for not being the golden file's shows nothing about a
    // planted share device.
    let mut drifted = configured_backend();
    drifted.script_mut().configuration_comparison = Some(ConfigurationComparison {
        observed: golden(b"drifted"),
        ..approved()
    });
    let golden_only = refusal(&mut drifted, &host, &request("exe-3", 1));
    assert_eq!(
        results.clone().negative(
            ControlledFault::PlantedShareDevice,
            host.stamped(golden_only)
        ),
        Err(RecordInputError::NotRefusedForFault {
            fault: ControlledFault::PlantedShareDevice
        })
    );
    // A planted launch the backend sealed anyway: the control did not hold.
    let mut missed = results.clone();
    let anyway = launch(&mut configured_backend(), &host, &request("exe-4", 1));
    missed
        .negative(ControlledFault::PlantedShareDevice, sealed(anyway))
        .unwrap();
    assert_eq!(
        status(&missed.outcomes(), 3, &context),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::ControlFailed {
                id: id("cp03.planted-share-device-detected")
            }
        }
    );

    // Under another configuration the records' configuration stamps no longer apply.
    let reconfigured = JudgeContext {
        configuration: configuration("host-b"),
        ..context
    };
    assert!(matches!(
        status(&outcomes, 2, &reconfigured),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            }
        }
    ));
}

#[test]
fn a_record_without_configuration_facts_leaves_vm_cp_02_and_vm_cp_03_not_tested() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    let mut results = results_of(&backend, linux());
    results
        .record(launch(&mut backend, &host, &request("exe-1", 1)))
        .unwrap();
    let mut configured = configured_backend();
    configured.script_mut().interface_listing = None;
    results
        .record(launch(&mut configured, &host, &request("exe-2", 1)))
        .unwrap();
    // Only the second record has a comparison, and neither has a listing.
    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![2]);
    let report = BoundaryReport::assemble(
        linux_strict(),
        results.inputs(),
        &host.judging(OsKind::Linux),
    )
    .unwrap();
    assert_eq!(
        report.entry(check_id(3)).unwrap().status,
        CheckStatus::NotTested {
            reason: super::outcome::NotTestedReason::NotRun
        }
    );
}

#[test]
fn a_records_gpu_orders_decide_vm_cp_31s_checks_before_assignment() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    assigned(&mut backend, GpuIsolation::complete());
    backend.check_gpus_before_assignment(vec![checked_now(&host, GpuIsolation::complete())]);
    host.advance(Duration::from_secs(2));
    let record = launch(&mut backend, &host, &gpu_request("exe-1"));
    assert_eq!(record.gpu_assignments().len(), 1);
    let mut results = results_of(&backend, linux());
    results.record(record.clone()).unwrap();
    // The checks before assignment alone leave the part out: the refusals of an
    // incomplete group and a display-owning GPU are not shown yet.
    assert!(!results.outcomes().contains_key(&check_id(31)));

    let mut faulty = kvm_backend();
    assigned(
        &mut faulty,
        lacking(GpuIsolationCheck::CompleteIsolationGroup),
    );
    let incomplete = refusal(&mut faulty, &host, &gpu_request("exe-2"));
    assigned(
        &mut faulty,
        lacking(GpuIsolationCheck::NoHostDisplayOrOtherUsers),
    );
    let display = refusal(&mut faulty, &host, &gpu_request("exe-3"));
    results
        .negative(
            ControlledFault::IncompleteIommuGroup,
            host.stamped(incomplete),
        )
        .unwrap();
    results
        .negative(ControlledFault::DisplayOwningGpu, host.stamped(display))
        .unwrap();
    let outcomes = results.outcomes();
    assert_eq!(checks(&outcomes), vec![31]);
    // Every observation holds; the control needs nvidia-smi in the guest, which no record
    // holds, so the check stays inconclusive.
    let context = host.judging(OsKind::Linux);
    assert_eq!(
        status(&outcomes, 31, &context),
        no_control("cp31.qualifying-device-assigns")
    );
    let run = run_of(&outcomes[&check_id(31)][0]);
    for name in ["cp31.reset-capability-checked", "cp31.acs-state-checked"] {
        assert_eq!(
            run.observations().get(&id(name)),
            Some(&Observed::Presence { present: true }),
            "{name}"
        );
        let stamps = run.read_from(id(name));
        assert_eq!(stamps.len(), 2, "{name}");
        assert_eq!(
            stamps[0].origin(),
            StampOrigin::RecordConfiguration {
                record: record.identity(),
                fact: ConfigurationFact::GpuChecked { device: gpu() },
            }
        );
        assert_eq!(
            stamps[1].origin(),
            StampOrigin::RecordConfiguration {
                record: record.identity(),
                fact: ConfigurationFact::GpuAssigned { device: gpu() },
            }
        );
        assert!(stamps[0].observed_at() < stamps[1].observed_at());
    }
    assert_eq!(run.records(), vec![record.identity()]);
    assert_eq!(run.refusals(), 2);
    // The checks made before assignment are the run's oldest facts.
    assert_eq!(
        run.age_at(host.registry.now()),
        RecordAge::Observed {
            age: Duration::from_secs(2)
        }
    );
}

#[test]
fn gpu_orders_that_hide_a_check_or_an_acs_bypass_are_refused_before_a_record_exists() {
    let host = Host::new(HypervisorKind::Kvm);
    let mut backend = kvm_backend();
    assigned(&mut backend, GpuIsolation::complete());
    for (execution, isolation) in [
        (
            "exe-1",
            lacking(GpuIsolationCheck::SafeResetAndReassignment),
        ),
        (
            "exe-2",
            GpuIsolation {
                unsafe_settings: BTreeSet::from([UnsafeDeviceSetting::AcsOverride]),
                ..GpuIsolation::complete()
            },
        ),
    ] {
        backend.check_gpus_before_assignment(vec![checked_now(&host, isolation)]);
        host.advance(Duration::from_secs(1));
        let refused = refusal(&mut backend, &host, &gpu_request(execution));
        assert!(
            matches!(
                refused.failed_checks()[0].failure(),
                Some(crate::sandbox::backend::CheckFailure::DeviceNotIsolated { .. })
            ),
            "{refused}"
        );
    }
    // A record with a GPU but without orders decides neither check.
    backend.check_gpus_before_assignment(Vec::new());
    let mut results = results_of(&backend, linux());
    results
        .record(launch(&mut backend, &host, &gpu_request("exe-3")))
        .unwrap();
    let mut no_gpu = kvm_backend();
    no_gpu.check_gpus_before_assignment(vec![checked_now(&host, GpuIsolation::complete())]);
    host.advance(Duration::from_secs(1));
    // An order for a GPU the host did not observe assigned refuses a CPU-only launch.
    assert!(matches!(
        refusal(&mut no_gpu, &host, &request("exe-4", 1)).failed_checks()[0].failure(),
        Some(crate::sandbox::backend::CheckFailure::InventoryDiffersFromProfile { .. })
    ));
    assert!(results.outcomes().is_empty());
}

#[test]
fn vm_cp_31_from_records_reads_not_tested_on_a_host_that_is_not_linux() {
    let windows = build(OsKind::Windows, "26100.1");
    let host = Host::new(HypervisorKind::Whpx);
    let mut backend = backend_on(windows.clone(), HypervisorKind::Whpx);
    assigned(&mut backend, GpuIsolation::complete());
    // A GPU with an incomplete group, assigned anyway: on Linux this decides VM-CP-31.
    let anyway = launch(&mut backend, &host, &gpu_request("exe-1"));
    let mut results = results_of(&backend, windows.clone());
    results
        .negative(ControlledFault::IncompleteIommuGroup, sealed(anyway))
        .unwrap();
    assert!(!results.outcomes().contains_key(&check_id(31)));
    let profile = HostProfile {
        host: windows,
        backend: BackendKind::Fake,
        profiles: BTreeSet::from([RunProfile::Strict, RunProfile::GpuVm]),
    };
    let report =
        BoundaryReport::assemble(profile, results.inputs(), &host.judging(OsKind::Windows))
            .unwrap();
    assert_eq!(
        report.entry(check_id(31)).unwrap().status,
        CheckStatus::NotTested {
            reason: super::outcome::NotTestedReason::NoObservationForHost {
                os: OsKind::Windows
            }
        }
    );
}

/// A process of a host's list, as a runner reads it.
fn listed(pid: u32, parent: u32, image: &str, created: u64, command: Option<&str>) -> ListedProcess {
    ListedProcess {
        pid,
        parent,
        image: image.to_owned(),
        created: Some(created),
        command_line: command.map(|text| text.split_whitespace().map(str::to_owned).collect()),
    }
}

/// `scan`, stamped now as the host observed it.
fn scanned(host: &Host, scan: ProcessScan) -> HostObserved<ProcessScan> {
    HostObserved::stamp(scan, host.registry.now(), FRESH, configuration(HOST_CONFIG))
}

/// The refusal of a launch whose hypervisor process ran emulated.
fn emulated() -> LaunchRefusal {
    LaunchRefusal::NotHardwareVirtualized {
        observed: Accelerator::Emulation {
            emulator: Emulator::Tcg,
        },
    }
}

/// PROVES VM-CP-01 is decided whole on a Windows host once the doctor's process scan is
/// given: a normal WHPX launch, a launch refused for running emulated and a scan with no
/// emulated hypervisor pass it; an emulated hypervisor anywhere on the host fails it, and
/// a hypervisor whose command line could not be read leaves the part out.
#[test]
fn the_examination_scan_decides_vm_cp_01s_process_list() {
    let windows = build(OsKind::Windows, "26300.1");
    let host = Host::new(HypervisorKind::Whpx);
    let mut backend = backend_on(windows.clone(), HypervisorKind::Whpx);
    let mut results = results_of(&backend, windows);
    results
        .record(launch(&mut backend, &host, &request("exe-1", 1)))
        .unwrap();
    results
        .negative(ControlledFault::HypervisorUnavailable, host.stamped(emulated()))
        .unwrap();
    let context = host.judging(OsKind::Windows);
    assert!(!checks(&results.outcomes()).contains(&1), "the process list is open");

    let engine = 10;
    let clean = vec![
        listed(10, 1, "yougori-engine.exe", 100, None),
        listed(20, 10, "qemu-system-x86_64.exe", 200, Some("qemu -accel whpx,kernel-irqchip=off")),
        listed(30, 1, "explorer.exe", 50, None),
    ];
    let mut passing = results.clone();
    passing.scan(scanned(
        &host,
        ProcessScan::build(ScanMoment::Examination, &clean, engine, None),
    ));
    let outcomes = passing.outcomes();
    assert_eq!(status(&outcomes, 1, &context), CheckStatus::Passed);
    let run = run_of(&outcomes[&check_id(1)][0]);
    assert_eq!(
        run.observations().get(&id("cp01.no-tcg-hypervisor")),
        Some(&Observed::Presence { present: false })
    );
    assert_eq!(
        run.read_from(id("cp01.no-tcg-hypervisor"))[0].origin(),
        StampOrigin::ProcessScan {
            moment: ScanMoment::Examination
        }
    );

    // Another program's QEMU without an accelerator runs emulated: the check fails.
    let mut with_emulated = clean.clone();
    with_emulated.push(listed(40, 30, "qemu-system-x86_64.exe", 300, Some("qemu -m 128 -nographic")));
    let mut failing = results.clone();
    failing.scan(scanned(
        &host,
        ProcessScan::build(ScanMoment::Examination, &with_emulated, engine, None),
    ));
    assert_eq!(
        status(&failing.outcomes(), 1, &context),
        failed("cp01.no-tcg-hypervisor", Part::Primary)
    );

    // A hypervisor the scan could not read leaves the observation, and the part, open.
    let mut unread = clean.clone();
    unread.push(listed(50, 1, "qemu-system-aarch64.exe", 300, None));
    let mut open = results.clone();
    open.scan(scanned(
        &host,
        ProcessScan::build(ScanMoment::Examination, &unread, engine, None),
    ));
    assert!(!checks(&open.outcomes()).contains(&1));
}

/// PROVES VM-CP-33 is decided whole on a Windows host by the WHPX and GPU refusals and the
/// scans after them: no start left passes it, a start the refused launch left running fails
/// it whatever another scan shows, and a scan taken without the list from before the attempt
/// decides nothing.
#[test]
fn the_after_refusal_scans_decide_vm_cp_33s_fallback_start() {
    let windows = build(OsKind::Windows, "26300.1");
    let host = Host::new(HypervisorKind::Whpx);
    let backend = backend_on(windows.clone(), HypervisorKind::Whpx);
    let mut results = results_of(&backend, windows);
    results
        .negative(ControlledFault::HypervisorUnavailable, host.stamped(emulated()))
        .unwrap();
    results
        .negative(
            ControlledFault::GpuPathUnavailable,
            host.stamped(LaunchRefusal::Unsupported {
                feature: Feature::GpuAssignment,
            }),
        )
        .unwrap();
    let context = host.judging(OsKind::Windows);
    assert!(!checks(&results.outcomes()).contains(&33), "the fallback start is open");

    let engine = 10;
    let before = vec![
        listed(10, 1, "yougori-engine.exe", 100, None),
        listed(15, 10, "yougori-engine.exe", 150, None),
    ];
    let after_whpx = ScanMoment::AfterRefusal {
        fault: ControlledFault::HypervisorUnavailable,
    };
    let after_gpu = ScanMoment::AfterRefusal {
        fault: ControlledFault::GpuPathUnavailable,
    };
    let mut passing = results.clone();
    passing.scan(scanned(&host, ProcessScan::build(after_whpx, &before, engine, Some(&before))));
    passing.scan(scanned(&host, ProcessScan::build(after_gpu, &before, engine, Some(&before))));
    let outcomes = passing.outcomes();
    assert_eq!(status(&outcomes, 33, &context), CheckStatus::Passed);
    assert_eq!(
        run_of(&outcomes[&check_id(33)][0])
            .observations()
            .get(&id("cp33.fallback-start")),
        Some(&Observed::Presence { present: false })
    );

    // The refused launch left an emulated QEMU running: the check fails.
    let mut leftover = before.clone();
    leftover.push(listed(60, 10, "qemu-system-x86_64.exe", 400, Some("qemu -accel tcg")));
    let mut failing = passing.clone();
    failing.scan(scanned(&host, ProcessScan::build(after_gpu, &leftover, engine, Some(&before))));
    assert_eq!(
        status(&failing.outcomes(), 33, &context),
        failed("cp33.fallback-start", Part::Primary)
    );

    // A scan without the earlier list cannot attribute a start, so it decides nothing.
    let mut blind = results.clone();
    blind.scan(scanned(&host, ProcessScan::build(after_whpx, &leftover, engine, None)));
    assert!(!checks(&blind.outcomes()).contains(&33));
}

/// A drill whose every case went as the plan wants, or with `change` applied to one case.
fn drill(change: Option<(DrillCase, DrillAttempt)>) -> ConnectionDrill {
    let refused = DrillAttempt { refused: 1, admitted: 0, callee_opens: 0 };
    let passed = DrillAttempt { refused: 0, admitted: 1, callee_opens: 1 };
    let mut attempts: std::collections::BTreeMap<DrillCase, DrillAttempt> = DrillCase::ALL
        .into_iter()
        .map(|case| (case, if case.refusal_expected() { refused } else { passed }))
        .collect();
    if let Some((case, attempt)) = change {
        attempts.insert(case, attempt);
    }
    ConnectionDrill { attempts, shared_state: Some(false) }
}

/// PROVES VM-CP-29 is decided from a connection drill's host observations alone: a drill where
/// every negative case was refused with nothing asked of the callee and the granted connections
/// reached it passes the check, its positive control included, each observation stamped as the
/// drill; a transitive connection that went through fails it; an expired grant the host saw no
/// attempt under leaves the part out; a control that did not pass leaves the check inconclusive;
/// shared state fails it; and without a drill nothing of it is decided.
#[test]
fn a_connection_drill_decides_vm_cp_29() {
    let windows = build(OsKind::Windows, "26300.1");
    let host = Host::new(HypervisorKind::Whpx);
    let mut backend = backend_on(windows.clone(), HypervisorKind::Whpx);
    let mut results = results_of(&backend, windows);
    results
        .record(launch(&mut backend, &host, &request("exe-1", 1)))
        .unwrap();
    let context = host.judging(OsKind::Windows);
    assert!(!checks(&results.outcomes()).contains(&29), "no drill, nothing decided");
    let stamped = |drill: ConnectionDrill| HostObserved::stamp(drill, host.registry.now(), FRESH, configuration(HOST_CONFIG));

    let mut passing = results.clone();
    passing.drill(stamped(drill(None)));
    let outcomes = passing.outcomes();
    assert_eq!(status(&outcomes, 29, &context), CheckStatus::Passed);
    let run = run_of(&outcomes[&check_id(29)][0]);
    assert_eq!(run.observations().get(&id("cp29.transitive-connection")), Some(&Observed::Attempt { refused: true }));
    assert_eq!(run.observations().get(&id("cp29.second-grant-passes")), Some(&Observed::Attempt { refused: false }));
    assert_eq!(run.read_from(id("cp29.expired-grant"))[0].origin(), StampOrigin::ConnectionDrill);

    let through = DrillAttempt { refused: 0, admitted: 1, callee_opens: 1 };
    let mut transitive = results.clone();
    transitive.drill(stamped(drill(Some((DrillCase::Transitive, through)))));
    assert_eq!(status(&transitive.outcomes(), 29, &context), failed("cp29.transitive-connection", Part::Primary));

    let unseen = DrillAttempt::default();
    let mut open = results.clone();
    open.drill(stamped(drill(Some((DrillCase::Expired, unseen)))));
    assert!(!checks(&open.outcomes()).contains(&29), "an attempt the host never saw decides nothing");

    let blocked = DrillAttempt { refused: 1, admitted: 0, callee_opens: 0 };
    let mut no_control = results.clone();
    no_control.drill(stamped(drill(Some((DrillCase::TransitiveControl, blocked)))));
    assert!(
        matches!(status(&no_control.outcomes(), 29, &context), CheckStatus::Inconclusive { .. }),
        "the second grant must pass in the same run"
    );

    let mut shared = results.clone();
    let mut sharing = drill(None);
    sharing.shared_state = Some(true);
    shared.drill(stamped(sharing));
    assert_eq!(status(&shared.outcomes(), 29, &context), failed("cp29.shared-caches-and-volumes", Part::Primary));
}
