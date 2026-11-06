//! The provider API adapters through a real CORE-01 registry on a manual clock: reported,
//! not reported, stale and changed reports; VM-D5; exactly one adapter per subject.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use super::adapters::ProviderProbe;
use super::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ComputePlatform, EvidenceRefusal, GpuDeviceSubject,
    HostChange, Observation, ObservationResult, ProbeAdapter, ProbeRegistry, ProviderKind,
    ProviderSubject, RegistryError, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass,
    Staleness, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, Digest, ExecutionCategory, ManualClock, MonotonicTime};
use crate::sandbox_contract::remote::{OfferingKind, OfferingName, ProviderInstance, RegionName};

const SECOND: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3_600);

const CATEGORY: Capability = Capability::RuntimeCategory;
const PLATFORM: Capability = Capability::ComputePlatform;
const CONTAINER: Capability = Capability::ProviderContainer;

/// A registry and a report store on one manual clock, with the provider adapters
/// registered.
struct World {
    clock: Arc<ManualClock>,
    reports: Arc<ProviderReports<ManualClock>>,
    registry: ProbeRegistry<Arc<ManualClock>>,
}

impl World {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(
            1_000_000_000_000,
        )));
        let reports = Arc::new(ProviderReports::new(Arc::clone(&clock)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        register_provider_adapters(&mut registry, &reports).unwrap();
        Self {
            clock,
            reports,
            registry,
        }
    }

    /// Records `report` from a call that started now.
    fn record(&self, report: ProviderReport) -> RecordOutcome {
        self.reports.record(report, self.reports.now()).unwrap()
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    fn refresh(&mut self, capability: Capability, subject: &Subject) -> ObservationResult {
        let envelope = self.registry.refresh(capability, subject).unwrap();
        assert_eq!(envelope.source(), SourceClass::ProviderApi);
        envelope.result().clone()
    }

    fn fresh_for(&self, capability: Capability, subject: &Subject) -> Duration {
        self.registry
            .latest(capability, subject)
            .unwrap()
            .fresh_for()
    }

    fn evaluate(&self, capability: Capability, subject: &Subject) -> Result<(), EvidenceRefusal> {
        let requirement = self.reports.requirement(capability, subject).unwrap();
        self.registry.evaluate(&requirement).map(|_| ())
    }
}

fn provider_of(kind: OfferingKind) -> ProviderKind {
    match kind {
        OfferingKind::ProviderContainer => ProviderKind::RunPod,
        OfferingKind::BareMetal => ProviderKind::Latitude,
        OfferingKind::DedicatedVm | OfferingKind::PerSandboxVmHost => ProviderKind::Crusoe,
    }
}

fn instance_digest(name: &str) -> Digest {
    digest("yougori/test/provider-instance/v1", &[name.as_bytes()])
}

fn instance(kind: OfferingKind, name: &str) -> ProviderInstance {
    ProviderInstance {
        provider: provider_of(kind),
        region: RegionName::new("us-east-1").unwrap(),
        offering: OfferingName::new("gpu-1x").unwrap(),
        kind,
        instance: instance_digest(name),
    }
}

/// What V12's provider port reports about instance `i1` of `kind`.
fn reported(kind: OfferingKind) -> ProviderReport {
    ProviderReport::instance_only(instance(kind, "i1"))
}

fn cuda(version: &str) -> Option<CudaVersion> {
    Some(CudaVersion::new(version).unwrap())
}

fn nvidia(count: u32, version: Option<CudaVersion>) -> Option<ReportedAccelerators> {
    Some(ReportedAccelerators::NvidiaGpus {
        count: NonZeroU32::new(count).unwrap(),
        cuda: version,
    })
}

/// A report with every field reported: gVisor and nvproxy on, one NVIDIA GPU with CUDA
/// 12.4.
fn complete(kind: OfferingKind) -> ProviderReport {
    ProviderReport {
        gvisor: Some(true),
        nvproxy: Some(true),
        accelerators: nvidia(1, cuda("12.4")),
        ..reported(kind)
    }
}

fn runtime_subject(category: ExecutionCategory, instance: Digest) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance,
    }
}

fn runtime(category: ExecutionCategory, report: &ProviderReport) -> Subject {
    Subject::Runtime(runtime_subject(category, report.instance.instance))
}

fn resource(report: &ProviderReport) -> Subject {
    Subject::Provider(ProviderSubject {
        provider: report.instance.provider,
        resource: report.instance.instance,
    })
}

fn supported(detail: SupportDetail) -> ObservationResult {
    ObservationResult::Supported { detail }
}

fn unsupported(reason: UnsupportedReason) -> ObservationResult {
    ObservationResult::Unsupported { reason }
}

fn unknown(reason: UnknownReason) -> ObservationResult {
    ObservationResult::Unknown { reason }
}

fn category_detail(category: ExecutionCategory) -> ObservationResult {
    supported(SupportDetail::RuntimeCategory { category })
}

fn platform_detail(platform: ComputePlatform) -> ObservationResult {
    supported(SupportDetail::ComputePlatform { platform })
}

#[test]
fn a_reported_dedicated_vm_is_a_vm_sandbox_on_provider_api_evidence() {
    let mut world = World::new();
    let report = complete(OfferingKind::DedicatedVm);
    world.record(report.clone());
    let vm = runtime(ExecutionCategory::VmSandbox, &report);
    assert_eq!(
        world.refresh(CATEGORY, &vm),
        category_detail(ExecutionCategory::VmSandbox)
    );
    assert_eq!(world.fresh_for(CATEGORY, &vm), PROVIDER_CATEGORY_FRESH_FOR);
    assert_eq!(world.evaluate(CATEGORY, &vm), Ok(()));
    assert_eq!(
        world.refresh(PLATFORM, &vm),
        platform_detail(ComputePlatform::Cuda)
    );
    assert_eq!(world.fresh_for(PLATFORM, &vm), PROVIDER_COMPUTE_FRESH_FOR);
    assert_eq!(
        world.refresh(CONTAINER, &resource(&report)),
        unsupported(UnsupportedReason::NotAProviderContainer)
    );
    let as_pod = runtime(ExecutionCategory::ProviderContainerRuntime, &report);
    assert_eq!(
        world.refresh(CATEGORY, &as_pod),
        unsupported(UnsupportedReason::DifferentCategory)
    );
    assert_eq!(
        world.refresh(PLATFORM, &as_pod),
        unknown(UnknownReason::InconsistentReport)
    );

    let configuration = world.reports.configuration(&vm).unwrap();
    let offer = RuntimeOffer::observe(
        &world.registry,
        runtime_subject(ExecutionCategory::VmSandbox, report.instance.instance),
        HOUR,
        configuration,
    )
    .unwrap();
    assert_eq!(offer.evidence().source(), SourceClass::ProviderApi);
    assert!(RuntimeRequirement::VmSandbox.admit(&offer).is_ok());
}

#[test]
fn a_provider_container_is_never_a_vm_sandbox() {
    let flags = [None, Some(false), Some(true)];
    let accelerators = [
        None,
        Some(ReportedAccelerators::CpuOnly),
        nvidia(1, None),
        nvidia(8, cuda("12.4")),
    ];
    for gvisor in flags {
        for nvproxy in flags {
            for attached in &accelerators {
                let mut world = World::new();
                let report = ProviderReport {
                    gvisor,
                    nvproxy,
                    accelerators: attached.clone(),
                    ..reported(OfferingKind::ProviderContainer)
                };
                world.record(report.clone());
                let as_vm = runtime(ExecutionCategory::VmSandbox, &report);
                assert_eq!(
                    world.refresh(CATEGORY, &as_vm),
                    unsupported(UnsupportedReason::DifferentCategory),
                    "{report:?}"
                );
                let refusal = RuntimeOffer::observe(
                    &world.registry,
                    runtime_subject(ExecutionCategory::VmSandbox, report.instance.instance),
                    HOUR,
                    world.reports.configuration(&as_vm).unwrap(),
                )
                .unwrap_err();
                assert_eq!(
                    refusal,
                    EvidenceRefusal::Unsupported {
                        capability: CATEGORY,
                        reason: UnsupportedReason::DifferentCategory,
                    }
                );
                assert_ne!(
                    world.refresh(PLATFORM, &as_vm),
                    platform_detail(ComputePlatform::Cuda)
                );
                let pod = runtime(ExecutionCategory::ProviderContainerRuntime, &report);
                assert_eq!(
                    world.refresh(CATEGORY, &pod),
                    category_detail(ExecutionCategory::ProviderContainerRuntime)
                );
            }
        }
    }

    // Admitted as what it is, the pod still never passes a VM-required request.
    let mut world = World::new();
    let report = reported(OfferingKind::ProviderContainer);
    world.record(report.clone());
    let pod = runtime(ExecutionCategory::ProviderContainerRuntime, &report);
    world.refresh(CATEGORY, &pod);
    let offer = RuntimeOffer::observe(
        &world.registry,
        runtime_subject(
            ExecutionCategory::ProviderContainerRuntime,
            report.instance.instance,
        ),
        HOUR,
        world.reports.configuration(&pod).unwrap(),
    )
    .unwrap();
    let refusal = RuntimeRequirement::VmSandbox.admit(&offer).unwrap_err();
    assert_eq!(refusal.decision(), Some("VM-D5"));
}

#[test]
fn a_host_that_launches_per_sandbox_vms_is_never_the_sandbox_itself() {
    for kind in [OfferingKind::BareMetal, OfferingKind::PerSandboxVmHost] {
        let mut world = World::new();
        let report = complete(kind);
        world.record(report.clone());
        for category in [
            ExecutionCategory::VmSandbox,
            ExecutionCategory::ProviderContainerRuntime,
        ] {
            let host = runtime(category, &report);
            assert_eq!(
                world.refresh(CATEGORY, &host),
                unsupported(UnsupportedReason::DifferentCategory),
                "{kind:?}"
            );
            assert_eq!(
                world.refresh(PLATFORM, &host),
                unknown(UnknownReason::InconsistentReport)
            );
        }
        assert_eq!(
            world.refresh(CONTAINER, &resource(&report)),
            unsupported(UnsupportedReason::NotAProviderContainer)
        );
        // The per-sandbox VM is another instance, which the provider never reports.
        let sandbox = Subject::Runtime(runtime_subject(
            ExecutionCategory::VmSandbox,
            digest("yougori/test/remote-vm/v1", &[&[1]]),
        ));
        assert_eq!(
            world.registry.refresh(CATEGORY, &sandbox).unwrap_err(),
            RegistryError::NoAdapter {
                capability: CATEGORY
            }
        );
    }
}

#[test]
fn nothing_is_observed_about_an_instance_the_provider_did_not_report() {
    let mut world = World::new();
    let report = complete(OfferingKind::ProviderContainer);
    for subject in [
        runtime(ExecutionCategory::ProviderContainerRuntime, &report),
        runtime(ExecutionCategory::VmSandbox, &report),
    ] {
        for capability in [CATEGORY, PLATFORM] {
            assert_eq!(
                world.registry.refresh(capability, &subject).unwrap_err(),
                RegistryError::NoAdapter { capability }
            );
            assert_eq!(
                world.reports.requirement(capability, &subject),
                Err(NotProviderObserved::Subject)
            );
        }
    }
    assert_eq!(
        world
            .registry
            .refresh(CONTAINER, &resource(&report))
            .unwrap_err(),
        RegistryError::NoAdapter {
            capability: CONTAINER
        }
    );
    world.record(report.clone());
    // The same resource digest under another provider is not what was reported.
    let elsewhere = Subject::Provider(ProviderSubject {
        provider: ProviderKind::Vast,
        resource: report.instance.instance,
    });
    assert_eq!(
        world.registry.refresh(CONTAINER, &elsewhere).unwrap_err(),
        RegistryError::NoAdapter {
            capability: CONTAINER
        }
    );
    assert_eq!(
        world.refresh(CONTAINER, &resource(&report)),
        supported(SupportDetail::ProviderContainer {
            gvisor: true,
            nvproxy: true
        })
    );
}

#[test]
fn the_compute_platform_comes_only_from_reported_accelerators() {
    let cases = [
        (None, unknown(UnknownReason::NotTested)),
        (
            Some(ReportedAccelerators::CpuOnly),
            platform_detail(ComputePlatform::Cpu),
        ),
        (nvidia(2, None), unknown(UnknownReason::NotTested)),
        (
            nvidia(2, cuda("12.4")),
            platform_detail(ComputePlatform::Cuda),
        ),
    ];
    for kind in [OfferingKind::DedicatedVm, OfferingKind::ProviderContainer] {
        for (accelerators, expected) in &cases {
            let mut world = World::new();
            let report = ProviderReport {
                accelerators: accelerators.clone(),
                ..reported(kind)
            };
            world.record(report.clone());
            let category = report.instance_category().unwrap();
            assert_eq!(
                &world.refresh(PLATFORM, &runtime(category, &report)),
                expected,
                "{report:?}"
            );
        }
    }
}

#[test]
fn container_hardening_is_only_what_the_provider_reported() {
    let cases = [
        (None, None, unknown(UnknownReason::NotTested)),
        (Some(true), None, unknown(UnknownReason::NotTested)),
        (None, Some(false), unknown(UnknownReason::NotTested)),
        (
            Some(false),
            Some(true),
            unknown(UnknownReason::InconsistentReport),
        ),
        (
            Some(false),
            Some(false),
            supported(SupportDetail::ProviderContainer {
                gvisor: false,
                nvproxy: false,
            }),
        ),
        (
            Some(true),
            Some(false),
            supported(SupportDetail::ProviderContainer {
                gvisor: true,
                nvproxy: false,
            }),
        ),
        (
            Some(true),
            Some(true),
            supported(SupportDetail::ProviderContainer {
                gvisor: true,
                nvproxy: true,
            }),
        ),
    ];
    for (gvisor, nvproxy, expected) in cases {
        let mut world = World::new();
        let report = ProviderReport {
            gvisor,
            nvproxy,
            ..reported(OfferingKind::ProviderContainer)
        };
        world.record(report.clone());
        assert_eq!(world.refresh(CONTAINER, &resource(&report)), expected);
        // A VM reported with hardening flags is still not a container.
        let mut world = World::new();
        let vm = ProviderReport {
            gvisor,
            nvproxy,
            ..reported(OfferingKind::DedicatedVm)
        };
        world.record(vm.clone());
        assert_eq!(
            world.refresh(CONTAINER, &resource(&vm)),
            unsupported(UnsupportedReason::NotAProviderContainer)
        );
    }
}

/// Each capability, the subject it is observed on, and its freshness.
fn observed(report: &ProviderReport) -> [(Capability, Subject, Duration); 3] {
    [
        (CONTAINER, resource(report), PROVIDER_CONTAINER_FRESH_FOR),
        (
            CATEGORY,
            runtime(ExecutionCategory::ProviderContainerRuntime, report),
            PROVIDER_CATEGORY_FRESH_FOR,
        ),
        (
            PLATFORM,
            runtime(ExecutionCategory::ProviderContainerRuntime, report),
            PROVIDER_COMPUTE_FRESH_FOR,
        ),
    ]
}

#[test]
fn freshness_counts_from_the_calls_start_and_a_stale_report_reads_not_tested() {
    let report = complete(OfferingKind::ProviderContainer);
    for (capability, subject, fresh_for) in observed(&report) {
        let mut world = World::new();
        let started = world.reports.now();
        // The call took 10 s; it is recorded with the time it started.
        world.advance(10 * SECOND);
        world.reports.record(report.clone(), started).unwrap();
        assert!(matches!(
            world.refresh(capability, &subject),
            ObservationResult::Supported { .. }
        ));
        assert_eq!(
            world.fresh_for(capability, &subject),
            fresh_for - 10 * SECOND
        );
        world.advance(fresh_for - 10 * SECOND + SECOND);
        assert!(matches!(
            world.evaluate(capability, &subject),
            Err(EvidenceRefusal::Stale {
                staleness: Staleness::TooOld { .. },
                ..
            })
        ));
        // Observed again from the same, now stale report: not tested, never supported.
        assert_eq!(
            world.refresh(capability, &subject),
            unknown(UnknownReason::NotTested)
        );
        assert_eq!(world.fresh_for(capability, &subject), Duration::ZERO);
        assert_eq!(
            world.evaluate(capability, &subject),
            Err(EvidenceRefusal::Unknown {
                capability,
                reason: UnknownReason::NotTested,
            })
        );
        // A new call makes it fresh again under the same configuration.
        assert!(matches!(
            world.record(report.clone()),
            RecordOutcome::Refreshed { .. }
        ));
        world.refresh(capability, &subject);
        assert_eq!(world.evaluate(capability, &subject), Ok(()));
    }
}

#[test]
fn a_changed_report_changes_the_fingerprint_and_old_evidence_no_longer_applies() {
    let before = complete(OfferingKind::ProviderContainer);
    let after = ProviderReport {
        accelerators: nvidia(2, cuda("12.4")),
        ..before.clone()
    };
    for (capability, subject, _) in observed(&before) {
        let mut world = World::new();
        let RecordOutcome::New { configuration: old } = world.record(before.clone()) else {
            panic!("the first report is new");
        };
        world.refresh(capability, &subject);
        assert_eq!(world.evaluate(capability, &subject), Ok(()));
        world.advance(SECOND);
        let RecordOutcome::Changed { previous, current } = world.record(after.clone()) else {
            panic!("the report changed");
        };
        assert_eq!(previous, old);
        assert_ne!(current, old);
        assert_eq!(world.reports.configuration(&subject), Some(current));
        assert_eq!(
            world.evaluate(capability, &subject),
            Err(EvidenceRefusal::FingerprintChanged {
                capability,
                observed_under: old,
                current,
            })
        );
        assert_eq!(world.registry.invalidate_configuration(previous), 1);
        world.refresh(capability, &subject);
        assert_eq!(
            world
                .registry
                .latest(capability, &subject)
                .unwrap()
                .configuration(),
            current
        );
        assert_eq!(world.evaluate(capability, &subject), Ok(()));
    }
}

#[test]
fn every_reported_field_is_part_of_the_fingerprint() {
    let base = complete(OfferingKind::ProviderContainer);
    let mut variants = vec![ProviderReport::instance_only(base.instance.clone())];
    let mut changed = base.clone();
    changed.instance.region = RegionName::new("eu-west-1").unwrap();
    variants.push(changed);
    let mut changed = base.clone();
    changed.instance.offering = OfferingName::new("gpu-2x").unwrap();
    variants.push(changed);
    let mut changed = base.clone();
    changed.instance.kind = OfferingKind::DedicatedVm;
    variants.push(changed);
    let mut changed = base.clone();
    changed.instance.provider = ProviderKind::Vast;
    variants.push(changed);
    let mut changed = base.clone();
    changed.instance.instance = instance_digest("i2");
    variants.push(changed);
    for (gvisor, nvproxy) in [(None, Some(true)), (Some(false), Some(true))] {
        variants.push(ProviderReport {
            gvisor,
            nvproxy,
            ..base.clone()
        });
    }
    variants.push(ProviderReport {
        nvproxy: None,
        ..base.clone()
    });
    for accelerators in [
        None,
        Some(ReportedAccelerators::CpuOnly),
        nvidia(1, None),
        nvidia(2, cuda("12.4")),
        nvidia(1, cuda("12.8")),
    ] {
        variants.push(ProviderReport {
            accelerators,
            ..base.clone()
        });
    }
    let mut seen = vec![base.configuration().unwrap()];
    for variant in &variants {
        let configuration = variant.configuration().unwrap();
        assert!(!seen.contains(&configuration), "{variant:?}");
        seen.push(configuration);
    }
    assert_eq!(
        base.configuration().unwrap(),
        base.clone().configuration().unwrap()
    );
    assert!(CudaVersion::new("12.4 ").is_err());
    assert!(CudaVersion::new("").is_err());
}

#[test]
fn reports_are_recorded_in_call_order_from_one_provider() {
    let world = World::new();
    let report = reported(OfferingKind::DedicatedVm);
    let early = world.reports.now();
    world.advance(SECOND);
    let RecordOutcome::New { configuration } = world.record(report.clone()) else {
        panic!("the first report is new");
    };
    let in_force = world.reports.get(&report.instance.instance).unwrap();
    assert_eq!(in_force.started_at(), world.reports.now());
    assert_eq!(in_force.configuration(), configuration);
    assert_eq!(in_force.report(), &report);

    // A call that started earlier but answered later does not replace it.
    let late_answer = complete(OfferingKind::DedicatedVm);
    assert_eq!(
        world.reports.record(late_answer, early),
        Ok(RecordOutcome::Superseded {
            in_force_started_at: in_force.started_at()
        })
    );
    assert_eq!(world.reports.get(&report.instance.instance), Some(in_force));

    let future = MonotonicTime::from_nanos(world.reports.now().as_nanos() + 1);
    assert_eq!(
        world.reports.record(report.clone(), future),
        Err(ReportError::StartedAfterNow {
            started_at: future,
            now: world.reports.now(),
        })
    );
    let mut other = report.clone();
    other.instance.provider = ProviderKind::Nebius;
    let refusal = world
        .reports
        .record(other, world.reports.now())
        .unwrap_err();
    assert_eq!(
        refusal,
        ReportError::ProviderChanged {
            recorded: ProviderKind::Crusoe,
            reported: ProviderKind::Nebius,
        }
    );
    assert!(refusal.to_string().contains("never changes silently"));

    assert_eq!(world.reports.all().len(), 1);
    assert_eq!(
        world.reports.forget(&report.instance.instance),
        Some(configuration)
    );
    assert_eq!(world.reports.forget(&report.instance.instance), None);
    assert!(world.reports.all().is_empty());
}

#[test]
fn registration_adds_three_provider_api_adapters_once() {
    let mut world = World::new();
    for capability in [CONTAINER, CATEGORY, PLATFORM] {
        assert_eq!(
            world.registry.sources(capability),
            vec![SourceClass::ProviderApi]
        );
    }
    let again = Arc::new(ProviderReports::new(Arc::clone(&world.clock)));
    assert_eq!(
        register_provider_adapters(&mut world.registry, &again),
        Err(RegistryError::AlreadyRegistered {
            capability: CONTAINER,
            source: SourceClass::ProviderApi,
        })
    );

    // Beside host probes of the same capabilities, and refused as a whole when only one
    // of the three is already taken.
    let clock = Arc::new(ManualClock::default());
    let reports = Arc::new(ProviderReports::new(Arc::clone(&clock)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    registry
        .register(Box::new(FakeProbe::runtime_category(
            SourceClass::HostProbe,
        )))
        .unwrap();
    registry
        .register(Box::new(FakeProbe::new(PLATFORM, SourceClass::HostProbe)))
        .unwrap();
    registry
        .register(Box::new(FakeProbe::new(PLATFORM, SourceClass::ProviderApi)))
        .unwrap();
    assert_eq!(
        register_provider_adapters(&mut registry, &reports),
        Err(RegistryError::AlreadyRegistered {
            capability: PLATFORM,
            source: SourceClass::ProviderApi,
        })
    );
    assert!(!registry.is_registered(CONTAINER));
    assert_eq!(registry.sources(CATEGORY), vec![SourceClass::HostProbe]);

    for capability in ProviderCapability::ALL {
        let probe = ProviderProbe {
            capability,
            reports: Arc::clone(&reports),
        };
        assert_eq!(probe.host_changes(), Vec::<HostChange>::new());
        assert_eq!(probe.source(), SourceClass::ProviderApi);
        assert_eq!(probe.capability(), capability.capability());
    }
}

#[test]
fn exactly_one_adapter_observes_each_remote_subject_and_none_a_host_subject() {
    let mut world = World::new();
    // Host probes as host_evidence registers them: the local runtimes it bound and the
    // GPUs of this machine, here scripted for one WSL runtime and one GPU.
    let host_category =
        Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe).scripted_only());
    let host_platform = Arc::new(FakeProbe::new(PLATFORM, SourceClass::HostProbe).scripted_only());
    world
        .registry
        .register(Box::new(Arc::clone(&host_category)))
        .unwrap();
    world
        .registry
        .register(Box::new(Arc::clone(&host_platform)))
        .unwrap();

    let pod = complete(OfferingKind::ProviderContainer);
    let vm = ProviderReport {
        instance: instance(OfferingKind::DedicatedVm, "i2"),
        ..complete(OfferingKind::DedicatedVm)
    };
    let metal = ProviderReport {
        instance: instance(OfferingKind::BareMetal, "i3"),
        ..complete(OfferingKind::BareMetal)
    };
    for report in [&pod, &vm, &metal] {
        world.record(report.clone());
    }
    // A local runtime that even shares a reported instance digest stays the host's.
    let local = runtime(ExecutionCategory::SharedKernelGpuRuntime, &pod);
    let configuration = world.reports.configuration(&resource(&pod)).unwrap();
    host_category.respond(
        &local,
        Observation::supported(
            configuration,
            HOUR,
            SupportDetail::RuntimeCategory {
                category: ExecutionCategory::SharedKernelGpuRuntime,
            },
        ),
    );
    host_platform.respond(
        &local,
        Observation::supported(
            configuration,
            HOUR,
            SupportDetail::ComputePlatform {
                platform: ComputePlatform::Cuda,
            },
        ),
    );
    for capability in [CATEGORY, PLATFORM] {
        let envelope = world.registry.refresh(capability, &local).unwrap();
        assert_eq!(envelope.source(), SourceClass::HostProbe);
    }

    let probes = ProviderCapability::ALL.map(|capability| ProviderProbe {
        capability,
        reports: Arc::clone(&world.reports),
    });
    for report in [&pod, &vm, &metal] {
        for category in ExecutionCategory::ALL {
            let subject = runtime(category, report);
            let remote = matches!(
                category,
                ExecutionCategory::VmSandbox | ExecutionCategory::ProviderContainerRuntime
            );
            for probe in &probes {
                let runtime_capability = probe.capability != ProviderCapability::ProviderContainer;
                assert_eq!(
                    probe.observes(&subject),
                    remote && runtime_capability,
                    "{category:?} {:?}",
                    probe.capability
                );
            }
            if remote {
                for capability in [CATEGORY, PLATFORM] {
                    let envelope = world.registry.refresh(capability, &subject).unwrap();
                    assert_eq!(envelope.source(), SourceClass::ProviderApi);
                }
            }
        }
        let provider = resource(report);
        for probe in &probes {
            assert_eq!(
                probe.observes(&provider),
                probe.capability == ProviderCapability::ProviderContainer
            );
        }
        assert_eq!(
            world
                .registry
                .refresh(CONTAINER, &provider)
                .unwrap()
                .source(),
            SourceClass::ProviderApi
        );
    }
    // A local runtime on an unreported instance, a native Metal runner and a GPU of this
    // machine are never the provider's.
    let wsl = Subject::Runtime(runtime_subject(
        ExecutionCategory::SharedKernelGpuRuntime,
        instance_digest("wsl"),
    ));
    let metal_runner = Subject::Runtime(runtime_subject(
        ExecutionCategory::HostProcessModelRuntime,
        instance_digest("mac"),
    ));
    let gpu = Subject::GpuDevice(GpuDeviceSubject {
        machine: digest("yougori/test/machine/v1", &[b"m1"]),
        device: pod.instance.instance,
    });
    for subject in [&wsl, &metal_runner, &gpu] {
        for probe in &probes {
            assert!(!probe.observes(subject));
        }
    }
}

#[test]
fn every_other_capability_is_refused_with_a_typed_result() {
    let world = World::new();
    let report = complete(OfferingKind::ProviderContainer);
    world.record(report.clone());
    let pod = runtime(ExecutionCategory::ProviderContainerRuntime, &report);
    for capability in Capability::ALL {
        match ProviderCapability::try_from(capability) {
            Ok(observed) => {
                assert_eq!(observed.capability(), capability);
                let subject = if capability == CONTAINER {
                    resource(&report)
                } else {
                    pod.clone()
                };
                let requirement = world.reports.requirement(capability, &subject).unwrap();
                assert_eq!(requirement.max_age, observed.fresh_for());
                assert_eq!(requirement.minimum_source, capability.weakest_source());
            }
            Err(refusal) => {
                assert_eq!(refusal, NotProviderObserved::Capability { capability });
                assert!(refusal
                    .to_string()
                    .contains("not observed from the provider API"));
                assert_eq!(world.reports.requirement(capability, &pod), Err(refusal));
            }
        }
    }
    assert_eq!(
        ProviderCapability::ALL.map(ProviderCapability::capability),
        [CONTAINER, CATEGORY, PLATFORM]
    );
    // The right capability on the wrong kind of subject is not the provider's either.
    assert_eq!(
        world.reports.requirement(CONTAINER, &pod),
        Err(NotProviderObserved::Subject)
    );
}
