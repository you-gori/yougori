//! Registry, gate and fallback flows on fake adapters driven by a manual clock.

use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::fakes::FakeProbe;
use super::*;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, ExecutionCategory, ManualClock, MonotonicTime,
};

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);

fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

fn config(profile: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", "580.1"), ("profile", profile)]).unwrap()
}

fn vllm(version: &str) -> BackendRelease {
    BackendRelease::new(Backend::Vllm, version).unwrap()
}

fn runtime_on(
    category: ExecutionCategory,
    release: BackendRelease,
    instance: &str,
) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release,
        instance: digest("yougori/test/instance/v1", &[instance.as_bytes()]),
    }
}

fn wsl_runtime() -> RuntimeSubject {
    runtime_on(
        ExecutionCategory::SharedKernelGpuRuntime,
        vllm("0.31.0"),
        "wsl",
    )
}

fn hypervisor(kind: HypervisorKind) -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: kind,
    })
}

fn pod() -> Subject {
    Subject::Provider(ProviderSubject {
        provider: ProviderKind::RunPod,
        resource: digest("yougori/test/pod/v1", &[b"pod-1"]),
    })
}

fn start() -> ManualClock {
    ManualClock::new(MonotonicTime::ZERO)
}

fn register(registry: &mut ProbeRegistry<&ManualClock>, probe: &Arc<FakeProbe>) {
    registry.register(Box::new(Arc::clone(probe))).unwrap();
}

fn plain(configuration: ConfigurationFingerprint) -> Observation {
    Observation::supported(configuration, HOUR, SupportDetail::Plain)
}

fn mode_on(release: &BackendRelease, configuration: ConfigurationFingerprint) -> Observation {
    Observation::supported(
        configuration,
        HOUR,
        SupportDetail::BackendMode {
            release: release.clone(),
        },
    )
}

fn host_policy() -> EvidencePolicy {
    EvidencePolicy {
        minimum_source: SourceClass::HostProbe,
        max_age: MINUTE,
    }
}

fn profile(runtime: RuntimeSubject, permitted: &[Optimization]) -> RuntimeProfile {
    RuntimeProfile {
        runtime,
        configuration: config("p1"),
        permitted: permitted
            .iter()
            .map(|optimization| (*optimization, host_policy()))
            .collect(),
    }
}

fn request(entries: &[(Optimization, Necessity)]) -> LoaderRequest {
    LoaderRequest {
        optimizations: entries.iter().copied().collect(),
    }
}

#[test]
fn registry_refresh_and_invalidation_follow_the_manual_clock() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::hypervisor_availability());
    register(&mut registry, &probe);
    let whpx = hypervisor(HypervisorKind::Whpx);
    probe.respond(
        &whpx,
        Observation::supported(
            config("a"),
            Duration::from_secs(600),
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        ),
    );
    let requirement = Requirement::host_only(
        Capability::HypervisorAvailable,
        whpx.clone(),
        MINUTE,
        config("a"),
    );

    assert!(matches!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::Missing { .. })
    ));
    let envelope = registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap();
    assert_eq!(envelope.observed_at(), MonotonicTime::ZERO);
    assert_eq!(envelope.source(), SourceClass::HostProbe);
    assert_eq!(envelope.clock(), registry.session());
    assert!(registry.evaluate(&requirement).is_ok());

    clock.advance(MINUTE);
    assert!(registry.evaluate(&requirement).is_ok());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::Stale {
            capability: Capability::HypervisorAvailable,
            staleness: Staleness::TooOld {
                age: Duration::from_secs(61),
                limit: MINUTE,
            },
        })
    );

    let refreshed = registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap();
    assert_eq!(refreshed.observed_at(), clock.now());
    assert_eq!(registry.evidence().len(), 1);
    assert_eq!(probe.calls(), 2);
    let satisfied = registry.evaluate(&requirement).unwrap();
    assert_eq!(
        satisfied.observed_at(),
        MonotonicTime::from_nanos(61_000_000_000)
    );

    assert!(registry.invalidate(Capability::HypervisorAvailable, &whpx));
    assert!(!registry.invalidate(Capability::HypervisorAvailable, &whpx));
    assert!(matches!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::Missing { .. })
    ));

    registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap();
    assert_eq!(registry.invalidate_subject(&whpx), 1);
    assert!(registry
        .latest(Capability::HypervisorAvailable, &whpx)
        .is_none());

    registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap();
    assert_eq!(registry.invalidate_configuration(config("b")), 0);
    assert_eq!(registry.invalidate_configuration(config("a")), 1);
    assert!(registry.evidence().is_empty());
}

#[test]
fn a_configuration_change_invalidates_evidence_through_the_registry() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(Capability::IoUring, SourceClass::HostProbe));
    register(&mut registry, &probe);
    let runtime = Subject::Runtime(wsl_runtime());
    probe.respond(&runtime, plain(config("kernel-6.6")));
    registry.refresh(Capability::IoUring, &runtime).unwrap();

    let after_upgrade = Requirement::host_only(
        Capability::IoUring,
        runtime.clone(),
        HOUR,
        config("kernel-6.12"),
    );
    assert_eq!(
        registry.evaluate(&after_upgrade),
        Err(EvidenceRefusal::FingerprintChanged {
            capability: Capability::IoUring,
            observed_under: config("kernel-6.6"),
            current: config("kernel-6.12"),
        })
    );

    assert_eq!(registry.invalidate_configuration(config("kernel-6.6")), 1);
    let before_upgrade = Requirement::host_only(
        Capability::IoUring,
        runtime.clone(),
        HOUR,
        config("kernel-6.6"),
    );
    assert!(matches!(
        registry.evaluate(&before_upgrade),
        Err(EvidenceRefusal::Missing { .. })
    ));

    probe.respond(
        &runtime,
        Observation::unsupported(
            config("kernel-6.12"),
            HOUR,
            UnsupportedReason::DisabledByPolicy,
        ),
    );
    registry.refresh(Capability::IoUring, &runtime).unwrap();
    assert_eq!(
        registry.evaluate(&after_upgrade).unwrap_err().remedy(),
        Remedy::ChooseSupportedRuntime
    );
}

#[test]
fn a_guest_report_is_refused_for_a_host_only_requirement() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let guest = Arc::new(FakeProbe::guest_report(Capability::IoUring));
    register(&mut registry, &guest);
    let runtime = Subject::Runtime(runtime_on(
        ExecutionCategory::VmSandbox,
        vllm("0.31.0"),
        "vm-1",
    ));
    guest.respond(&runtime, plain(config("p1")));
    registry.refresh(Capability::IoUring, &runtime).unwrap();

    let host_only =
        Requirement::host_only(Capability::IoUring, runtime.clone(), HOUR, config("p1"));
    let refusal = registry.evaluate(&host_only).unwrap_err();
    assert_eq!(
        refusal,
        EvidenceRefusal::SourceTooWeak {
            capability: Capability::IoUring,
            observed: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
        }
    );

    let in_guest = Requirement::new(
        Capability::IoUring,
        runtime,
        SourceClass::GuestReport,
        HOUR,
        config("p1"),
    );
    assert_eq!(
        registry.evaluate(&in_guest).unwrap().source(),
        SourceClass::GuestReport
    );
}

/// Relays what a guest agent sends; the guest controls the payload, not the source class.
struct GuestAgent {
    payload: serde_json::Value,
}

impl ProbeAdapter for GuestAgent {
    fn capability(&self) -> Capability {
        Capability::HypervisorAvailable
    }

    fn source(&self) -> SourceClass {
        SourceClass::GuestReport
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observe(&self, _subject: &Subject) -> Observation {
        match serde_json::from_value::<ObservationResult>(self.payload["result"].clone()) {
            Ok(result) => Observation {
                configuration: config("a"),
                fresh_for: HOUR,
                result,
            },
            Err(_) => Observation::unknown(config("a"), HOUR, UnknownReason::InconsistentReport),
        }
    }
}

#[test]
fn a_forged_guest_claim_stays_a_guest_report() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let whpx = hypervisor(HypervisorKind::Whpx);
    let forged = serde_json::json!({
        "source": "host_probe",
        "all_probes_passed": true,
        "result": {"outcome": "supported", "detail": {"kind": "hypervisor", "hypervisor": "whpx"}},
    });
    registry
        .register(Box::new(GuestAgent { payload: forged }))
        .unwrap();
    let envelope = registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap()
        .clone();
    assert_eq!(envelope.source(), SourceClass::GuestReport);
    let requirement = Requirement::new(
        Capability::HypervisorAvailable,
        whpx.clone(),
        SourceClass::GuestReport,
        HOUR,
        config("a"),
    );
    assert!(matches!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::SourceTooWeak {
            required: SourceClass::HostProbe,
            ..
        })
    ));

    let mut forged_envelope = serde_json::to_value(envelope).unwrap();
    forged_envelope["source"] = "host_probe".into();
    let read_back: EvidenceEnvelope = serde_json::from_value(forged_envelope).unwrap();
    assert_eq!(read_back.source(), SourceClass::HostProbe);
    assert_eq!(
        registry
            .latest(Capability::HypervisorAvailable, &whpx)
            .unwrap()
            .source(),
        SourceClass::GuestReport
    );
}

#[test]
fn legacy_ipc_and_vmm_handles_are_separate_capabilities() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let legacy = Arc::new(FakeProbe::legacy_cuda_ipc());
    let vmm = Arc::new(FakeProbe::cuda_vmm_shareable_handles());
    register(&mut registry, &legacy);
    register(&mut registry, &vmm);
    assert_eq!(
        registry.register(Box::new(FakeProbe::legacy_cuda_ipc())),
        Err(RegistryError::AlreadyRegistered {
            capability: Capability::CudaIpcLegacy,
            source: SourceClass::HostProbe,
        })
    );

    let runtime = Subject::Runtime(wsl_runtime());
    legacy.respond(
        &runtime,
        Observation::supported(config("p1"), HOUR, SupportDetail::CudaIpcLegacy),
    );
    vmm.respond(
        &runtime,
        Observation::unsupported(config("p1"), HOUR, UnsupportedReason::OperationFailed),
    );
    registry
        .refresh(Capability::CudaIpcLegacy, &runtime)
        .unwrap();
    registry
        .refresh(Capability::CudaIpcVmmShareableHandle, &runtime)
        .unwrap();

    let legacy_needed = Requirement::host_only(
        Capability::CudaIpcLegacy,
        runtime.clone(),
        HOUR,
        config("p1"),
    );
    let vmm_needed = Requirement::host_only(
        Capability::CudaIpcVmmShareableHandle,
        runtime.clone(),
        HOUR,
        config("p1"),
    );
    assert_eq!(
        registry.evaluate(&legacy_needed).unwrap().detail(),
        &SupportDetail::CudaIpcLegacy
    );
    assert_eq!(
        registry.evaluate(&vmm_needed),
        Err(EvidenceRefusal::Unsupported {
            capability: Capability::CudaIpcVmmShareableHandle,
            reason: UnsupportedReason::OperationFailed,
        })
    );

    vmm.respond(
        &runtime,
        Observation::supported(config("p1"), HOUR, SupportDetail::CudaIpcLegacy),
    );
    registry
        .refresh(Capability::CudaIpcVmmShareableHandle, &runtime)
        .unwrap();
    assert_eq!(
        registry.evaluate(&vmm_needed),
        Err(EvidenceRefusal::Unknown {
            capability: Capability::CudaIpcVmmShareableHandle,
            reason: UnknownReason::InconsistentReport,
        })
    );

    vmm.respond(
        &runtime,
        Observation::supported(
            config("p1"),
            HOUR,
            SupportDetail::CudaIpcVmmShareableHandle {
                handle: ShareableHandle::PosixFileDescriptor,
            },
        ),
    );
    registry
        .refresh(Capability::CudaIpcVmmShareableHandle, &runtime)
        .unwrap();
    assert!(registry.evaluate(&vmm_needed).is_ok());
}

#[test]
fn the_hypervisor_check_reports_each_hypervisor() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::hypervisor_availability());
    register(&mut registry, &probe);
    let whpx = hypervisor(HypervisorKind::Whpx);
    let hcs = hypervisor(HypervisorKind::Hcs);
    let kvm = hypervisor(HypervisorKind::Kvm);
    probe.respond(
        &whpx,
        Observation::supported(
            config("a"),
            HOUR,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        ),
    );
    probe.respond(
        &hcs,
        Observation::unsupported(config("a"), HOUR, UnsupportedReason::HypervisorUnavailable),
    );
    for subject in [&whpx, &hcs, &kvm] {
        registry
            .refresh(Capability::HypervisorAvailable, subject)
            .unwrap();
    }
    let needs = |subject: &Subject| {
        Requirement::host_only(
            Capability::HypervisorAvailable,
            subject.clone(),
            HOUR,
            config("a"),
        )
    };
    assert_eq!(
        registry.evaluate(&needs(&whpx)).unwrap().detail(),
        &SupportDetail::Hypervisor {
            hypervisor: HypervisorKind::Whpx
        }
    );
    let unavailable = registry.evaluate(&needs(&hcs)).unwrap_err();
    assert_eq!(unavailable.remedy(), Remedy::EnableHypervisorYourself);
    assert_eq!(
        registry.evaluate(&needs(&kvm)),
        Err(EvidenceRefusal::Unknown {
            capability: Capability::HypervisorAvailable,
            reason: UnknownReason::NotTested,
        })
    );

    let calls = probe.calls();
    assert_eq!(
        registry
            .refresh(
                Capability::HypervisorAvailable,
                &Subject::Runtime(wsl_runtime())
            )
            .unwrap_err(),
        RegistryError::WrongSubjectKind {
            capability: Capability::HypervisorAvailable,
            expected: SubjectKind::Hypervisor,
            found: SubjectKind::Runtime,
        }
    );
    assert_eq!(probe.calls(), calls);
}

#[test]
fn the_provider_container_check_is_a_provider_report() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::provider_container());
    register(&mut registry, &probe);
    probe.respond(
        &pod(),
        Observation::supported(
            config("pod"),
            HOUR,
            SupportDetail::ProviderContainer {
                gvisor: true,
                nvproxy: true,
            },
        ),
    );
    registry
        .refresh(Capability::ProviderContainer, &pod())
        .unwrap();
    let provider = Requirement::new(
        Capability::ProviderContainer,
        pod(),
        SourceClass::ProviderApi,
        HOUR,
        config("pod"),
    );
    assert_eq!(
        registry.evaluate(&provider).unwrap().detail(),
        &SupportDetail::ProviderContainer {
            gvisor: true,
            nvproxy: true
        }
    );
    let host_only =
        Requirement::host_only(Capability::ProviderContainer, pod(), HOUR, config("pod"));
    assert!(matches!(
        registry.evaluate(&host_only),
        Err(EvidenceRefusal::SourceTooWeak {
            observed: SourceClass::ProviderApi,
            ..
        })
    ));

    let mut pod_side = ProbeRegistry::new(&clock);
    let self_report = Arc::new(FakeProbe::guest_report(Capability::ProviderContainer));
    register(&mut pod_side, &self_report);
    self_report.respond(
        &pod(),
        Observation::supported(
            config("pod"),
            HOUR,
            SupportDetail::ProviderContainer {
                gvisor: true,
                nvproxy: true,
            },
        ),
    );
    pod_side
        .refresh(Capability::ProviderContainer, &pod())
        .unwrap();
    let lenient = Requirement::new(
        Capability::ProviderContainer,
        pod(),
        SourceClass::GuestReport,
        HOUR,
        config("pod"),
    );
    assert!(matches!(
        pod_side.evaluate(&lenient),
        Err(EvidenceRefusal::SourceTooWeak {
            required: SourceClass::ProviderApi,
            ..
        })
    ));

    probe.respond(
        &pod(),
        Observation::unsupported(
            config("pod"),
            HOUR,
            UnsupportedReason::NotAProviderContainer,
        ),
    );
    registry
        .refresh(Capability::ProviderContainer, &pod())
        .unwrap();
    assert!(matches!(
        registry.evaluate(&provider),
        Err(EvidenceRefusal::Unsupported {
            reason: UnsupportedReason::NotAProviderContainer,
            ..
        })
    ));
}

#[test]
fn adapters_that_change_host_state_are_refused() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    for change in HostChange::ALL {
        let probe = FakeProbe::new(Capability::GpuDirectStorage, SourceClass::HostProbe);
        probe.declare_host_change(change);
        let refused = registry.register(Box::new(probe)).unwrap_err();
        assert_eq!(
            refused,
            RegistryError::ChangesHostState {
                capability: Capability::GpuDirectStorage,
                changes: vec![change],
            }
        );
        assert!(refused.to_string().contains("only observe"));
    }
    assert!(!registry.is_registered(Capability::GpuDirectStorage));

    let probe = Arc::new(FakeProbe::new(
        Capability::GpuDirectStorage,
        SourceClass::HostProbe,
    ));
    register(&mut registry, &probe);
    let runtime = Subject::Runtime(wsl_runtime());
    let other = Subject::Runtime(runtime_on(
        ExecutionCategory::VmSandbox,
        vllm("0.31.0"),
        "vm-1",
    ));
    for subject in [&runtime, &other] {
        probe.respond(subject, plain(config("p1")));
        registry
            .refresh(Capability::GpuDirectStorage, subject)
            .unwrap();
    }
    probe.declare_host_change(HostChange::PowerPolicy);
    assert!(matches!(
        registry.refresh(Capability::GpuDirectStorage, &runtime),
        Err(RegistryError::ChangesHostState { .. })
    ));
    assert_eq!(probe.calls(), 2);
    assert!(registry.evidence().is_empty());
}

#[test]
fn refresh_needs_a_registered_adapter() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    assert_eq!(
        registry
            .refresh(Capability::CudaCheckpoint, &Subject::Runtime(wsl_runtime()))
            .unwrap_err(),
        RegistryError::NoAdapter {
            capability: Capability::CudaCheckpoint
        }
    );
}

#[test]
fn an_optimization_without_evidence_falls_back_or_refuses() {
    let clock = start();
    let registry = ProbeRegistry::new(&clock);
    let gate = LoaderGate::recorded();
    let profile = profile(wsl_runtime(), &[Optimization::IoUring]);

    let plan = gate
        .plan(
            &profile,
            &request(&[(Optimization::IoUring, Necessity::Optional)]),
            &registry,
        )
        .unwrap();
    assert!(plan.is_ordinary_loader());
    assert!(!plan.is_enabled(Optimization::IoUring));
    assert!(matches!(
        plan.ordinary().get(&Optimization::IoUring),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::Missing { .. }
        })
    ));

    let refusal = gate
        .plan(
            &profile,
            &request(&[(Optimization::IoUring, Necessity::Required)]),
            &registry,
        )
        .unwrap_err();
    assert_eq!(refusal.optimization, Optimization::IoUring);
    assert_eq!(refusal.remedy(), Remedy::RunCheck);
    assert!(refusal.to_string().contains("io_uring is required"));

    let empty = gate
        .plan(&profile, &LoaderRequest::default(), &registry)
        .unwrap();
    assert!(empty.is_ordinary_loader());
    assert!(empty.ordinary().is_empty());
}

#[test]
fn an_optimization_with_fresh_trusted_evidence_is_enabled_until_it_goes_stale() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(Capability::IoUring, SourceClass::HostProbe));
    register(&mut registry, &probe);
    let runtime = wsl_runtime();
    probe.respond(&Subject::Runtime(runtime.clone()), plain(config("p1")));
    registry
        .refresh(Capability::IoUring, &Subject::Runtime(runtime.clone()))
        .unwrap();
    let gate = LoaderGate::recorded();
    let profile = profile(runtime, &[Optimization::IoUring]);
    let wanted = request(&[(Optimization::IoUring, Necessity::Optional)]);

    let plan = gate.plan(&profile, &wanted, &registry).unwrap();
    assert!(plan.is_enabled(Optimization::IoUring));
    assert_eq!(
        plan.evidence_for(Optimization::IoUring).unwrap().source(),
        SourceClass::HostProbe
    );
    assert_eq!(plan.enabled_set(), BTreeSet::from([Optimization::IoUring]));

    clock.advance(MINUTE + Duration::from_nanos(1));
    let plan = gate.plan(&profile, &wanted, &registry).unwrap();
    assert!(plan.is_ordinary_loader());
    assert!(matches!(
        plan.ordinary().get(&Optimization::IoUring),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::Stale { .. }
        })
    ));

    let restarted = ProbeRegistry::new(&clock);
    assert_ne!(restarted.session(), registry.session());
    let plan = gate.plan(&profile, &wanted, &restarted).unwrap();
    assert!(matches!(
        plan.ordinary().get(&Optimization::IoUring),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::Missing { .. }
        })
    ));
}

#[test]
fn support_evidence_never_enables_what_the_profile_does_not_permit() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(Capability::IoUring, SourceClass::HostProbe));
    register(&mut registry, &probe);
    let runtime = runtime_on(ExecutionCategory::VmSandbox, vllm("0.31.0"), "vm-1");
    probe.respond(&Subject::Runtime(runtime.clone()), plain(config("p1")));
    registry
        .refresh(Capability::IoUring, &Subject::Runtime(runtime.clone()))
        .unwrap();
    let gate = LoaderGate::recorded();
    let strict = profile(runtime, &[]);

    let plan = gate
        .plan(
            &strict,
            &request(&[(Optimization::IoUring, Necessity::Optional)]),
            &registry,
        )
        .unwrap();
    assert_eq!(
        plan.ordinary().get(&Optimization::IoUring),
        Some(&NotEnabled::NotPermitted)
    );
    let refusal = gate
        .plan(
            &strict,
            &request(&[(Optimization::IoUring, Necessity::Required)]),
            &registry,
        )
        .unwrap_err();
    assert_eq!(refusal.reason, NotEnabled::NotPermitted);
    assert_eq!(refusal.remedy(), Remedy::UseOrdinaryLoader);
}

#[test]
fn evidence_counts_only_for_the_exact_runtime_and_profile() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(
        Capability::GpuDirectStorage,
        SourceClass::HostProbe,
    ));
    register(&mut registry, &probe);
    let observed = wsl_runtime();
    probe.respond(&Subject::Runtime(observed.clone()), plain(config("p1")));
    registry
        .refresh(
            Capability::GpuDirectStorage,
            &Subject::Runtime(observed.clone()),
        )
        .unwrap();
    let gate = LoaderGate::recorded();
    let wanted = request(&[(Optimization::GpuDirectStorage, Necessity::Optional)]);

    for other in [
        runtime_on(
            ExecutionCategory::SharedKernelGpuRuntime,
            vllm("0.31.0"),
            "other",
        ),
        runtime_on(
            ExecutionCategory::SharedKernelGpuRuntime,
            vllm("0.29.0"),
            "wsl",
        ),
        runtime_on(ExecutionCategory::VmSandbox, vllm("0.31.0"), "wsl"),
    ] {
        let plan = gate
            .plan(
                &profile(other, &[Optimization::GpuDirectStorage]),
                &wanted,
                &registry,
            )
            .unwrap();
        assert!(matches!(
            plan.ordinary().get(&Optimization::GpuDirectStorage),
            Some(NotEnabled::Evidence {
                refusal: EvidenceRefusal::Missing { .. }
            })
        ));
    }

    let mut changed = profile(observed.clone(), &[Optimization::GpuDirectStorage]);
    changed.configuration = config("p2");
    let plan = gate.plan(&changed, &wanted, &registry).unwrap();
    assert!(matches!(
        plan.ordinary().get(&Optimization::GpuDirectStorage),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::FingerprintChanged { .. }
        })
    ));

    let exact = gate
        .plan(
            &profile(observed, &[Optimization::GpuDirectStorage]),
            &wanted,
            &registry,
        )
        .unwrap();
    assert!(exact.is_enabled(Optimization::GpuDirectStorage));
}

#[test]
fn guest_evidence_meets_only_a_guest_report_policy() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let guest = Arc::new(FakeProbe::guest_report(Capability::CudaCheckpoint));
    register(&mut registry, &guest);
    let runtime = runtime_on(ExecutionCategory::VmSandbox, vllm("0.31.0"), "vm-1");
    guest.respond(&Subject::Runtime(runtime.clone()), plain(config("p1")));
    registry
        .refresh(
            Capability::CudaCheckpoint,
            &Subject::Runtime(runtime.clone()),
        )
        .unwrap();
    let gate = LoaderGate::recorded();
    let wanted = request(&[(Optimization::CudaCheckpoint, Necessity::Optional)]);

    let host = profile(runtime.clone(), &[Optimization::CudaCheckpoint]);
    let plan = gate.plan(&host, &wanted, &registry).unwrap();
    assert!(matches!(
        plan.ordinary().get(&Optimization::CudaCheckpoint),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::SourceTooWeak { .. }
        })
    ));

    let mut in_guest = host;
    in_guest.permitted.insert(
        Optimization::CudaCheckpoint,
        EvidencePolicy {
            minimum_source: SourceClass::GuestReport,
            max_age: MINUTE,
        },
    );
    let plan = gate.plan(&in_guest, &wanted, &registry).unwrap();
    assert!(plan.is_enabled(Optimization::CudaCheckpoint));

    let mut fixture_policy = in_guest;
    fixture_policy.permitted.insert(
        Optimization::CudaCheckpoint,
        EvidencePolicy {
            minimum_source: SourceClass::Fixture,
            max_age: MINUTE,
        },
    );
    let fixture_registry_clock = start();
    let mut fixtures = ProbeRegistry::new(&fixture_registry_clock);
    let fixture = Arc::new(FakeProbe::new(
        Capability::CudaCheckpoint,
        SourceClass::Fixture,
    ));
    register(&mut fixtures, &fixture);
    fixture.respond(&Subject::Runtime(runtime.clone()), plain(config("p1")));
    fixtures
        .refresh(Capability::CudaCheckpoint, &Subject::Runtime(runtime))
        .unwrap();
    let plan = gate.plan(&fixture_policy, &wanted, &fixtures).unwrap();
    assert!(matches!(
        plan.ordinary().get(&Optimization::CudaCheckpoint),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::SourceTooWeak {
                observed: SourceClass::Fixture,
                ..
            }
        })
    ));
}

/// A registry with host-probe evidence for both vLLM 0.31.0 backend modes.
fn backend_modes<'c>(
    clock: &'c ManualClock,
    runtime: &RuntimeSubject,
) -> ProbeRegistry<&'c ManualClock> {
    let mut registry = ProbeRegistry::new(clock);
    let subject = Subject::Runtime(runtime.clone());
    for capability in [Capability::ZeroCopyPreload, Capability::SleepWeightOffload] {
        let probe = Arc::new(FakeProbe::new(capability, SourceClass::HostProbe));
        probe.respond(&subject, mode_on(&runtime.release, config("p1")));
        register(&mut registry, &probe);
        registry.refresh(capability, &subject).unwrap();
    }
    registry
}

#[test]
fn vllm_0_31_0_preload_with_sleep_offload_is_refused_while_each_alone_is_allowed() {
    let clock = start();
    let runtime = wsl_runtime();
    let registry = backend_modes(&clock, &runtime);
    let gate = LoaderGate::recorded();
    let profile = profile(
        runtime,
        &[
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
        ],
    );
    let plan =
        |entries: &[(Optimization, Necessity)]| gate.plan(&profile, &request(entries), &registry);

    for mode in [
        Optimization::ZeroCopyPreload,
        Optimization::SleepWeightOffload,
    ] {
        let alone = plan(&[(mode, Necessity::Required)]).unwrap();
        assert!(alone.is_enabled(mode));
        assert!(alone.ordinary().is_empty());
    }

    let refusal = plan(&[
        (Optimization::ZeroCopyPreload, Necessity::Required),
        (Optimization::SleepWeightOffload, Necessity::Required),
    ])
    .unwrap_err();
    assert!(matches!(
        &refusal.reason,
        NotEnabled::Conflict {
            refusal: ModeRefusal::DocumentedConflict { source, .. },
            ..
        } if source == VLLM_0_31_0_PRELOAD_DOC
    ));
    assert_eq!(refusal.remedy(), Remedy::UseOneModeAtATime);

    let preload_first = plan(&[
        (Optimization::ZeroCopyPreload, Necessity::Required),
        (Optimization::SleepWeightOffload, Necessity::Optional),
    ])
    .unwrap();
    assert_eq!(
        preload_first.enabled_set(),
        BTreeSet::from([Optimization::ZeroCopyPreload])
    );
    assert!(matches!(
        preload_first
            .ordinary()
            .get(&Optimization::SleepWeightOffload),
        Some(NotEnabled::Conflict {
            with: Optimization::ZeroCopyPreload,
            ..
        })
    ));

    let sleep_first = plan(&[
        (Optimization::ZeroCopyPreload, Necessity::Optional),
        (Optimization::SleepWeightOffload, Necessity::Required),
    ])
    .unwrap();
    assert_eq!(
        sleep_first.enabled_set(),
        BTreeSet::from([Optimization::SleepWeightOffload])
    );

    let neither = plan(&[
        (Optimization::ZeroCopyPreload, Necessity::Optional),
        (Optimization::SleepWeightOffload, Necessity::Optional),
    ])
    .unwrap();
    assert!(neither.is_ordinary_loader());
    assert_eq!(neither.ordinary().len(), 2);
}

#[test]
fn backend_modes_on_an_unknown_release_are_never_assumed() {
    let clock = start();
    let gate = LoaderGate::recorded();
    for release in [vllm("0.29.0"), vllm("0.31.1")] {
        let runtime = runtime_on(ExecutionCategory::SharedKernelGpuRuntime, release, "wsl");
        let registry = backend_modes(&clock, &runtime);
        let profile = profile(
            runtime,
            &[
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ],
        );
        for mode in [
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
        ] {
            let plan = gate
                .plan(
                    &profile,
                    &request(&[(mode, Necessity::Optional)]),
                    &registry,
                )
                .unwrap();
            assert!(matches!(
                plan.ordinary().get(&mode),
                Some(NotEnabled::Release {
                    refusal: ModeRefusal::UnknownRelease { .. }
                })
            ));
            let refusal = gate
                .plan(
                    &profile,
                    &request(&[(mode, Necessity::Required)]),
                    &registry,
                )
                .unwrap_err();
            assert_eq!(refusal.remedy(), Remedy::UseRecordedBackendRelease);
        }
    }
}

#[test]
fn a_checkpoint_is_capability_gated_and_kept_apart_from_other_modes() {
    let clock = start();
    let runtime = wsl_runtime();
    let mut registry = backend_modes(&clock, &runtime);
    let checkpoint = Arc::new(FakeProbe::new(
        Capability::CudaCheckpoint,
        SourceClass::HostProbe,
    ));
    checkpoint.respond(&Subject::Runtime(runtime.clone()), plain(config("p1")));
    register(&mut registry, &checkpoint);
    registry
        .refresh(
            Capability::CudaCheckpoint,
            &Subject::Runtime(runtime.clone()),
        )
        .unwrap();
    let gate = LoaderGate::recorded();
    let profile = profile(
        runtime,
        &[
            Optimization::CudaCheckpoint,
            Optimization::SleepWeightOffload,
        ],
    );

    let alone = gate
        .plan(
            &profile,
            &request(&[(Optimization::CudaCheckpoint, Necessity::Required)]),
            &registry,
        )
        .unwrap();
    assert!(alone.is_enabled(Optimization::CudaCheckpoint));

    let together = gate
        .plan(
            &profile,
            &request(&[
                (Optimization::CudaCheckpoint, Necessity::Optional),
                (Optimization::SleepWeightOffload, Necessity::Optional),
            ]),
            &registry,
        )
        .unwrap();
    assert!(together.is_ordinary_loader());
    assert!(matches!(
        together.ordinary().get(&Optimization::CudaCheckpoint),
        Some(NotEnabled::Conflict {
            refusal: ModeRefusal::NotTestedTogether { .. },
            ..
        })
    ));
}

#[test]
fn legacy_ipc_evidence_never_enables_vmm_ipc() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let legacy = Arc::new(FakeProbe::legacy_cuda_ipc());
    register(&mut registry, &legacy);
    let runtime = wsl_runtime();
    legacy.respond(
        &Subject::Runtime(runtime.clone()),
        Observation::supported(config("p1"), HOUR, SupportDetail::CudaIpcLegacy),
    );
    registry
        .refresh(
            Capability::CudaIpcLegacy,
            &Subject::Runtime(runtime.clone()),
        )
        .unwrap();
    let gate = LoaderGate::recorded();
    let profile = profile(
        runtime,
        &[
            Optimization::CudaIpcLegacy,
            Optimization::CudaIpcVmmShareableHandle,
        ],
    );
    let plan = gate
        .plan(
            &profile,
            &request(&[
                (Optimization::CudaIpcLegacy, Necessity::Optional),
                (Optimization::CudaIpcVmmShareableHandle, Necessity::Optional),
            ]),
            &registry,
        )
        .unwrap();
    assert_eq!(
        plan.enabled_set(),
        BTreeSet::from([Optimization::CudaIpcLegacy])
    );
    assert!(matches!(
        plan.ordinary()
            .get(&Optimization::CudaIpcVmmShareableHandle),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::Missing {
                capability: Capability::CudaIpcVmmShareableHandle
            }
        })
    ));
}

/// The settings a runtime runs with under `plan`, with authority on `registry`'s clock.
fn settings_for(registry: &ProbeRegistry<&ManualClock>, plan: &LoaderPlan) -> RuntimeSettings {
    RuntimeSettings {
        execution_category: plan.runtime().category,
        network: BTreeSet::new(),
        authority: AuthorityGrant {
            epoch: AuthorizationEpoch::FIRST,
            clock: registry.session(),
            expires_at: MonotonicTime::from_nanos(u64::MAX),
        },
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::from([digest("yougori/test/artifact/v1", &[b"weights"])]),
        },
        loader: plan.enabled_set(),
        batch_size: NonZeroU32::MIN,
        residency: Residency::Device,
    }
}

#[test]
fn a_fallback_stays_within_what_the_gate_enabled() {
    let clock = start();
    let runtime = wsl_runtime();
    let registry = backend_modes(&clock, &runtime);
    let gate = LoaderGate::recorded();
    let plan = gate
        .plan(
            &profile(runtime, &[Optimization::ZeroCopyPreload]),
            &request(&[(Optimization::ZeroCopyPreload, Necessity::Optional)]),
            &registry,
        )
        .unwrap();
    let authorized = settings_for(&registry, &plan);
    let guard =
        |proposed: RuntimeSettings| guard_fallback(&gate, &registry, &plan, &authorized, proposed);

    let mut ordinary = authorized.clone();
    ordinary.loader.clear();
    ordinary.residency = Residency::HostMemory;
    let approved = guard(ordinary).unwrap();
    assert_eq!(
        approved.changes(),
        &BTreeSet::from([AllowedChange::Loader, AllowedChange::Residency])
    );

    let mut sleep = authorized.clone();
    sleep.loader = BTreeSet::from([Optimization::SleepWeightOffload]);
    assert!(matches!(
        guard(sleep).unwrap_err().violations(),
        [FallbackViolation::EnablesUngatedOptimization { .. }]
    ));

    let mut into_vm = authorized.clone();
    into_vm.execution_category = ExecutionCategory::VmSandbox;
    assert!(guard(into_vm).is_err());
}

/// The guard runs the backend-mode rules itself: a plan made under a table that recorded
/// a tested pair does not carry that pair past a guard whose rules have no such record.
#[test]
fn the_guard_applies_its_own_mode_rules_to_the_loader() {
    let clock = start();
    let tested_release = vllm("9.9.9");
    let runtime = runtime_on(
        ExecutionCategory::SharedKernelGpuRuntime,
        tested_release.clone(),
        "wsl",
    );
    let registry = backend_modes(&clock, &runtime);
    let tested = LoaderGate::new(
        BackendModeRules::new([BackendModeRule {
            release: tested_release,
            supported: BTreeSet::from([
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ]),
            tested_together: BTreeSet::from([ModePair::new(
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            )
            .unwrap()]),
            conflicts: Vec::new(),
        }])
        .unwrap(),
    );
    let both = [
        (Optimization::ZeroCopyPreload, Necessity::Required),
        (Optimization::SleepWeightOffload, Necessity::Required),
    ];
    let plan = tested
        .plan(
            &profile(
                runtime,
                &[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload,
                ],
            ),
            &request(&both),
            &registry,
        )
        .unwrap();
    assert_eq!(plan.enabled_set().len(), 2);
    let authorized = settings_for(&registry, &plan);
    assert!(guard_fallback(&tested, &registry, &plan, &authorized, authorized.clone()).is_ok());
    let refused = guard_fallback(
        &LoaderGate::recorded(),
        &registry,
        &plan,
        &authorized,
        authorized.clone(),
    )
    .unwrap_err();
    assert!(matches!(
        refused.violations(),
        [FallbackViolation::IncompatibleModes {
            refusal: ModeRefusal::UnknownRelease { .. }
        }]
    ));
}

/// Review finding 7: the observation time was read after the probe returned, so a 50 s
/// probe made 110 s old evidence pass a 60 s maximum age.
#[test]
fn a_slow_probe_is_stamped_when_it_started() {
    struct SlowProbe {
        clock: Arc<ManualClock>,
        takes: Duration,
    }

    impl ProbeAdapter for SlowProbe {
        fn capability(&self) -> Capability {
            Capability::IoUring
        }

        fn source(&self) -> SourceClass {
            SourceClass::HostProbe
        }

        fn host_changes(&self) -> Vec<HostChange> {
            Vec::new()
        }

        fn observe(&self, _subject: &Subject) -> Observation {
            self.clock.advance(self.takes);
            plain(config("p1"))
        }
    }

    let clock = Arc::new(start());
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    registry
        .register(Box::new(SlowProbe {
            clock: Arc::clone(&clock),
            takes: Duration::from_secs(50),
        }))
        .unwrap();
    let runtime = Subject::Runtime(wsl_runtime());
    let envelope = registry.refresh(Capability::IoUring, &runtime).unwrap();
    assert_eq!(envelope.observed_at(), MonotonicTime::ZERO);
    assert_eq!(clock.now(), MonotonicTime::from_nanos(50_000_000_000));

    let requirement = Requirement::host_only(Capability::IoUring, runtime, MINUTE, config("p1"));
    assert!(registry.evaluate(&requirement).is_ok());
    clock.advance(MINUTE);
    assert_eq!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::Stale {
            capability: Capability::IoUring,
            staleness: Staleness::TooOld {
                age: Duration::from_secs(110),
                limit: MINUTE,
            },
        })
    );
}

/// Review finding 3: the registry read `source()` on every refresh, so an adapter
/// registered as a guest report could later claim to be a host probe.
#[test]
fn the_source_class_is_fixed_at_registration() {
    struct Relay {
        claims_host: AtomicBool,
    }

    impl ProbeAdapter for Relay {
        fn capability(&self) -> Capability {
            Capability::HypervisorAvailable
        }

        fn source(&self) -> SourceClass {
            if self.claims_host.load(Ordering::SeqCst) {
                SourceClass::HostProbe
            } else {
                SourceClass::GuestReport
            }
        }

        fn host_changes(&self) -> Vec<HostChange> {
            Vec::new()
        }

        fn observe(&self, _subject: &Subject) -> Observation {
            Observation::supported(
                config("a"),
                HOUR,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Whpx,
                },
            )
        }
    }

    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let relay = Arc::new(Relay {
        claims_host: AtomicBool::new(false),
    });
    registry.register(Box::new(Arc::clone(&relay))).unwrap();
    relay.claims_host.store(true, Ordering::SeqCst);
    let whpx = hypervisor(HypervisorKind::Whpx);
    let envelope = registry
        .refresh(Capability::HypervisorAvailable, &whpx)
        .unwrap();
    assert_eq!(envelope.source(), SourceClass::GuestReport);
    assert_eq!(
        registry.sources(Capability::HypervisorAvailable),
        vec![SourceClass::GuestReport]
    );
    let host_only =
        Requirement::host_only(Capability::HypervisorAvailable, whpx, HOUR, config("a"));
    assert!(matches!(
        registry.evaluate(&host_only),
        Err(EvidenceRefusal::SourceTooWeak {
            observed: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
            ..
        })
    ));
}

fn category_confirmed(category: ExecutionCategory) -> Observation {
    Observation::supported(
        config("launch"),
        HOUR,
        SupportDetail::RuntimeCategory { category },
    )
}

#[test]
fn one_capability_can_have_one_adapter_per_source() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let host = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe).scripted_only());
    let provider = Arc::new(FakeProbe::runtime_category(SourceClass::ProviderApi).scripted_only());
    register(&mut registry, &host);
    register(&mut registry, &provider);
    assert_eq!(
        registry.sources(Capability::RuntimeCategory),
        vec![SourceClass::ProviderApi, SourceClass::HostProbe]
    );
    assert_eq!(
        registry.register(Box::new(FakeProbe::runtime_category(
            SourceClass::HostProbe
        ))),
        Err(RegistryError::AlreadyRegistered {
            capability: Capability::RuntimeCategory,
            source: SourceClass::HostProbe,
        })
    );

    let local = runtime_on(ExecutionCategory::VmSandbox, vllm("0.31.0"), "vm-1");
    let remote = runtime_on(
        ExecutionCategory::ProviderContainerRuntime,
        vllm("0.31.0"),
        "pod-1",
    );
    host.respond(
        &Subject::Runtime(local.clone()),
        category_confirmed(ExecutionCategory::VmSandbox),
    );
    provider.respond(
        &Subject::Runtime(remote.clone()),
        category_confirmed(ExecutionCategory::ProviderContainerRuntime),
    );
    for (runtime, source) in [
        (&local, SourceClass::HostProbe),
        (&remote, SourceClass::ProviderApi),
    ] {
        let envelope = registry
            .refresh(
                Capability::RuntimeCategory,
                &Subject::Runtime(runtime.clone()),
            )
            .unwrap();
        assert_eq!(envelope.source(), source);
    }
    let vm = RuntimeOffer::observe(&registry, local, HOUR, config("launch")).unwrap();
    let pod = RuntimeOffer::observe(&registry, remote, HOUR, config("launch")).unwrap();
    assert!(RuntimeRequirement::VmSandbox.admit(&vm).is_ok());
    assert!(RuntimeRequirement::VmSandbox.admit(&pod).is_err());

    let nobody = Subject::Runtime(runtime_on(
        ExecutionCategory::HostProcessModelRuntime,
        vllm("0.31.0"),
        "metal",
    ));
    assert_eq!(
        registry
            .refresh(Capability::RuntimeCategory, &nobody)
            .unwrap_err(),
        RegistryError::NoAdapter {
            capability: Capability::RuntimeCategory
        }
    );
    let contested = Subject::Runtime(wsl_runtime());
    host.respond(
        &contested,
        category_confirmed(ExecutionCategory::SharedKernelGpuRuntime),
    );
    provider.respond(
        &contested,
        category_confirmed(ExecutionCategory::SharedKernelGpuRuntime),
    );
    let calls = host.calls() + provider.calls();
    assert!(matches!(
        registry.refresh(Capability::RuntimeCategory, &contested),
        Err(RegistryError::AmbiguousAdapters { .. })
    ));
    assert_eq!(host.calls() + provider.calls(), calls);
}

// The scratch tests of the R1a review, kept as refusal tests: each passed only while its
// gap existed.

/// R1a: a custom table marked the recorded vLLM 0.31.0 conflict as tested together and
/// the gate enabled both modes.
#[test]
fn review_a_custom_table_cannot_combine_preload_and_sleep_on_vllm_0_31_0() {
    let tested: BackendModeRule = serde_json::from_value(serde_json::json!({
        "release": {"backend": "vllm", "version": "0.31.0"},
        "supported": ["zero_copy_preload", "sleep_weight_offload"],
        "tested_together": [["zero_copy_preload", "sleep_weight_offload"]],
        "conflicts": []
    }))
    .unwrap();
    assert!(matches!(
        BackendModeRules::new([tested.clone()]),
        Err(ModeRuleError::TestedAndConflicting { .. })
    ));

    let mut silent = tested;
    silent.tested_together.clear();
    let gate = LoaderGate::new(BackendModeRules::new([silent]).unwrap());
    let clock = start();
    let runtime = wsl_runtime();
    let registry = backend_modes(&clock, &runtime);
    let refusal = gate
        .plan(
            &profile(
                runtime,
                &[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload,
                ],
            ),
            &request(&[
                (Optimization::ZeroCopyPreload, Necessity::Required),
                (Optimization::SleepWeightOffload, Necessity::Required),
            ]),
            &registry,
        )
        .unwrap_err();
    assert!(matches!(
        refusal.reason,
        NotEnabled::Conflict {
            refusal: ModeRefusal::DocumentedConflict { .. },
            ..
        }
    ));
}

/// R1a: the guard approved a listed loader that never passed the gate and combined
/// documented-incompatible modes.
#[test]
fn review_the_guard_refuses_a_baseline_that_never_passed_the_gate() {
    let clock = start();
    let runtime = wsl_runtime();
    let registry = backend_modes(&clock, &runtime);
    let gate = LoaderGate::recorded();
    let plan = gate
        .plan(
            &profile(
                runtime,
                &[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload,
                ],
            ),
            &request(&[
                (Optimization::ZeroCopyPreload, Necessity::Optional),
                (Optimization::SleepWeightOffload, Necessity::Optional),
            ]),
            &registry,
        )
        .unwrap();
    assert!(plan.is_ordinary_loader());
    let authorized: RuntimeSettings = serde_json::from_value(serde_json::json!({
        "execution_category": "shared_kernel_gpu_runtime",
        "network": [],
        "authority": {"epoch": 1, "clock": registry.session(), "expires_at": 1000},
        "artifact_verification": {"verification": "verified", "artifacts": []},
        "loader": ["zero_copy_preload", "sleep_weight_offload", "gpu_direct_storage"],
        "batch_size": 8,
        "residency": "device"
    }))
    .unwrap();
    let mut proposed = authorized.clone();
    proposed.batch_size = NonZeroU32::new(4).unwrap();
    let violations = guard_fallback(&gate, &registry, &plan, &authorized, proposed)
        .unwrap_err()
        .violations()
        .to_vec();
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(matches!(
        &violations[0],
        FallbackViolation::EnablesUngatedOptimization { added } if added.len() == 3
    ));
    assert!(matches!(
        &violations[1],
        FallbackViolation::IncompatibleModes {
            refusal: ModeRefusal::DocumentedConflict { .. }
        }
    ));
}

/// R1a: a plan outlived its evidence, and a fallback could drop a required mode.
#[test]
fn review_a_plan_needs_its_evidence_and_keeps_required_modes() {
    let clock = start();
    let runtime = wsl_runtime();
    let subject = Subject::Runtime(runtime.clone());
    let mut registry = ProbeRegistry::new(&clock);
    let preload = Arc::new(FakeProbe::new(
        Capability::ZeroCopyPreload,
        SourceClass::HostProbe,
    ));
    preload.respond(&subject, mode_on(&runtime.release, config("p1")));
    register(&mut registry, &preload);
    registry
        .refresh(Capability::ZeroCopyPreload, &subject)
        .unwrap();
    let gate = LoaderGate::recorded();
    let plan = gate
        .plan(
            &profile(runtime, &[Optimization::ZeroCopyPreload]),
            &request(&[(Optimization::ZeroCopyPreload, Necessity::Required)]),
            &registry,
        )
        .unwrap();
    let authorized = settings_for(&registry, &plan);
    assert!(guard_fallback(&gate, &registry, &plan, &authorized, authorized.clone()).is_ok());

    let mut dropped = authorized.clone();
    dropped.loader.clear();
    assert!(matches!(
        guard_fallback(&gate, &registry, &plan, &authorized, dropped)
            .unwrap_err()
            .violations(),
        [FallbackViolation::DropsRequiredOptimization { .. }]
    ));

    assert_eq!(registry.invalidate_configuration(config("p1")), 1);
    assert!(matches!(
        guard_fallback(&gate, &registry, &plan, &authorized, authorized.clone())
            .unwrap_err()
            .violations(),
        [FallbackViolation::LoaderEvidenceNoLongerHolds {
            refusal: EvidenceRefusal::Missing { .. },
            ..
        }]
    ));
    clock.advance(HOUR);
    assert!(matches!(
        plan.recheck(Optimization::ZeroCopyPreload, &registry),
        Err(EvidenceRefusal::Stale {
            staleness: Staleness::TooOld { .. },
            ..
        })
    ));
    assert!(guard_fallback(&gate, &registry, &plan, &authorized, authorized.clone()).is_err());
}

/// R1a: provider-container evidence played no part in admission, so the same pod offered
/// under the caller's VM label was admitted.
#[test]
fn review_provider_container_evidence_alone_admits_nothing() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let pods = Arc::new(FakeProbe::provider_container());
    register(&mut registry, &pods);
    pods.respond(
        &pod(),
        Observation::supported(
            config("pod"),
            HOUR,
            SupportDetail::ProviderContainer {
                gvisor: false,
                nvproxy: false,
            },
        ),
    );
    registry
        .refresh(Capability::ProviderContainer, &pod())
        .unwrap();
    let labelled_vm = runtime_on(ExecutionCategory::VmSandbox, vllm("0.31.0"), "pod-1");
    assert_eq!(
        RuntimeOffer::observe(&registry, labelled_vm, HOUR, config("pod")).unwrap_err(),
        EvidenceRefusal::Missing {
            capability: Capability::RuntimeCategory
        }
    );
}

// The capabilities other modules asked for so they can drop their local ports.

fn gpu(name: &str) -> Digest {
    digest("yougori/test/device/v1", &[name.as_bytes()])
}

fn allocation(ordinal: u32, handle: Option<ShareableHandle>) -> Subject {
    Subject::CudaAllocation(CudaAllocationSubject {
        runtime: wsl_runtime(),
        device_ordinal: ordinal,
        requested_handle: handle,
    })
}

fn needs(capability: Capability, subject: &Subject, source: SourceClass) -> Requirement {
    Requirement::new(capability, subject.clone(), source, HOUR, config("p1"))
}

#[test]
fn vmm_granularity_is_kept_per_device_and_handle_type() {
    let clock = start();
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::guest_report(Capability::CudaVmmAllocation));
    register(&mut registry, &probe);
    let granularity = |bytes: u64| SupportDetail::CudaVmmAllocation {
        granularity_bytes: NonZeroU64::new(bytes).unwrap(),
    };
    let posix = allocation(0, Some(ShareableHandle::PosixFileDescriptor));
    let second_device = allocation(1, Some(ShareableHandle::PosixFileDescriptor));
    let unexported = allocation(0, None);
    probe.respond(
        &posix,
        Observation::supported(config("p1"), HOUR, granularity(2 << 20)),
    );
    probe.respond(
        &second_device,
        Observation::supported(config("p1"), HOUR, granularity(4 << 20)),
    );
    probe.respond(
        &unexported,
        Observation::unsupported(config("p1"), HOUR, UnsupportedReason::FeatureAbsent),
    );
    for subject in [&posix, &second_device, &unexported] {
        registry
            .refresh(Capability::CudaVmmAllocation, subject)
            .unwrap();
    }
    assert_eq!(registry.evidence().len(), 3);
    let guest = SourceClass::GuestReport;
    assert_eq!(
        registry
            .evaluate(&needs(Capability::CudaVmmAllocation, &posix, guest))
            .unwrap()
            .detail(),
        &granularity(2 << 20)
    );
    assert_eq!(
        registry
            .evaluate(&needs(Capability::CudaVmmAllocation, &second_device, guest))
            .unwrap()
            .detail(),
        &granularity(4 << 20)
    );
    assert!(matches!(
        registry.evaluate(&needs(Capability::CudaVmmAllocation, &unexported, guest)),
        Err(EvidenceRefusal::Unsupported { .. })
    ));
    let win32 = allocation(0, Some(ShareableHandle::Win32Handle));
    assert!(matches!(
        registry.evaluate(&needs(Capability::CudaVmmAllocation, &win32, guest)),
        Err(EvidenceRefusal::Missing { .. })
    ));
    assert!(matches!(
        registry.refresh(
            Capability::CudaVmmAllocation,
            &Subject::Runtime(wsl_runtime())
        ),
        Err(RegistryError::WrongSubjectKind {
            expected: SubjectKind::CudaAllocation,
            ..
        })
    ));

    let mut declared = ProbeRegistry::new(&clock);
    let declaration = Arc::new(FakeProbe::new(
        Capability::CudaVmmAllocation,
        SourceClass::RecordedDeclaration,
    ));
    register(&mut declared, &declaration);
    declaration.respond(
        &posix,
        Observation::supported(config("p1"), HOUR, granularity(2 << 20)),
    );
    declared
        .refresh(Capability::CudaVmmAllocation, &posix)
        .unwrap();
    assert!(matches!(
        declared.evaluate(&needs(
            Capability::CudaVmmAllocation,
            &posix,
            SourceClass::Fixture
        )),
        Err(EvidenceRefusal::SourceTooWeak { .. })
    ));
}

#[test]
fn the_compute_platform_is_observed_never_asserted() {
    let clock = start();
    let runtime = Subject::Runtime(runtime_on(
        ExecutionCategory::HostProcessModelRuntime,
        BackendRelease::new(Backend::LlamaCpp, "b4568").unwrap(),
        "metal",
    ));
    let metal = SupportDetail::ComputePlatform {
        platform: ComputePlatform::Metal,
    };
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(
        Capability::ComputePlatform,
        SourceClass::HostProbe,
    ));
    register(&mut registry, &probe);
    probe.respond(
        &runtime,
        Observation::supported(config("p1"), HOUR, metal.clone()),
    );
    registry
        .refresh(Capability::ComputePlatform, &runtime)
        .unwrap();
    let required = needs(
        Capability::ComputePlatform,
        &runtime,
        SourceClass::HostProbe,
    );
    assert_eq!(registry.evaluate(&required).unwrap().detail(), &metal);

    let mut declared = ProbeRegistry::new(&clock);
    let declaration = Arc::new(FakeProbe::new(
        Capability::ComputePlatform,
        SourceClass::RecordedDeclaration,
    ));
    register(&mut declared, &declaration);
    declaration.respond(&runtime, Observation::supported(config("p1"), HOUR, metal));
    declared
        .refresh(Capability::ComputePlatform, &runtime)
        .unwrap();
    assert!(matches!(
        declared.evaluate(&needs(
            Capability::ComputePlatform,
            &runtime,
            SourceClass::Fixture
        )),
        Err(EvidenceRefusal::SourceTooWeak {
            required: SourceClass::GuestReport,
            ..
        })
    ));
}

#[test]
fn free_gpu_memory_is_a_host_observation() {
    let clock = start();
    let device = Subject::GpuDevice(GpuDeviceSubject {
        machine: machine(),
        device: gpu("gpu0"),
    });
    let memory = |free: u64, total: u64| SupportDetail::GpuMemory {
        free_bytes: free,
        total_bytes: NonZeroU64::new(total).unwrap(),
    };
    let lenient = needs(Capability::GpuFreeMemory, &device, SourceClass::GuestReport);
    assert!(lenient.is_host_only());

    let mut guest_side = ProbeRegistry::new(&clock);
    let guest = Arc::new(FakeProbe::guest_report(Capability::GpuFreeMemory));
    register(&mut guest_side, &guest);
    guest.respond(
        &device,
        Observation::supported(config("p1"), HOUR, memory(10, 24)),
    );
    guest_side
        .refresh(Capability::GpuFreeMemory, &device)
        .unwrap();
    assert!(matches!(
        guest_side.evaluate(&lenient),
        Err(EvidenceRefusal::SourceTooWeak {
            observed: SourceClass::GuestReport,
            required: SourceClass::HostProbe,
            ..
        })
    ));

    let mut host_side = ProbeRegistry::new(&clock);
    let host = Arc::new(FakeProbe::new(
        Capability::GpuFreeMemory,
        SourceClass::HostProbe,
    ));
    register(&mut host_side, &host);
    host.respond(
        &device,
        Observation::supported(config("p1"), HOUR, memory(10, 24)),
    );
    host_side
        .refresh(Capability::GpuFreeMemory, &device)
        .unwrap();
    assert_eq!(
        host_side.evaluate(&lenient).unwrap().detail(),
        &memory(10, 24)
    );
    host.respond(
        &device,
        Observation::supported(config("p1"), HOUR, memory(30, 24)),
    );
    host_side
        .refresh(Capability::GpuFreeMemory, &device)
        .unwrap();
    assert_eq!(
        host_side.evaluate(&lenient),
        Err(EvidenceRefusal::Unknown {
            capability: Capability::GpuFreeMemory,
            reason: UnknownReason::InconsistentReport,
        })
    );
}

#[test]
fn gpu_peer_access_is_kept_per_direction() {
    let clock = start();
    let pair = |from: &str, to: &str| {
        Subject::GpuPair(GpuPairSubject {
            machine: machine(),
            from: gpu(from),
            to: gpu(to),
        })
    };
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::guest_report(Capability::GpuPeerAccess));
    register(&mut registry, &probe);
    let forward = pair("gpu0", "gpu1");
    let back = pair("gpu1", "gpu0");
    let itself = pair("gpu0", "gpu0");
    probe.respond(
        &forward,
        Observation::supported(config("p1"), HOUR, SupportDetail::GpuPeerAccess),
    );
    probe.respond(
        &back,
        Observation::unsupported(config("p1"), HOUR, UnsupportedReason::FeatureAbsent),
    );
    probe.respond(
        &itself,
        Observation::supported(config("p1"), HOUR, SupportDetail::GpuPeerAccess),
    );
    for subject in [&forward, &back, &itself] {
        registry
            .refresh(Capability::GpuPeerAccess, subject)
            .unwrap();
    }
    let guest = SourceClass::GuestReport;
    assert!(registry
        .evaluate(&needs(Capability::GpuPeerAccess, &forward, guest))
        .is_ok());
    assert!(matches!(
        registry.evaluate(&needs(Capability::GpuPeerAccess, &back, guest)),
        Err(EvidenceRefusal::Unsupported { .. })
    ));
    assert!(matches!(
        registry.evaluate(&needs(Capability::GpuPeerAccess, &itself, guest)),
        Err(EvidenceRefusal::Unknown {
            reason: UnknownReason::InconsistentReport,
            ..
        })
    ));
    assert!(matches!(
        registry.evaluate(&needs(
            Capability::GpuPeerAccess,
            &pair("gpu0", "gpu2"),
            guest
        )),
        Err(EvidenceRefusal::Missing { .. })
    ));
}

#[test]
fn a_peer_topology_counts_only_when_complete() {
    let clock = start();
    let runtime = Subject::Runtime(wsl_runtime());
    let path = |from: u32, to: u32, link: PeerLink| PeerPath {
        from,
        to,
        link,
        access: PeerAccess::Verified,
    };
    let complete = SupportDetail::PeerTopology {
        device_count: NonZeroU32::new(2).unwrap(),
        paths: vec![
            path(0, 1, PeerLink::PcieSwitch),
            path(1, 0, PeerLink::PcieSwitch),
        ],
    };
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::guest_report(Capability::PeerTopology));
    register(&mut registry, &probe);
    probe.respond(
        &runtime,
        Observation::supported(config("p1"), HOUR, complete.clone()),
    );
    registry
        .refresh(Capability::PeerTopology, &runtime)
        .unwrap();
    let required = needs(Capability::PeerTopology, &runtime, SourceClass::GuestReport);
    assert_eq!(registry.evaluate(&required).unwrap().detail(), &complete);

    probe.respond(
        &runtime,
        Observation::supported(
            config("p1"),
            HOUR,
            SupportDetail::PeerTopology {
                device_count: NonZeroU32::new(2).unwrap(),
                paths: vec![path(0, 1, PeerLink::NvLink)],
            },
        ),
    );
    registry
        .refresh(Capability::PeerTopology, &runtime)
        .unwrap();
    assert!(matches!(
        registry.evaluate(&required),
        Err(EvidenceRefusal::Unknown {
            reason: UnknownReason::InconsistentReport,
            ..
        })
    ));
}

#[test]
fn checkpoint_compatibility_is_kept_per_checkpoint_engine_and_hardware() {
    let clock = start();
    let subject = |checkpoint: &str, hardware: &str| {
        Subject::ModelCheckpoint(ModelCheckpointSubject {
            checkpoint: digest("yougori/test/checkpoint/v1", &[checkpoint.as_bytes()]),
            release: vllm("0.31.0"),
            image: digest("yougori/test/image/v1", &[b"image"]),
            hardware: digest("yougori/test/hardware/v1", &[hardware.as_bytes()]),
        })
    };
    let record = digest("yougori/test/record/v1", &[b"qwen-on-2x4090"]);
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::guest_report(Capability::CheckpointCompatibility));
    register(&mut registry, &probe);
    let measured = subject("qwen", "2x4090");
    probe.respond(
        &measured,
        Observation::supported(
            config("p1"),
            HOUR,
            SupportDetail::CheckpointCompatibility { record },
        ),
    );
    registry
        .refresh(Capability::CheckpointCompatibility, &measured)
        .unwrap();
    let guest = SourceClass::GuestReport;
    assert_eq!(
        registry
            .evaluate(&needs(
                Capability::CheckpointCompatibility,
                &measured,
                guest
            ))
            .unwrap()
            .detail(),
        &SupportDetail::CheckpointCompatibility { record }
    );
    for other in [subject("llama", "2x4090"), subject("qwen", "1x4090")] {
        assert!(matches!(
            registry.evaluate(&needs(Capability::CheckpointCompatibility, &other, guest)),
            Err(EvidenceRefusal::Missing { .. })
        ));
    }
}

#[test]
fn a_must_probe_timeout_is_inconclusive_and_only_the_host_shows_enforcement() {
    let clock = start();
    let rule = |principal: &str| {
        Subject::PerimeterRule(PerimeterRuleSubject {
            machine: machine(),
            perimeter: digest("yougori/test/perimeter/v1", &[b"strict"]),
            rule: digest("yougori/test/rule/v1", &[b"block-private-ranges"]),
            principal: digest("yougori/test/principal/v1", &[principal.as_bytes()]),
        })
    };
    let broker = rule("broker");
    let required = needs(
        Capability::PerimeterRuleEnforced,
        &broker,
        SourceClass::GuestReport,
    );
    assert!(required.is_host_only());
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(
        Capability::PerimeterRuleEnforced,
        SourceClass::HostProbe,
    ));
    register(&mut registry, &probe);

    probe.respond(
        &broker,
        Observation::unknown(config("p1"), HOUR, UnknownReason::Inconclusive),
    );
    registry
        .refresh(Capability::PerimeterRuleEnforced, &broker)
        .unwrap();
    let timeout = registry.evaluate(&required).unwrap_err();
    assert_eq!(
        timeout,
        EvidenceRefusal::Unknown {
            capability: Capability::PerimeterRuleEnforced,
            reason: UnknownReason::Inconclusive,
        }
    );
    assert!(timeout.to_string().contains("never passes"));

    probe.respond(
        &broker,
        Observation::unsupported(config("p1"), HOUR, UnsupportedReason::NotEnforced),
    );
    registry
        .refresh(Capability::PerimeterRuleEnforced, &broker)
        .unwrap();
    assert_eq!(
        registry.evaluate(&required).unwrap_err().remedy(),
        Remedy::RepairPerimeter
    );

    probe.respond(
        &broker,
        Observation::supported(config("p1"), HOUR, SupportDetail::PerimeterRuleEnforced),
    );
    registry
        .refresh(Capability::PerimeterRuleEnforced, &broker)
        .unwrap();
    assert!(registry.evaluate(&required).is_ok());
    assert!(matches!(
        registry.evaluate(&needs(
            Capability::PerimeterRuleEnforced,
            &rule("guest-agent"),
            SourceClass::HostProbe
        )),
        Err(EvidenceRefusal::Missing { .. })
    ));

    let mut guest_side = ProbeRegistry::new(&clock);
    let guest = Arc::new(FakeProbe::guest_report(Capability::PerimeterRuleEnforced));
    register(&mut guest_side, &guest);
    guest.respond(
        &broker,
        Observation::supported(config("p1"), HOUR, SupportDetail::PerimeterRuleEnforced),
    );
    guest_side
        .refresh(Capability::PerimeterRuleEnforced, &broker)
        .unwrap();
    assert!(matches!(
        guest_side.evaluate(&required),
        Err(EvidenceRefusal::SourceTooWeak {
            required: SourceClass::HostProbe,
            ..
        })
    ));
}

#[test]
fn sleep_weight_discard_is_its_own_backend_mode() {
    let clock = start();
    let runtime = wsl_runtime();
    let subject = Subject::Runtime(runtime.clone());
    let only_offload = backend_modes(&clock, &runtime);
    let mut registry = backend_modes(&clock, &runtime);
    let discard = Arc::new(FakeProbe::new(
        Capability::SleepWeightDiscard,
        SourceClass::HostProbe,
    ));
    discard.respond(&subject, mode_on(&runtime.release, config("p1")));
    register(&mut registry, &discard);
    registry
        .refresh(Capability::SleepWeightDiscard, &subject)
        .unwrap();
    let permitted = profile(
        runtime,
        &[
            Optimization::SleepWeightDiscard,
            Optimization::SleepWeightOffload,
        ],
    );
    assert!(Optimization::SleepWeightDiscard.is_backend_mode());
    assert!(Optimization::SleepWeightDiscard.is_switching_mode());

    let recorded = LoaderGate::recorded()
        .plan(
            &permitted,
            &request(&[(Optimization::SleepWeightDiscard, Necessity::Optional)]),
            &registry,
        )
        .unwrap();
    assert!(matches!(
        recorded.ordinary().get(&Optimization::SleepWeightDiscard),
        Some(NotEnabled::Release {
            refusal: ModeRefusal::ModeNotSupported { .. }
        })
    ));

    let gate = LoaderGate::new(
        BackendModeRules::new([BackendModeRule {
            release: vllm("0.31.0"),
            supported: BTreeSet::from([
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
                Optimization::SleepWeightDiscard,
            ]),
            tested_together: BTreeSet::new(),
            conflicts: Vec::new(),
        }])
        .unwrap(),
    );
    let alone = request(&[(Optimization::SleepWeightDiscard, Necessity::Required)]);
    assert!(gate
        .plan(&permitted, &alone, &registry)
        .unwrap()
        .is_enabled(Optimization::SleepWeightDiscard));
    assert!(matches!(
        gate.plan(&permitted, &alone, &only_offload),
        Err(LoaderRefusal {
            reason: NotEnabled::Evidence {
                refusal: EvidenceRefusal::Missing {
                    capability: Capability::SleepWeightDiscard
                }
            },
            ..
        })
    ));
    let both = gate
        .plan(
            &permitted,
            &request(&[
                (Optimization::SleepWeightDiscard, Necessity::Optional),
                (Optimization::SleepWeightOffload, Necessity::Optional),
            ]),
            &registry,
        )
        .unwrap();
    assert!(both.is_ordinary_loader());
    assert!(matches!(
        both.ordinary().get(&Optimization::SleepWeightDiscard),
        Some(NotEnabled::Conflict {
            refusal: ModeRefusal::NotTestedTogether { .. },
            ..
        })
    ));
}

#[test]
fn execute_while_load_is_enabled_only_on_evidence() {
    let clock = start();
    let runtime = wsl_runtime();
    let subject = Subject::Runtime(runtime.clone());
    let mut registry = ProbeRegistry::new(&clock);
    let probe = Arc::new(FakeProbe::new(
        Capability::ExecuteWhileLoad,
        SourceClass::HostProbe,
    ));
    register(&mut registry, &probe);
    let gate = LoaderGate::recorded();
    let permitted = profile(
        runtime,
        &[Optimization::ExecuteWhileLoad, Optimization::IoUring],
    );
    let optional = request(&[(Optimization::ExecuteWhileLoad, Necessity::Optional)]);
    let plan = gate.plan(&permitted, &optional, &registry).unwrap();
    assert!(plan.is_ordinary_loader());
    assert!(matches!(
        plan.ordinary().get(&Optimization::ExecuteWhileLoad),
        Some(NotEnabled::Evidence {
            refusal: EvidenceRefusal::Missing { .. }
        })
    ));
    assert!(gate
        .plan(
            &permitted,
            &request(&[(Optimization::ExecuteWhileLoad, Necessity::Required)]),
            &registry
        )
        .is_err());

    probe.respond(
        &subject,
        Observation::supported(config("p1"), HOUR, SupportDetail::ExecuteWhileLoad),
    );
    registry
        .refresh(Capability::ExecuteWhileLoad, &subject)
        .unwrap();
    let plan = gate.plan(&permitted, &optional, &registry).unwrap();
    assert!(plan.is_enabled(Optimization::ExecuteWhileLoad));
    assert!(!Optimization::ExecuteWhileLoad.is_backend_mode());
    assert!(!Optimization::ExecuteWhileLoad.is_switching_mode());
}

/// A subject for each VM boundary fact (M08), on the kind its capability names.
fn boundary_subject(capability: Capability) -> Subject {
    let part = |name: &[u8]| digest("yougori/test/boundary/v1", &[name]);
    let launch = SandboxBootSubject {
        machine: machine(),
        vm: part(b"vm"),
        boot: crate::foundation::ids::SandboxBootGeneration::new(4),
    };
    match capability.subject_kind() {
        SubjectKind::HypervisorProcess => Subject::HypervisorProcess(HypervisorProcessSubject {
            launch,
            process: part(b"process"),
        }),
        SubjectKind::SandboxBoot => Subject::SandboxBoot(launch),
        SubjectKind::TransportBroker => Subject::TransportBroker(TransportBrokerSubject {
            machine: machine(),
            perimeter: part(b"perimeter"),
            broker: part(b"broker"),
            policy: part(b"policy"),
        }),
        SubjectKind::CredentialScan => Subject::CredentialScan(CredentialScanSubject {
            launch,
            locations: part(b"locations"),
        }),
        SubjectKind::SnapshotClones => Subject::SnapshotClones(SnapshotClonesSubject {
            machine: machine(),
            snapshot: part(b"golden"),
            clones: part(b"clones"),
        }),
        SubjectKind::GpuDevice => Subject::GpuDevice(GpuDeviceSubject {
            machine: machine(),
            device: gpu("gpu0"),
        }),
        other => panic!("{capability} is not a VM boundary fact; it is about a {other}"),
    }
}

#[test]
fn only_a_host_probe_shows_a_vm_boundary_fact() {
    let boundary = [
        (
            Capability::HypervisorConfigurationMatches,
            UnsupportedReason::ConfigurationNotApproved,
        ),
        (
            Capability::HypervisorConfined,
            UnsupportedReason::NotConfined,
        ),
        (
            Capability::BootedImageMatchesManifest,
            UnsupportedReason::ImageNotAsSigned,
        ),
        (
            Capability::DestinationPolicyEnforced,
            UnsupportedReason::DestinationNotRefused,
        ),
        (
            Capability::NoGuestNetworkDevice,
            UnsupportedReason::GuestNetworkPath,
        ),
        (
            Capability::CredentialAbsentFromScannedLocations,
            UnsupportedReason::CredentialExposed,
        ),
        (
            Capability::CloneIdentityReset,
            UnsupportedReason::CloneIdentityShared,
        ),
        (
            Capability::DeviceAssignmentIsolated,
            UnsupportedReason::DeviceNotIsolated,
        ),
    ];
    let clock = start();
    for (capability, refusal) in boundary {
        let subject = boundary_subject(capability);
        // Asking for less than a host probe is raised to it.
        let required = needs(capability, &subject, SourceClass::GuestReport);
        assert!(required.is_host_only(), "{capability}");

        let mut guest_side = ProbeRegistry::new(&clock);
        let guest = Arc::new(FakeProbe::guest_report(capability));
        register(&mut guest_side, &guest);
        guest.respond(&subject, plain(config("p1")));
        let envelope = guest_side.refresh(capability, &subject).unwrap();
        assert!(matches!(
            envelope.result(),
            ObservationResult::Supported { .. }
        ));
        assert_eq!(
            guest_side.evaluate(&required),
            Err(EvidenceRefusal::SourceTooWeak {
                capability,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            })
        );

        let mut host_side = ProbeRegistry::new(&clock);
        let host = Arc::new(FakeProbe::new(capability, SourceClass::HostProbe));
        register(&mut host_side, &host);
        host.respond(&subject, plain(config("p1")));
        host_side.refresh(capability, &subject).unwrap();
        let satisfied = host_side.evaluate(&required).unwrap();
        assert_eq!(satisfied.detail(), &SupportDetail::Plain);
        // Evidence observed under another configuration no longer counts.
        let changed = Requirement::new(
            capability,
            subject.clone(),
            SourceClass::HostProbe,
            HOUR,
            config("p2"),
        );
        assert!(matches!(
            host_side.evaluate(&changed),
            Err(EvidenceRefusal::FingerprintChanged { .. })
        ));

        host.respond(
            &subject,
            Observation::unsupported(config("p1"), HOUR, refusal),
        );
        host_side.refresh(capability, &subject).unwrap();
        let refused = host_side.evaluate(&required).unwrap_err();
        assert_eq!(
            refused,
            EvidenceRefusal::Unsupported {
                capability,
                reason: refusal
            }
        );
        assert_eq!(refused.remedy(), Remedy::ChooseSupportedRuntime);
    }
}
