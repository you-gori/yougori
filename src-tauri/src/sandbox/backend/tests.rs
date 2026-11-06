//! Scenario tests of the backend contract through the fake backend and a real CORE-01
//! registry on a manual clock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;
use crate::foundation::coordination::{
    RestoreAction, RestoreFailure, SandboxGenerations, SnapshotContent, SnapshotDefect, SnapshotId,
    SnapshotManifest, SnapshotOrigin,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    BackendVersion, Capability, ConfigurationFingerprint, EvidenceRefusal, HypervisorKind,
    HypervisorSubject, Observation, OsKind, PerimeterRuleSubject, ProbeRegistry, Remedy,
    Requirement, SourceClass, Staleness, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, ExecutionId, GpuDeviceKey, ManualClock, PolicyEpoch,
    SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::ReservationId;

const MINUTE: Duration = Duration::from_secs(60);

/// A host: a manual clock and a CORE-01 registry with one hypervisor probe.
struct Host {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    probe: Arc<FakeProbe>,
}

fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"m"])
}

fn config(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

fn image() -> Digest {
    digest("yougori/test/image/v1", &[b"alpine"])
}

fn artifact() -> Digest {
    digest("yougori/test/backend/v1", &[b"fake"])
}

fn contract(name: &[u8]) -> Digest {
    digest("yougori/test/contract/v1", &[name])
}

fn hypervisor_subject(kind: HypervisorKind) -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: kind,
    })
}

fn reservation(number: u64) -> ReservationId {
    serde_json::from_value(number.into()).unwrap()
}

/// A host whose hypervisor probe reports from `source` and has not run yet.
fn host_with(source: SourceClass) -> Host {
    let clock = Arc::new(ManualClock::default());
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::new(Capability::HypervisorAvailable, source));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    Host {
        clock,
        registry,
        probe,
    }
}

impl Host {
    /// The probe finds `kind` available under `configuration`, fresh for ten minutes.
    fn observe_available(&mut self, kind: HypervisorKind, configuration: ConfigurationFingerprint) {
        self.probe.respond(
            &hypervisor_subject(kind),
            Observation::supported(
                configuration,
                Duration::from_secs(600),
                SupportDetail::Hypervisor { hypervisor: kind },
            ),
        );
        self.registry
            .refresh(Capability::HypervisorAvailable, &hypervisor_subject(kind))
            .unwrap();
    }

    fn observe_unavailable(
        &mut self,
        kind: HypervisorKind,
        configuration: ConfigurationFingerprint,
    ) {
        self.probe.respond(
            &hypervisor_subject(kind),
            Observation::unsupported(
                configuration,
                Duration::from_secs(600),
                UnsupportedReason::HypervisorUnavailable,
            ),
        );
        self.registry
            .refresh(Capability::HypervisorAvailable, &hypervisor_subject(kind))
            .unwrap();
    }
}

/// A host whose probe found KVM available under configuration "a".
fn fresh_host() -> Host {
    let mut host = host_with(SourceClass::HostProbe);
    host.observe_available(HypervisorKind::Kvm, config("a"));
    host
}

fn host_build() -> HostBuild {
    HostBuild {
        os: OsKind::Linux,
        build: BuildId::new("6.6.0").unwrap(),
        architecture: Architecture::X86_64,
    }
}

fn script() -> HostScript {
    HostScript::hardware_vm(HypervisorKind::Kvm, host_build(), image(), config("a"))
}

fn fresh_backend() -> FakeBackend {
    FakeBackend::new(
        HypervisorKind::Kvm,
        BackendVersion::new("0.1.0").unwrap(),
        artifact(),
        script(),
    )
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
        configuration: config("a"),
        contract: contract(b"c1"),
        pinned: PinnedArtifacts {
            guest_image: image(),
            backend: artifact(),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/profile/v1", &[b"minimal"]),
            devices: DeviceExposure::cpu_only(),
        },
        required: RequiredProperties::strictest(MINUTE),
        reservation: reservation(1),
    }
}

fn emulation_request() -> EmulationRequest {
    EmulationRequest {
        execution: ExecutionId::new("exe-dev").unwrap(),
        guest_image: image(),
        reservation: reservation(9),
    }
}

fn kvm() -> Accelerator {
    Accelerator::Hardware {
        hypervisor: HypervisorKind::Kvm,
    }
}

#[test]
fn a_hardware_vm_launches_with_a_sealed_record() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let request = request("exe-1", 1);
    let launched = backend.launch(&request, &host.registry).unwrap();
    let record = &launched.record;
    assert_eq!(record.vm(), launched.vm);
    assert_eq!(
        launched.vm,
        vm_handle(
            BackendKind::Fake,
            &request.execution,
            SandboxBootGeneration::FIRST
        )
    );
    assert_eq!(record.sandbox().execution, request.execution);
    assert_eq!(record.sandbox().tenant, request.tenant);
    assert_eq!(record.sandbox().generations, request.generations);
    assert_eq!(record.contract(), request.contract);
    assert_eq!(record.reservation(), request.reservation);
    assert_eq!(record.backend().kind, BackendKind::Fake);
    assert_eq!(record.pinned(), request.pinned);
    assert_eq!(record.restored_from(), None);
    assert_eq!(record.device_profile(), &request.device_profile);
    assert_eq!(record.required(), &request.required);
    assert_eq!(record.configuration(), config("a"));
    assert_eq!(*record.accelerator().value(), kvm());
    assert_eq!(
        record.hypervisor_evidence().source(),
        SourceClass::HostProbe
    );
    assert_eq!(
        record.hypervisor_evidence().subject(),
        hypervisor_subject(HypervisorKind::Kvm).identity()
    );
    assert_eq!(record.checks().len(), Facet::ALL.len());
    assert!(record.checks().iter().all(RequiredCheck::is_satisfied));
    assert_eq!(
        record
            .checks()
            .iter()
            .map(RequiredCheck::facet)
            .collect::<Vec<Facet>>(),
        Facet::ALL.to_vec()
    );
    assert!(record
        .fact_sources()
        .iter()
        .all(|(_, source)| *source == FactSource::HostObserved));
    assert_eq!(record.recorded_at(), host.clock.now());
    assert_eq!(record.clock(), host.registry.session());
    assert_eq!(record.assert_current(host.registry.now()), Ok(()));

    assert_eq!(backend.running(), vec![launched.vm]);
    assert_eq!(
        backend.actual_accelerator(&launched.vm).unwrap(),
        *record.accelerator()
    );
    assert_eq!(
        backend.confinement_evidence(&launched.vm).unwrap(),
        *record.host_observed()
    );
    assert!(backend.calls().iter().any(|call| matches!(
        call,
        FakeCall::Create { vm, .. } if *vm == launched.vm
    )));

    let json = serde_json::to_value(record).unwrap();
    assert_eq!(json["identity"], record.identity().to_hex());
    assert!(json.get("host_observed").is_some());
    assert!(json.get("guest_asserted").is_some());
    assert_eq!(
        json["accelerator"]["value"]["hardware"]["hypervisor"],
        "kvm"
    );
    assert_eq!(json["accelerator"]["source"]["how"], "observed");
    assert_eq!(json["host_observed"]["confinement"]["fact"], "observed");
    assert_eq!(json["checks"][0]["facet"], "isolation");
    assert_eq!(json["checks"][0]["outcome"]["outcome"], "satisfied");
    assert_eq!(json["checks"][0]["outcome"]["source"], "host_observed");
    assert_eq!(json["sandbox"]["generations"]["boot"], 1);
    assert_eq!(json["hypervisor_evidence"]["source"], "host_probe");
    assert!(json.get("score").is_none());
}

#[test]
fn a_launch_without_host_observed_evidence_is_refused_before_anything_is_created() {
    let host = host_with(SourceClass::HostProbe);
    let mut backend = fresh_backend();
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::Missing {
                capability: Capability::HypervisorAvailable
            }
        }
    );
    assert!(backend.running().is_empty());
    assert!(!backend
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Create { .. })));

    // Hypervisor evidence alone is not enough: an unobserved facet refuses, and the VM
    // that was created to observe it is torn down.
    let host = fresh_host();
    let mut backend = fresh_backend();
    backend.script_mut().confinement = Scripted::Unavailable {
        reason: UnknownReason::Inconclusive,
    };
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    let failed = refusal.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].facet(), Facet::HypervisorConfinement);
    assert_eq!(
        failed[0].failure(),
        Some(&CheckFailure::NotObserved {
            reason: UnknownReason::Inconclusive
        })
    );
    assert!(refusal
        .to_string()
        .contains("hypervisor confinement: no host observation"));
    assert!(backend.running().is_empty());
    assert!(matches!(
        backend.calls().last(),
        Some(FakeCall::Teardown { .. })
    ));
    if let LaunchRefusal::PropertiesNotSatisfied { checks } = &refusal {
        assert_eq!(checks.len(), Facet::ALL.len());
        let json = serde_json::to_value(&refusal).unwrap();
        assert_eq!(json["kind"], "properties_not_satisfied");
        assert_eq!(
            json["checks"][1]["outcome"]["failure"]["failure"],
            "not_observed"
        );
    } else {
        unreachable!("{refusal:?}");
    }
}

#[test]
fn a_guest_report_never_satisfies_a_host_only_requirement() {
    // A guest-report adapter for hypervisor availability.
    let mut host = host_with(SourceClass::GuestReport);
    host.observe_available(HypervisorKind::Kvm, config("a"));
    let mut backend = fresh_backend();
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::SourceTooWeak {
                capability: Capability::HypervisorAvailable,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            }
        }
    );
    assert!(refusal
        .to_string()
        .contains("never satisfies a host-only requirement"));
    assert!(backend.running().is_empty());

    // Guest assertions of facets the host did not observe.
    let host = fresh_host();
    let mut backend = fresh_backend();
    let script = backend.script_mut();
    script.confinement = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    script.guest.confinement = Some(ConfinementControl::all());
    script.network = Scripted::Unavailable {
        reason: UnknownReason::Unreachable,
    };
    script.guest.network = Some(NetworkAuthority::offline());
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    let failed = refusal.failed_checks();
    assert_eq!(
        failed.iter().map(|check| check.facet()).collect::<Vec<_>>(),
        vec![Facet::HypervisorConfinement, Facet::NetworkAuthority]
    );
    assert_eq!(
        failed[0].failure(),
        Some(&CheckFailure::OnlyGuestAsserted {
            reason: UnknownReason::NotTested
        })
    );
    assert_eq!(
        failed[1].failure(),
        Some(&CheckFailure::OnlyGuestAsserted {
            reason: UnknownReason::Unreachable
        })
    );
    assert!(refusal
        .to_string()
        .contains("never satisfies a requirement"));
    assert!(backend.running().is_empty());
}

#[test]
fn missing_hardware_virtualization_refuses_and_nothing_retries_into_emulation() {
    let features = BackendFeatures::of([Feature::DeveloperEmulation]);
    let no_emulation_and_nothing_running = |backend: &FakeBackend| {
        assert_eq!(backend.emulation_launches(), 0);
        assert!(backend.running().is_empty());
        assert!(backend.emulated().is_empty());
        assert!(!backend
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Emulate { .. })));
    };

    // The host probe found no usable hypervisor.
    let mut host = host_with(SourceClass::HostProbe);
    host.observe_unavailable(HypervisorKind::Kvm, config("a"));
    let mut backend = fresh_backend().with_features(features.clone());
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::Unsupported {
                capability: Capability::HypervisorAvailable,
                reason: UnsupportedReason::HypervisorUnavailable,
            }
        }
    );
    assert!(!backend
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Create { .. })));
    no_emulation_and_nothing_running(&backend);

    // A forced hardware failure while creating.
    let host = fresh_host();
    let mut backend = fresh_backend().with_features(features.clone());
    backend.script_mut().hardware_failure = Some(HardwareFailure {
        hypervisor: HypervisorKind::Kvm,
        detail: "KVM_CREATE_VM: EBUSY".to_owned(),
    });
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert!(matches!(
        refusal,
        LaunchRefusal::HardwareVirtualizationFailed { .. }
    ));
    assert!(refusal
        .to_string()
        .contains("nothing is retried in emulation"));
    assert!(!backend
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Create { .. })));
    no_emulation_and_nothing_running(&backend);

    // The VM came up in emulation, whatever the guest says about it.
    let mut backend = fresh_backend().with_features(features);
    backend.script_mut().accelerator = Scripted::HostObserved(Accelerator::Emulation {
        emulator: Emulator::Tcg,
    });
    backend.script_mut().guest.accelerator = Some(kvm());
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::NotHardwareVirtualized {
            observed: Accelerator::Emulation {
                emulator: Emulator::Tcg
            }
        }
    );
    assert!(matches!(
        backend.calls().last(),
        Some(FakeCall::Teardown { .. })
    ));
    no_emulation_and_nothing_running(&backend);

    // An unobserved accelerator, and a hardware hypervisor other than the backend's.
    backend.script_mut().accelerator = Scripted::Unavailable {
        reason: UnknownReason::Inconclusive,
    };
    assert_eq!(
        backend
            .launch(&request("exe-1", 1), &host.registry)
            .unwrap_err(),
        LaunchRefusal::AcceleratorNotObserved {
            reason: UnknownReason::Inconclusive
        }
    );
    backend.script_mut().accelerator = Scripted::HostObserved(Accelerator::Hardware {
        hypervisor: HypervisorKind::Whpx,
    });
    assert_eq!(
        backend
            .launch(&request("exe-1", 1), &host.registry)
            .unwrap_err(),
        LaunchRefusal::UnexpectedAccelerator {
            expected: HypervisorKind::Kvm,
            observed: Accelerator::Hardware {
                hypervisor: HypervisorKind::Whpx
            },
        }
    );
    no_emulation_and_nothing_running(&backend);
}

#[test]
fn the_record_carries_the_actual_accelerator_and_keeps_sources_apart() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let control = digest("yougori/test/control/v1", &[b"credential-scan"]);
    let script = backend.script_mut();
    script.guest.accelerator = Some(Accelerator::Hardware {
        hypervisor: HypervisorKind::Whpx,
    });
    script.guest.network = Some(NetworkAuthority::of([NetworkChannel::PublishedService]));
    script.credentials = Scripted::Verified {
        value: CredentialExposure::none(),
        control,
    };
    let launched = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let record = &launched.record;

    assert_eq!(*record.accelerator().value(), kvm());
    assert_eq!(record.accelerator().source(), FactSource::HostObserved);
    let asserted = record.guest_asserted().accelerator.as_ref().unwrap();
    assert_eq!(
        *asserted.value(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx
        }
    );
    assert_eq!(asserted.source(), FactSource::GuestAsserted);
    assert!(record.host_observed().network.value().unwrap().is_offline());
    assert!(record.guest_asserted().confinement.is_none());

    let sources: BTreeMap<FactName, FactSource> = record.fact_sources().into_iter().collect();
    assert_eq!(sources[&FactName::Credentials], FactSource::Verified);
    assert_eq!(sources[&FactName::Network], FactSource::HostObserved);
    assert_eq!(sources[&FactName::Accelerator], FactSource::HostObserved);
    let credentials = record
        .checks()
        .iter()
        .find(|check| check.facet() == Facet::CredentialExposure)
        .unwrap();
    assert_eq!(
        credentials.outcome(),
        &CheckOutcome::Satisfied {
            source: FactSource::Verified
        }
    );

    let json = serde_json::to_value(record).unwrap();
    assert_eq!(
        json["guest_asserted"]["accelerator"]["value"]["hardware"]["hypervisor"],
        "whpx"
    );
    assert_eq!(
        json["guest_asserted"]["network"]["value"]["channels"][0],
        "published_service"
    );
    assert_eq!(
        json["host_observed"]["network"]["observation"]["value"]["channels"],
        serde_json::json!([])
    );
    assert_eq!(
        json["host_observed"]["credentials"]["observation"]["source"]["how"],
        "verified"
    );
    assert_eq!(
        json["host_observed"]["credentials"]["observation"]["source"]["control"],
        control.to_hex()
    );
    assert!(json["guest_asserted"]["confinement"].is_null());
}

#[test]
fn stale_or_wrongly_fingerprinted_evidence_refuses() {
    // The hypervisor evidence is older than the required freshness.
    let host = fresh_host();
    let mut backend = fresh_backend();
    host.clock.advance(Duration::from_secs(61));
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::Stale {
                capability: Capability::HypervisorAvailable,
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                },
            }
        }
    );
    assert!(backend.running().is_empty());

    // The evidence was observed under another configuration fingerprint.
    let mut host = fresh_host();
    let mut other = request("exe-1", 1);
    other.configuration = config("b");
    let refusal = backend.launch(&other, &host.registry).unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::FingerprintChanged {
                capability: Capability::HypervisorAvailable,
                observed_under: config("a"),
                current: config("b"),
            }
        }
    );

    // The backend's own observations under another configuration than the request's.
    host.observe_available(HypervisorKind::Kvm, config("b"));
    let refusal = backend.launch(&other, &host.registry).unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Accelerator,
            problem: ObservationProblem::OtherConfiguration {
                observed_under: config("a"),
                current: config("b"),
            },
        }
    );
    assert!(refusal.to_string().contains("another host configuration"));
    assert!(backend.running().is_empty());
    backend.script_mut().configuration = config("b");
    assert!(backend.launch(&other, &host.registry).is_ok());
}

#[test]
fn admission_refuses_unbound_or_stale_evidence_and_stale_observations() {
    let mut host = fresh_host();
    host.observe_available(HypervisorKind::Whpx, config("a"));
    let backend = fresh_backend();
    let request = request("exe-1", 1);
    let vm = vm_handle(
        BackendKind::Fake,
        &request.execution,
        SandboxBootGeneration::FIRST,
    );

    // Evidence about another hypervisor is not bound to this launch.
    let whpx = Requirement::host_only(
        Capability::HypervisorAvailable,
        hypervisor_subject(HypervisorKind::Whpx),
        MINUTE,
        config("a"),
    );
    let unbound = host.registry.evaluate(&whpx).unwrap();
    let refusal = admit(
        &request,
        backend.identity(),
        &host.registry,
        unbound,
        backend.script().facts(host.registry.now()),
        vm,
        None,
    )
    .unwrap_err();
    assert!(matches!(refusal, LaunchRefusal::EvidenceNotBound { .. }));
    assert!(refusal.to_string().contains("not host-probe evidence"));

    // Observations older than the required freshness, with fresh evidence.
    let old_evidence = precheck(
        &request,
        backend.identity(),
        backend.features(),
        &host.registry,
    )
    .unwrap();
    let old_facts = backend.script().facts(host.registry.now());
    host.clock.advance(Duration::from_secs(61));
    host.observe_available(HypervisorKind::Kvm, config("a"));
    let fresh_evidence = precheck(
        &request,
        backend.identity(),
        backend.features(),
        &host.registry,
    )
    .unwrap();
    let refusal = admit(
        &request,
        backend.identity(),
        &host.registry,
        fresh_evidence,
        old_facts,
        vm,
        None,
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Accelerator,
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                }
            },
        }
    );

    // Evidence that was fresh when evaluated but has since expired.
    let refusal = admit(
        &request,
        backend.identity(),
        &host.registry,
        old_evidence,
        backend.script().facts(host.registry.now()),
        vm,
        None,
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::Stale {
                capability: Capability::HypervisorAvailable,
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                },
            }
        }
    );
}

#[test]
fn unsupported_features_are_typed_refusals_naming_the_feature() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let launched = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    assert_eq!(
        backend
            .snapshot(&launched.vm, SnapshotOrigin::PreTenantGolden)
            .unwrap_err(),
        BackendRefusal::Unsupported {
            feature: Feature::Snapshot
        }
    );
    let manifest = SnapshotManifest {
        snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"s"])),
        origin: SnapshotOrigin::PreTenantGolden,
        image_profile: image(),
        contents: BTreeSet::new(),
        source_vm: launched.vm,
        guest_identity: digest("yougori/test/guest/v1", &[b"g"]),
    };
    assert_eq!(
        backend
            .restore(&request("exe-1", 2), &manifest, &host.registry)
            .unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::Restore
        }
    );
    assert_eq!(
        backend
            .launch_emulated(&emulation_request(), &host.registry)
            .unwrap_err(),
        BackendRefusal::Unsupported {
            feature: Feature::DeveloperEmulation
        }
    );

    let gpu = GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[b"gpu0"]),
    };
    let mut with_gpu = request("exe-2", 1);
    with_gpu.device_profile.devices.gpus.insert(gpu);
    with_gpu.required.devices.gpus.insert(gpu);
    assert_eq!(
        backend.launch(&with_gpu, &host.registry).unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::GpuAssignment
        }
    );
    let mut with_display = request("exe-3", 1);
    with_display.device_profile.devices.display = true;
    with_display.required.devices.display = true;
    assert_eq!(
        backend.launch(&with_display, &host.registry).unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::Display
        }
    );
    let mut confidential = request("exe-4", 1);
    confidential.required.confidentiality = OperatorConfidentiality::VerifiedConfidentialVm {
        scope: digest("yougori/test/scope/v1", &[b"tee"]),
    };
    assert_eq!(
        backend.launch(&confidential, &host.registry).unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::ConfidentialVm
        }
    );
    let mut dedicated = request("exe-5", 1);
    dedicated.required.isolation.physical_host = PhysicalHost::Dedicated;
    assert_eq!(
        backend.launch(&dedicated, &host.registry).unwrap_err(),
        LaunchRefusal::Unsupported {
            feature: Feature::DedicatedHost
        }
    );
    // Nothing was created for any of them.
    assert_eq!(backend.running(), vec![launched.vm]);
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Create { .. }))
            .count(),
        1
    );
}

#[test]
fn a_handle_is_never_a_pid_and_survives_pid_reuse() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let first = backend
        .launch(&request("exe-a", 1), &host.registry)
        .unwrap();
    let first_pid = backend.pid_of(&first.vm).unwrap();
    assert_eq!(backend.stop(&first.vm), Ok(StopOutcome::Stopped));
    assert_eq!(backend.pid_of(&first.vm), None);

    let second = backend
        .launch(&request("exe-b", 1), &host.registry)
        .unwrap();
    assert_ne!(second.vm, first.vm);
    assert_eq!(backend.pid_of(&second.vm), Some(first_pid));
    assert_eq!(backend.pids_reused(), 1);

    // The stale handle reaches nothing: the process that inherited its PID runs on.
    assert_eq!(backend.stop(&first.vm), Ok(StopOutcome::AlreadyGone));
    assert_eq!(backend.running(), vec![second.vm]);
    assert_eq!(backend.pid_of(&second.vm), Some(first_pid));
    assert!(backend.actual_accelerator(&second.vm).is_ok());
    assert_eq!(
        backend.actual_accelerator(&first.vm).unwrap_err(),
        BackendRefusal::NoSuchVm { vm: first.vm }
    );
    assert_eq!(
        backend.confinement_evidence(&first.vm).unwrap_err(),
        BackendRefusal::NoSuchVm { vm: first.vm }
    );
    assert!(BackendRefusal::NoSuchVm { vm: first.vm }
        .to_string()
        .contains("no VM has the handle"));

    // Handles are digests of the sandbox and boot generation, not of the PID.
    assert_eq!(
        first.vm,
        vm_handle(
            BackendKind::Fake,
            &ExecutionId::new("exe-a").unwrap(),
            SandboxBootGeneration::FIRST
        )
    );
    assert_ne!(first.vm.digest().to_hex(), first_pid.to_string());
}

#[test]
fn a_repeated_launch_is_the_same_object_and_a_boot_generation_is_used_once() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let first = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    host.clock.advance(Duration::from_secs(5));
    let again = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Create { .. }))
            .count(),
        1
    );
    backend.stop(&first.vm).unwrap();
    assert_eq!(
        backend
            .launch(&request("exe-1", 1), &host.registry)
            .unwrap_err(),
        LaunchRefusal::BootGenerationUsed {
            execution: ExecutionId::new("exe-1").unwrap(),
            boot: SandboxBootGeneration::FIRST,
        }
    );
    let next = backend
        .launch(&request("exe-1", 2), &host.registry)
        .unwrap();
    assert_ne!(next.vm, first.vm);
    assert_ne!(next.record.identity(), first.record.identity());
}

#[test]
fn the_record_identity_changes_with_any_bound_field() {
    // One host, so every variant differs from the base only by the field it changes.
    let mut host = fresh_host();
    let identity_of = |host: &Host, change: &dyn Fn(&mut LaunchRequest, &mut FakeBackend)| {
        let mut backend = fresh_backend();
        let mut request = request("exe-1", 1);
        change(&mut request, &mut backend);
        backend
            .launch(&request, &host.registry)
            .unwrap()
            .record
            .identity()
    };
    let base = identity_of(&host, &|_, _| {});
    assert_eq!(
        base,
        identity_of(&host, &|_, _| {}),
        "the identity is deterministic"
    );

    let other_image = digest("yougori/test/image/v1", &[b"other"]);
    let variants: Vec<(&str, Box<dyn Fn(&mut LaunchRequest, &mut FakeBackend)>)> = vec![
        ("contract", Box::new(|r, _| r.contract = contract(b"c2"))),
        (
            "boot generation",
            Box::new(|r, _| r.generations.boot = SandboxBootGeneration::new(2)),
        ),
        (
            "policy epoch",
            Box::new(|r, _| r.generations.policy = PolicyEpoch::new(2)),
        ),
        (
            "authorization epoch",
            Box::new(|r, _| r.generations.authorization = AuthorizationEpoch::new(2)),
        ),
        (
            "tenant",
            Box::new(|r, _| r.tenant = TenantId::new("tenant-2").unwrap()),
        ),
        (
            "execution",
            Box::new(|r, _| r.execution = ExecutionId::new("exe-2").unwrap()),
        ),
        (
            "reservation",
            Box::new(|r, _| r.reservation = reservation(2)),
        ),
        (
            "guest image",
            Box::new(move |r, b| {
                r.pinned.guest_image = other_image;
                b.script_mut().guest_image = Scripted::HostObserved(other_image);
            }),
        ),
        (
            "device profile",
            Box::new(|r, _| {
                r.device_profile.identity = digest("yougori/test/profile/v1", &[b"other"])
            }),
        ),
        (
            "required network",
            Box::new(|r, _| {
                r.required.network = NetworkAuthority::of([NetworkChannel::NamedTransportRoutes])
            }),
        ),
        (
            "required freshness",
            Box::new(|r, _| r.required.evidence.max_age = Duration::from_secs(120)),
        ),
        (
            "observation source",
            Box::new(|_, b| {
                b.script_mut().credentials = Scripted::Verified {
                    value: CredentialExposure::none(),
                    control: digest("yougori/test/control/v1", &[b"scan"]),
                }
            }),
        ),
        (
            "observed host build",
            Box::new(|_, b| {
                b.script_mut().host = Scripted::HostObserved(HostBuild {
                    build: BuildId::new("6.6.1").unwrap(),
                    ..host_build()
                })
            }),
        ),
        (
            "guest assertion",
            Box::new(|_, b| b.script_mut().guest.network = Some(NetworkAuthority::offline())),
        ),
    ];
    let mut seen = BTreeSet::from([base]);
    for (name, change) in &variants {
        assert!(
            seen.insert(identity_of(&host, change.as_ref())),
            "{name} did not change the identity"
        );
    }

    // Another backend build.
    let other_artifact = digest("yougori/test/backend/v1", &[b"other"]);
    let mut other = FakeBackend::new(
        HypervisorKind::Kvm,
        BackendVersion::new("0.2.0").unwrap(),
        other_artifact,
        script(),
    );
    let mut pinned_to_other = request("exe-1", 1);
    pinned_to_other.pinned.backend = other_artifact;
    assert!(seen.insert(
        other
            .launch(&pinned_to_other, &host.registry)
            .unwrap()
            .record
            .identity()
    ));

    // The configuration fingerprint: the registry keeps one latest envelope per subject,
    // so this comes after the variants under configuration "a".
    host.observe_available(HypervisorKind::Kvm, config("b"));
    assert!(seen.insert(identity_of(&host, &|r, b| {
        r.configuration = config("b");
        b.script_mut().configuration = config("b");
    })));

    // The timestamp, and the clock session of another host, are bound too.
    host.observe_available(HypervisorKind::Kvm, config("a"));
    host.clock.advance(Duration::from_secs(1));
    assert!(seen.insert(identity_of(&host, &|_, _| {})));
    let other_host = fresh_host();
    assert!(seen.insert(identity_of(&other_host, &|_, _| {})));
    assert_eq!(seen.len(), variants.len() + 5);
}

#[test]
fn an_unvalidated_combination_is_never_supported() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let record = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap()
        .record;
    let lifecycle: BTreeSet<LifecycleCheck> = [LifecycleCheck::StopVerified].into_iter().collect();
    let key = EvidenceRowKey::of_record(&record, lifecycle.clone()).unwrap();
    assert_eq!(key.host, host_build());
    assert_eq!(key.backend, *record.backend());
    assert_eq!(key.guest_image, image());
    assert_eq!(key.accelerator, kvm());
    assert_eq!(key.confinement, ConfinementControl::all());
    assert!(key.devices.is_cpu_only());
    assert!(key.network.is_offline());
    assert_eq!(key.lifecycle, lifecycle);

    let mut profile = ReleaseProfile::new();
    assert_eq!(
        profile.status_of_record(&record, lifecycle.clone()),
        Ok(SupportStatus::Unavailable)
    );
    // A passed test of exactly this combination, on the fake: still not supported.
    let row = EvidenceRow {
        key: key.clone(),
        result: TestResult::Passed {
            report: digest("yougori/test/report/v1", &[b"r1"]),
            combination: key.identity(),
        },
    };
    assert_eq!(row.status(), SupportStatus::Experimental);
    profile.add(row).unwrap();
    assert_eq!(
        profile.status_of_record(&record, lifecycle.clone()),
        Ok(SupportStatus::Experimental)
    );
    // Another lifecycle behaviour is another combination.
    assert_eq!(
        profile.status_of_record(&record, BTreeSet::new()),
        Ok(SupportStatus::Unavailable)
    );
}

#[test]
fn a_restore_yields_a_fresh_generation_or_refuses() {
    let host = fresh_host();
    let mut backend =
        fresh_backend().with_features(BackendFeatures::of([Feature::Snapshot, Feature::Restore]));
    let first = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let golden = backend
        .snapshot(&first.vm, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    assert_eq!(golden.source_vm, first.vm);
    assert_eq!(golden.image_profile, image());
    assert!(golden.contents.is_empty());
    let unknown = vm_handle(
        BackendKind::Fake,
        &ExecutionId::new("exe-x").unwrap(),
        SandboxBootGeneration::FIRST,
    );
    assert_eq!(
        backend
            .snapshot(&unknown, SnapshotOrigin::PreTenantGolden)
            .unwrap_err(),
        BackendRefusal::NoSuchVm { vm: unknown }
    );
    backend.stop(&first.vm).unwrap();

    let restored = backend
        .restore(&request("exe-1", 2), &golden, &host.registry)
        .unwrap();
    assert_ne!(restored.launched.vm, first.vm);
    assert_eq!(restored.verified.vm(), restored.launched.vm);
    assert_eq!(restored.verified.boot(), SandboxBootGeneration::new(2));
    assert_eq!(restored.verified.snapshot(), golden.snapshot);
    assert_eq!(
        restored.launched.record.restored_from(),
        Some(golden.snapshot)
    );
    assert_ne!(restored.report.guest_identity, golden.guest_identity);
    assert_eq!(restored.report.source, SourceClass::HostProbe);
    assert!(restored.report.presented_epochs.is_empty());
    assert_ne!(restored.launched.record.identity(), first.record.identity());
    assert_eq!(backend.running(), vec![restored.launched.vm]);

    // A boot generation is never used twice, for a restore or a launch.
    assert_eq!(
        backend
            .restore(&request("exe-1", 2), &golden, &host.registry)
            .unwrap_err(),
        LaunchRefusal::BootGenerationUsed {
            execution: ExecutionId::new("exe-1").unwrap(),
            boot: SandboxBootGeneration::new(2),
        }
    );
    assert!(matches!(
        backend.launch(&request("exe-1", 1), &host.registry),
        Err(LaunchRefusal::BootGenerationUsed { .. })
    ));

    // A tenant-workload snapshot is never a base for restore.
    let dirty = backend
        .snapshot(&restored.launched.vm, SnapshotOrigin::TenantWorkload)
        .unwrap();
    assert_eq!(
        backend
            .restore(&request("exe-1", 3), &dirty, &host.registry)
            .unwrap_err(),
        LaunchRefusal::SnapshotNotRestorable {
            defects: vec![SnapshotDefect::NotPreTenant]
        }
    );
    // Forbidden contents disqualify a golden snapshot.
    backend
        .script_mut()
        .snapshot_contents
        .insert(SnapshotContent::InMemoryCredentials);
    let leaky = backend
        .snapshot(&restored.launched.vm, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    assert!(matches!(
        backend.restore(&request("exe-1", 3), &leaky, &host.registry),
        Err(LaunchRefusal::SnapshotNotRestorable { defects })
            if defects == vec![SnapshotDefect::Contains { content: SnapshotContent::InMemoryCredentials }]
    ));
    backend.script_mut().snapshot_contents.clear();

    // A restore that brings the old VM and guest identity back is refused and leaves
    // nothing behind.
    backend.script_mut().restore_reuses_identity = true;
    let refusal = backend
        .restore(&request("exe-1", 3), &golden, &host.registry)
        .unwrap_err();
    match &refusal {
        LaunchRefusal::RestoreRefused { refusal } => {
            let failures = refusal.failures();
            assert!(failures.contains(&RestoreFailure::VmIdentityReused { vm: first.vm }));
            assert!(failures.contains(&RestoreFailure::GuestIdentityReused));
        }
        other => unreachable!("{other:?}"),
    }
    assert_eq!(backend.running(), vec![restored.launched.vm]);
    assert!(matches!(
        backend.calls().last(),
        Some(FakeCall::Teardown { .. })
    ));
    backend.script_mut().restore_reuses_identity = false;

    // A missing required reset action is refused (VM part §6.6).
    backend
        .script_mut()
        .restore_actions
        .remove(&RestoreAction::KernelEntropyReseeded);
    let refusal = backend
        .restore(&request("exe-1", 3), &golden, &host.registry)
        .unwrap_err();
    assert!(matches!(
        &refusal,
        LaunchRefusal::RestoreRefused { refusal }
            if refusal.failures().iter().any(|failure| matches!(
                failure,
                RestoreFailure::MissingAction { action: RestoreAction::KernelEntropyReseeded, .. }
            ))
    ));
    assert_eq!(backend.running(), vec![restored.launched.vm]);

    // Boot generation 3 was never used by the refused restores.
    backend
        .script_mut()
        .restore_actions
        .insert(RestoreAction::KernelEntropyReseeded);
    let third = backend
        .restore(&request("exe-1", 3), &golden, &host.registry)
        .unwrap();
    assert_eq!(third.verified.boot(), SandboxBootGeneration::new(3));
    assert_eq!(backend.running().len(), 2);
}

#[test]
fn pinned_artifacts_must_match_the_backend_and_the_booted_image() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let other_backend = digest("yougori/test/backend/v1", &[b"other"]);
    let mut pinned_elsewhere = request("exe-1", 1);
    pinned_elsewhere.pinned.backend = other_backend;
    assert_eq!(
        backend
            .launch(&pinned_elsewhere, &host.registry)
            .unwrap_err(),
        LaunchRefusal::BackendArtifactMismatch {
            pinned: other_backend,
            actual: artifact(),
        }
    );
    assert!(backend
        .calls()
        .iter()
        .all(|call| matches!(call, FakeCall::Precheck { .. })));

    let other_image = digest("yougori/test/image/v1", &[b"other"]);
    backend.script_mut().guest_image = Scripted::HostObserved(other_image);
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    let failed = refusal.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].facet(), Facet::Evidence);
    assert_eq!(
        failed[0].failure(),
        Some(&CheckFailure::ArtifactMismatch {
            pinned: image(),
            observed: other_image,
        })
    );

    backend.script_mut().guest_image = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal.failed_checks()[0].failure(),
        Some(&CheckFailure::NotObserved {
            reason: UnknownReason::NotTested
        })
    );

    backend.script_mut().guest_image = Scripted::HostObserved(image());
    backend.script_mut().host = Scripted::Unavailable {
        reason: UnknownReason::Unreachable,
    };
    let refusal = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap_err();
    assert_eq!(refusal.failed_checks()[0].facet(), Facet::Evidence);
    assert_eq!(
        refusal.failed_checks()[0].failure(),
        Some(&CheckFailure::NotObserved {
            reason: UnknownReason::Unreachable
        })
    );
    assert!(backend.running().is_empty());
}

#[test]
fn device_inventories_are_measured_and_assigned_gpus_need_isolation_evidence() {
    let host = fresh_host();
    let gpu = GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[b"gpu0"]),
    };
    let observed = |isolation: GpuIsolation| DeviceInventory {
        paravirtualized_gpu: false,
            display: false,
        gpus: [ObservedGpu {
            device: gpu,
            isolation,
        }]
        .into_iter()
        .collect(),
    };
    let mut backend = fresh_backend().with_features(BackendFeatures::of([
        Feature::GpuAssignment,
        Feature::Display,
    ]));
    let mut with_gpu = request("exe-1", 1);
    with_gpu.device_profile.devices.gpus.insert(gpu);
    with_gpu.required.devices.gpus.insert(gpu);

    // The host measured no GPU: the inventory is not the approved profile.
    let refusal = backend.launch(&with_gpu, &host.registry).unwrap_err();
    assert_eq!(
        refusal.failed_checks()[0].failure(),
        Some(&CheckFailure::InventoryDiffersFromProfile {
            profile: with_gpu.device_profile.devices.clone(),
            observed: DeviceExposure::cpu_only(),
        })
    );

    // Measured with complete §7.5 isolation evidence.
    backend.script_mut().devices = Scripted::HostObserved(observed(GpuIsolation::complete()));
    let launched = backend.launch(&with_gpu, &host.registry).unwrap();
    assert_eq!(launched.record.device_profile(), &with_gpu.device_profile);
    assert_eq!(
        launched
            .record
            .host_observed()
            .devices
            .value()
            .unwrap()
            .exposure(),
        with_gpu.device_profile.devices
    );
    backend.stop(&launched.vm).unwrap();
    let mut boot2 = with_gpu.clone();
    boot2.generations.boot = SandboxBootGeneration::new(2);

    // A missing check refuses (VM-P39).
    let mut partial = GpuIsolation::complete();
    partial
        .checks
        .remove(&GpuIsolationCheck::SafeResetAndReassignment);
    backend.script_mut().devices = Scripted::HostObserved(observed(partial));
    let refusal = backend.launch(&boot2, &host.registry).unwrap_err();
    assert_eq!(
        refusal.failed_checks()[0].failure(),
        Some(&CheckFailure::DeviceNotIsolated {
            device: gpu,
            missing: [GpuIsolationCheck::SafeResetAndReassignment]
                .into_iter()
                .collect(),
            unsafe_settings: BTreeSet::new(),
        })
    );
    assert!(refusal.to_string().contains("lacks 1 isolation check"));

    // An unsafe setting refuses even with every check (§7.5 lines 2407–2409).
    let mut bypass = GpuIsolation::complete();
    bypass
        .unsafe_settings
        .insert(UnsafeDeviceSetting::UnsafeInterrupts);
    backend.script_mut().devices = Scripted::HostObserved(observed(bypass));
    let refusal = backend.launch(&boot2, &host.registry).unwrap_err();
    assert!(matches!(
        refusal.failed_checks()[0].failure(),
        Some(CheckFailure::DeviceNotIsolated { unsafe_settings, missing, .. })
            if unsafe_settings.contains(&UnsafeDeviceSetting::UnsafeInterrupts) && missing.is_empty()
    ));

    // A profile wider than the requirement refuses, even when measured exactly.
    backend.script_mut().devices = Scripted::HostObserved(observed(GpuIsolation::complete()));
    let mut wider = boot2.clone();
    wider.required.devices = DeviceExposure::cpu_only();
    let refusal = backend.launch(&wider, &host.registry).unwrap_err();
    assert!(matches!(
        refusal.failed_checks()[0].failure(),
        Some(CheckFailure::NotMet {
            required: FacetValue::Devices { .. },
            ..
        })
    ));
    assert!(backend.running().is_empty());

    // A display is measured like any other device.
    let mut display = request("exe-2", 1);
    display.device_profile.devices.display = true;
    display.required.devices.display = true;
    backend.script_mut().devices = Scripted::HostObserved(DeviceInventory {
        paravirtualized_gpu: false,
            display: true,
        gpus: BTreeSet::new(),
    });
    assert!(backend.launch(&display, &host.registry).is_ok());
    assert_eq!(backend.running().len(), 1);
}

#[test]
fn every_facet_is_judged_by_its_rule() {
    let host = fresh_host();
    let mut backend = fresh_backend().with_features(BackendFeatures::of([
        Feature::DedicatedHost,
        Feature::ConfidentialVm,
    ]));
    let failing = |backend: &mut FakeBackend, request: &LaunchRequest, facet: Facet| {
        let refusal = backend.launch(request, &host.registry).unwrap_err();
        let failed = refusal.failed_checks();
        assert_eq!(failed.len(), 1, "{refusal}");
        assert_eq!(failed[0].facet(), facet);
        failed[0].failure().unwrap().clone()
    };

    // Network authority: at most what is required.
    backend.script_mut().network =
        Scripted::HostObserved(NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]));
    assert!(matches!(
        failing(&mut backend, &request("exe-1", 1), Facet::NetworkAuthority),
        CheckFailure::NotMet { .. }
    ));
    let mut routes = request("exe-1", 1);
    routes.required.network = NetworkAuthority::of([
        NetworkChannel::NamedTransportRoutes,
        NetworkChannel::TypedCredentialedOperations,
    ]);
    let launched = backend.launch(&routes, &host.registry).unwrap();
    backend.stop(&launched.vm).unwrap();
    backend.script_mut().network = Scripted::HostObserved(NetworkAuthority::offline());

    // Credential exposure: at most what is required.
    backend.script_mut().credentials = Scripted::HostObserved(CredentialExposure::of([
        CredentialKind::ExternalProviderCredentials,
    ]));
    assert!(matches!(
        failing(
            &mut backend,
            &request("exe-2", 1),
            Facet::CredentialExposure
        ),
        CheckFailure::NotMet { .. }
    ));
    backend.script_mut().credentials = Scripted::HostObserved(CredentialExposure::none());

    // Persistence: exactly what is required.
    backend.script_mut().persistence = Scripted::HostObserved(Persistence::DeclaredDataVolumes {
        volumes: BTreeSet::new(),
    });
    let failure = failing(&mut backend, &request("exe-3", 1), Facet::Persistence);
    assert_eq!(
        failure.to_string(),
        "required ephemeral_task, observed declared_data_volumes"
    );
    backend.script_mut().persistence = Scripted::HostObserved(Persistence::EphemeralTask);

    // Hypervisor confinement: at least the required controls.
    let mut fewer = ConfinementControl::all();
    fewer.remove(&ConfinementControl::SyscallRestrictions);
    backend.script_mut().confinement = Scripted::HostObserved(fewer);
    assert!(matches!(
        failing(
            &mut backend,
            &request("exe-4", 1),
            Facet::HypervisorConfinement
        ),
        CheckFailure::NotMet { .. }
    ));
    backend.script_mut().confinement = Scripted::HostObserved(ConfinementControl::all());

    // Isolation: a dedicated host is required, a shared one observed; then no own kernel.
    let mut dedicated = request("exe-5", 1);
    dedicated.required.isolation.physical_host = PhysicalHost::Dedicated;
    assert!(matches!(
        failing(&mut backend, &dedicated, Facet::Isolation),
        CheckFailure::NotMet {
            observed: FacetValue::Isolation {
                physical_host: PhysicalHost::Shared,
                ..
            },
            ..
        }
    ));
    backend.script_mut().isolation = Scripted::HostObserved(IsolationObservation {
        own_guest_kernel: true,
        physical_host: PhysicalHost::Dedicated,
    });
    let launched = backend.launch(&dedicated, &host.registry).unwrap();
    backend.stop(&launched.vm).unwrap();
    backend.script_mut().isolation = Scripted::HostObserved(IsolationObservation {
        own_guest_kernel: false,
        physical_host: PhysicalHost::Dedicated,
    });
    assert!(matches!(
        failing(&mut backend, &request("exe-6", 1), Facet::Isolation),
        CheckFailure::NotMet {
            observed: FacetValue::Isolation {
                own_guest_kernel: false,
                ..
            },
            ..
        }
    ));
    backend.script_mut().isolation = Scripted::HostObserved(IsolationObservation {
        own_guest_kernel: true,
        physical_host: PhysicalHost::Shared,
    });

    // Operator confidentiality: the stated scope, verified, or nothing.
    let scope = digest("yougori/test/scope/v1", &[b"tee"]);
    let mut confidential = request("exe-7", 1);
    confidential.required.confidentiality =
        OperatorConfidentiality::VerifiedConfidentialVm { scope };
    assert!(matches!(
        failing(&mut backend, &confidential, Facet::OperatorConfidentiality),
        CheckFailure::NotMet { .. }
    ));
    backend.script_mut().confidentiality =
        Scripted::HostObserved(OperatorConfidentiality::VerifiedConfidentialVm {
            scope: digest("yougori/test/scope/v1", &[b"other"]),
        });
    assert!(matches!(
        failing(&mut backend, &confidential, Facet::OperatorConfidentiality),
        CheckFailure::NotMet { .. }
    ));
    backend.script_mut().confidentiality =
        Scripted::HostObserved(OperatorConfidentiality::VerifiedConfidentialVm { scope });
    assert!(backend.launch(&confidential, &host.registry).is_ok());

    // Several failing facets are all listed.
    backend.script_mut().network =
        Scripted::HostObserved(NetworkAuthority::of([NetworkChannel::PublishedService]));
    backend.script_mut().persistence =
        Scripted::HostObserved(Persistence::ControlledServiceRenewal {
            volumes: BTreeSet::new(),
        });
    let refusal = backend
        .launch(&request("exe-8", 1), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal
            .failed_checks()
            .iter()
            .map(|check| check.facet())
            .collect::<Vec<_>>(),
        vec![Facet::NetworkAuthority, Facet::Persistence]
    );
    assert!(refusal
        .to_string()
        .starts_with("2 required properties are not satisfied: network authority:"));
}

#[test]
fn developer_emulation_is_a_separate_non_sandbox_facility() {
    let host = fresh_host();
    let mut backend =
        fresh_backend().with_features(BackendFeatures::of([Feature::DeveloperEmulation]));
    let emulated = backend
        .launch_emulated(&emulation_request(), &host.registry)
        .unwrap();
    assert_eq!(emulated.emulator, Emulator::Tcg);
    assert_eq!(emulated.execution.as_str(), "exe-dev");
    assert_eq!(backend.emulation_launches(), 1);
    assert_eq!(backend.emulated(), vec![emulated.vm]);
    assert!(backend.pid_of(&emulated.vm).is_some());
    // Not a sandbox: not among the running sandboxes, with no record or evidence.
    assert!(backend.running().is_empty());
    assert_eq!(
        backend.actual_accelerator(&emulated.vm).unwrap_err(),
        BackendRefusal::NoSuchVm { vm: emulated.vm }
    );
    let json = serde_json::to_value(&emulated).unwrap();
    assert!(json.get("record").is_none());
    assert!(json.get("required").is_none());
    assert_eq!(backend.stop(&emulated.vm), Ok(StopOutcome::Stopped));
    assert!(backend.emulated().is_empty());
    assert_eq!(backend.stop(&emulated.vm), Ok(StopOutcome::AlreadyGone));
}

#[test]
fn a_record_is_not_presented_as_current_once_its_evidence_ages() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let record = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap()
        .record;
    assert_eq!(record.assert_current(host.registry.now()), Ok(()));
    host.clock.advance(MINUTE);
    assert_eq!(record.assert_current(host.registry.now()), Ok(()));
    host.clock.advance(Duration::from_secs(1));
    let stale = record.assert_current(host.registry.now()).unwrap_err();
    assert_eq!(
        stale,
        StaleFact {
            fact: FactName::HypervisorEvidence,
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                }
            },
        }
    );
    assert!(stale.to_string().contains("is not current"));

    // On another clock session nothing is current.
    let restarted = ProbeRegistry::new(Arc::clone(&host.clock));
    assert_eq!(
        record.assert_current(restarted.now()),
        Err(StaleFact {
            fact: FactName::HypervisorEvidence,
            problem: ObservationProblem::Stale {
                staleness: Staleness::OtherClock
            },
        })
    );
}

#[test]
fn a_failed_creation_leaves_nothing_behind() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    backend.script_mut().create_failure = Some("no free root".to_owned());
    assert_eq!(
        backend
            .launch(&request("exe-1", 1), &host.registry)
            .unwrap_err(),
        LaunchRefusal::CreateFailed {
            detail: "no free root".to_owned()
        }
    );
    assert!(backend.running().is_empty());
    let handle = vm_handle(
        BackendKind::Fake,
        &ExecutionId::new("exe-1").unwrap(),
        SandboxBootGeneration::FIRST,
    );
    assert_eq!(backend.pid_of(&handle), None);
    // The generation was not consumed by a launch that created nothing.
    backend.script_mut().create_failure = None;
    assert!(backend.launch(&request("exe-1", 1), &host.registry).is_ok());
}

#[test]
fn scripts_are_inputs_that_refuse_unknown_fields() {
    let script = script();
    let json = serde_json::to_value(&script).unwrap();
    assert_eq!(
        json["accelerator"]["host_observed"]["hardware"]["hypervisor"],
        "kvm"
    );
    assert_eq!(
        serde_json::from_value::<HostScript>(json.clone()).unwrap(),
        script
    );
    let mut extra = json;
    extra["pid"] = 1.into();
    assert!(serde_json::from_value::<HostScript>(extra).is_err());
    assert!(serde_json::from_value::<Scripted<u8>>(serde_json::json!({
        "unavailable": {"reason": "not_tested", "value": 1}
    }))
    .is_err());
    assert_eq!(
        serde_json::from_value::<Scripted<u8>>(serde_json::json!({"host_observed": 7})).unwrap(),
        Scripted::HostObserved(7)
    );
}

// ---- the independent perimeter (§4.4 lines 2153–2165; VM-CP-11 line 3161) ----

fn perimeter_id() -> Digest {
    digest("yougori/test/perimeter/v1", &[b"host"])
}

fn broker() -> Digest {
    digest("yougori/test/principal/v1", &[b"broker"])
}

fn block_rule(name: &[u8]) -> Digest {
    digest("yougori/test/rule/v1", &[name])
}

fn rule_subject(rule: Digest, principal: Digest) -> PerimeterRuleSubject {
    PerimeterRuleSubject {
        machine: machine(),
        perimeter: perimeter_id(),
        rule,
        principal,
    }
}

/// A launch whose network facet asks for an independent perimeter whose `rules`
/// restrict the broker.
fn perimeter_request(execution: &str, rules: &[Digest]) -> LaunchRequest {
    let mut request = request(execution, 1);
    request.required.perimeter = PerimeterRequirement::Independent {
        perimeter: perimeter_id(),
        principal: broker(),
        rules: rules.iter().copied().collect(),
    };
    request
}

/// A host with fresh hypervisor evidence and a perimeter probe of `source` that has not
/// run yet.
fn perimeter_host(source: SourceClass) -> (Host, Arc<FakeProbe>) {
    let mut host = fresh_host();
    let probe = Arc::new(FakeProbe::new(Capability::PerimeterRuleEnforced, source));
    host.registry
        .register(Box::new(Arc::clone(&probe)))
        .unwrap();
    (host, probe)
}

/// The must-probe of `rule` returns `observation`, and the registry stores it.
fn observe_rule(
    host: &mut Host,
    probe: &FakeProbe,
    rule: PerimeterRuleSubject,
    observation: Observation,
) {
    let subject = Subject::PerimeterRule(rule);
    probe.respond(&subject, observation);
    host.registry
        .refresh(Capability::PerimeterRuleEnforced, &subject)
        .unwrap();
}

fn enforced(configuration: ConfigurationFingerprint, fresh_for: Duration) -> Observation {
    Observation::supported(
        configuration,
        fresh_for,
        SupportDetail::PerimeterRuleEnforced,
    )
}

fn created(backend: &FakeBackend) -> bool {
    backend
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Create { .. }))
}

#[test]
fn perimeter_requirements_are_host_only_per_rule_for_the_launch_principal() {
    assert!(perimeter_requirements(&request("exe-1", 1)).is_empty());
    let rules = [block_rule(b"private-ranges"), block_rule(b"metadata")];
    let request = perimeter_request("exe-1", &rules);
    let requirements = perimeter_requirements(&request);
    assert_eq!(requirements.len(), 2);
    for (subject, requirement) in &requirements {
        assert_eq!(requirement.capability, Capability::PerimeterRuleEnforced);
        assert!(requirement.is_host_only());
        assert_eq!(requirement.subject, Subject::PerimeterRule(*subject));
        assert_eq!(requirement.max_age, MINUTE);
        assert_eq!(requirement.configuration, request.configuration);
        assert_eq!(subject.machine, request.machine);
        assert_eq!(subject.perimeter, perimeter_id());
        assert_eq!(subject.principal, broker());
    }
    let named: BTreeSet<Digest> = requirements
        .iter()
        .map(|(subject, _)| subject.rule)
        .collect();
    assert_eq!(named, rules.into_iter().collect());
}

/// §4.4 and VM-CP-11: where the network facet asks for an independent perimeter,
/// admission needs host-probe evidence for every block rule and the principal the
/// launch uses, under the current configuration; each failure is refused by rule and
/// nothing is created.
#[test]
fn admission_needs_perimeter_evidence_for_every_rule_and_the_launch_principal() {
    let (mut host, probe) = perimeter_host(SourceClass::HostProbe);
    let mut backend = fresh_backend();
    let ordered: Vec<Digest> = [block_rule(b"private-ranges"), block_rule(b"metadata")]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let request = perimeter_request("exe-1", &ordered);
    let first = rule_subject(ordered[0], broker());
    let second = rule_subject(ordered[1], broker());

    // No evidence at all: the first rule is refused by name, before anything exists.
    let refusal = backend.launch(&request, &host.registry).unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::PerimeterNotEvidenced {
            rule: first,
            refusal: EvidenceRefusal::Missing {
                capability: Capability::PerimeterRuleEnforced
            }
        }
    );
    assert!(refusal.to_string().contains("is not shown enforced"));
    assert_eq!(
        serde_json::to_value(&refusal).unwrap()["kind"],
        "perimeter_not_evidenced"
    );
    assert!(!created(&backend));
    assert!(backend.running().is_empty());

    // One rule shown enforced: the other is still refused by name.
    observe_rule(&mut host, &probe, first, enforced(config("a"), MINUTE));
    let refusal = backend.launch(&request, &host.registry).unwrap_err();
    assert!(
        matches!(
            &refusal,
            LaunchRefusal::PerimeterNotEvidenced {
                rule,
                refusal: EvidenceRefusal::Missing { .. }
            } if *rule == second
        ),
        "{refusal:?}"
    );

    // Evidence for another principal never stands in for the launch's broker.
    let other = digest("yougori/test/principal/v1", &[b"other-service"]);
    observe_rule(
        &mut host,
        &probe,
        rule_subject(ordered[1], other),
        enforced(config("a"), MINUTE),
    );
    assert!(matches!(
        backend.launch(&request, &host.registry).unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            refusal: EvidenceRefusal::Missing { .. },
            ..
        }
    ));

    // Observed under another configuration: it no longer applies.
    observe_rule(&mut host, &probe, second, enforced(config("b"), MINUTE));
    assert!(matches!(
        backend.launch(&request, &host.registry).unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            refusal: EvidenceRefusal::FingerprintChanged { .. },
            ..
        }
    ));

    // The must-probe connected: the perimeter does not enforce the rule.
    observe_rule(
        &mut host,
        &probe,
        second,
        Observation::unsupported(config("a"), MINUTE, UnsupportedReason::NotEnforced),
    );
    let refusal = backend.launch(&request, &host.registry).unwrap_err();
    let LaunchRefusal::PerimeterNotEvidenced { refusal, .. } = refusal else {
        panic!("{refusal:?}");
    };
    assert_eq!(
        refusal,
        EvidenceRefusal::Unsupported {
            capability: Capability::PerimeterRuleEnforced,
            reason: UnsupportedReason::NotEnforced
        }
    );
    assert_eq!(refusal.remedy(), Remedy::RepairPerimeter);

    // A timeout to an unused address is inconclusive, never a pass (§4.4 line 2165).
    observe_rule(
        &mut host,
        &probe,
        second,
        Observation::unknown(config("a"), MINUTE, UnknownReason::Inconclusive),
    );
    assert!(matches!(
        backend.launch(&request, &host.registry).unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            refusal: EvidenceRefusal::Unknown {
                reason: UnknownReason::Inconclusive,
                ..
            },
            ..
        }
    ));
    assert!(!created(&backend), "no refusal created anything");

    // Both rules enforced for the broker: admitted, and the record binds the evidence.
    observe_rule(&mut host, &probe, second, enforced(config("a"), MINUTE));
    let launched = backend.launch(&request, &host.registry).unwrap();
    let evidence = launched.record.perimeter_evidence();
    assert_eq!(evidence.len(), 2);
    for (satisfied, rule) in evidence.iter().zip(&ordered) {
        assert_eq!(satisfied.capability(), Capability::PerimeterRuleEnforced);
        assert_eq!(satisfied.source(), SourceClass::HostProbe);
        assert_eq!(satisfied.configuration(), config("a"));
        assert_eq!(
            satisfied.subject(),
            Subject::PerimeterRule(rule_subject(*rule, broker())).identity()
        );
    }
    assert_eq!(
        launched.record.required().perimeter,
        request.required.perimeter
    );
    let json = serde_json::to_value(&launched.record).unwrap();
    assert_eq!(json["perimeter_evidence"].as_array().unwrap().len(), 2);

    // A launch whose network facet asks for no perimeter needs none and records none.
    let plain = backend
        .launch(&self::request("exe-2", 1), &host.registry)
        .unwrap();
    assert!(plain.record.perimeter_evidence().is_empty());
    let json = serde_json::to_value(&plain.record).unwrap();
    assert!(json.get("perimeter_evidence").is_none());
    assert!(json["required"].get("perimeter").is_none());
}

#[test]
fn a_guest_report_never_shows_the_perimeter() {
    let (mut host, probe) = perimeter_host(SourceClass::GuestReport);
    let mut backend = fresh_backend();
    let rule = block_rule(b"private-ranges");
    let request = perimeter_request("exe-1", &[rule]);
    observe_rule(
        &mut host,
        &probe,
        rule_subject(rule, broker()),
        enforced(config("a"), MINUTE),
    );
    assert_eq!(
        backend.launch(&request, &host.registry).unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            rule: rule_subject(rule, broker()),
            refusal: EvidenceRefusal::SourceTooWeak {
                capability: Capability::PerimeterRuleEnforced,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe
            }
        }
    );
    assert!(!created(&backend));
}

/// The perimeter's evidence must still be fresh at admission, after the VM was created,
/// and a record whose perimeter evidence went stale is no longer current.
#[test]
fn stale_perimeter_evidence_refuses_admission_and_ages_the_record() {
    let (mut host, probe) = perimeter_host(SourceClass::HostProbe);
    let backend = fresh_backend();
    let rule = rule_subject(block_rule(b"private-ranges"), broker());
    let request = perimeter_request("exe-1", &[rule.rule]);
    observe_rule(
        &mut host,
        &probe,
        rule,
        enforced(config("a"), Duration::from_secs(30)),
    );
    let evidence = precheck(
        &request,
        backend.identity(),
        backend.features(),
        &host.registry,
    )
    .unwrap();
    host.clock.advance(Duration::from_secs(31));
    let vm = vm_handle(
        BackendKind::Fake,
        &request.execution,
        SandboxBootGeneration::FIRST,
    );
    let refusal = admit(
        &request,
        backend.identity(),
        &host.registry,
        evidence,
        script().facts(host.registry.now()),
        vm,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(
            refusal,
            LaunchRefusal::PerimeterNotEvidenced {
                refusal: EvidenceRefusal::Stale { .. },
                ..
            }
        ),
        "{refusal:?}"
    );

    // Fresh again: admitted. Once the perimeter evidence ages out, the record is no
    // longer current, named as the network enforcement fact.
    let mut backend = fresh_backend();
    host.observe_available(HypervisorKind::Kvm, config("a"));
    observe_rule(
        &mut host,
        &probe,
        rule,
        enforced(config("a"), Duration::from_secs(30)),
    );
    let launched = backend.launch(&request, &host.registry).unwrap();
    assert_eq!(launched.record.assert_current(host.registry.now()), Ok(()));
    host.clock.advance(Duration::from_secs(31));
    let stale = launched
        .record
        .assert_current(host.registry.now())
        .unwrap_err();
    assert_eq!(stale.fact, FactName::Network);
    assert!(matches!(
        stale.problem,
        ObservationProblem::Stale {
            staleness: Staleness::TooOld { .. }
        }
    ));
    assert!(matches!(
        backend
            .launch(&perimeter_request("exe-2", &[rule.rule]), &host.registry)
            .unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            refusal: EvidenceRefusal::Stale { .. },
            ..
        }
    ));
}

#[test]
fn a_perimeter_without_block_rules_is_refused_by_name() {
    let (host, _) = perimeter_host(SourceClass::HostProbe);
    let mut backend = fresh_backend();
    let refusal = backend
        .launch(&perimeter_request("exe-1", &[]), &host.registry)
        .unwrap_err();
    assert_eq!(
        refusal,
        LaunchRefusal::NoPerimeterRules {
            perimeter: perimeter_id(),
            principal: broker()
        }
    );
    assert!(refusal.to_string().contains("names no block rule"));
    assert!(!created(&backend));
}

/// A restore reapplies the perimeter requirement (§6.6 line 2347: "reapply current
/// policy, perimeter and evidence requirements").
#[test]
fn a_restore_needs_the_perimeter_evidence_too() {
    let (mut host, probe) = perimeter_host(SourceClass::HostProbe);
    let mut backend =
        fresh_backend().with_features(BackendFeatures::of([Feature::Snapshot, Feature::Restore]));
    let first = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let golden = backend
        .snapshot(&first.vm, SnapshotOrigin::PreTenantGolden)
        .unwrap();
    backend.stop(&first.vm).unwrap();
    let rule = rule_subject(block_rule(b"private-ranges"), broker());
    let mut restore = perimeter_request("exe-1", &[rule.rule]);
    restore.generations.boot = SandboxBootGeneration::new(2);
    assert!(matches!(
        backend
            .restore(&restore, &golden, &host.registry)
            .unwrap_err(),
        LaunchRefusal::PerimeterNotEvidenced {
            refusal: EvidenceRefusal::Missing { .. },
            ..
        }
    ));
    observe_rule(&mut host, &probe, rule, enforced(config("a"), MINUTE));
    let restored = backend.restore(&restore, &golden, &host.registry).unwrap();
    assert_eq!(restored.launched.record.perimeter_evidence().len(), 1);
}

// ---- observing a running VM again (§8.1 line 2439; VM-W04 row, line 2589) ----

/// A backend that keeps the contract's default re-observation.
struct WithoutReobservation(FakeBackend);

impl VmBackend for WithoutReobservation {
    fn identity(&self) -> &BackendIdentity {
        self.0.identity()
    }

    fn features(&self) -> &BackendFeatures {
        self.0.features()
    }

    fn launch(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal> {
        self.0.launch(request, host)
    }

    fn stop(
        &mut self,
        vm: &crate::foundation::coordination::VmInstanceId,
    ) -> Result<StopOutcome, BackendRefusal> {
        self.0.stop(vm)
    }

    fn snapshot(
        &mut self,
        vm: &crate::foundation::coordination::VmInstanceId,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal> {
        self.0.snapshot(vm, origin)
    }

    fn restore(
        &mut self,
        request: &LaunchRequest,
        snapshot: &SnapshotManifest,
        host: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal> {
        self.0.restore(request, snapshot, host)
    }

    fn actual_accelerator(
        &self,
        vm: &crate::foundation::coordination::VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal> {
        self.0.actual_accelerator(vm)
    }

    fn confinement_evidence(
        &self,
        vm: &crate::foundation::coordination::VmInstanceId,
    ) -> Result<ObservedProperties, BackendRefusal> {
        self.0.confinement_evidence(vm)
    }

    fn running(&self) -> Vec<crate::foundation::coordination::VmInstanceId> {
        self.0.running()
    }
}

#[test]
fn a_stale_record_is_current_again_only_on_a_fresh_reobservation() {
    let mut host = fresh_host();
    let mut backend = fresh_backend();
    let launched = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let record = &launched.record;

    // Before the launch-time facts age, a re-observation also presents the launch as
    // current; the record itself is unchanged.
    let early = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert_eq!(early.vm(), launched.vm);
    assert_eq!(early.record(), record.identity());
    assert_eq!(early.observed_at(), host.clock.now());
    assert_eq!(early.clock(), host.registry.session());
    assert_eq!(
        record.assert_current_with(host.registry.now(), &early),
        Ok(())
    );
    assert!(backend
        .calls()
        .contains(&FakeCall::Reobserve { vm: launched.vm }));

    // Past the required freshness the launch-time facts are stale, and so is the early
    // re-observation, whose CORE-01 evidence is the probe's last observation.
    host.clock.advance(MINUTE + Duration::from_secs(1));
    assert!(record.assert_current(host.registry.now()).is_err());
    assert!(matches!(
        record.assert_current_with(host.registry.now(), &early),
        Err(ReobservationRefusal::Refused { .. })
    ));
    // Without fresh CORE-01 evidence, re-observing does not help: readiness stays
    // unavailable until the host probe observes again.
    let refusal = backend.reobserve(&launched.vm, &host.registry).unwrap_err();
    assert!(
        matches!(
            &refusal,
            ReobservationRefusal::Refused { refusal }
                if matches!(**refusal, LaunchRefusal::Evidence {
                    refusal: EvidenceRefusal::Stale { .. }
                })
        ),
        "{refusal:?}"
    );
    assert!(refusal.to_string().starts_with("observed again: "));

    host.observe_available(HypervisorKind::Kvm, config("a"));
    let fresh = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert_eq!(
        record.assert_current_with(host.registry.now(), &fresh),
        Ok(())
    );
    assert_eq!(fresh.hypervisor_evidence().observed_at(), host.clock.now());
    assert!(fresh
        .accelerator()
        .observation()
        .is_some_and(|observed| observed.observed_at() == host.clock.now()));
    assert_eq!(
        fresh.host_observed().confinement.value(),
        Some(&ConfinementControl::all())
    );
    let json = serde_json::to_value(&fresh).unwrap();
    assert_eq!(json["record"], record.identity().to_hex());
    assert!(json.get("perimeter_evidence").is_none());

    // The fresh re-observation ages like any observation.
    host.clock.advance(MINUTE + Duration::from_secs(1));
    assert!(record
        .assert_current_with(host.registry.now(), &fresh)
        .is_err());
}

#[test]
fn a_reobservation_that_no_longer_satisfies_the_launch_is_refused() {
    let mut host = fresh_host();
    let mut backend = fresh_backend();
    let launched = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    host.clock.advance(MINUTE + Duration::from_secs(1));
    host.observe_available(HypervisorKind::Kvm, config("a"));

    // The host now observes fewer confinement controls than the launch requires.
    backend.script_mut().confinement =
        Scripted::HostObserved(BTreeSet::from([ConfinementControl::AccountIdentity]));
    let weaker = backend.reobserve(&launched.vm, &host.registry).unwrap();
    let refusal = launched
        .record
        .assert_current_with(host.registry.now(), &weaker)
        .unwrap_err();
    let ReobservationRefusal::Refused { refusal } = &refusal else {
        panic!("{refusal:?}");
    };
    assert_eq!(
        refusal
            .failed_checks()
            .iter()
            .map(|check| check.facet())
            .collect::<Vec<Facet>>(),
        vec![Facet::HypervisorConfinement]
    );

    // Only the guest asserts the confinement: never counted.
    backend.script_mut().confinement = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    backend.script_mut().guest.confinement = Some(ConfinementControl::all());
    let asserted = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert!(asserted.guest_asserted().confinement.is_some());
    let refusal = launched
        .record
        .assert_current_with(host.registry.now(), &asserted)
        .unwrap_err();
    assert!(
        matches!(
            &refusal,
            ReobservationRefusal::Refused { refusal }
                if refusal.failed_checks().iter().any(|check| matches!(
                    check.failure(),
                    Some(CheckFailure::OnlyGuestAsserted { .. })
                ))
        ),
        "{refusal:?}"
    );

    // Emulation observed now refuses as at launch.
    backend.script_mut().confinement = Scripted::HostObserved(ConfinementControl::all());
    backend.script_mut().accelerator = Scripted::HostObserved(Accelerator::Emulation {
        emulator: Emulator::Tcg,
    });
    let emulated = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert!(matches!(
        launched
            .record
            .assert_current_with(host.registry.now(), &emulated),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::NotHardwareVirtualized { .. })
    ));

    // Observations made under another configuration than the launch's do not apply, and
    // CORE-01 evidence observed under another configuration does not satisfy the
    // launch's requirement.
    backend.script_mut().accelerator = Scripted::HostObserved(kvm());
    backend.script_mut().configuration = config("b");
    let other = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert!(matches!(
        launched
            .record
            .assert_current_with(host.registry.now(), &other),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::ObservationNotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            })
    ));
    backend.script_mut().configuration = config("a");
    host.observe_available(HypervisorKind::Kvm, config("b"));
    assert!(matches!(
        backend.reobserve(&launched.vm, &host.registry),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::Evidence { .. })
    ));

    // The backend's own failure to observe is a typed refusal.
    host.observe_available(HypervisorKind::Kvm, config("a"));
    backend.script_mut().reobserve_failure = Some("the host lost the VM's handle".to_owned());
    assert_eq!(
        backend.reobserve(&launched.vm, &host.registry),
        Err(ReobservationRefusal::Refused {
            refusal: Box::new(LaunchRefusal::BackendSpecific {
                backend: BackendKind::Fake,
                detail: "the host lost the VM's handle".to_owned(),
            })
        })
    );
}

#[test]
fn a_reobservation_belongs_to_one_launch_and_one_running_vm() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    let first = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let second = backend
        .launch(&request("exe-2", 1), &host.registry)
        .unwrap();
    let of_second = backend.reobserve(&second.vm, &host.registry).unwrap();
    assert_eq!(
        first
            .record
            .assert_current_with(host.registry.now(), &of_second),
        Err(ReobservationRefusal::OtherLaunch {
            record: first.record.identity(),
            reobserved: second.record.identity(),
        })
    );

    // A stopped VM, or one this backend never ran, is not observed again.
    backend.stop(&first.vm).unwrap();
    assert_eq!(
        backend.reobserve(&first.vm, &host.registry),
        Err(ReobservationRefusal::NoSuchVm { vm: first.vm })
    );

    // A re-observation made before a restart revives nothing on the new clock session.
    let restarted = ProbeRegistry::new(Arc::clone(&host.clock));
    assert!(matches!(
        second
            .record
            .assert_current_with(restarted.now(), &of_second),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::ObservationNotCurrent {
                fact: FactName::HypervisorEvidence,
                problem: ObservationProblem::Stale { staleness: Staleness::OtherClock },
            })
    ));

    // A backend that cannot observe again says so; its records go stale and stay so.
    let mut without = WithoutReobservation(fresh_backend());
    let launched = without
        .launch(&request("exe-3", 1), &host.registry)
        .unwrap();
    let refusal = without.reobserve(&launched.vm, &host.registry).unwrap_err();
    assert_eq!(
        refusal,
        ReobservationRefusal::Unsupported {
            backend: BackendKind::Fake
        }
    );
    assert!(refusal.to_string().contains("not renewed"));
    assert_eq!(
        serde_json::to_value(&refusal).unwrap()["kind"],
        "unsupported"
    );
}

#[test]
fn a_reobservation_evaluates_the_perimeter_evidence_again() {
    let (mut host, probe) = perimeter_host(SourceClass::HostProbe);
    let mut backend = fresh_backend();
    let rule = rule_subject(block_rule(b"private-ranges"), broker());
    let request = perimeter_request("exe-1", &[rule.rule]);
    observe_rule(&mut host, &probe, rule, enforced(config("a"), MINUTE));
    let launched = backend.launch(&request, &host.registry).unwrap();
    host.clock.advance(MINUTE + Duration::from_secs(1));
    host.observe_available(HypervisorKind::Kvm, config("a"));
    // The hypervisor evidence is fresh again, the perimeter's is not.
    assert!(matches!(
        backend.reobserve(&launched.vm, &host.registry),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::PerimeterNotEvidenced {
                refusal: EvidenceRefusal::Stale { .. },
                ..
            })
    ));
    observe_rule(&mut host, &probe, rule, enforced(config("a"), MINUTE));
    let again = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert_eq!(again.perimeter_evidence().len(), 1);
    assert_eq!(
        launched
            .record
            .assert_current_with(host.registry.now(), &again),
        Ok(())
    );
}

// ---- a refused launch whose cleanup is incomplete ----

#[test]
fn a_refused_launch_whose_vm_did_not_end_says_what_is_left() {
    let host = fresh_host();
    let mut backend = fresh_backend();
    backend.script_mut().devices = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    backend.script_mut().teardown_failure = Some("the VM did not exit".to_owned());
    let request = request("exe-1", 1);
    let refusal = backend.launch(&request, &host.registry).unwrap_err();
    let vm = vm_handle(
        BackendKind::Fake,
        &request.execution,
        request.generations.boot,
    );
    let LaunchRefusal::CleanupIncomplete {
        vm: left_vm,
        refusal: cause,
        left,
    } = &refusal
    else {
        panic!("{refusal:?}");
    };
    assert_eq!(*left_vm, vm);
    assert!(matches!(
        **cause,
        LaunchRefusal::PropertiesNotSatisfied { .. }
    ));
    assert_eq!(
        left,
        &vec![LeftBehind::Process {
            detail: "the VM did not exit".to_owned()
        }]
    );
    assert_eq!(refusal.left_behind(), Some((vm, left.as_slice())));
    assert_eq!(refusal.cause(), &**cause);
    assert_eq!(refusal.failed_checks(), Vec::<&RequiredCheck>::new());
    let text = refusal.to_string();
    assert!(text.contains("cleanup of VM"), "{text}");
    assert!(text.contains("may remain"), "{text}");
    assert!(!text.contains("nothing is left"), "{text}");
    let json = serde_json::to_value(&refusal).unwrap();
    assert_eq!(json["kind"], "cleanup_incomplete");
    assert_eq!(json["refusal"]["kind"], "properties_not_satisfied");
    assert_eq!(json["left"][0]["left"], "process");

    // The VM stays listed, is never observed again as a launch, and its boot generation
    // is used.
    assert_eq!(backend.running(), vec![vm]);
    assert!(backend.pid_of(&vm).is_some());
    assert_eq!(
        backend.reobserve(&vm, &host.registry),
        Err(ReobservationRefusal::NotAdmitted { vm })
    );
    assert!(matches!(
        backend.launch(&request, &host.registry),
        Err(LaunchRefusal::BootGenerationUsed { .. })
    ));
    // A stop fails while the VM does not end, and succeeds once it does.
    assert!(matches!(
        backend.stop(&vm),
        Err(BackendRefusal::Failed {
            operation: BackendOperation::Stop,
            ..
        })
    ));
    assert_eq!(backend.running(), vec![vm]);
    backend.script_mut().teardown_failure = None;
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::Stopped));
    assert!(backend.running().is_empty());
    assert_eq!(backend.stop(&vm), Ok(StopOutcome::AlreadyGone));
}

#[test]
fn scripts_written_before_the_cleanup_and_reobservation_faults_still_read() {
    let mut json = serde_json::to_value(script()).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("teardown_failure").is_some());
    assert!(object.remove("reobserve_failure").is_some());
    let read: HostScript = serde_json::from_value(json).unwrap();
    assert_eq!(read, script());
}

// ---- the hypervisor configuration facts (VM-CP-02, VM-CP-03 and VM-CP-31; §17 lines
// 3152, 3153 and 3181) ----

fn golden_file(name: &[u8]) -> Digest {
    digest("yougori/test/golden/v1", &[name])
}

fn approved_comparison() -> ConfigurationComparison {
    ConfigurationComparison {
        golden: golden_file(b"approved"),
        observed: golden_file(b"approved"),
        network_device: false,
        console: false,
        balloon: false,
        undeclared_pci_transport: false,
    }
}

/// A fake whose host compares the running configuration with the golden file and checks
/// the listing, both clean.
fn configured_backend() -> FakeBackend {
    let mut backend = fresh_backend();
    backend.script_mut().configuration_comparison = Some(approved_comparison());
    backend.script_mut().interface_listing = Some(HostInterfaceListing::clean());
    backend
}

fn gpu_key(name: &[u8]) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[name]),
    }
}

fn gpu_launch(execution: &str, gpus: &[GpuDeviceKey]) -> LaunchRequest {
    let mut with_gpus = request(execution, 1);
    with_gpus.device_profile.devices.gpus = gpus.iter().copied().collect();
    with_gpus.required.devices.gpus = gpus.iter().copied().collect();
    with_gpus
}

/// A fake with GPU assignment whose host observes `gpus` assigned with complete
/// isolation.
fn gpu_backend(gpus: &[GpuDeviceKey]) -> FakeBackend {
    let mut backend = fresh_backend().with_features(BackendFeatures::of([Feature::GpuAssignment]));
    backend.script_mut().devices = Scripted::HostObserved(DeviceInventory {
        paravirtualized_gpu: false,
            display: false,
        gpus: gpus
            .iter()
            .map(|device| ObservedGpu {
                device: *device,
                isolation: GpuIsolation::complete(),
            })
            .collect(),
    });
    backend
}

/// The host's checks of `device` before assignment, made now.
fn checked_now(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    device: GpuDeviceKey,
    isolation: GpuIsolation,
) -> HostObserved<ObservedGpu> {
    HostObserved::stamp(
        ObservedGpu { device, isolation },
        registry.now(),
        Duration::from_secs(600),
        config("a"),
    )
}

fn without(check: GpuIsolationCheck) -> GpuIsolation {
    let mut isolation = GpuIsolation::complete();
    isolation.checks.remove(&check);
    isolation
}

#[test]
fn a_record_without_configuration_facts_keeps_its_identity_and_one_with_them_binds_them() {
    let host = fresh_host();
    let request = request("exe-1", 1);
    let backend = fresh_backend();
    let evidence = precheck(
        &request,
        backend.identity(),
        backend.features(),
        &host.registry,
    )
    .unwrap();
    let vm = vm_handle(
        BackendKind::Fake,
        &request.execution,
        request.generations.boot,
    );
    let facts = || backend.script().facts(host.registry.now());
    let plain = admit(
        &request,
        backend.identity(),
        &host.registry,
        evidence.clone(),
        facts(),
        vm,
        None,
    )
    .unwrap();
    let with_none = admit_with_configuration(
        &request,
        backend.identity(),
        &host.registry,
        evidence,
        facts(),
        ConfigurationFacts::none(),
        vm,
        None,
    )
    .unwrap();
    assert_eq!(plain, with_none);
    assert!(ConfigurationFacts::none().is_empty());
    let json = serde_json::to_value(&plain).unwrap();
    for key in [
        "configuration_comparison",
        "interface_listing",
        "gpu_assignments",
    ] {
        assert!(json.get(key).is_none(), "{key}");
    }
    assert_eq!(plain.configuration_comparison(), None);
    assert_eq!(plain.interface_listing(), None);
    assert!(plain.gpu_assignments().is_empty());
    // The fake's own launch without them seals that very record.
    let mut fake = fresh_backend();
    assert_eq!(
        fake.launch(&request, &host.registry)
            .unwrap()
            .record
            .identity(),
        plain.identity()
    );

    // With them, the record binds both facts, stamped as the host made them.
    let mut configured = configured_backend();
    let record = configured.launch(&request, &host.registry).unwrap().record;
    assert_ne!(record.identity(), plain.identity());
    let comparison = record.configuration_comparison().unwrap();
    assert_eq!(*comparison.value(), approved_comparison());
    assert!(comparison.value().matches() && comparison.value().approved());
    assert_eq!(comparison.source(), FactSource::HostObserved);
    assert_eq!(comparison.observed_at(), record.recorded_at());
    assert_eq!(comparison.configuration(), config("a"));
    let listing = record.interface_listing().unwrap();
    assert_eq!(*listing.value(), HostInterfaceListing::clean());
    assert!(listing.value().approved());
    assert!(record.gpu_assignments().is_empty());
    assert_eq!(record.assert_current(host.registry.now()), Ok(()));
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(
        json["configuration_comparison"]["value"]["golden"],
        golden_file(b"approved").to_hex()
    );
    assert_eq!(
        json["interface_listing"]["value"]["monitor_socket_private"],
        true
    );
    assert!(json.get("gpu_assignments").is_none());

    // Another approved golden file is another record.
    let mut other = configured_backend();
    other.script_mut().configuration_comparison = Some(ConfigurationComparison {
        golden: golden_file(b"next"),
        observed: golden_file(b"next"),
        ..approved_comparison()
    });
    assert_ne!(
        other
            .launch(&request, &host.registry)
            .unwrap()
            .record
            .identity(),
        record.identity()
    );
}

#[test]
fn a_configuration_that_is_not_the_golden_files_or_breaks_the_listing_is_refused() {
    let host = fresh_host();
    let golden = BTreeSet::from([ConfigurationCheck::GoldenConfiguration]);
    let interfaces = BTreeSet::from([ConfigurationCheck::HostInterfaces]);
    let comparison = |change: &dyn Fn(&mut ConfigurationComparison)| {
        let mut comparison = approved_comparison();
        change(&mut comparison);
        comparison
    };
    let listing = |change: &dyn Fn(&mut HostInterfaceListing)| {
        let mut listing = HostInterfaceListing::clean();
        change(&mut listing);
        listing
    };
    let clean = HostInterfaceListing::clean();
    let cases = [
        (
            comparison(&|c| c.observed = golden_file(b"drifted")),
            clean,
            golden.clone(),
            "is not the golden file",
        ),
        (
            comparison(&|c| c.network_device = true),
            clean,
            golden.clone(),
            "has a network device",
        ),
        (
            comparison(&|c| c.console = true),
            clean,
            golden.clone(),
            "has a console",
        ),
        (
            comparison(&|c| c.balloon = true),
            clean,
            golden.clone(),
            "has a balloon",
        ),
        (
            comparison(&|c| c.undeclared_pci_transport = true),
            clean,
            golden.clone(),
            "a PCI transport the device profile does not declare",
        ),
        (
            approved_comparison(),
            listing(&|l| l.share_device = true),
            interfaces.clone(),
            "a host filesystem share device",
        ),
        (
            approved_comparison(),
            listing(&|l| l.management_listener = true),
            interfaces.clone(),
            "a monitor on a network listener",
        ),
        (
            approved_comparison(),
            listing(&|l| l.monitor_socket_private = false),
            interfaces.clone(),
            "outside the launch's private directory",
        ),
        (
            approved_comparison(),
            listing(&|l| l.old_agent_port_forward = true),
            interfaces.clone(),
            "a host port forward to the old agent port",
        ),
        (
            comparison(&|c| c.balloon = true),
            listing(&|l| l.share_device = true),
            golden.union(&interfaces).copied().collect(),
            "a host filesystem share device",
        ),
    ];
    for (index, (comparison, listing, failed, finding)) in cases.into_iter().enumerate() {
        let mut backend = configured_backend();
        backend.script_mut().configuration_comparison = Some(comparison);
        backend.script_mut().interface_listing = Some(listing);
        let refusal = backend
            .launch(&request(&format!("exe-{index}"), 1), &host.registry)
            .unwrap_err();
        match &refusal {
            LaunchRefusal::ConfigurationNotApproved {
                backend: kind,
                checks,
                findings,
            } => {
                assert_eq!(*kind, BackendKind::Fake);
                assert_eq!(checks, &failed, "{finding}");
                assert!(
                    findings.iter().any(|found| found.contains(finding)),
                    "{findings:?}"
                );
            }
            other => panic!("{finding}: {other:?}"),
        }
        assert!(refusal.to_string().contains("(VM-CP-0"), "{refusal}");
        assert!(backend.running().is_empty());
        assert!(backend
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Teardown { .. })));
    }
}

#[test]
fn stale_or_reconfigured_configuration_facts_refuse_admission() {
    let mut host = fresh_host();
    let backend = fresh_backend();
    let early = HostObserved::stamp(
        approved_comparison(),
        host.registry.now(),
        Duration::from_secs(600),
        config("a"),
    );
    host.clock.advance(MINUTE + Duration::from_secs(1));
    host.observe_available(HypervisorKind::Kvm, config("a"));
    let request = request("exe-1", 1);
    let vm = vm_handle(
        BackendKind::Fake,
        &request.execution,
        request.generations.boot,
    );
    let admit_now = |configuration: ConfigurationFacts| {
        let evidence = precheck(
            &request,
            backend.identity(),
            backend.features(),
            &host.registry,
        )
        .unwrap();
        admit_with_configuration(
            &request,
            backend.identity(),
            &host.registry,
            evidence,
            backend.script().facts(host.registry.now()),
            configuration,
            vm,
            None,
        )
    };
    assert_eq!(
        admit_now(ConfigurationFacts {
            comparison: Some(early),
            ..ConfigurationFacts::none()
        }),
        Err(LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Devices,
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: MINUTE + Duration::from_secs(1),
                    limit: MINUTE,
                }
            },
        })
    );
    let reconfigured = HostObserved::stamp(
        HostInterfaceListing::clean(),
        host.registry.now(),
        Duration::from_secs(600),
        config("b"),
    );
    assert!(matches!(
        admit_now(ConfigurationFacts {
            listing: Some(reconfigured),
            ..ConfigurationFacts::none()
        }),
        Err(LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Devices,
            problem: ObservationProblem::OtherConfiguration { .. },
        })
    ));
    assert!(admit_now(ConfigurationFacts::none()).is_ok());
}

#[test]
fn an_assigned_gpu_needs_its_checks_made_before_its_assignment() {
    let host = fresh_host();
    let gpu = gpu_key(b"gpu0");
    let second = gpu_key(b"gpu1");
    let mut backend = gpu_backend(&[gpu]);

    // Without an order a GPU launch is admitted as before.
    let before = backend
        .launch(&gpu_launch("exe-0", &[gpu]), &host.registry)
        .unwrap();
    assert!(before.record.gpu_assignments().is_empty());

    // Checked, then assigned at a later launch: the record shows the order.
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        GpuIsolation::complete(),
    )]);
    host.clock.advance(Duration::from_secs(5));
    let launched = backend
        .launch(&gpu_launch("exe-1", &[gpu]), &host.registry)
        .unwrap();
    let orders = launched.record.gpu_assignments();
    assert_eq!(orders.len(), 1);
    let order = &orders[0];
    assert_eq!(order.device(), gpu);
    assert_eq!(*order.assigned.value(), gpu);
    assert!(order.checked_before_assignment());
    assert!(order.checked.observed_at() < order.assigned.observed_at());
    assert_eq!(order.assigned.observed_at(), launched.record.recorded_at());
    assert!(order.missing_before_assignment().is_empty());
    for check in CHECKED_BEFORE_ASSIGNMENT {
        assert!(order.shows_before_assignment(check), "{check:?}");
    }
    let json = serde_json::to_value(&launched.record).unwrap();
    assert_eq!(json["gpu_assignments"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["gpu_assignments"][0]["checked"]["source"]["how"],
        "observed"
    );
    assert_ne!(launched.record.identity(), before.record.identity());

    // Only the four checks VM-CP-31 names must come before assignment.
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        without(GpuIsolationCheck::DriverAndGuestCompatible),
    )]);
    host.clock.advance(Duration::from_secs(1));
    assert!(backend
        .launch(&gpu_launch("exe-2", &[gpu]), &host.registry)
        .is_ok());

    let refused =
        |backend: &mut FakeBackend, host: &Host, execution: &str, gpus: &[GpuDeviceKey]| {
            let refusal = backend
                .launch(&gpu_launch(execution, gpus), &host.registry)
                .unwrap_err();
            let failed = refusal.failed_checks();
            assert_eq!(failed.len(), 1, "{refusal}");
            assert_eq!(failed[0].facet(), Facet::DeviceExposure);
            failed[0].failure().cloned().unwrap()
        };

    // Checked at the same instant as the assignment: the stamps show no order.
    host.clock.advance(Duration::from_secs(1));
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        GpuIsolation::complete(),
    )]);
    let failure = refused(&mut backend, &host, "exe-3", &[gpu]);
    assert_eq!(
        failure,
        CheckFailure::NotCheckedBeforeAssignment { device: gpu }
    );
    assert!(failure.to_string().contains("made before it was assigned"));

    // A reset method or an ACS state not shown before assignment refuses, as does an ACS
    // override, even though the running VM's inventory shows complete isolation.
    for (isolation, missing, unsafe_settings) in [
        (
            without(GpuIsolationCheck::SafeResetAndReassignment),
            BTreeSet::from([GpuIsolationCheck::SafeResetAndReassignment]),
            BTreeSet::new(),
        ),
        (
            without(GpuIsolationCheck::NoUnsafeAcsOrIommuBypass),
            BTreeSet::from([GpuIsolationCheck::NoUnsafeAcsOrIommuBypass]),
            BTreeSet::new(),
        ),
        (
            GpuIsolation {
                unsafe_settings: BTreeSet::from([UnsafeDeviceSetting::AcsOverride]),
                ..GpuIsolation::complete()
            },
            BTreeSet::new(),
            BTreeSet::from([UnsafeDeviceSetting::AcsOverride]),
        ),
    ] {
        backend.check_gpus_before_assignment(vec![checked_now(&host.registry, gpu, isolation)]);
        host.clock.advance(Duration::from_secs(1));
        assert_eq!(
            refused(&mut backend, &host, "exe-4", &[gpu]),
            CheckFailure::DeviceNotIsolated {
                device: gpu,
                missing,
                unsafe_settings,
            }
        );
    }

    // An order for a device the host did not observe assigned.
    backend.check_gpus_before_assignment(vec![
        checked_now(&host.registry, gpu, GpuIsolation::complete()),
        checked_now(&host.registry, second, GpuIsolation::complete()),
    ]);
    host.clock.advance(Duration::from_secs(1));
    assert_eq!(
        refused(&mut backend, &host, "exe-5", &[gpu]),
        CheckFailure::InventoryDiffersFromProfile {
            profile: DeviceExposure {
                paravirtualized_gpu: false,
            display: false,
                gpus: BTreeSet::from([gpu]),
            },
            observed: DeviceExposure {
                paravirtualized_gpu: false,
            display: false,
                gpus: BTreeSet::from([gpu, second]),
            },
        }
    );

    // Two orders for one device do not show one order.
    backend.check_gpus_before_assignment(vec![
        checked_now(&host.registry, gpu, GpuIsolation::complete()),
        checked_now(&host.registry, gpu, GpuIsolation::complete()),
    ]);
    host.clock.advance(Duration::from_secs(1));
    assert_eq!(
        refused(&mut backend, &host, "exe-6", &[gpu]),
        CheckFailure::NotCheckedBeforeAssignment { device: gpu }
    );

    // Two GPUs assigned and only one checked.
    let mut both = gpu_backend(&[gpu, second]);
    both.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        GpuIsolation::complete(),
    )]);
    host.clock.advance(Duration::from_secs(1));
    assert_eq!(
        refused(&mut both, &host, "exe-7", &[gpu, second]),
        CheckFailure::NotCheckedBeforeAssignment { device: second }
    );

    // Checks stamped on another clock session, such as before a restart, are not current.
    let restarted = ProbeRegistry::new(Arc::clone(&host.clock));
    backend.check_gpus_before_assignment(vec![checked_now(
        &restarted,
        gpu,
        GpuIsolation::complete(),
    )]);
    host.clock.advance(Duration::from_secs(1));
    assert_eq!(
        backend
            .launch(&gpu_launch("exe-8", &[gpu]), &host.registry)
            .unwrap_err(),
        LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Devices,
            problem: ObservationProblem::Stale {
                staleness: Staleness::OtherClock
            },
        }
    );
}

#[test]
fn a_gpus_checks_before_assignment_age_the_record_first() {
    let mut host = fresh_host();
    let gpu = gpu_key(b"gpu0");
    let mut backend = gpu_backend(&[gpu]);
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        GpuIsolation::complete(),
    )]);
    host.clock.advance(Duration::from_secs(30));
    host.observe_available(HypervisorKind::Kvm, config("a"));
    let record = backend
        .launch(&gpu_launch("exe-1", &[gpu]), &host.registry)
        .unwrap()
        .record;
    assert_eq!(record.assert_current(host.registry.now()), Ok(()));
    host.clock.advance(Duration::from_secs(31));
    assert_eq!(
        record.assert_current(host.registry.now()),
        Err(StaleFact {
            fact: FactName::Devices,
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                }
            },
        })
    );
}

#[test]
fn an_acs_bypass_hides_the_acs_state_and_equal_stamps_show_no_order() {
    let host = fresh_host();
    let gpu = gpu_key(b"gpu0");
    let first = host.registry.now();
    let checked = |isolation: GpuIsolation| {
        HostObserved::stamp(
            ObservedGpu {
                device: gpu,
                isolation,
            },
            first,
            MINUTE,
            config("a"),
        )
    };
    let at_once = GpuAssignmentOrder {
        checked: checked(GpuIsolation::complete()),
        assigned: HostObserved::stamp(gpu, first, MINUTE, config("a")),
    };
    assert!(!at_once.checked_before_assignment());
    assert!(!at_once.shows_before_assignment(GpuIsolationCheck::SafeResetAndReassignment));

    host.clock.advance(Duration::from_secs(1));
    let assigned = HostObserved::stamp(gpu, host.registry.now(), MINUTE, config("a"));
    let order = GpuAssignmentOrder {
        checked: checked(GpuIsolation::complete()),
        assigned: assigned.clone(),
    };
    assert!(order.checked_before_assignment());
    // Another device's assignment is not this one's.
    let other = GpuAssignmentOrder {
        assigned: HostObserved::stamp(gpu_key(b"gpu1"), host.registry.now(), MINUTE, config("a")),
        ..order.clone()
    };
    assert!(!other.checked_before_assignment());
    // An ACS override or IOMMU bypass hides the ACS state, not the reset method.
    for setting in ACS_BYPASS_SETTINGS {
        let bypassed = GpuAssignmentOrder {
            checked: checked(GpuIsolation {
                unsafe_settings: BTreeSet::from([setting]),
                ..GpuIsolation::complete()
            }),
            assigned: assigned.clone(),
        };
        assert!(!bypassed.shows_before_assignment(GpuIsolationCheck::NoUnsafeAcsOrIommuBypass));
        assert!(bypassed.shows_before_assignment(GpuIsolationCheck::SafeResetAndReassignment));
    }
    let interrupts = GpuAssignmentOrder {
        checked: checked(GpuIsolation {
            unsafe_settings: BTreeSet::from([UnsafeDeviceSetting::UnsafeInterrupts]),
            ..GpuIsolation::complete()
        }),
        assigned,
    };
    assert!(interrupts.shows_before_assignment(GpuIsolationCheck::NoUnsafeAcsOrIommuBypass));
    assert_eq!(
        ConfigurationFact::GpuChecked { device: gpu }.to_string(),
        format!("checks of GPU {} before assignment", gpu.device)
    );
}

#[test]
fn scripts_written_before_the_configuration_facts_still_read() {
    let mut json = serde_json::to_value(script()).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("configuration_comparison").is_some());
    assert!(object.remove("interface_listing").is_some());
    let read: HostScript = serde_json::from_value(json).unwrap();
    assert_eq!(read, script());
    let mut configured = serde_json::to_value(configured_backend().script()).unwrap();
    assert_eq!(
        configured["interface_listing"]["monitor_socket_private"],
        true
    );
    configured["interface_listing"]["hgfs"] = true.into();
    assert!(serde_json::from_value::<HostScript>(configured).is_err());
}

// ---- the configuration facts made again (VM-CP-02, VM-CP-03 and VM-CP-31; §8.1 line
// 2439: re-evaluate relevant evidence) ----

#[test]
fn a_reobservation_carries_the_configuration_facts_and_the_record_judges_them() {
    let mut host = fresh_host();
    let mut backend = configured_backend();
    let launched = backend
        .launch(&request("exe-1", 1), &host.registry)
        .unwrap();
    let record = &launched.record;

    // Made again, the comparison and the listing present the launch as current, before
    // and after the launch-time facts are stale.
    let early = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert_eq!(
        record.assert_current_with(host.registry.now(), &early),
        Ok(())
    );
    host.clock.advance(MINUTE + Duration::from_secs(1));
    host.observe_available(HypervisorKind::Kvm, config("a"));
    assert!(record.assert_current(host.registry.now()).is_err());
    let again = backend.reobserve(&launched.vm, &host.registry).unwrap();
    let comparison = again.configuration_comparison().unwrap();
    assert_eq!(*comparison.value(), approved_comparison());
    assert_eq!(comparison.observed_at(), host.clock.now());
    assert_eq!(
        again.interface_listing().map(|listing| *listing.value()),
        Some(HostInterfaceListing::clean())
    );
    assert!(again.gpu_assignments().is_empty());
    assert_eq!(
        record.assert_current_with(host.registry.now(), &again),
        Ok(())
    );
    let json = serde_json::to_value(&again).unwrap();
    assert_eq!(
        json["configuration_comparison"]["value"]["golden"],
        golden_file(b"approved").to_hex()
    );
    assert_eq!(
        json["interface_listing"]["value"]["monitor_socket_private"],
        true
    );
    assert!(json.get("gpu_assignments").is_none());

    // The configuration drifted from the golden file, a share device appeared, or the host
    // compared it with another golden file than the launch's: refused as admission refuses,
    // by the check that failed.
    let golden = BTreeSet::from([ConfigurationCheck::GoldenConfiguration]);
    let interfaces = BTreeSet::from([ConfigurationCheck::HostInterfaces]);
    let cases = [
        (
            ConfigurationComparison {
                observed: golden_file(b"drifted"),
                ..approved_comparison()
            },
            HostInterfaceListing::clean(),
            golden.clone(),
            "is not the golden file",
        ),
        (
            approved_comparison(),
            HostInterfaceListing {
                share_device: true,
                ..HostInterfaceListing::clean()
            },
            interfaces,
            "a host filesystem share device",
        ),
        (
            ConfigurationComparison {
                golden: golden_file(b"next"),
                observed: golden_file(b"next"),
                ..approved_comparison()
            },
            HostInterfaceListing::clean(),
            golden,
            "not the launch's golden file",
        ),
    ];
    for (comparison, listing, failed, finding) in cases {
        backend.script_mut().configuration_comparison = Some(comparison);
        backend.script_mut().interface_listing = Some(listing);
        let changed = backend.reobserve(&launched.vm, &host.registry).unwrap();
        let refusal = record
            .assert_current_with(host.registry.now(), &changed)
            .unwrap_err();
        let ReobservationRefusal::Refused { refusal } = &refusal else {
            panic!("{finding}: {refusal:?}");
        };
        let LaunchRefusal::ConfigurationNotApproved {
            backend: BackendKind::Fake,
            checks,
            findings,
        } = &**refusal
        else {
            panic!("{finding}: {refusal:?}");
        };
        assert_eq!(checks, &failed, "{finding}");
        assert!(
            findings.iter().any(|found| found.contains(finding)),
            "{findings:?}"
        );
    }

    // A re-observation without them leaves the record's own, which have aged by now.
    backend.script_mut().configuration_comparison = None;
    backend.script_mut().interface_listing = None;
    let without = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert_eq!(without.configuration_comparison(), None);
    let json = serde_json::to_value(&without).unwrap();
    assert!(json.get("configuration_comparison").is_none());
    assert!(json.get("interface_listing").is_none());
    assert_eq!(
        record.assert_current_with(host.registry.now(), &without),
        Err(ReobservationRefusal::refused(
            LaunchRefusal::ObservationNotCurrent {
                fact: FactName::Devices,
                problem: ObservationProblem::Stale {
                    staleness: Staleness::TooOld {
                        age: MINUTE + Duration::from_secs(1),
                        limit: MINUTE,
                    }
                },
            }
        ))
    );

    // While the record's own are current, a re-observation without them does not refuse.
    backend.script_mut().configuration_comparison = Some(approved_comparison());
    backend.script_mut().interface_listing = Some(HostInterfaceListing::clean());
    let second = backend
        .launch(&request("exe-2", 1), &host.registry)
        .unwrap();
    backend.script_mut().configuration_comparison = None;
    backend.script_mut().interface_listing = None;
    let soon = backend.reobserve(&second.vm, &host.registry).unwrap();
    assert_eq!(
        second
            .record
            .assert_current_with(host.registry.now(), &soon),
        Ok(())
    );

    // A record without configuration facts judges those a re-observation carries all the
    // same.
    let mut plain = fresh_backend();
    let unconfigured = plain.launch(&request("exe-3", 1), &host.registry).unwrap();
    assert_eq!(unconfigured.record.configuration_comparison(), None);
    plain.script_mut().configuration_comparison = Some(ConfigurationComparison {
        observed: golden_file(b"drifted"),
        ..approved_comparison()
    });
    let drifted = plain.reobserve(&unconfigured.vm, &host.registry).unwrap();
    assert!(matches!(
        unconfigured
            .record
            .assert_current_with(host.registry.now(), &drifted),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::ConfigurationNotApproved { .. })
    ));
}

#[test]
fn a_reobservation_orders_each_assigned_gpus_checks_again() {
    let mut host = fresh_host();
    let gpu = gpu_key(b"gpu0");
    let mut backend = gpu_backend(&[gpu]);
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        GpuIsolation::complete(),
    )]);
    host.clock.advance(Duration::from_secs(5));
    let launched = backend
        .launch(&gpu_launch("exe-1", &[gpu]), &host.registry)
        .unwrap();
    let record = &launched.record;
    assert_eq!(record.gpu_assignments().len(), 1);

    // Observed again, the fake orders the checks before an assignment it observes now.
    host.clock.advance(Duration::from_secs(1));
    let again = backend.reobserve(&launched.vm, &host.registry).unwrap();
    let orders = again.gpu_assignments();
    assert_eq!(orders.len(), 1);
    assert!(orders[0].checked_before_assignment());
    assert_eq!(orders[0].assigned.observed_at(), host.clock.now());
    assert_eq!(
        record.assert_current_with(host.registry.now(), &again),
        Ok(())
    );

    // Checks made again that no longer show a safe reset refuse on the device exposure
    // facet.
    backend.check_gpus_before_assignment(vec![checked_now(
        &host.registry,
        gpu,
        without(GpuIsolationCheck::SafeResetAndReassignment),
    )]);
    host.clock.advance(Duration::from_secs(1));
    let weaker = backend.reobserve(&launched.vm, &host.registry).unwrap();
    let refusal = record
        .assert_current_with(host.registry.now(), &weaker)
        .unwrap_err();
    let ReobservationRefusal::Refused { refusal } = &refusal else {
        panic!("{refusal:?}");
    };
    let failed = refusal.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].facet(), Facet::DeviceExposure);
    assert!(matches!(
        failed[0].failure(),
        Some(CheckFailure::DeviceNotIsolated { device, .. }) if *device == gpu
    ));

    // Without orders made again, the record's own must still be current: they are until
    // the checks made before the assignment age.
    backend.check_gpus_before_assignment(Vec::new());
    let unordered = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert!(unordered.gpu_assignments().is_empty());
    assert_eq!(
        record.assert_current_with(host.registry.now(), &unordered),
        Ok(())
    );
    host.clock.advance(MINUTE);
    host.observe_available(HypervisorKind::Kvm, config("a"));
    let late = backend.reobserve(&launched.vm, &host.registry).unwrap();
    assert!(matches!(
        record.assert_current_with(host.registry.now(), &late),
        Err(ReobservationRefusal::Refused { refusal })
            if matches!(*refusal, LaunchRefusal::ObservationNotCurrent {
                fact: FactName::Devices,
                problem: ObservationProblem::Stale { .. },
            })
    ));
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

/// ST1's table checks on a type read back whose enums are all externally tagged or
/// unit-only: `sample` writes back unchanged; any string in it, each variant name
/// included, swapped for the variant index 0 is refused, read straight from JSON, from a
/// JSON value and buffered as the field of a tagged enum; and a key repeated in any one
/// object is refused.
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
fn the_enums_read_back_are_externally_tagged_and_read_strictly() {
    // ST1 converts the internally and adjacently tagged enums read back. Every tagged enum
    // of this module is written only (records, refusals, observations); every enum it
    // reads back is externally tagged or unit-only, whose variant name serde never takes
    // as an index, so none needs converting. Samples with each such variant:
    let mut every_facet = request("exe-2", 1);
    every_facet.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: BTreeSet::from([digest("yougori/test/volume/v1", &[b"v"])]),
    };
    every_facet.required.confidentiality = OperatorConfidentiality::VerifiedConfidentialVm {
        scope: contract(b"scope"),
    };
    every_facet.required.perimeter = PerimeterRequirement::Independent {
        perimeter: perimeter_id(),
        principal: broker(),
        rules: BTreeSet::from([block_rule(b"private-ranges")]),
    };
    assert_reads_strictly(&request("exe-1", 1));
    assert_reads_strictly(&every_facet);

    let mut scripted = configured_backend().script().clone();
    scripted.host = Scripted::Unavailable {
        reason: UnknownReason::Unreachable,
    };
    scripted.accelerator = Scripted::Verified {
        value: Accelerator::Emulation {
            emulator: Emulator::Tcg,
        },
        control: contract(b"control"),
    };
    scripted.hardware_failure = Some(HardwareFailure {
        hypervisor: HypervisorKind::Kvm,
        detail: "KVM_CREATE_VM: EPERM".to_owned(),
    });
    scripted.persistence = Scripted::HostObserved(Persistence::ControlledServiceRenewal {
        volumes: BTreeSet::new(),
    });
    scripted.guest.accelerator = Some(kvm());
    assert_reads_strictly(&script());
    assert_reads_strictly(&scripted);

    let vm = vm_handle(
        BackendKind::Fake,
        &ExecutionId::new("exe-1").unwrap(),
        SandboxBootGeneration::FIRST,
    );
    for refusal in [
        BackendRefusal::Unsupported {
            feature: Feature::Restore,
        },
        BackendRefusal::NoSuchVm { vm },
        BackendRefusal::Failed {
            operation: BackendOperation::Stop,
            detail: "the VM did not exit".to_owned(),
        },
    ] {
        assert_reads_strictly(&refusal);
    }
    let report = digest("yougori/test/report/v1", &[b"r"]);
    for result in [
        TestResult::NotRun,
        TestResult::Failed { report },
        TestResult::Passed {
            report,
            combination: contract(b"combination"),
        },
    ] {
        assert_reads_strictly(&result);
    }
    assert_reads_strictly(&BackendFeatures::of([
        Feature::Snapshot,
        Feature::GpuAssignment,
    ]));
    assert_reads_strictly(&approved_comparison());
}
