//! The first VM scenarios on fakes (§12.2 lines 2776–2825; §17 lines 3151–3185; S6
//! INT-02, INT-04 and INT-10, lines 270, 272 and 278): the fake backend of VB1 behind the
//! port, the lifecycle supervisor over the real CORE-04 coordinator and CORE-03 ledger,
//! one audit stream, the assurance ledger and a V01 policy plan, all on a manual clock.
//! Each scenario names the family it covers.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::assurance::{measurement_citations, revocation_claim, vm_only_execution_claim};
use super::audit_sink::{AuditSink, SinkRefusal, SUPERVISOR_OPERATION};
use super::backend_port::{LaunchAttempt, LaunchProblem};
use super::fakes::{
    artifact, at, broker, call, config, execution, image, machine, named, operation, parts,
    perimeter, perimeter_rule, port, real_ledger, session, stream_config, supervisor_config,
    MemorySegments, MemorySpool, World, WorldOptions, HOUR, MINUTE, SECOND,
};
use super::ClaimRefusal;
use crate::foundation::coordination::{
    network_grant_id, CancelCause, GrantId, LaunchFailure, LeaseKind, LeaseRefusal, LedgerCapacity,
    SandboxRecovery, SandboxState, SnapshotOrigin,
};
use crate::foundation::events::{
    AuditEntry, AuditHealth, AuditRefusal, Durability, EventContext, GrantRevocation,
    HostFact as AuditFact, JournalHead, JournalId, LogConfig, LogError, OwnerError, Phase,
    ProducerId, RedactedValue, RevocationReason, StoreRefusal, Takeover,
};
use crate::foundation::evidence::{
    Capability, EvidenceRefusal, HypervisorKind, NetworkGrant, SourceClass, UnknownReason,
    UnsupportedReason,
};
use crate::foundation::ids::{AuthorizationEpoch, Clock, SandboxBootGeneration};
use crate::foundation::report::{Label, Quantile, RunSubstrate};
use crate::sandbox::audit::{
    verify_segments, ClaimId, ClaimStatus, DurableError, Invalidation, LedgerError, NoAnchor,
    SegmentStorage as _, StreamDirectory, StreamError,
};
use crate::sandbox::backend::{
    admit, precheck, vm_handle, Accelerator, BackendFeatures, BackendIdentity, BackendKind,
    FakeBackend, FakeCall, Feature, HardwareFailure, LaunchRefusal, Scripted, VmBackend as _,
};
use crate::sandbox::lifecycle::{
    AckRefusal, Acknowledgment, ActivityKind, ActivityRefusal, Binding, BindingField,
    BindingRefusal, BootPath, CheckoutDecision, CleanupRefusal, CleanupReport, CleanupTarget,
    ColdFallback, GoldenSnapshot, GrantRevocationCause, HandleIdentity, LaunchReceipt,
    LifecycleReceipt, LimitKind, LogicalCleanupAction, PathRefusal, RelativePath, RevocationCause,
    SandboxClass, SnapshotProvenance, StateReset, StopOutcome, StopPhase, Supervisor,
    SupervisorError, TargetAssessment, TargetClaim, TerminationGate, TerminationTiming,
    VmBackend as _, VolumeKind, WarmPool, STOP_TARGET,
};
use crate::sandbox_contract::policy::{plan_launch, LaunchRefusalReason};

fn genesis() -> JournalHead {
    JournalHead::genesis(
        JournalId::new("supervisor").unwrap(),
        ProducerId::new("supervisor.audit").unwrap(),
    )
}

fn text(value: &str) -> RedactedValue {
    RedactedValue::Text {
        text: value.to_owned(),
        full_bytes: value.len() as u64,
    }
}

/// The host facts of `event`, in chain order.
fn host_facts(world: &World, event: &str) -> Vec<crate::foundation::events::AuditRecord> {
    world
        .audit_records()
        .into_iter()
        .filter(|record| {
            matches!(
                record.event().payload(),
                AuditEntry::HostFact { fields, .. } if fields.get("event") == Some(&text(event))
            )
        })
        .collect()
}

/// VM-P01 and VM-CP-01: the launch transaction end to end. A V01 plan supplies the
/// contract digest; the backend prechecks and admits on CORE-01 host-probe evidence and
/// seals a record bound to the coordinator's CORE-03 reservation; the lifecycle grants
/// authority after host-observed readiness; the receipts and the record reach the audit
/// stream under one operation; a claim on the record's hypervisor evidence is supported
/// until the evidence goes stale or the configuration changes.
#[test]
fn the_launch_transaction_runs_from_plan_to_record_to_audit_to_claim() {
    let mut world = World::new();
    let contract = world.set_profile("exe-task");
    let boot = world.launched("exe-task", SandboxClass::Task);
    assert_eq!(boot, SandboxBootGeneration::FIRST);
    assert!(matches!(
        world.backend.calls(),
        [FakeCall::Precheck { .. }, FakeCall::Create { .. }]
    ));
    assert_eq!(world.state("exe-task"), SandboxState::AuthorityActive);

    let record = world.record("exe-task").clone();
    assert_eq!(record.contract(), contract.digest());
    assert_eq!(record.sandbox().execution, execution("exe-task"));
    assert_eq!(record.sandbox().generations.boot, boot);
    assert!(record.accelerator().value().is_hardware_virtualized());
    assert_eq!(
        record.hypervisor_evidence().source(),
        SourceClass::HostProbe
    );
    let key = world
        .supervisor
        .coordinator()
        .sandbox(&execution("exe-task"))
        .unwrap()
        .reservation()
        .unwrap();
    let ledger_record = world
        .supervisor
        .coordinator()
        .capacity()
        .record(&key)
        .unwrap();
    assert_eq!(
        record.reservation(),
        ledger_record.id(),
        "the backend bound the reservation the launch transaction made"
    );
    let handle = world.handle("exe-task");
    assert_eq!(handle.token, record.identity());
    assert_eq!(handle.vm, record.vm());

    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [LifecycleReceipt::Launched { .. }]
    ));
    assert!(drain.receipts.iter().all(Result::is_ok));
    assert!(drain.refusals.is_empty());
    let launch = drain.launches[0].as_ref().unwrap();
    assert_eq!(launch.host_fact.durability, Durability::Durable);
    assert!(launch.guest_report.is_none(), "the guest asserted nothing");
    let records = world.audit_records();
    assert_eq!(records.len(), 2);
    let AuditEntry::HostFact { fact, fields } = records[1].event().payload() else {
        panic!("{:?}", records[1]);
    };
    assert_eq!(*fact, AuditFact::LaunchFact);
    assert_eq!(
        fields.get("record"),
        Some(&RedactedValue::Digest {
            digest: record.identity()
        })
    );
    assert_eq!(
        fields.get("contract"),
        Some(&RedactedValue::Digest {
            digest: contract.digest()
        })
    );
    assert_eq!(fields.get("accelerator"), Some(&text("hardware:kvm")));
    assert_eq!(fields.get("backend"), Some(&text("fake")));
    assert_eq!(
        fields.get("reservation"),
        Some(&RedactedValue::Unsigned {
            value: record.reservation().get()
        })
    );
    assert_eq!(fields.omitted_fields(), 0);
    assert_eq!(
        records[1].event().operation(),
        records[0].event().operation(),
        "the record is correlated with the launch receipt"
    );
    assert_eq!(records[1].event().phase(), Phase::Booting);
    assert_eq!(records[1].event().generations().sandbox_boot, Some(boot));
    assert_eq!(
        records[1].event().generations().authorization,
        Some(AuthorizationEpoch::FIRST)
    );
    assert_eq!(
        records[1].event().provenance().source(),
        SourceClass::HostProbe
    );
    assert_eq!(
        records[1]
            .event()
            .provenance()
            .evidence()
            .map(|link| link.capability),
        Some(Capability::HypervisorAvailable)
    );
    let chain = verify_segments(&genesis(), &world.storage.snapshot()).unwrap();
    assert_eq!(chain.records, 2);
    assert!(chain.damage.is_empty());
    assert_eq!(world.sink.totals().uncorrelated, 0);

    // A record of the fake backend certifies nothing (S2 line 206; VM-P50).
    assert_eq!(
        vm_only_execution_claim(&record, machine(), parts("p01")).err(),
        Some(ClaimRefusal::FakeBackend {
            backend: BackendKind::Fake
        })
    );
    // The same admission under a real backend identity: the claim cites the CORE-01
    // hypervisor evidence and is supported while that evidence is fresh.
    let firecracker = BackendIdentity::new(
        BackendKind::Firecracker,
        "1.10.1",
        artifact(),
        HypervisorKind::Kvm,
    )
    .unwrap();
    let mut request = World::direct_request("exe-task", 1);
    request.contract = contract.digest();
    let evidence = precheck(
        &request,
        &firecracker,
        &BackendFeatures::none(),
        &world.registry,
    )
    .unwrap();
    let facts = world.backend.script().facts(world.registry.now());
    let real = admit(
        &request,
        &firecracker,
        &world.registry,
        evidence,
        facts,
        vm_handle(
            BackendKind::Firecracker,
            &execution("exe-task"),
            SandboxBootGeneration::FIRST,
        ),
        None,
    )
    .unwrap();
    let claim = vm_only_execution_claim(&real, machine(), parts("p01")).unwrap();
    world.assurance.add_claim(claim).unwrap();
    let id = ClaimId::new("p01").unwrap();
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Supported {
            citations: 1,
            fresh_until: Some(until)
        } if until == at(160)
    ));
    // Older than the record's required freshness: invalidated, and the record itself is
    // no longer presented as current.
    world.advance(MINUTE + SECOND);
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::Stale {
                capability: Capability::HypervisorAvailable,
                ..
            }
        }
    ));
    assert!(real.assert_current(world.registry.now()).is_err());
    // Re-observed under another configuration than the one in force: invalidated.
    world.observe_hypervisor(true, config("b"));
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::EvidenceConfigurationChanged {
                capability: Capability::HypervisorAvailable,
                ..
            }
        }
    ));
    // The ledger's own configuration changed: invalidated outright.
    assert_eq!(world.assurance.set_configuration(config("b")), 1);
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Invalidated {
            reason: Invalidation::ClaimConfigurationChanged { .. }
        }
    ));
    // A claim on a record whose evidence is about another machine is refused.
    assert!(matches!(
        vm_only_execution_claim(&real, image(), parts("p01-other")),
        Err(ClaimRefusal::EvidenceSubjectMismatch { .. })
    ));
}

/// VM-P01 and VM-P29: a launch refused for stale or guest-only evidence leaves no
/// authority and no record of success, and the refusal is in the audit stream with its
/// typed kind. A forged guest report of the accelerator never counts.
#[test]
fn a_launch_refused_for_stale_or_guest_only_evidence_leaves_no_authority() {
    // Stale: the hypervisor evidence is older than the profile's required freshness.
    let mut world = World::new();
    world.set_profile("exe-stale");
    world.advance(MINUTE + SECOND);
    let receipt = world.launch("exe-stale", SandboxClass::Task);
    assert!(
        matches!(
            receipt,
            LaunchReceipt::RolledBack {
                failure: LaunchFailure::Port { .. },
                ..
            }
        ),
        "{receipt:?}"
    );
    assert_eq!(world.state("exe-stale"), SandboxState::Stopped);
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .sandbox(&execution("exe-stale"))
            .unwrap()
            .authority(),
        None
    );
    assert!(
        world.table.records().next().is_none(),
        "no record of success"
    );
    assert!(world.supervisor.handles().is_empty());
    assert!(world.backend.running().is_empty());
    assert!(
        world
            .backend
            .calls()
            .iter()
            .all(|call| !matches!(call, FakeCall::Create { .. })),
        "nothing was created: {:?}",
        world.backend.calls()
    );
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::Evidence {
                refusal: EvidenceRefusal::Stale { .. }
            }
        }
    ));
    assert!(matches!(
        world.work("exe-stale", "op"),
        Err(SupervisorError::UnknownSandbox { .. })
    ));
    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [LifecycleReceipt::LaunchFailed { .. }]
    ));
    assert!(drain.launches.is_empty());
    assert_eq!(drain.refusals.len(), 1);
    let records = world.audit_records();
    assert_eq!(records.len(), 2);
    let AuditEntry::HostFact { fact, fields } = records[1].event().payload() else {
        panic!("{:?}", records[1]);
    };
    assert_eq!(*fact, AuditFact::AuthorizationDecision);
    assert_eq!(fields.get("decision"), Some(&text("launch_refused")));
    assert_eq!(fields.get("problem"), Some(&text("backend")));
    assert_eq!(fields.get("refusal"), Some(&text("evidence")));
    assert_eq!(fields.get("attempt"), Some(&text("launch")));
    assert_eq!(
        records[1].event().operation(),
        records[0].event().operation()
    );
    assert_eq!(records[1].event().phase(), Phase::Failed);
    let AuditEntry::HostFact { fields, .. } = records[0].event().payload() else {
        panic!("{:?}", records[0]);
    };
    assert_eq!(fields.get("failure"), Some(&text("port")));

    // Guest-only: the hypervisor probe is a guest report. V01 refuses to plan, and the
    // backend refuses to launch under a profile set anyway.
    let mut world = World::with(WorldOptions {
        hypervisor_source: SourceClass::GuestReport,
        ..WorldOptions::default()
    });
    let resolved = World::resolved_contract();
    let _ = world.admit();
    let refusal = plan_launch(&resolved, &world.registry, &World::launch_targets()).unwrap_err();
    assert!(refusal
        .reasons
        .iter()
        .any(|reason| matches!(reason, LaunchRefusalReason::RequirementUnmet { .. })));
    world.set_profile_under("exe-guest", resolved.identity());
    let receipt = world.launch("exe-guest", SandboxClass::Task);
    assert!(matches!(receipt, LaunchReceipt::RolledBack { .. }));
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::Evidence {
                refusal: EvidenceRefusal::SourceTooWeak {
                    observed: SourceClass::GuestReport,
                    required: SourceClass::HostProbe,
                    ..
                }
            }
        }
    ));
    assert!(world.table.records().next().is_none());
    assert_eq!(world.state("exe-guest"), SandboxState::Stopped);

    // VM-P29: the host did not observe the accelerator; the guest says it is KVM. The
    // guest assertion never counts, the VM is torn down and nothing is kept.
    let mut world = World::new();
    world.backend.script_mut().accelerator = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    world.backend.script_mut().guest.accelerator = Some(Accelerator::Hardware {
        hypervisor: HypervisorKind::Kvm,
    });
    let receipt = world.launch("exe-forged", SandboxClass::Task);
    assert!(matches!(receipt, LaunchReceipt::RolledBack { .. }));
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::AcceleratorNotObserved {
                reason: UnknownReason::NotTested
            }
        }
    ));
    assert!(matches!(
        world.backend.calls(),
        [
            FakeCall::Precheck { .. },
            FakeCall::Create { .. },
            FakeCall::Teardown { .. }
        ]
    ));
    assert!(world.backend.running().is_empty());
    assert!(world.table.records().next().is_none());
    world.drain_audit();
    let records = world.audit_records();
    let AuditEntry::HostFact { fields, .. } = records[1].event().payload() else {
        panic!("{:?}", records[1]);
    };
    assert_eq!(
        fields.get("refusal"),
        Some(&text("accelerator_not_observed"))
    );
}

/// VM-P01 and VM-P42 (VM-CP-01, VM-CP-33): a hardware virtualization failure refuses the
/// launch and nothing retries into emulation, although the backend offers the separate
/// developer facility; missing acceleration refuses before anything is created.
#[test]
fn a_hardware_failure_refuses_and_never_retries_into_emulation() {
    let mut world = World::new();
    world.backend = FakeBackend::new(
        HypervisorKind::Kvm,
        crate::foundation::evidence::BackendVersion::new("0.1.0").unwrap(),
        artifact(),
        super::fakes::host_script(),
    )
    .with_features(BackendFeatures::of([Feature::DeveloperEmulation]));
    world.backend.script_mut().hardware_failure = Some(HardwareFailure {
        hypervisor: HypervisorKind::Kvm,
        detail: "KVM_CREATE_VM: EPERM".to_owned(),
    });
    let receipt = world.launch("exe-task", SandboxClass::Task);
    assert!(matches!(
        receipt,
        LaunchReceipt::RolledBack {
            failure: LaunchFailure::Port { .. },
            ..
        }
    ));
    assert_eq!(world.backend.emulation_launches(), 0);
    assert!(world.backend.emulated().is_empty());
    assert!(world.backend.running().is_empty());
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::HardwareVirtualizationFailed { .. }
        }
    ));
    world.drain_audit();
    let records = world.audit_records();
    let AuditEntry::HostFact { fields, .. } = records[1].event().payload() else {
        panic!("{:?}", records[1]);
    };
    assert_eq!(
        fields.get("refusal"),
        Some(&text("hardware_virtualization_failed"))
    );

    // Missing acceleration: the host probe says the hypervisor is unavailable.
    world.backend.script_mut().hardware_failure = None;
    world.observe_hypervisor(false, config("a"));
    let receipt = world.launch("exe-task", SandboxClass::Task);
    assert!(matches!(receipt, LaunchReceipt::RolledBack { .. }));
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::Evidence {
                refusal: EvidenceRefusal::Unsupported { .. }
            }
        }
    ));
    assert_eq!(world.backend.emulation_launches(), 0);
    assert!(world
        .backend
        .calls()
        .iter()
        .all(|call| !matches!(call, FakeCall::Create { .. } | FakeCall::Emulate { .. })));
}

/// VM-P14 and VM-CP-14: a revocation reaches the five acknowledgments through the port,
/// every receipt is in the audit stream, the four phases are reported as separate
/// distributions, the two-second figure is an observation against a target, and a claim
/// on fake-substrate measurements is refused (VM-P50).
#[test]
fn revocation_reaches_the_five_acknowledgments_with_receipts_in_audit() {
    let mut world = World::new();
    world.set_profile("exe-task");
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.provider_bills = true;
    assert!(matches!(
        world.launch_request(request).unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let exe = execution("exe-task");
    let lease = world.work("exe-task", "op-stream").unwrap();
    world.advance(10 * SECOND);

    let progress = {
        let mut port = port!(world);
        world
            .supervisor
            .revoke(&exe, RevocationCause::UserRequested, &mut port)
            .unwrap()
    };
    assert!(
        progress.acknowledged.is_empty(),
        "the decision alone acknowledges nothing: {progress:?}"
    );
    assert!(matches!(
        world.work("exe-task", "op-late"),
        Err(SupervisorError::Revoked { .. })
    ));
    assert!(matches!(
        world.supervisor.coordinator().check_lease(lease.id()),
        Err(LeaseRefusal::Cancelled { .. } | LeaseRefusal::RevokedAuthorization { .. })
    ));
    assert_eq!(
        world.stops_of("exe-task"),
        0,
        "nothing stops before the gate"
    );
    world.advance(SECOND);
    world
        .supervisor
        .acknowledge(&exe, Acknowledgment::ChannelsClosed)
        .unwrap();
    world
        .supervisor
        .coordinator_mut()
        .acknowledge_cancellation(lease.id())
        .unwrap();
    world.advance(SECOND);
    let progress = {
        let mut port = port!(world);
        world.supervisor.advance(&exe, &mut port).unwrap()
    };
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(world.stops_of("exe-task"), 1);
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert!(!world.backend.running().contains(&world.vm("exe-task")));
    world.advance(20 * SECOND);
    world
        .supervisor
        .provider_acknowledged(
            &exe,
            crate::sandbox::lifecycle::ProviderAcknowledgment {
                provider: super::fakes::named("yougori/test/provider/v1", "cloud"),
                at: world.clock.now(),
            },
        )
        .unwrap();
    world.advance(5 * SECOND);
    assert!(!world
        .supervisor
        .finish_cleanup(
            &exe,
            CleanupReport::logical([LogicalCleanupAction::OverlayDeleted])
        )
        .unwrap());
    let run = world.supervisor.revocation(&exe).unwrap();
    assert!(run.is_complete());
    assert_eq!(run.elapsed(Acknowledgment::ChannelsClosed), Some(SECOND));
    assert_eq!(run.elapsed(Acknowledgment::VmStopped), Some(2 * SECOND));

    // Every receipt is in the stream: the revocation as a revocation record, the rest as
    // termination receipts under the same operation.
    let drain = world.drain_audit();
    assert!(drain.receipts.iter().all(Result::is_ok), "{drain:?}");
    let records = world.audit_records();
    let revocations: Vec<_> = records
        .iter()
        .filter_map(|record| match record.event().payload() {
            AuditEntry::Revocation { revocation } => Some((record, revocation.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(revocations.len(), 1);
    assert_eq!(revocations[0].1.epoch, AuthorizationEpoch::new(2));
    assert_eq!(revocations[0].1.reason, RevocationReason::UserRequested);
    assert_eq!(revocations[0].0.event().phase(), Phase::Revoked);
    assert_eq!(
        revocations[0].0.event().generations().authorization,
        Some(AuthorizationEpoch::new(2))
    );
    let acknowledged = host_facts(&world, "acknowledged");
    let tags: Vec<_> = acknowledged
        .iter()
        .map(|record| match record.event().payload() {
            AuditEntry::HostFact { fields, .. } => fields.get("acknowledgment").cloned(),
            _ => None,
        })
        .collect();
    assert_eq!(
        tags,
        [
            Some(text("new_authorizations_denied")),
            Some(text("channels_closed")),
            Some(text("provider_billing_stopped"))
        ]
    );
    // Each with what established it: the coordinator's own refusal of the late request,
    // the host's acknowledgment of every channel, and the provider's word.
    let field = |index: usize, name: &str| match acknowledged[index].event().payload() {
        AuditEntry::HostFact { fields, .. } => fields.get(name).cloned(),
        _ => None,
    };
    assert_eq!(
        field(0, "milestone"),
        Some(text("first_denied_authorization"))
    );
    assert_eq!(field(0, "established_by"), Some(text("coordinator")));
    assert_eq!(field(1, "milestone"), Some(text("all_channels_closed")));
    assert_eq!(field(1, "established_by"), Some(text("acknowledged")));
    assert_eq!(field(1, "source_class"), Some(text("host_probe")));
    assert_eq!(field(2, "source"), Some(text("provider")));
    assert_eq!(host_facts(&world, "vm_stopped").len(), 1);
    let finished = host_facts(&world, "cleanup_finished");
    let AuditEntry::HostFact { fact, fields } = finished[0].event().payload() else {
        panic!("{finished:?}");
    };
    assert_eq!(*fact, AuditFact::TerminationReceipt);
    assert_eq!(fields.get("physical"), Some(&text("not_proven")));
    assert_eq!(
        fields.get("late"),
        Some(&RedactedValue::Flag { value: false })
    );
    let operations: BTreeSet<_> = records
        .iter()
        .map(|record| record.event().operation().clone())
        .collect();
    assert_eq!(
        operations.len(),
        1,
        "one operation for the sandbox's lifecycle"
    );
    assert_eq!(world.sink.totals().uncorrelated, 0);

    // The four phases, each its own distribution (VM-CP-14).
    let citations = measurement_citations(
        world.supervisor.measurements(),
        config("a"),
        RunSubstrate::FakeTimeControlled,
    )
    .unwrap();
    let p50 = |phase: StopPhase| {
        citations
            .iter()
            .find(|citation| citation.phase == phase)
            .unwrap()
            .summary
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .copied()
    };
    assert_eq!(p50(StopPhase::RevokeToDeny), Some(0.0));
    assert_eq!(p50(StopPhase::ChannelClose), Some(1e9));
    assert_eq!(p50(StopPhase::VmStop), Some(2e9));
    assert_eq!(p50(StopPhase::Cleanup), Some(25e9));
    let assessment = TargetAssessment::of(
        &world
            .supervisor
            .measurements()
            .summarize(StopPhase::VmStop)
            .unwrap(),
        STOP_TARGET,
    );
    assert_eq!(assessment.within_target, Some(true));
    assert_eq!(assessment.claim, TargetClaim::ObservationUnderTestLoad);
    assert_eq!(
        citations
            .iter()
            .find(|citation| citation.phase == StopPhase::VmStop)
            .unwrap()
            .assessment,
        Some(assessment)
    );
    // Measured on the fake substrate: no claim (VM-P50). The same plumbing under an
    // authorized disposable run is accepted and bound to its configuration.
    assert!(matches!(
        revocation_claim(
            world.supervisor.measurements(),
            config("a"),
            RunSubstrate::FakeTimeControlled,
            parts("p14")
        ),
        Err(ClaimRefusal::Ledger(
            LedgerError::FakeSubstrateIsNotEvidence { .. }
        ))
    ));
    let claim = revocation_claim(
        world.supervisor.measurements(),
        config("a"),
        RunSubstrate::AuthorizedDisposable {
            authorization: Label::new("plumbing-check-not-a-drill").unwrap(),
        },
        parts("p14"),
    )
    .unwrap();
    world.assurance.add_claim(claim).unwrap();
    let id = ClaimId::new("p14").unwrap();
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Supported {
            citations: 4,
            fresh_until: None
        }
    ));
    world.assurance.set_configuration(config("b"));
    assert!(matches!(
        world.assurance.status(&id, &world.registry).unwrap(),
        ClaimStatus::Invalidated { .. }
    ));
}

/// VM-P18 (VM-CP-18) and VM-P19 (VM-CP-19): a busy stream of traffic is not activity and
/// the idle limit ends the task through the port; the engine's death ends task sandboxes
/// through their handles and leaves services running without new authorizations.
#[test]
fn expiry_during_a_busy_stream_and_engine_death_per_class() {
    let mut world = World::new();
    world.launched("exe-stream", SandboxClass::Task);
    for _ in 0..12 {
        world.advance(HOUR);
        assert!(matches!(
            world
                .supervisor
                .activity(&execution("exe-stream"), ActivityKind::NetworkTraffic),
            Err(SupervisorError::Activity {
                refusal: ActivityRefusal::NotActivity { .. }
            })
        ));
        if world.clock.now() < at(100).saturating_add(12 * HOUR) {
            let mut port = port!(world);
            assert!(world.supervisor.tick(&mut port).unwrap().expired.is_empty());
        }
    }
    let report = {
        let mut port = port!(world);
        world.supervisor.tick(&mut port).unwrap()
    };
    assert_eq!(report.expired.len(), 1);
    assert_eq!(report.expired[0].1.kind, LimitKind::Idle);
    assert_eq!(world.state("exe-stream"), SandboxState::Revoking);
    assert!(matches!(
        world.work("exe-stream", "op"),
        Err(SupervisorError::Revoked { .. })
    ));
    world
        .supervisor
        .acknowledge(&execution("exe-stream"), Acknowledgment::ChannelsClosed)
        .unwrap();
    {
        let mut port = port!(world);
        world
            .supervisor
            .advance(&execution("exe-stream"), &mut port)
            .unwrap();
    }
    assert_eq!(world.state("exe-stream"), SandboxState::Stopped);
    assert_eq!(world.stops_of("exe-stream"), 1);
    world.drain_audit();
    let records = world.audit_records();
    assert!(records.iter().any(|record| matches!(
        record.event().payload(),
        AuditEntry::Revocation { revocation }
            if revocation.reason == RevocationReason::AuthorizationExpired
    )));
    assert_eq!(host_facts(&world, "vm_stopped").len(), 1);

    // A stalled engine never acknowledges: the lease-expiry bound stops the VM anyway.
    let mut world = World::new();
    world.set_profile("exe-busy");
    let mut request = world.request("exe-busy", SandboxClass::Task);
    request.limits = crate::sandbox::lifecycle::LeaseLimits::defaults(SandboxClass::Task)
        .lower(LimitKind::Absolute, 2 * HOUR)
        .unwrap();
    world.launch_request(request).unwrap();
    for _ in 0..12 {
        world.advance(10 * 60 * SECOND);
        world
            .supervisor
            .activity(&execution("exe-busy"), ActivityKind::Command)
            .unwrap();
        let mut port = port!(world);
        let _ = world.supervisor.tick(&mut port).unwrap();
    }
    let progress = {
        let mut port = port!(world);
        world
            .supervisor
            .advance(&execution("exe-busy"), &mut port)
            .unwrap()
    };
    assert!(matches!(progress.gate, TerminationGate::Wait { .. }));
    world.advance(30 * SECOND);
    let progress = {
        let mut port = port!(world);
        world
            .supervisor
            .advance(&execution("exe-busy"), &mut port)
            .unwrap()
    };
    assert!(matches!(
        progress.gate,
        TerminationGate::BoundReached { .. }
    ));
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(progress.uncertain, 1);

    // VM-D7: the engine dies; the task ends through its handle, the service continues.
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    world.launched("exe-service", SandboxClass::Service);
    let lease = world.work("exe-service", "op-serving").unwrap();
    let report = {
        let mut port = port!(world);
        world.supervisor.engine_died(&mut port).unwrap()
    };
    assert_eq!(report.ended, [execution("exe-task")]);
    assert_eq!(report.continued, [execution("exe-service")]);
    assert_eq!(world.stops_of("exe-task"), 1);
    assert_eq!(world.stops_of("exe-service"), 0);
    assert!(world.backend.running().contains(&world.vm("exe-service")));
    assert_eq!(world.state("exe-service"), SandboxState::AuthorityActive);
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(lease.id())
        .is_ok());
    assert!(matches!(
        world.work("exe-service", "op-new"),
        Err(SupervisorError::EngineDown { .. })
    ));
    world.drain_audit();
    let died = host_facts(&world, "engine_died");
    let AuditEntry::HostFact { fields, .. } = died[0].event().payload() else {
        panic!("{died:?}");
    };
    assert_eq!(
        fields.get("tasks_ended"),
        Some(&RedactedValue::Unsigned { value: 1 })
    );
    assert_eq!(
        died[0].event().operation().as_str(),
        SUPERVISOR_OPERATION,
        "a receipt about no sandbox travels under the supervisor's operation"
    );
    assert_eq!(world.sink.totals().uncorrelated, 0);
}

/// VM-P21 (VM-CP-21): two clones restored from one golden snapshot get fresh boot
/// generations, distinct VM and guest identities and a record naming the snapshot; the
/// old capability fails; a backend without a declared state reset cold-boots instead.
#[test]
fn a_restored_snapshot_gets_a_fresh_generation_and_old_capabilities_fail() {
    let mut world = World::with(WorldOptions {
        features: BackendFeatures::of([Feature::Snapshot, Feature::Restore]),
        state_reset: StateReset::Supported,
        ..WorldOptions::default()
    });
    world.launched("exe-a", SandboxClass::Service);
    world.launched("exe-b", SandboxClass::Service);
    let old_tuple = world
        .supervisor
        .current_tuple(&execution("exe-a"), None)
        .unwrap();
    let old_capability = Binding::new(
        crate::sandbox::lifecycle::BoundKind::OperationCapability,
        old_tuple.clone(),
    )
    .unwrap();
    let handle = world.handle("exe-a");
    let manifest = {
        let mut port = port!(world);
        port.snapshot(&handle, SnapshotOrigin::PreTenantGolden)
            .unwrap()
    };
    assert_eq!(manifest.image_profile, image());
    let golden = GoldenSnapshot::certify(
        manifest.clone(),
        SnapshotProvenance {
            before_tenant_inputs: true,
            before_credentials: true,
            before_external_connections: true,
        },
        image(),
    )
    .unwrap();
    let mut pool = WarmPool::new(2);
    pool.set_golden(golden);
    pool.replenish(2);
    world.stop_fully("exe-a");
    world.stop_fully("exe-b");
    world.advance(HOUR);
    // An hour later the hypervisor evidence is older than the profile's required
    // freshness: the restore is refused like a launch and nothing is exposed.
    let request = world.request("exe-a", SandboxClass::Service);
    let receipt = {
        let mut port = port!(world);
        world
            .supervisor
            .checkout(request, &mut pool, &mut port, &world.registry)
            .unwrap()
    };
    assert_eq!(receipt.decision, CheckoutDecision::Restore);
    assert!(matches!(
        receipt.launch,
        LaunchReceipt::RolledBack {
            failure: LaunchFailure::Port { .. },
            ..
        }
    ));
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::Evidence {
                refusal: EvidenceRefusal::Stale { .. }
            }
        }
    ));
    assert_eq!(world.table.refused()[0].attempt, LaunchAttempt::Restore);
    assert_eq!(world.state("exe-a"), SandboxState::Stopped);
    assert_eq!(
        pool.available(),
        1,
        "the failed checkout consumed its clone"
    );
    pool.replenish(1);
    // The host observes the hypervisor again: both clones restore.
    world.observe_hypervisor(true, config("a"));
    // The refused restore consumed boot generation 2 of exe-a; a generation is never
    // reused, so its restore gets generation 3.
    for (name, expected) in [("exe-a", 3), ("exe-b", 2)] {
        let request = world.request(name, SandboxClass::Service);
        let receipt = {
            let mut port = port!(world);
            world
                .supervisor
                .checkout(request, &mut pool, &mut port, &world.registry)
                .unwrap()
        };
        assert_eq!(receipt.decision, CheckoutDecision::Restore);
        assert!(
            matches!(
                receipt.launch,
                LaunchReceipt::AuthorityActive { boot, path: BootPath::WarmRestore, .. }
                    if boot == SandboxBootGeneration::new(expected)
            ),
            "{receipt:?}"
        );
    }
    let new_tuple = world
        .supervisor
        .current_tuple(&execution("exe-a"), None)
        .unwrap();
    assert_ne!(new_tuple.boot, old_tuple.boot);
    assert_ne!(new_tuple.authorization, old_tuple.authorization);
    assert_eq!(new_tuple.snapshot, Some(manifest.snapshot));
    assert!(matches!(
        world.supervisor.check_binding(&old_capability),
        Err(SupervisorError::Binding {
            refusal: BindingRefusal::Stale {
                field: BindingField::Boot
            }
        })
    ));
    let record_a = world.record("exe-a").clone();
    assert_eq!(record_a.restored_from(), Some(manifest.snapshot));
    assert_eq!(
        record_a.sandbox().generations.boot,
        SandboxBootGeneration::new(3)
    );
    assert_ne!(record_a.vm(), handle.vm, "a fresh VM identity");
    assert_ne!(world.vm("exe-a"), world.vm("exe-b"));
    let guest_a = world
        .table
        .restored(&world.vm("exe-a"))
        .unwrap()
        .guest_identity;
    let guest_b = world
        .table
        .restored(&world.vm("exe-b"))
        .unwrap()
        .guest_identity;
    assert_ne!(guest_a, guest_b, "distinct guest identities in both clones");
    assert_ne!(guest_a, manifest.guest_identity);
    world.drain_audit();
    let restored = world
        .audit_records()
        .into_iter()
        .filter(|record| {
            matches!(
                record.event().payload(),
                AuditEntry::HostFact { fields, .. }
                    if fields.get("restored_from")
                        == Some(&RedactedValue::Digest {
                            digest: manifest.snapshot.digest()
                        })
            )
        })
        .count();
    assert_eq!(restored, 2, "both restored records name the snapshot");

    // Without a declared state reset the checkout cold-boots, named as such (§6.6).
    let mut world = World::with(WorldOptions {
        features: BackendFeatures::of([Feature::Snapshot, Feature::Restore]),
        ..WorldOptions::default()
    });
    world.launched("exe-c", SandboxClass::Service);
    let handle = world.handle("exe-c");
    let manifest = {
        let mut port = port!(world);
        port.snapshot(&handle, SnapshotOrigin::PreTenantGolden)
            .unwrap()
    };
    let mut pool = WarmPool::new(1);
    pool.set_golden(
        GoldenSnapshot::certify(
            manifest,
            SnapshotProvenance {
                before_tenant_inputs: true,
                before_credentials: true,
                before_external_connections: true,
            },
            image(),
        )
        .unwrap(),
    );
    pool.replenish(1);
    world.stop_fully("exe-c");
    let request = world.request("exe-c", SandboxClass::Service);
    let receipt = {
        let mut port = port!(world);
        world
            .supervisor
            .checkout(request, &mut pool, &mut port, &world.registry)
            .unwrap()
    };
    assert!(matches!(
        receipt.decision,
        CheckoutDecision::ColdBoot {
            fallback: ColdFallback::StateResetUnsupported { .. }
        }
    ));
    assert_eq!(pool.available(), 1);
    assert_eq!(world.record("exe-c").restored_from(), None);
}

/// VM-P24 and VM-P49: cleanup plans only inside a managed root after the VM stopped, a
/// guest-chosen path has no way in, user source data is preserved, and the finished
/// cleanup is recorded as logical, never as wiping.
#[test]
fn cleanup_refuses_a_guest_path_and_is_recorded_as_logical() {
    let mut world = World::new();
    world.launched("exe-task", SandboxClass::Task);
    let exe = execution("exe-task");
    let now = world.clock.now();
    let overlay =
        world
            .supervisor
            .roots_mut()
            .create(&exe, VolumeKind::ExecutableEnvironmentCache, now);
    let source = world
        .supervisor
        .roots_mut()
        .create(&exe, VolumeKind::SourceWorkspace, now);
    let path = RelativePath::new("tmp/build").unwrap();
    assert_eq!(
        RelativePath::new("../../etc/passwd"),
        Err(PathRefusal::ParentComponent)
    );
    assert_eq!(RelativePath::new("/var/lib/vm"), Err(PathRefusal::Absolute));
    assert_eq!(
        RelativePath::new("D:\\data"),
        Err(PathRefusal::ForbiddenCharacter { character: ':' })
    );
    {
        let mut port = port!(world);
        world
            .supervisor
            .revoke(&exe, RevocationCause::UserRequested, &mut port)
            .unwrap();
    }
    assert!(matches!(
        world.supervisor.plan_cleanup(
            &exe,
            CleanupTarget {
                root: overlay,
                path: path.clone()
            }
        ),
        Err(SupervisorError::Acknowledgment {
            refusal: AckRefusal::VmNotStopped
        })
    ));
    world.stop_fully("exe-task");
    let plan = world
        .supervisor
        .plan_cleanup(
            &exe,
            CleanupTarget {
                root: overlay,
                path: path.clone(),
            },
        )
        .unwrap();
    assert_eq!(plan.root.sandbox, exe);
    assert!(matches!(
        world.supervisor.plan_cleanup(
            &exe,
            CleanupTarget {
                root: source,
                path: path.clone()
            }
        ),
        Err(SupervisorError::Cleanup {
            refusal: CleanupRefusal::UserSourcePreserved { .. }
        })
    ));
    let report = CleanupReport::logical([
        LogicalCleanupAction::OverlayDeleted,
        LogicalCleanupAction::PerimeterRemoved,
    ]);
    assert!(!world.supervisor.finish_cleanup(&exe, report).unwrap());
    assert_eq!(world.supervisor.roots().of(&exe).count(), 0);
    world.drain_audit();
    let finished = host_facts(&world, "cleanup_finished");
    assert_eq!(finished.len(), 1);
    let AuditEntry::HostFact { fields, .. } = finished[0].event().payload() else {
        panic!("{finished:?}");
    };
    assert_eq!(fields.get("physical"), Some(&text("not_proven")));
    assert_eq!(
        fields.get("actions"),
        Some(&RedactedValue::Unsigned { value: 2 })
    );
    assert_eq!(finished[0].event().phase(), Phase::Completed);
}

/// VM-P22 and INT-10 (VM-CP-22): an audit flood fills storage and the spool until the
/// stream fails closed; the revocation still happens, its durable copy takes the reserve,
/// the next ordinary record is refused visibly, and closing the stream does not wait.
#[test]
fn an_audit_flood_never_blocks_the_revocation_lane() {
    let mut world = World::with(WorldOptions {
        storage_capacity: 6,
        spool_records: 3,
        ..WorldOptions::default()
    });
    world.launched("exe-task", SandboxClass::Task);
    world.drain_audit();
    assert_eq!(world.audit_records().len(), 2);
    let exe = execution("exe-task");
    let flood = |step: u64| LifecycleReceipt::FirstCommand {
        execution: execution("exe-task"),
        boot: SandboxBootGeneration::FIRST,
        elapsed: std::time::Duration::from_secs(step),
    };
    let mut outcomes = Vec::new();
    for step in 1..=7 {
        outcomes.push(world.sink.record_receipt(&flood(step)));
    }
    assert!(outcomes[..4].iter().all(|outcome| matches!(
        outcome,
        Ok(receipt) if receipt.durability == Durability::Durable
    )));
    assert!(matches!(
        outcomes[4],
        Ok(receipt) if receipt.durability == Durability::Spooled { spooled_records: 1 }
    ));
    assert!(matches!(
        outcomes[5],
        Ok(receipt) if receipt.durability == Durability::Spooled { spooled_records: 2 }
    ));
    assert!(matches!(
        outcomes[6],
        Err(SinkRefusal::Stream(
            crate::sandbox::audit::StreamRefusal::Audit(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                ..
            })
        ))
    ));
    assert!(matches!(
        world.sink.stream().health(),
        AuditHealth::FailClosed { .. }
    ));

    // The revocation lane is the supervisor's; it never waited on the stream.
    let progress = {
        let mut port = port!(world);
        world
            .supervisor
            .revoke(&exe, RevocationCause::Violation, &mut port)
            .unwrap()
    };
    assert!(progress.acknowledged.is_empty(), "{progress:?}");
    assert!(matches!(
        world.work("exe-task", "op-late"),
        Err(SupervisorError::Revoked { .. })
    ));
    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [LifecycleReceipt::Revoked { .. }]
    ));
    assert!(
        matches!(
            drain.receipts[0],
            Ok(receipt) if receipt.durability == Durability::Spooled { spooled_records: 3 }
        ),
        "the durable copy of the revocation took the reserve: {:?}",
        drain.receipts
    );
    assert!(
        matches!(
            world.sink.record_receipt(&flood(8)),
            Err(SinkRefusal::Stream(_))
        ),
        "an ordinary record is still refused, visibly"
    );
    assert_eq!(world.sink.totals().refused, 2);
    assert!(world.supervisor.revocation(&exe).is_some());
    let chain = verify_segments(&genesis(), &world.storage.snapshot()).unwrap();
    assert_eq!(
        chain.records, 6,
        "storage holds exactly what it took, in order"
    );

    // Closing a failed-closed stream does not block: one flush, one seal, no wait.
    let storage = MemorySegments::new(1);
    let mut directory = StreamDirectory::new();
    let mut sink = AuditSink::open(
        &mut directory,
        JournalId::new("warden").unwrap(),
        ProducerId::new("warden.audit").unwrap(),
        storage.clone(),
        MemorySpool::new(),
        NoAnchor,
        Arc::new(crate::foundation::ids::ManualClock::new(at(1))),
        stream_config(2),
    )
    .unwrap();
    for step in 1..=3 {
        let _ = sink.record_receipt(&flood(step));
    }
    assert!(matches!(
        sink.stream().health(),
        AuditHealth::FailClosed { .. } | AuditHealth::Spooling { .. }
    ));
    let closed = sink.close().unwrap();
    assert_eq!(storage.all_records().len(), 1);
    assert!(closed.anchor.is_none());
}

/// VM-P49 and VM-CP-19: a stale handle whose VM is gone stops nothing although another
/// VM now runs with its PID; recovery from a state that predates the reuse drops the
/// handle as gone and signals nothing.
#[test]
fn a_reused_pid_never_kills_the_wrong_object() {
    let mut world = World::new();
    world.launched("exe-a", SandboxClass::Task);
    let handle_a = world.handle("exe-a");
    let pid_a = world.backend.pid_of(&handle_a.vm).unwrap();
    let persisted = world.supervisor.persist();
    world.stop_fully("exe-a");
    world.launched("exe-b", SandboxClass::Task);
    let vm_b = world.vm("exe-b");
    assert_eq!(
        world.backend.pid_of(&vm_b),
        Some(pid_a),
        "the new VM inherited the old PID"
    );
    assert_eq!(world.backend.pids_reused(), 1);
    let calls_before = world.backend.calls().len();
    {
        let mut port = port!(world);
        assert_eq!(port.check_handle(&handle_a), HandleIdentity::Gone);
        assert_eq!(port.stop(&handle_a).unwrap(), StopOutcome::AlreadyGone);
    }
    assert!(world.backend.running().contains(&vm_b));
    assert_eq!(world.stops_of("exe-b"), 0);

    // An unrelated VM the integration never launched takes the PID next; recovery from
    // the state in which A was alive finds A gone and signals nothing.
    world.stop_fully("exe-b");
    let foreign = world
        .backend
        .launch(&World::direct_request("exe-foreign", 77), &world.registry)
        .unwrap();
    assert_eq!(world.backend.pid_of(&foreign.vm), Some(pid_a));
    let stops_before = world.backend.calls()[calls_before..]
        .iter()
        .filter(|call| matches!(call, FakeCall::Stop { .. }))
        .count();
    let capacity = LedgerCapacity::new(real_ledger(&world.clock)).into_shared();
    let (recovered, report) = {
        let mut port = port!(world);
        Supervisor::recover(
            persisted,
            Arc::clone(&world.clock),
            session(2),
            capacity,
            supervisor_config(TerminationTiming::AfterChannelAcknowledgmentOrBound),
            &mut port,
        )
        .unwrap()
    };
    assert_eq!(report.handles_gone, [handle_a.vm]);
    assert!(report.handles_reused.is_empty());
    assert!(matches!(
        report.coordination.sandboxes.get(&execution("exe-a")),
        Some(SandboxRecovery::VmLost { .. })
    ));
    assert!(report.coordination.untrusted_vms_terminated.is_empty());
    assert!(recovered.handles().is_empty());
    assert_eq!(
        world.backend.calls()[calls_before..]
            .iter()
            .filter(|call| matches!(call, FakeCall::Stop { .. }))
            .count(),
        stops_before,
        "nothing was signalled during recovery: {:?}",
        &world.backend.calls()[calls_before..]
    );
    assert!(
        world.backend.running().contains(&foreign.vm),
        "the unrelated process lives"
    );
    assert_eq!(
        world.table.unrecorded(),
        &BTreeSet::from([foreign.vm]),
        "a VM this integration never launched gets no handle"
    );
}

/// CORE-04 per-grant revocation through the supervisor (§6.3 step 1, line 2308; the S04
/// bystander decision): one network grant of a running sandbox is revoked alone. Its work
/// is cancelled and refused while the sandbox keeps its epoch, its VM, its launch record,
/// its other grant and its other work. The receipt reaches the audit stream as a typed
/// grant revocation under the sandbox's operation, never as a revocation; nothing about it
/// can be acknowledged, and a later revocation of the sandbox starts from nothing.
#[test]
fn a_grant_revocation_leaves_the_sandboxs_other_grants_alive() {
    let mut world = World::new();
    world.set_profile("exe-task");
    let route_a = NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", "a"),
    };
    let route_b = NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", "b"),
    };
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.settings.network = [route_a, route_b].into_iter().collect();
    assert!(matches!(
        world.launch_request(request).unwrap(),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let exe = execution("exe-task");
    let (grant_a, grant_b) = (network_grant_id(&route_a), network_grant_id(&route_b));
    let granted_work = |world: &mut World, op: &str, grant: GrantId| {
        world.supervisor.authorize_granted_work(
            &exe,
            operation(op),
            LeaseKind::ChildWork,
            call(),
            [grant].into_iter().collect(),
        )
    };
    let on_a = granted_work(&mut world, "op-a", grant_a).unwrap();
    let on_b = granted_work(&mut world, "op-b", grant_b).unwrap();
    let plain = world.work("exe-task", "op-plain").unwrap();
    let vm = world.vm("exe-task");
    let record = world.record("exe-task").identity();
    world.drain_audit();
    world.advance(SECOND);

    let revoked = world
        .supervisor
        .revoke_grant(&exe, grant_a, GrantRevocationCause::Violation)
        .unwrap();
    assert_eq!(revoked.revoked.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(revoked.revoked.network, Some(route_a));
    assert_eq!(
        world.supervisor.coordinator().check_lease(on_a.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(on_b.id())
        .is_ok());
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(plain.id())
        .is_ok());
    assert!(matches!(
        granted_work(&mut world, "op-a2", grant_a),
        Err(SupervisorError::Lease {
            refusal: LeaseRefusal::GrantRevoked { .. }
        })
    ));
    assert!(granted_work(&mut world, "op-b2", grant_b).is_ok());
    assert_eq!(world.state("exe-task"), SandboxState::AuthorityActive);
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .sandbox(&exe)
            .unwrap()
            .generations()
            .authorization,
        AuthorizationEpoch::FIRST
    );
    assert!(world.backend.running().contains(&vm));
    assert_eq!(world.stops_of("exe-task"), 0);
    assert_eq!(world.handle("exe-task").token, record);
    assert!(world.supervisor.revocation(&exe).is_none());
    assert!(matches!(
        world
            .supervisor
            .acknowledge(&exe, Acknowledgment::ChannelsClosed),
        Err(SupervisorError::NotRevoking { .. })
    ));

    // In the audit stream: one typed grant revocation under the sandbox's operation, and
    // no revocation.
    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [LifecycleReceipt::GrantRevoked { .. }]
    ));
    assert!(drain.receipts.iter().all(Result::is_ok), "{drain:?}");
    let records = world.audit_records();
    assert!(records
        .iter()
        .all(|record| !matches!(record.event().payload(), AuditEntry::Revocation { .. })));
    assert!(host_facts(&world, "grant_revoked").is_empty());
    let grants: Vec<_> = records
        .iter()
        .filter_map(|record| match record.event().payload() {
            AuditEntry::GrantRevocation { revocation } => Some((record, revocation)),
            _ => None,
        })
        .collect();
    let [(record, revocation)] = grants.as_slice() else {
        panic!("{records:?}");
    };
    assert_eq!(revocation.execution, exe);
    assert_eq!(revocation.grant, grant_a);
    assert_eq!(revocation.epoch, AuthorizationEpoch::FIRST);
    assert_eq!(revocation.reason, RevocationReason::SecurityEvent);
    assert_eq!(record.event().phase(), Phase::Revoked);
    assert_eq!(
        record.event().operation(),
        records[0].event().operation(),
        "one operation for the sandbox's lifecycle"
    );
    assert_eq!(world.sink.totals().uncorrelated, 0);

    // A later revocation of the sandbox starts from nothing: the grant's refused lease is
    // no denial of it, and only a request refused after its decision is.
    let progress = {
        let mut port = port!(world);
        world
            .supervisor
            .revoke(&exe, RevocationCause::UserRequested, &mut port)
            .unwrap()
    };
    assert!(progress.acknowledged.is_empty(), "{progress:?}");
    assert!(world
        .supervisor
        .coordinator()
        .check_lease(on_a.id())
        .is_err());
    assert!(world.supervisor.sync_revocation(&exe).unwrap().is_empty());
    assert!(matches!(
        world.work("exe-task", "op-late"),
        Err(SupervisorError::Revoked { .. })
    ));
    assert_eq!(
        world.supervisor.sync_revocation(&exe).unwrap(),
        [Acknowledgment::NewAuthorizationsDenied]
    );
    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [
            LifecycleReceipt::Revoked { .. },
            LifecycleReceipt::Acknowledged {
                acknowledgment: Acknowledgment::NewAuthorizationsDenied,
                ..
            }
        ]
    ));
    assert_eq!(
        world
            .audit_records()
            .iter()
            .filter(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
            .count(),
        1
    );
}

/// §4.4 lines 2153–2165 and VM-CP-11 (VM-P11): where the network facet asks for an
/// independent perimeter, the backend admits a launch only on CORE-01 host-probe evidence
/// that every block rule is enforced for the broker under the current configuration.
/// Without it the launch is refused by rule before anything is created, no authority is
/// granted, and the refusal reaches the audit stream naming the rule and principal; a
/// must-probe that connected, another configuration or a guest's report never counts;
/// with the evidence the record binds it.
#[test]
fn admission_is_refused_without_perimeter_evidence() {
    let mut world = World::new();
    let (private, metadata) = (perimeter_rule("private-ranges"), perimeter_rule("metadata"));
    let (first, second) = if private.rule < metadata.rule {
        (private, metadata)
    } else {
        (metadata, private)
    };
    world.set_perimeter_profile("exe-none", &[private, metadata]);
    let receipt = world.launch("exe-none", SandboxClass::Task);
    assert!(
        matches!(
            receipt,
            LaunchReceipt::RolledBack {
                failure: LaunchFailure::Port { .. },
                ..
            }
        ),
        "{receipt:?}"
    );
    assert_eq!(
        world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::PerimeterNotEvidenced {
                rule: first,
                refusal: EvidenceRefusal::Missing {
                    capability: Capability::PerimeterRuleEnforced
                }
            }
        }
    );
    assert!(world
        .backend
        .calls()
        .iter()
        .all(|call| !matches!(call, FakeCall::Create { .. })));
    assert!(world.table.records().next().is_none());
    assert!(world.supervisor.handles().is_empty());
    assert_eq!(world.state("exe-none"), SandboxState::Stopped);
    assert_eq!(
        world
            .supervisor
            .coordinator()
            .sandbox(&execution("exe-none"))
            .unwrap()
            .authority(),
        None
    );
    let drain = world.drain_audit();
    assert_eq!(drain.refusals.len(), 1);
    assert!(drain.refusals.iter().all(Result::is_ok));
    assert!(drain.launches.is_empty());
    let refused: Vec<_> = world
        .audit_records()
        .into_iter()
        .filter(|record| {
            matches!(
                record.event().payload(),
                AuditEntry::HostFact { fields, .. }
                    if fields.get("decision") == Some(&text("launch_refused"))
            )
        })
        .collect();
    let AuditEntry::HostFact { fields, .. } = refused[0].event().payload() else {
        panic!("{refused:?}");
    };
    assert_eq!(
        fields.get("refusal"),
        Some(&text("perimeter_not_evidenced"))
    );
    assert_eq!(fields.get("evidence"), Some(&text("missing")));
    assert_eq!(
        fields.get("perimeter_rule"),
        Some(&RedactedValue::Digest { digest: first.rule })
    );
    assert_eq!(
        fields.get("principal"),
        Some(&RedactedValue::Digest { digest: broker() })
    );
    assert_eq!(
        fields.get("perimeter"),
        Some(&RedactedValue::Digest {
            digest: perimeter()
        })
    );

    // One rule enforced, the must-probe of the other connected: refused by that rule.
    world.observe_perimeter_rule(first, true, config("a"));
    world.observe_perimeter_rule(second, false, config("a"));
    world.set_perimeter_profile("exe-open", &[private, metadata]);
    assert!(matches!(
        world.launch("exe-open", SandboxClass::Task),
        LaunchReceipt::RolledBack { .. }
    ));
    assert_eq!(
        world.table.refused().last().unwrap().problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::PerimeterNotEvidenced {
                rule: second,
                refusal: EvidenceRefusal::Unsupported {
                    capability: Capability::PerimeterRuleEnforced,
                    reason: UnsupportedReason::NotEnforced
                }
            }
        }
    );

    // Enforced, but observed under another configuration: it no longer applies.
    world.observe_perimeter_rule(second, true, config("b"));
    world.set_perimeter_profile("exe-changed", &[private, metadata]);
    assert!(matches!(
        world.launch("exe-changed", SandboxClass::Task),
        LaunchReceipt::RolledBack { .. }
    ));
    assert!(matches!(
        &world.table.refused().last().unwrap().problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::PerimeterNotEvidenced {
                refusal: EvidenceRefusal::FingerprintChanged { .. },
                ..
            }
        }
    ));
    assert!(world.table.records().next().is_none());

    // Both rules shown enforced for the broker under the current configuration: admitted,
    // and the record and its audit fact carry the perimeter's evidence.
    world.observe_perimeter_rule(second, true, config("a"));
    world.set_perimeter_profile("exe-ok", &[private, metadata]);
    assert!(matches!(
        world.launch("exe-ok", SandboxClass::Task),
        LaunchReceipt::AuthorityActive { .. }
    ));
    let evidence = world.record("exe-ok").perimeter_evidence().to_vec();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().all(|satisfied| {
        satisfied.capability() == Capability::PerimeterRuleEnforced
            && satisfied.source() == SourceClass::HostProbe
            && satisfied.configuration() == config("a")
    }));
    world.drain_audit();
    let launched: Vec<_> = world
        .audit_records()
        .into_iter()
        .filter(|record| {
            matches!(
                record.event().payload(),
                AuditEntry::HostFact { fields, .. } if fields.get("perimeter_rules").is_some()
            )
        })
        .collect();
    assert_eq!(launched.len(), 1);
    let AuditEntry::HostFact { fields, .. } = launched[0].event().payload() else {
        panic!("{launched:?}");
    };
    assert_eq!(
        fields.get("perimeter_rules"),
        Some(&RedactedValue::Unsigned { value: 2 })
    );
    assert_eq!(
        fields.get("perimeter_evidence_source"),
        Some(&text("host_probe"))
    );

    // A guest's report never shows the perimeter.
    let mut world = World::with(WorldOptions {
        perimeter_source: SourceClass::GuestReport,
        ..WorldOptions::default()
    });
    world.set_perimeter_profile("exe-guest", &[private]);
    world.observe_perimeter_rule(private, true, config("a"));
    assert!(matches!(
        world.launch("exe-guest", SandboxClass::Task),
        LaunchReceipt::RolledBack { .. }
    ));
    assert_eq!(
        world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::PerimeterNotEvidenced {
                rule: private,
                refusal: EvidenceRefusal::SourceTooWeak {
                    capability: Capability::PerimeterRuleEnforced,
                    observed: SourceClass::GuestReport,
                    required: SourceClass::HostProbe
                }
            }
        }
    );
    assert!(world.table.records().next().is_none());
}

/// §8.2 lines 2441–2450 (VM-P22) and §6.3 step 1: a grant revocation takes effect in
/// CORE-04 whatever the audit stream does, and its record rides the revocation reserve as
/// a revocation of the sandbox does. With the stream failed closed for ordinary records,
/// the typed grant revocation is recorded on the reserve, an ordinary record is still
/// refused visibly, and a later revocation of the sandbox takes the reserve too.
#[test]
fn a_grant_revocation_is_recorded_on_the_reserve_while_the_audit_fails_closed() {
    let mut world = World::with(WorldOptions {
        storage_capacity: 6,
        spool_records: 4,
        revocation_reserve: 2,
        ..WorldOptions::default()
    });
    world.set_profile("exe-task");
    let route = NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", "a"),
    };
    let mut request = world.request("exe-task", SandboxClass::Task);
    request.settings.network = [route].into_iter().collect();
    world.launch_request(request).unwrap();
    let exe = execution("exe-task");
    let grant = network_grant_id(&route);
    let lease = world
        .supervisor
        .authorize_granted_work(
            &exe,
            operation("op-a"),
            LeaseKind::ChildWork,
            call(),
            [grant].into_iter().collect(),
        )
        .unwrap();
    world.drain_audit();
    let flood = |step: u64| LifecycleReceipt::FirstCommand {
        execution: execution("exe-task"),
        boot: SandboxBootGeneration::FIRST,
        elapsed: std::time::Duration::from_secs(step),
    };
    let mut step = 0;
    while !matches!(world.sink.stream().health(), AuditHealth::FailClosed { .. }) {
        step += 1;
        assert!(step < 32, "the stream never failed closed");
        let _ = world.sink.record_receipt(&flood(step));
    }

    world
        .supervisor
        .revoke_grant(&exe, grant, GrantRevocationCause::Violation)
        .unwrap();
    let drain = world.drain_audit();
    assert!(matches!(
        drain.lifecycle[..],
        [LifecycleReceipt::GrantRevoked { .. }]
    ));
    assert!(
        matches!(
            drain.receipts[..],
            [Ok(receipt)] if receipt.durability == Durability::Spooled { spooled_records: 3 }
        ),
        "recorded on the reserve: {:?}",
        drain.receipts
    );
    assert!(
        matches!(
            world.sink.record_receipt(&flood(99)),
            Err(SinkRefusal::Stream(
                crate::sandbox::audit::StreamRefusal::Audit(AuditRefusal::FailClosed { .. })
            ))
        ),
        "an ordinary record is still refused, visibly"
    );
    assert_eq!(world.sink.totals().refused, 1);
    assert!(world.supervisor.coordinator().grant_revoked(&exe, grant));
    assert_eq!(
        world.supervisor.coordinator().check_lease(lease.id()),
        Err(LeaseRefusal::Cancelled {
            cause: CancelCause::GrantRevoked
        })
    );

    let _ = {
        let mut port = port!(world);
        world
            .supervisor
            .revoke(&exe, RevocationCause::Violation, &mut port)
            .unwrap()
    };
    let drain = world.drain_audit();
    assert!(
        matches!(
            drain.receipts[0],
            Ok(receipt) if receipt.durability == Durability::Spooled { spooled_records: 4 }
        ),
        "the revocation of the sandbox took the reserve too: {:?}",
        drain.receipts
    );
    assert_eq!(world.sink.stream().state().spooled_records, 4);
}

/// S06 and VM-P22: the sink on a CORE-06 durable stream. Its owner is the stream's only
/// appender, so a second sink on the stream is refused while the first lives, here or
/// through another directory; its receipts, the typed grant revocation among them, land
/// in the durable log; after a restart the sink resumes after the last record, and what
/// the log holds verifies as one chain.
#[test]
fn the_audit_sink_runs_on_a_durable_stream_across_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = StreamDirectory::durable(root.path());
    let clock = Arc::new(crate::foundation::ids::ManualClock::new(at(1)));
    let log = LogConfig {
        max_entries: 10_000,
        max_bytes: 1 << 26,
        segment_entries: 64,
        segment_bytes: 1 << 16,
    };
    let open = |directory: &mut StreamDirectory| {
        AuditSink::open_durable(
            directory,
            JournalId::new("supervisor").unwrap(),
            ProducerId::new("supervisor.audit").unwrap(),
            MemorySpool::new(),
            NoAnchor,
            Arc::clone(&clock),
            stream_config(8),
            log,
        )
    };
    let (mut sink, opening) = open(&mut directory).unwrap();
    assert!(opening.resume.is_none() && opening.log.created);
    let exe = execution("exe-task");
    let launched = sink
        .record_receipt(&LifecycleReceipt::Launched {
            execution: exe.clone(),
            boot: SandboxBootGeneration::FIRST,
            context: EventContext::new(operation("op-task"), Phase::Booting),
        })
        .unwrap();
    assert_eq!(launched.durability, Durability::Durable);
    let route = NetworkGrant::NamedRoute {
        route: named("yougori/test/route/v1", "a"),
    };
    let revoked = GrantRevocation {
        execution: exe.clone(),
        grant: network_grant_id(&route),
        epoch: AuthorizationEpoch::FIRST,
        reason: RevocationReason::SecurityEvent,
    };
    let receipt = sink
        .record_receipt(&LifecycleReceipt::GrantRevoked {
            revocation: revoked.clone(),
            cause: GrantRevocationCause::Violation,
            cancelled: Vec::new(),
            context: EventContext::new(operation("op-task"), Phase::Revoked),
        })
        .unwrap();
    assert_eq!(
        (receipt.sequence.get(), receipt.durability),
        (2, Durability::Durable)
    );

    assert!(matches!(
        open(&mut directory).err(),
        Some(StreamError::AuthorityLive { .. })
    ));
    assert!(matches!(
        open(&mut StreamDirectory::durable(root.path())).err(),
        Some(StreamError::Durable(DurableError::Log(LogError::Owner(
            OwnerError::HeldInProcess { .. }
        ))))
    ));
    sink.close().unwrap();

    let (mut sink, opening) = open(&mut directory).unwrap();
    let resumed = opening.resume.unwrap();
    assert_eq!(resumed.report.chain.records, 2);
    assert!(matches!(opening.log.takeover, Takeover::Released { .. }));
    let next = sink
        .record_receipt(&LifecycleReceipt::FirstCommand {
            execution: exe.clone(),
            boot: SandboxBootGeneration::FIRST,
            elapsed: std::time::Duration::from_secs(1),
        })
        .unwrap();
    assert_eq!(next.sequence.get(), 3);
    // The sandbox's context was not kept across the restart.
    assert_eq!(sink.totals().uncorrelated, 1);
    let segments = sink
        .stream()
        .with_storage(|storage| storage.segments().unwrap());
    let chain = verify_segments(&genesis(), &segments).unwrap();
    assert_eq!(chain.records, 3);
    let records: Vec<_> = segments
        .iter()
        .flat_map(|segment| segment.records.iter())
        .collect();
    assert!(matches!(
        records[1].event().payload(),
        AuditEntry::GrantRevocation { revocation } if *revocation == revoked
    ));
    assert_eq!(records[1].event().operation(), &operation("op-task"));
}

/// Leftover entries H01, S01, M02 and M08 (§8.1 line 2439): launch-time evidence does not
/// stay current. Once the record's facts are stale, the supervisor asks the backend to
/// observe the VM again; readiness stays unavailable, and no new work is authorized, until
/// fresh CORE-01 evidence and a fresh re-observation that passes admission's rules exist.
#[test]
fn stale_launch_evidence_makes_readiness_unavailable_until_the_vm_is_observed_again() {
    let mut world = World::new();
    world.set_profile("exe-task");
    world.launched("exe-task", SandboxClass::Task);
    assert_eq!(
        world.observe_readiness("exe-task").unwrap(),
        crate::sandbox::lifecycle::ObservedReadiness::Ready {
            at: world.clock.now()
        }
    );
    assert!(world.work("exe-task", "op-1").is_ok());

    // The record's facts and the CORE-01 evidence age out: unavailable, and work refused.
    world.advance(MINUTE + SECOND);
    let unavailable = world.observe_readiness("exe-task").unwrap();
    assert!(
        matches!(
            &unavailable,
            crate::sandbox::lifecycle::ObservedReadiness::Unavailable { since, detail }
                if *since == world.clock.now() && detail.contains("not current")
        ),
        "{unavailable:?}"
    );
    assert!(matches!(
        world.work("exe-task", "op-2"),
        Err(SupervisorError::ReadinessUnavailable { .. })
    ));
    assert!(world.table.reobservation(&world.vm("exe-task")).is_none());

    // The host probe observes again, and so does the backend: ready on the fresh
    // re-observation, while the launch record itself stays stale.
    world.observe_hypervisor(true, config("a"));
    assert!(matches!(
        world.observe_readiness("exe-task").unwrap(),
        crate::sandbox::lifecycle::ObservedReadiness::Ready { .. }
    ));
    assert!(world
        .record("exe-task")
        .assert_current(world.registry.now())
        .is_err());
    assert!(world.table.reobservation(&world.vm("exe-task")).is_some());
    assert!(world.work("exe-task", "op-3").is_ok());

    // Admission on fresh readiness: once the readiness is older than the configured age
    // and the record's facts are stale, the supervisor asks the backend again through
    // the port before it authorizes work, and the port re-observes the VM.
    world.advance(MINUTE + SECOND);
    world.observe_hypervisor(true, config("a"));
    let reobserves = |world: &World| {
        world
            .backend
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Reobserve { .. }))
            .count()
    };
    let before = reobserves(&world);
    {
        let mut port = port!(world);
        assert!(world
            .supervisor
            .authorize_observed_work(
                &execution("exe-task"),
                operation("op-observed"),
                crate::foundation::coordination::LeaseKind::ChildWork,
                call(),
                BTreeSet::new(),
                &mut port,
            )
            .is_ok());
    }
    assert_eq!(reobserves(&world), before + 1);

    // The host now observes the VM with a network channel the launch did not allow:
    // unavailable again, whatever the evidence says.
    world.advance(MINUTE + SECOND);
    world.observe_hypervisor(true, config("a"));
    world.backend.script_mut().network =
        Scripted::HostObserved(crate::sandbox::backend::NetworkAuthority::of([
            crate::sandbox::backend::NetworkChannel::PublishedService,
        ]));
    assert!(world
        .observe_readiness("exe-task")
        .unwrap()
        .is_unavailable());
    assert!(matches!(
        world.work("exe-task", "op-4"),
        Err(SupervisorError::ReadinessUnavailable { .. })
    ));
}

/// A refused launch whose cleanup is incomplete never claims that nothing is left: the
/// boot's perimeter and its reservation stay held while the VM may run, the rollback
/// stalls, and the audit stream records the refusal with what may remain.
#[test]
fn a_refused_launch_whose_cleanup_is_incomplete_keeps_what_its_vm_may_use() {
    let mut world = World::new();
    world.set_profile("exe-left");
    world.backend.script_mut().devices = Scripted::Unavailable {
        reason: UnknownReason::NotTested,
    };
    world.backend.script_mut().teardown_failure = Some("the VM did not exit".to_owned());
    let receipt = world.launch("exe-left", SandboxClass::Task);
    assert!(
        matches!(
            receipt,
            LaunchReceipt::RollbackStalled {
                failure: LaunchFailure::Port { .. },
                ..
            }
        ),
        "{receipt:?}"
    );
    assert_eq!(world.state("exe-left"), SandboxState::CleanupPending);
    let sandbox = world
        .supervisor
        .coordinator()
        .sandbox(&execution("exe-left"))
        .unwrap();
    assert_eq!(sandbox.authority(), None);
    let key = sandbox.reservation().unwrap();
    assert!(
        world
            .supervisor
            .coordinator()
            .capacity()
            .record(&key)
            .is_some(),
        "the reservation is not released while the VM may run"
    );
    let left: Vec<_> = world.table.left_behind().values().copied().collect();
    assert_eq!(left.len(), 1);
    assert_eq!(world.backend.running(), left);
    assert!(matches!(
        &world.table.refused()[0].problem,
        LaunchProblem::Backend {
            refusal: LaunchRefusal::CleanupIncomplete { .. }
        }
    ));

    let drain = world.drain_audit();
    assert_eq!(drain.refusals.len(), 1);
    let decision = world
        .audit_records()
        .into_iter()
        .find_map(|record| match record.event().payload() {
            AuditEntry::HostFact {
                fact: AuditFact::AuthorizationDecision,
                fields,
            } => Some(fields.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(decision.get("refusal"), Some(&text("cleanup_incomplete")));
    assert_eq!(
        decision.get("cleanup_refusal"),
        Some(&text("properties_not_satisfied"))
    );
    assert_eq!(
        decision.get("left"),
        Some(&RedactedValue::Unsigned { value: 1 })
    );
    assert_eq!(
        decision.get("left_process"),
        Some(&RedactedValue::Flag { value: true })
    );
    assert_eq!(
        decision.get("vm"),
        Some(&RedactedValue::Digest {
            digest: left[0].digest()
        })
    );
}
