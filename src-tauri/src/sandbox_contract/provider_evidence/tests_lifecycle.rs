//! V12 remote runs confirmed on these adapters instead of the fake provider-API probe:
//! the store filled through V12's provider port, a dedicated VM and a provider container
//! admitted on `RuntimeCategory` evidence, and a per-sandbox VM the provider API never
//! establishes.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, EvidenceRefusal, ObservationResult, ProbeRegistry,
    ProviderKind, ProviderSubject, RegistryError, RuntimeOffer, RuntimeSubject, SourceClass,
    Staleness, Subject, SupportDetail, UnsupportedReason,
};
use crate::foundation::ids::{Digest, ExecutionCategory, ManualClock};
use crate::sandbox_contract::provider::{SharedSpendLedger, SpendLedger};
use crate::sandbox_contract::remote::fakes::{
    account, attempt, config, container_offering, dedicated_offering, explicit_container, host_key,
    metal_offering, parent, pod_execution, provision_effect, vm_id, vm_request, FakeProvider,
    HostWorld, HOUR, SECOND,
};
use crate::sandbox_contract::remote::{
    AdapterState, AttemptId, BillingReport, EnrollmentEvidence, KnownHosts, LookupOutcome,
    OfferingKind, ProviderError, ProviderInstance, ProvisionOutcome, ProvisionRequest,
    RemoteOffering, RemoteProviderPort, RemoteRequest, RemoteVmAdapter, TerminationOutcome,
    UncertainCause,
};

/// A V12 run on the home host's clock, with the provider adapters registered in a CORE-01
/// registry on that clock.
struct Run {
    world: HostWorld<Arc<ManualClock>>,
    reports: Arc<ProviderReports<ManualClock>>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    provider: FakeProvider,
    ledger: SharedSpendLedger,
    known: KnownHosts,
    adapter: RemoteVmAdapter<Arc<ManualClock>>,
}

impl Run {
    fn with(offering: RemoteOffering, request: RemoteRequest) -> Self {
        let world = HostWorld::new(4 * HOUR);
        let reports = Arc::new(ProviderReports::new(Arc::clone(&world.clock)));
        let mut registry = ProbeRegistry::new(Arc::clone(&world.clock));
        register_provider_adapters(&mut registry, &reports).unwrap();
        let ledger = SharedSpendLedger::new(SpendLedger::new());
        ledger
            .with(|book| book.open_account(account(), 100_000_000))
            .unwrap();
        let execution = if offering.kind == OfferingKind::ProviderContainer {
            pod_execution()
        } else {
            parent()
        };
        let adapter = RemoteVmAdapter::plan(
            Arc::clone(&world.clock),
            attempt(1),
            execution,
            &request,
            &[offering],
            config(),
        )
        .unwrap();
        Self {
            world,
            reports,
            registry,
            provider: FakeProvider::default(),
            ledger,
            known: KnownHosts::new(),
            adapter,
        }
    }

    /// Reserves spend, provisions through the reporting port and enrolls the host key.
    fn provision_and_enroll(&mut self) -> ProviderInstance {
        self.adapter
            .reserve_spend(&self.ledger, &provision_effect(account(), 10_000_000, 1))
            .unwrap();
        let mut port = ReportingPort::new(&mut self.provider, &*self.reports);
        let instance = self.adapter.provision(&mut port, &self.ledger).unwrap();
        assert!(matches!(
            port.log(),
            [PortRecord::Recorded {
                outcome: RecordOutcome::New { .. },
                ..
            }]
        ));
        self.adapter
            .enroll(
                &mut self.known,
                &host_key(1),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(1).fingerprint(),
                },
            )
            .unwrap();
        instance
    }

    /// Observes `runtime`'s category through the provider adapter and offers it under the
    /// configuration of the provider's latest report.
    fn offer(&mut self, runtime: RuntimeSubject) -> Result<RuntimeOffer, EvidenceRefusal> {
        let subject = Subject::Runtime(runtime.clone());
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let configuration = self.reports.configuration(&subject).unwrap();
        RuntimeOffer::observe(&self.registry, runtime, HOUR, configuration)
    }
}

fn runtime(category: ExecutionCategory, instance: Digest) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance,
    }
}

#[test]
fn a_dedicated_vm_run_is_confirmed_on_provider_api_evidence() {
    let mut run = Run::with(dedicated_offering(), vm_request());
    let instance = run.provision_and_enroll();
    assert_eq!(instance.kind, OfferingKind::DedicatedVm);
    let recorded = run.reports.get(&instance.instance).unwrap();
    assert_eq!(
        recorded.report(),
        &ProviderReport::instance_only(instance.clone())
    );

    let offer = run
        .offer(runtime(ExecutionCategory::VmSandbox, instance.instance))
        .unwrap();
    assert_eq!(offer.evidence().source(), SourceClass::ProviderApi);
    assert_eq!(offer.evidence().configuration(), recorded.configuration());
    let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
    assert!(admitted.is_vm_sandbox());
    assert_eq!(admitted.evidence().source(), SourceClass::ProviderApi);
    assert_eq!(run.adapter.state(), &AdapterState::RuntimeConfirmed);
    assert_eq!(run.adapter.runtime(), Some(&admitted));

    // V12's port reports nothing about hardening or accelerators: not tested, not guessed.
    let resource = Subject::Provider(ProviderSubject {
        provider: instance.provider,
        resource: instance.instance,
    });
    assert_eq!(
        run.registry
            .refresh(Capability::ProviderContainer, &resource)
            .unwrap()
            .result(),
        &ObservationResult::Unsupported {
            reason: UnsupportedReason::NotAProviderContainer
        }
    );
}

#[test]
fn an_explicit_provider_container_run_is_confirmed_labelled_never_as_a_vm() {
    let mut run = Run::with(container_offering(), explicit_container());
    let instance = run.provision_and_enroll();
    assert_eq!(instance.kind, OfferingKind::ProviderContainer);

    // The pod offered as a VM sandbox has no evidence for that category (VM-D5).
    let refusal = run
        .offer(runtime(ExecutionCategory::VmSandbox, instance.instance))
        .unwrap_err();
    assert_eq!(
        refusal,
        EvidenceRefusal::Unsupported {
            capability: Capability::RuntimeCategory,
            reason: UnsupportedReason::DifferentCategory,
        }
    );
    assert_eq!(run.adapter.state(), &AdapterState::IdentityEnrolled);

    let offer = run
        .offer(runtime(
            ExecutionCategory::ProviderContainerRuntime,
            instance.instance,
        ))
        .unwrap();
    assert_eq!(offer.evidence().source(), SourceClass::ProviderApi);
    assert_eq!(
        offer.evidence().detail(),
        &SupportDetail::RuntimeCategory {
            category: ExecutionCategory::ProviderContainerRuntime
        }
    );
    let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
    assert!(!admitted.is_vm_sandbox());
    assert_eq!(
        admitted.label(),
        "remote runtime (provider container), not a sandbox"
    );
    assert_eq!(admitted.decision(), Some("VM-D5"));
    assert_eq!(run.adapter.state(), &AdapterState::RuntimeConfirmed);
}

#[test]
fn the_provider_api_alone_never_confirms_a_per_sandbox_vm() {
    let mut run = Run::with(metal_offering(), vm_request());
    let instance = run.provision_and_enroll();
    assert_eq!(instance.kind, OfferingKind::BareMetal);

    // The bare host the provider reports is a host shell, not the sandbox.
    let refusal = run
        .offer(runtime(ExecutionCategory::VmSandbox, instance.instance))
        .unwrap_err();
    assert_eq!(
        refusal,
        EvidenceRefusal::Unsupported {
            capability: Capability::RuntimeCategory,
            reason: UnsupportedReason::DifferentCategory,
        }
    );
    // The per-sandbox VM is not a provider instance: no provider adapter observes it, and
    // V12 needs management evidence of the VM workload instead.
    let sandbox = Subject::Runtime(runtime(ExecutionCategory::VmSandbox, *vm_id(1).digest()));
    assert_eq!(
        run.registry
            .refresh(Capability::RuntimeCategory, &sandbox)
            .unwrap_err(),
        RegistryError::NoAdapter {
            capability: Capability::RuntimeCategory
        }
    );
    assert_eq!(run.reports.configuration(&sandbox), None);
    assert_eq!(run.adapter.state(), &AdapterState::IdentityEnrolled);
    assert!(run.adapter.runtime().is_none());
}

/// A provider whose calls take `delay` on the host clock.
struct SlowProvider {
    inner: FakeProvider,
    clock: Arc<ManualClock>,
    delay: Duration,
}

impl RemoteProviderPort for SlowProvider {
    fn provision(&mut self, request: &ProvisionRequest) -> ProvisionOutcome {
        self.clock.advance(self.delay);
        self.inner.provision(request)
    }

    fn terminate(&mut self, instance: &ProviderInstance) -> TerminationOutcome {
        self.clock.advance(self.delay);
        self.inner.terminate(instance)
    }

    fn find(&mut self, request: &ProvisionRequest) -> LookupOutcome {
        self.clock.advance(self.delay);
        self.inner.find(request)
    }

    fn final_bill(&mut self, attempt: &AttemptId) -> BillingReport {
        self.inner.final_bill(attempt)
    }
}

fn request(offering: &RemoteOffering) -> ProvisionRequest {
    ProvisionRequest {
        attempt: attempt(1),
        provider: offering.provider,
        region: offering.region.clone(),
        offering: offering.offering.clone(),
        kind: offering.kind,
        account: account(),
    }
}

#[test]
fn the_reporting_port_times_each_report_from_the_calls_start() {
    let run = Run::with(dedicated_offering(), vm_request());
    let mut registry = run.registry;
    let reports = run.reports;
    let clock = Arc::clone(&run.world.clock);
    let mut slow = SlowProvider {
        inner: FakeProvider::default(),
        clock: Arc::clone(&clock),
        delay: 50 * SECOND,
    };
    let started = reports.now();
    let mut port = ReportingPort::new(&mut slow, &*reports);
    let ProvisionOutcome::Created { instance } = port.provision(&request(&dedicated_offering()))
    else {
        panic!("the fake provider creates the instance");
    };
    assert_eq!(reports.now(), started.saturating_add(50 * SECOND));
    assert_eq!(
        reports.get(&instance.instance).unwrap().started_at(),
        started
    );

    let subject = Subject::Runtime(runtime(ExecutionCategory::VmSandbox, instance.instance));
    let envelope = registry
        .refresh(Capability::RuntimeCategory, &subject)
        .unwrap();
    assert_eq!(
        envelope.fresh_for(),
        PROVIDER_CATEGORY_FRESH_FOR - 50 * SECOND
    );
    clock.advance(11 * SECOND);
    let requirement = reports
        .requirement(Capability::RuntimeCategory, &subject)
        .unwrap();
    assert!(matches!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::Stale {
            staleness: Staleness::TooOld { .. },
            ..
        })
    ));
}

#[test]
fn the_reporting_port_records_only_what_the_provider_reported() {
    let run = Run::with(dedicated_offering(), vm_request());
    let mut registry = run.registry;
    let reports = run.reports;
    let offering = dedicated_offering();
    let created = FakeProvider::instance_for(&request(&offering));
    let mut provider = FakeProvider::default();
    provider.provisions.extend([
        ProvisionOutcome::NotCreated {
            error: ProviderError::CapacityUnavailable,
        },
        ProvisionOutcome::Unknown {
            cause: UncertainCause::Timeout,
        },
    ]);
    provider.lookups.extend([
        LookupOutcome::Unknown {
            cause: UncertainCause::ConnectionLost,
        },
        LookupOutcome::ConfirmedAbsent,
        LookupOutcome::Found {
            instance: created.clone(),
        },
    ]);
    provider.terminations.extend([
        TerminationOutcome::Failed {
            error: ProviderError::ProviderUnavailable,
        },
        TerminationOutcome::Unknown {
            cause: UncertainCause::Timeout,
        },
        TerminationOutcome::Confirmed,
    ]);
    let mut port = ReportingPort::new(&mut provider, &*reports);
    let provision = request(&offering);
    port.provision(&provision);
    port.provision(&provision);
    port.find(&provision);
    port.find(&provision);
    assert!(port.log().is_empty());
    assert!(reports.all().is_empty());

    // Found by its idempotency key: recorded as the port reports it.
    port.find(&provision);
    let configuration = reports.get(&created.instance).unwrap().configuration();
    assert_eq!(
        port.log(),
        &[PortRecord::Recorded {
            instance: created.instance,
            outcome: RecordOutcome::New { configuration },
        }]
    );
    // Created again later (the fake's default): the same report, refreshed.
    port.provision(&provision);
    assert_eq!(
        port.log()[1],
        PortRecord::Recorded {
            instance: created.instance,
            outcome: RecordOutcome::Refreshed { configuration },
        }
    );
    let subject = Subject::Runtime(runtime(ExecutionCategory::VmSandbox, created.instance));
    registry
        .refresh(Capability::RuntimeCategory, &subject)
        .unwrap();

    // Only a confirmed termination drops the report.
    port.terminate(&created);
    port.terminate(&created);
    assert!(reports.get(&created.instance).is_some());
    port.terminate(&created);
    assert_eq!(
        port.log()[2],
        PortRecord::Forgotten {
            instance: created.instance,
            configuration,
        }
    );
    assert_eq!(port.log().len(), 3);
    assert!(matches!(
        port.final_bill(&attempt(1)),
        BillingReport::Final { .. }
    ));
    assert_eq!(registry.invalidate_configuration(configuration), 1);
    assert_eq!(
        registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap_err(),
        RegistryError::NoAdapter {
            capability: Capability::RuntimeCategory
        }
    );
    // A provider already confirming it gone forgets nothing more.
    let mut gone = FakeProvider::default();
    gone.terminations.push_back(TerminationOutcome::AlreadyGone);
    let mut port = ReportingPort::new(&mut gone, &*reports);
    port.terminate(&created);
    assert!(port.log().is_empty());

    // Another provider reporting the same instance digest is refused, not recorded.
    let mut again = FakeProvider::default();
    let mut port = ReportingPort::new(&mut again, &*reports);
    port.provision(&provision);
    let mut renamed = provision.clone();
    renamed.provider = ProviderKind::Nebius;
    let mut lying = FakeProvider::default();
    let mut substituted = FakeProvider::instance_for(&provision);
    substituted.provider = renamed.provider;
    lying.lookups.push_back(LookupOutcome::Found {
        instance: substituted,
    });
    let mut port = ReportingPort::new(&mut lying, &*reports);
    port.find(&renamed);
    assert!(matches!(
        port.log(),
        [PortRecord::Refused {
            error: ReportError::ProviderChanged { .. },
            ..
        }]
    ));
}
