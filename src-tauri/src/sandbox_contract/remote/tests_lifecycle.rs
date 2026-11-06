//! The remote-VM adapter on fakes and a real CORE-04 coordinator: VM-W39 acceptance
//! ("provider/region failures, loss of control connection, stale identities, expiry and
//! uncertain billing handled; no silent provider or isolation change"), VM-W41
//! acceptance ("host-key changes rejected; remote reconnect cannot revive expired
//! authority; capability evidence distinguishes host shell from VM workload"), VM-P40,
//! VM-P42's remote case, VM-CP-32's lease half and VM-CP-33's remote case.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use super::adapter::{
    AdapterConfig, AdapterRefusal, AdapterState, AuthorityEnd, BillingOutcome, BillingReport,
    CleanupFailure, CleanupStatus, ConfidentialLaunch, Delegation, FrameOutcome, LookupOutcome,
    ProviderError, ProviderInstance, ProvisionOutcome, RemoteVmAdapter, Substitution,
    TerminationOutcome, UncertainCause,
};
use super::argv::{OptionTerminator, ProgramPath, RemoteCommand, RemoteInvocation};
use super::attestation::AttestationBook;
use super::control::{
    ControlBody, ControlFrame, ControlSession, GrantRef, LeaseGrant, RemoteIdentity, SealedFrame,
};
use super::fakes::{
    account, at, attempt, config, container_offering, control_key, dedicated_offering,
    explicit_container, host_key, identity, metal_offering, mgmt_key, parent, pod_execution,
    policy, provision_effect, resign, session_id, session_key, target, valid_report, vm_id,
    vm_request, workload, FakeProvider, FakeVendor, GrantAll, HostWorld, ProviderCall,
    RewindableClock, SeededNonces, SeededRng, HOUR, MINUTE, SECOND,
};
use super::lease::{remote_authority_bound, CoordinatorDelegation, HostAuthority};
use super::offering::{OfferingKind, RegionName, RemoteOffering, RemoteRequest};
use super::rejection::RejectionObserver;
use super::ssh::{
    EnrollmentEvidence, EnrollmentGeneration, EnrollmentPolicy, ExecutionContext, HostKeyRefusal,
    KnownHosts, ManagementAction, ManagementIdentity, RemoteAccountName, RemoteCapability,
    RemoteCapabilityEvidence, RemoteEvidenceRefusal, RemoteShellKind,
};
use crate::foundation::coordination::{
    CancelCause, CoordinationError, LeaseKind, LeaseRefusal, RenewalLimit, RevocationMilestone,
};
use crate::foundation::evidence::{CategoryRefusal, ProviderKind};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ExecutionCategory, LeaseId, ManualClock, MonotonicTime,
    OperationId,
};
use crate::sandbox_contract::effects::{
    AccountRef, RemoteEnforcementPoint, RemoteLease, RemoteRefusal,
};
use crate::sandbox_contract::files::{
    LifetimeRefusal, RemoteExpiry, RemoteObservation, SkewRefusal, WallClockGuard,
};
use crate::sandbox_contract::policy::SecurityPredicate;
use crate::sandbox_contract::provider::{
    SharedSpendLedger, SpendAccount, SpendLedger, SpendRefusal,
};

type HostDelegation = CoordinatorDelegation<Arc<ManualClock>, GrantAll>;

const BUDGET: u64 = 100_000_000;
/// The offering's 2,000,000 µ/h over the 2 h lifetime plus the 600 s termination
/// allowance: 7,800 s × 2,000,000 / 3,600 = 4,333,333.3, rounded up.
const RESERVED: u64 = 4_333_334;
const COST: u64 = 1_500_000;

struct Run {
    world: HostWorld<Arc<ManualClock>>,
    authority: HostDelegation,
    provider: FakeProvider,
    ledger: SharedSpendLedger,
    known: KnownHosts,
    adapter: RemoteVmAdapter<Arc<ManualClock>>,
    session_number: u8,
    remote_sequence: u64,
}

impl Run {
    fn with(offering: RemoteOffering, request: RemoteRequest, config: AdapterConfig) -> Self {
        let world = HostWorld::new(4 * HOUR);
        let authority = world.delegation();
        let ledger = SharedSpendLedger::new(SpendLedger::new());
        ledger
            .with(|book| book.open_account(account(), BUDGET))
            .unwrap();
        let execution = if offering.kind == OfferingKind::ProviderContainer {
            pod_execution()
        } else {
            parent()
        };
        let adapter = match RemoteVmAdapter::plan(
            Arc::clone(&world.clock),
            attempt(1),
            execution,
            &request,
            &[offering],
            config,
        ) {
            Ok(adapter) => adapter,
            Err(refusal) => panic!("{refusal:?}"),
        };
        Self {
            world,
            authority,
            provider: FakeProvider {
                default_cost_microunits: COST,
                ..FakeProvider::default()
            },
            ledger,
            known: KnownHosts::new(),
            adapter,
            session_number: 1,
            remote_sequence: 0,
        }
    }

    fn dedicated() -> Self {
        Self::with(dedicated_offering(), vm_request(), config())
    }

    fn reserve(&mut self) {
        self.adapter
            .reserve_spend(&self.ledger, &provision_effect(account(), 10_000_000, 1))
            .unwrap();
    }

    fn provision(&mut self) -> ProviderInstance {
        self.reserve();
        self.adapter
            .provision(&mut self.provider, &self.ledger)
            .unwrap()
    }

    fn enroll(&mut self) -> RemoteIdentity {
        self.adapter
            .enroll(
                &mut self.known,
                &host_key(1),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(1).fingerprint(),
                },
            )
            .unwrap()
    }

    fn confirm(&mut self) {
        let instance = self.adapter.instance().unwrap().instance;
        let offer = self
            .world
            .remote_offer(instance, ExecutionCategory::VmSandbox);
        self.adapter.confirm_runtime(&offer, None).unwrap();
    }

    fn session(&self, number: u8) -> ControlSession {
        ControlSession::open(
            self.adapter.identity().unwrap().clone(),
            session_id(number),
            session_key(number),
            control_key(number),
            self.world.now(),
        )
    }

    fn connect(&mut self, number: u8) -> Result<(), AdapterRefusal> {
        let session = self.session(number);
        let result = self
            .adapter
            .connect(&self.known, &host_key(1), session, &mut self.authority);
        if result.is_ok() {
            self.session_number = number;
            self.remote_sequence = 0;
        }
        result
    }

    fn launch(&mut self) -> SealedFrame {
        self.adapter
            .launch(
                &mut self.authority,
                OperationId::new("op-remote").unwrap(),
                None,
            )
            .unwrap()
    }

    fn running() -> Self {
        let mut run = Self::dedicated();
        run.provision();
        run.enroll();
        run.confirm();
        run.connect(1).unwrap();
        run.launch();
        run
    }

    fn remote(&mut self, body: ControlBody) -> SealedFrame {
        let frame = ControlFrame {
            session: session_id(self.session_number),
            identity: self.adapter.identity().unwrap().digest(),
            sequence: self.remote_sequence,
            body,
        }
        .seal(&control_key(self.session_number));
        self.remote_sequence += 1;
        frame
    }

    fn heartbeat(&mut self) -> Result<FrameOutcome, AdapterRefusal> {
        let frame = self.remote(ControlBody::Heartbeat);
        self.adapter.handle_frame(&frame, &mut self.authority)
    }

    fn renewal_request(&mut self) -> Result<FrameOutcome, AdapterRefusal> {
        let delegation = self.adapter.delegation().unwrap().clone();
        let frame = self.remote(ControlBody::RenewalRequest {
            authority: delegation.grant_ref(),
            clock: delegation.clock(),
        });
        self.adapter.handle_frame(&frame, &mut self.authority)
    }

    fn settle(&mut self) -> Result<BillingOutcome, AdapterRefusal> {
        self.adapter
            .settle_billing(&mut self.provider, &self.ledger, &mut self.authority)
    }

    fn spend(&self) -> SpendAccount {
        *self.ledger.snapshot().unwrap().account(&account()).unwrap()
    }

    fn advance(&self, by: Duration) {
        self.world.advance(by);
    }

    fn coordinator_honours(&self) -> bool {
        let lease = self.adapter.lease().unwrap().id();
        self.world
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check_lease(lease)
            .is_ok()
    }
}

#[test]
fn attached_ssh_hosts_never_reach_provider_or_billing_ports_and_only_close_exact_workloads() {
    let mut offering = metal_offering();
    offering.provider = ProviderKind::ExistingSsh;
    offering.kind = OfferingKind::PerSandboxVmHost;
    offering.price = None;
    let mut run = Run::with(offering, vm_request(), config());
    let budget = run.spend();
    assert_eq!(
        run.adapter.max_cost_microunits(),
        Err(AdapterRefusal::ExternallyManagedHost)
    );
    assert!(run
        .adapter
        .reserve_spend(&run.ledger, &provision_effect(account(), 10_000_000, 1))
        .is_err());
    assert_eq!(
        run.adapter.provision(&mut run.provider, &run.ledger),
        Err(AdapterRefusal::ExternallyManagedHost)
    );
    let host = FakeProvider::instance_for(&run.adapter.provision_request());
    let mut wrong = host.clone();
    wrong.provider = ProviderKind::RunPod;
    assert!(run.adapter.attach_existing(wrong).is_err());
    assert!(run.adapter.instance().is_none());
    run.adapter.attach_existing(host).unwrap();
    let identity = run
        .adapter
        .enroll(
            &mut run.known,
            &host_key(1),
            EnrollmentEvidence::OwnerPinned {
                expected: host_key(1).fingerprint(),
            },
        )
        .unwrap();
    let evidence = RemoteCapabilityEvidence::observed(
        run.known.enrollment(&identity.host).unwrap(),
        ExecutionContext::VmWorkload {
            host: identity.host,
            vm: vm_id(1),
        },
        RemoteCapability::VmRunning {
            hardware_accelerated: true,
        },
        run.world.now(),
    );
    let vm = *vm_id(1).digest();
    let offer = run.world.remote_offer(vm, ExecutionCategory::VmSandbox);
    run.adapter
        .confirm_runtime(&offer, Some(&evidence))
        .unwrap();
    run.connect(1).unwrap();
    run.launch();
    assert!(run.coordinator_honours());
    assert!(run
        .adapter
        .confirm_attached_workload_stopped(&identity, vm)
        .is_err());
    run.adapter.begin_termination(&mut run.authority).unwrap();
    assert!(!run.coordinator_honours());
    assert_eq!(
        run.adapter.terminate_step(&mut run.provider),
        Err(AdapterRefusal::ExternallyManagedHost)
    );
    assert_eq!(run.settle(), Err(AdapterRefusal::ExternallyManagedHost));
    let mut wrong = identity.clone();
    wrong.enrollment = EnrollmentGeneration::new(99);
    assert!(run
        .adapter
        .confirm_attached_workload_stopped(&wrong, vm)
        .is_err());
    assert!(run
        .adapter
        .confirm_attached_workload_stopped(&identity, *vm_id(2).digest())
        .is_err());
    run.adapter
        .confirm_attached_workload_stopped(&identity, vm)
        .unwrap();
    assert_eq!(
        run.adapter.state(),
        &AdapterState::Closed {
            billing: BillingOutcome::ExternallyManaged
        }
    );
    assert!(!run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
    assert_eq!(run.spend(), budget);
    assert!(run.provider.calls.is_empty());
}

fn kinds(run: &Run) -> Vec<&'static str> {
    run.adapter
        .history()
        .iter()
        .map(|entry| match entry.state {
            AdapterState::Planned => "planned",
            AdapterState::SpendReserved => "spend_reserved",
            AdapterState::Provisioned => "provisioned",
            AdapterState::IdentityEnrolled => "identity_enrolled",
            AdapterState::RuntimeConfirmed => "runtime_confirmed",
            AdapterState::Running => "running",
            AdapterState::AuthorityEnded { .. } => "authority_ended",
            AdapterState::Terminating => "terminating",
            AdapterState::Terminated => "terminated",
            AdapterState::Closed { .. } => "closed",
            AdapterState::Failed { .. } => "failed",
            AdapterState::Cancelled => "cancelled",
        })
        .collect()
}

fn lease_refusal(refusal: &AdapterRefusal) -> Option<&LeaseRefusal> {
    match refusal {
        AdapterRefusal::Authority {
            refusal: LifetimeRefusal::Lease { refusal },
        } => Some(refusal),
        _ => None,
    }
}

#[test]
fn a_remote_vm_runs_end_to_end_and_every_acknowledgment_is_recorded() {
    let mut run = Run::dedicated();
    assert_eq!(run.adapter.max_cost_microunits(), Ok(RESERVED));
    run.reserve();
    assert_eq!(run.spend().reserved_microunits, RESERVED);
    let instance = run
        .adapter
        .provision(&mut run.provider, &run.ledger)
        .unwrap();
    assert_eq!(instance.region.as_str(), "us-east-1");
    assert_eq!(instance.kind, OfferingKind::DedicatedVm);
    run.enroll();
    run.confirm();
    assert!(run.adapter.runtime().unwrap().is_vm_sandbox());
    run.connect(1).unwrap();
    let grant = run.launch();
    let ControlBody::Grant { grant } = grant.frame.body else {
        panic!("{grant:?}");
    };
    assert_eq!(grant.ttl_nanos, 600_000_000_000);
    let lease = run.adapter.lease().unwrap().clone();
    assert_eq!(lease.kind(), LeaseKind::Service);
    assert_eq!(lease.parent(), &parent());
    assert_eq!(grant.authority, GrantRef::Lease { lease: lease.id() });

    run.advance(5 * MINUTE);
    assert_eq!(run.heartbeat(), Ok(FrameOutcome::Heard));
    run.adapter.renew(&mut run.authority).unwrap();
    assert_eq!(
        run.adapter.lease().unwrap().expires_at(),
        run.world.now().saturating_add(10 * MINUTE)
    );

    run.adapter.begin_termination(&mut run.authority).unwrap();
    assert!(!run.coordinator_honours());
    assert_eq!(
        run.adapter.terminate_step(&mut run.provider),
        Ok(CleanupStatus::Confirmed { attempts: 1 })
    );
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Settled {
            charged_microunits: COST
        })
    );
    let spend = run.spend();
    assert_eq!(spend.spent_microunits, COST);
    assert_eq!(spend.reserved_microunits, 0);
    assert_eq!(spend.unknown_microunits, 0);
    assert_eq!(run.ledger.snapshot().unwrap().invariant_violation(), None);
    // Each milestone separately; the remote's sockets are not observed, so they are not
    // claimed closed.
    let acks: Vec<RevocationMilestone> = run.adapter.acknowledgments().keys().copied().collect();
    assert_eq!(
        acks,
        vec![
            RevocationMilestone::NewAuthorizationsDenied,
            RevocationMilestone::VmStopped,
            RevocationMilestone::ProviderStoppedBilling,
        ]
    );
    assert_eq!(
        kinds(&run),
        vec![
            "planned",
            "spend_reserved",
            "provisioned",
            "identity_enrolled",
            "runtime_confirmed",
            "running",
            "authority_ended",
            "terminating",
            "terminated",
            "closed"
        ]
    );
}

#[test]
fn spend_needs_a_covering_ceiling_the_right_account_and_room_in_the_budget() {
    let mut run = Run::dedicated();
    assert_eq!(
        run.adapter
            .reserve_spend(&run.ledger, &provision_effect(account(), RESERVED - 1, 1)),
        Err(AdapterRefusal::CostCeilingTooLow {
            required_microunits: RESERVED,
            ceiling_microunits: RESERVED - 1
        })
    );
    let other = AccountRef::new(digest("yougori/test/account/v1", &[b"someone-else"]));
    assert_eq!(
        run.adapter
            .reserve_spend(&run.ledger, &provision_effect(other, 10_000_000, 1)),
        Err(AdapterRefusal::WrongAccount {
            expected: account(),
            described: other
        })
    );
    assert_eq!(run.adapter.state(), &AdapterState::Planned);

    // Two runs on one account cannot both spend the same remaining budget.
    let ledger = SharedSpendLedger::new(SpendLedger::new());
    ledger
        .with(|book| book.open_account(account(), 6_000_000))
        .unwrap();
    let plan = |number: u8| {
        RemoteVmAdapter::plan(
            Arc::clone(&run.world.clock),
            attempt(number),
            parent(),
            &vm_request(),
            &[dedicated_offering()],
            config(),
        )
        .ok()
        .unwrap()
    };
    let mut first = plan(1);
    let mut second = plan(2);
    first
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 1))
        .unwrap();
    assert_eq!(
        second.reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 2)),
        Err(AdapterRefusal::Spend {
            refusal: SpendRefusal::Exhausted {
                requested_microunits: RESERVED,
                available_microunits: 6_000_000 - RESERVED
            }
        })
    );
}

#[test]
fn a_provider_or_region_failure_fails_the_attempt_and_changes_nothing_silently() {
    for error in [
        ProviderError::RegionUnavailable,
        ProviderError::CapacityUnavailable,
        ProviderError::QuotaExceeded,
        ProviderError::Unauthorized,
        ProviderError::ProviderUnavailable,
    ] {
        let mut run = Run::dedicated();
        run.provider
            .provisions
            .push_back(ProvisionOutcome::NotCreated { error });
        run.reserve();
        assert_eq!(
            run.adapter.provision(&mut run.provider, &run.ledger),
            Err(AdapterRefusal::ProvisionFailed { error })
        );
        assert_eq!(run.adapter.state(), &AdapterState::Failed { error });
        assert!(!run.adapter.needs_cleanup());
        let spend = run.spend();
        assert_eq!(
            (
                spend.reserved_microunits,
                spend.spent_microunits,
                spend.unknown_microunits
            ),
            (0, 0, 0)
        );
        // No retry in another region or with another provider: the attempt stays failed.
        assert!(matches!(
            run.adapter.provision(&mut run.provider, &run.ledger),
            Err(AdapterRefusal::InvalidStep { .. })
        ));
        assert!(matches!(
            run.adapter.begin_termination(&mut run.authority),
            Err(AdapterRefusal::InvalidStep { .. })
        ));
        assert_eq!(run.provider.provision_calls(), 1);
        let ProviderCall::Provision(request) = &run.provider.calls[0] else {
            panic!("{:?}", run.provider.calls);
        };
        assert_eq!(request.region.as_str(), "us-east-1");
        assert_eq!(request.provider, ProviderKind::Crusoe);
        assert_eq!(request.kind, OfferingKind::DedicatedVm);
        assert_eq!(
            run.settle(),
            Ok(BillingOutcome::Settled {
                charged_microunits: 0
            })
        );
        assert_eq!(run.adapter.state(), &AdapterState::Failed { error });
    }
}

#[test]
fn uncertain_provisioning_counts_as_spent_and_cleanup_retries_until_confirmed() {
    let mut run = Run::dedicated();
    run.provider
        .provisions
        .push_back(ProvisionOutcome::Unknown {
            cause: UncertainCause::Timeout,
        });
    run.reserve();
    assert_eq!(
        run.adapter.provision(&mut run.provider, &run.ledger),
        Err(AdapterRefusal::ProvisionUncertain {
            cause: UncertainCause::Timeout
        })
    );
    assert_eq!(run.adapter.state(), &AdapterState::Terminating);
    assert!(run.adapter.needs_cleanup());
    assert_eq!(run.spend().unknown_microunits, RESERVED);
    assert_eq!(run.spend().available_microunits(), BUDGET - RESERVED);

    let created = FakeProvider::instance_for(&run.adapter.provision_request());
    run.provider.lookups.push_back(LookupOutcome::Unknown {
        cause: UncertainCause::ConnectionLost,
    });
    run.provider.lookups.push_back(LookupOutcome::Found {
        instance: created.clone(),
    });
    run.provider
        .terminations
        .push_back(TerminationOutcome::Failed {
            error: ProviderError::ProviderUnavailable,
        });
    run.provider
        .terminations
        .push_back(TerminationOutcome::Unknown {
            cause: UncertainCause::Timeout,
        });
    let expected = [
        CleanupStatus::Retrying {
            attempts: 1,
            needs_operator: false,
            last: CleanupFailure::LookupUnknown {
                cause: UncertainCause::ConnectionLost,
            },
        },
        CleanupStatus::Retrying {
            attempts: 2,
            needs_operator: false,
            last: CleanupFailure::Termination {
                error: ProviderError::ProviderUnavailable,
            },
        },
        CleanupStatus::Retrying {
            attempts: 3,
            needs_operator: true,
            last: CleanupFailure::TerminationUnknown {
                cause: UncertainCause::Timeout,
            },
        },
    ];
    for status in expected {
        assert_eq!(run.adapter.terminate_step(&mut run.provider), Ok(status));
        assert_eq!(run.adapter.state(), &AdapterState::Terminating);
        assert_eq!(run.spend().unknown_microunits, RESERVED);
        assert!(!run
            .adapter
            .acknowledgments()
            .contains_key(&RevocationMilestone::VmStopped));
        // Billing cannot be settled before termination is confirmed.
        assert!(matches!(
            run.settle(),
            Err(AdapterRefusal::InvalidStep { .. })
        ));
    }
    assert_eq!(
        run.adapter.terminate_step(&mut run.provider),
        Ok(CleanupStatus::Confirmed { attempts: 4 })
    );
    assert_eq!(run.adapter.instance(), Some(&created));
    run.provider.bills.push_back(BillingReport::Final {
        cost_microunits: 250_000,
    });
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Settled {
            charged_microunits: 250_000
        })
    );
    let spend = run.spend();
    assert_eq!(
        (spend.unknown_microunits, spend.spent_microunits),
        (0, 250_000)
    );
    assert_eq!(run.provider.terminate_calls(), 3);
    assert_eq!(run.ledger.snapshot().unwrap().invariant_violation(), None);
}

#[test]
fn an_uncertain_provisioning_the_provider_shows_never_happened_is_confirmed_absent() {
    let mut run = Run::dedicated();
    run.provider
        .provisions
        .push_back(ProvisionOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse,
        });
    run.reserve();
    assert!(run
        .adapter
        .provision(&mut run.provider, &run.ledger)
        .is_err());
    assert_eq!(
        run.adapter.terminate_step(&mut run.provider),
        Ok(CleanupStatus::Confirmed { attempts: 1 })
    );
    assert_eq!(run.provider.terminate_calls(), 0);
    run.provider
        .bills
        .push_back(BillingReport::Final { cost_microunits: 0 });
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Settled {
            charged_microunits: 0
        })
    );
    assert_eq!(run.spend().unknown_microunits, 0);
}

#[test]
fn uncertain_billing_stays_spent_until_the_provider_reports_a_final_bill() {
    let mut run = Run::running();
    run.adapter.begin_termination(&mut run.authority).unwrap();
    run.adapter.terminate_step(&mut run.provider).unwrap();
    run.provider.bills.push_back(BillingReport::Unavailable);
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Uncertain {
            held_microunits: RESERVED
        })
    );
    assert_eq!(
        run.adapter.state(),
        &AdapterState::Closed {
            billing: BillingOutcome::Uncertain {
                held_microunits: RESERVED
            }
        }
    );
    assert_eq!(run.spend().unknown_microunits, RESERVED);
    assert_eq!(run.spend().spent_microunits, 0);
    assert!(!run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Settled {
            charged_microunits: COST
        })
    );
    assert_eq!(run.spend().unknown_microunits, 0);
    assert_eq!(run.spend().spent_microunits, COST);
    assert!(run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
}

#[test]
fn a_substituted_instance_is_refused_and_terminated() {
    type Change = fn(&mut ProviderInstance);
    let changes: [(Change, &str); 4] = [
        (
            |instance| instance.region = RegionName::new("eu-west-1").unwrap(),
            "region",
        ),
        (
            |instance| instance.provider = ProviderKind::RunPod,
            "provider",
        ),
        (
            |instance| instance.kind = OfferingKind::ProviderContainer,
            "kind",
        ),
        (
            |instance| instance.offering = super::offering::OfferingName::new("cheaper").unwrap(),
            "offering",
        ),
    ];
    for (change, field) in changes {
        let mut run = Run::dedicated();
        let mut delivered = FakeProvider::instance_for(&run.adapter.provision_request());
        change(&mut delivered);
        run.provider
            .provisions
            .push_back(ProvisionOutcome::Created {
                instance: delivered.clone(),
            });
        run.reserve();
        let refusal = run
            .adapter
            .provision(&mut run.provider, &run.ledger)
            .unwrap_err();
        let matched = matches!(
            (&refusal, field),
            (
                AdapterRefusal::Substituted {
                    substitution: Substitution::Region { .. }
                },
                "region"
            ) | (
                AdapterRefusal::Substituted {
                    substitution: Substitution::Provider { .. }
                },
                "provider"
            ) | (
                AdapterRefusal::Substituted {
                    substitution: Substitution::Kind { .. }
                },
                "kind"
            ) | (
                AdapterRefusal::Substituted {
                    substitution: Substitution::Offering { .. }
                },
                "offering"
            )
        );
        assert!(matched, "{field}: {refusal:?}");
        assert_eq!(run.adapter.state(), &AdapterState::Terminating);
        assert_eq!(
            run.adapter.terminate_step(&mut run.provider),
            Ok(CleanupStatus::Confirmed { attempts: 1 })
        );
        assert_eq!(
            run.provider.calls.last(),
            Some(&ProviderCall::Terminate(delivered))
        );
        assert!(!kinds(&run).contains(&"running"));
    }
}

#[test]
fn provider_container_evidence_for_a_vm_offering_is_refused_and_terminated() {
    let mut run = Run::dedicated();
    let instance = run.provision();
    run.enroll();
    let offer = run.world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    let refusal = run.adapter.confirm_runtime(&offer, None).unwrap_err();
    assert_eq!(
        refusal,
        AdapterRefusal::Category {
            refusal: CategoryRefusal::VmSandboxRequired {
                offered: ExecutionCategory::ProviderContainerRuntime
            }
        }
    );
    assert!(refusal
        .to_string()
        .contains("remote runtime (provider container), not a sandbox"));
    assert_eq!(run.adapter.state(), &AdapterState::Terminating);
    assert!(run.adapter.runtime().is_none());
}

#[test]
fn an_explicit_provider_container_runs_labelled_and_never_as_a_vm() {
    let mut run = Run::with(container_offering(), explicit_container(), config());
    assert_eq!(
        run.adapter.selection().label(),
        "remote runtime (provider container), not a sandbox"
    );
    let instance = run.provision();
    run.enroll();
    let offer = run.world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
    assert!(!admitted.is_vm_sandbox());
    assert_eq!(
        admitted.label(),
        "remote runtime (provider container), not a sandbox"
    );
    assert_eq!(admitted.decision(), Some("VM-D5"));

    // Evidence of a VM for a container offering is an isolation change too, and refused.
    let mut run = Run::with(container_offering(), explicit_container(), config());
    let instance = run.provision();
    run.enroll();
    let offer = run
        .world
        .remote_offer(instance.instance, ExecutionCategory::VmSandbox);
    assert!(matches!(
        run.adapter.confirm_runtime(&offer, None),
        Err(AdapterRefusal::Category {
            refusal: CategoryRefusal::NotExplicitlyAllowed { .. }
        })
    ));
    assert_eq!(run.adapter.state(), &AdapterState::Terminating);
}

#[test]
fn a_per_sandbox_vm_is_confirmed_only_from_vm_workload_evidence_never_the_host_shell() {
    let mut run = Run::with(metal_offering(), vm_request(), config());
    let instance = run.provision();
    let identity = run.enroll();
    let enrollment = run.known.enrollment(&identity.host).unwrap().clone();
    let now = run.world.now();
    let vm_offer = run
        .world
        .remote_offer(*vm_id(1).digest(), ExecutionCategory::VmSandbox);
    assert_eq!(
        run.adapter.confirm_runtime(&vm_offer, None),
        Err(AdapterRefusal::PerSandboxVmEvidenceMissing)
    );
    let host_shell = RemoteCapabilityEvidence::observed(
        &enrollment,
        ExecutionContext::RemoteHostShell {
            host: identity.host,
        },
        RemoteCapability::VmRunning {
            hardware_accelerated: true,
        },
        now,
    );
    assert_eq!(
        run.adapter.confirm_runtime(&vm_offer, Some(&host_shell)),
        Err(AdapterRefusal::ManagementEvidence {
            refusal: RemoteEvidenceRefusal::HostShellIsNotTheSandbox {
                predicate: SecurityPredicate::VmSandbox
            }
        })
    );
    assert_eq!(run.adapter.state(), &AdapterState::IdentityEnrolled);
    let workload_evidence = RemoteCapabilityEvidence::observed(
        &enrollment,
        ExecutionContext::VmWorkload {
            host: identity.host,
            vm: vm_id(1),
        },
        RemoteCapability::VmRunning {
            hardware_accelerated: true,
        },
        now,
    );
    // CORE-01 evidence about the host instance is not evidence about the VM.
    let host_offer = run
        .world
        .remote_offer(instance.instance, ExecutionCategory::VmSandbox);
    assert!(matches!(
        run.adapter
            .confirm_runtime(&host_offer, Some(&workload_evidence)),
        Err(AdapterRefusal::InstanceMismatch { .. })
    ));
    let mut stale = workload_evidence.clone();
    stale.enrollment = EnrollmentGeneration::new(99);
    assert_eq!(
        run.adapter.confirm_runtime(&vm_offer, Some(&stale)),
        Err(AdapterRefusal::EvidenceForAnotherIdentity)
    );
    run.adapter
        .confirm_runtime(&vm_offer, Some(&workload_evidence))
        .unwrap();
    assert_eq!(run.adapter.state(), &AdapterState::RuntimeConfirmed);
}

#[test]
fn an_emulated_per_sandbox_vm_is_refused_and_nothing_else_starts() {
    let mut run = Run::with(metal_offering(), vm_request(), config());
    run.provision();
    let identity = run.enroll();
    let enrollment = run.known.enrollment(&identity.host).unwrap().clone();
    let emulated = RemoteCapabilityEvidence::observed(
        &enrollment,
        ExecutionContext::VmWorkload {
            host: identity.host,
            vm: vm_id(1),
        },
        RemoteCapability::VmRunning {
            hardware_accelerated: false,
        },
        run.world.now(),
    );
    let vm_offer = run
        .world
        .remote_offer(*vm_id(1).digest(), ExecutionCategory::VmSandbox);
    assert_eq!(
        run.adapter.confirm_runtime(&vm_offer, Some(&emulated)),
        Err(AdapterRefusal::ManagementEvidence {
            refusal: RemoteEvidenceRefusal::EmulatedVm {
                predicate: SecurityPredicate::VmSandbox
            }
        })
    );
    assert_eq!(run.adapter.state(), &AdapterState::Terminating);
    run.adapter.terminate_step(&mut run.provider).unwrap();
    // The provider saw one provisioning and its termination: no container or other start.
    assert!(matches!(
        run.provider.calls.as_slice(),
        [ProviderCall::Provision(_), ProviderCall::Terminate(_)]
    ));
    assert!(!kinds(&run).contains(&"running"));
}

#[test]
fn with_no_vm_path_launch_refuses_and_nothing_is_provisioned_or_leased() {
    let world = HostWorld::new(4 * HOUR);
    let provider = FakeProvider::default();
    let leases_before = world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .leases()
        .count();
    for offerings in [
        vec![],
        vec![container_offering()],
        vec![container_offering(); 3],
    ] {
        let refusal = RemoteVmAdapter::plan(
            Arc::clone(&world.clock),
            attempt(1),
            parent(),
            &vm_request(),
            &offerings,
            config(),
        )
        .err()
        .unwrap();
        let AdapterRefusal::NoQualifyingOffering { refusal } = refusal else {
            panic!("{refusal:?}");
        };
        assert_eq!(refusal.refusals.len(), offerings.len());
    }
    assert!(provider.calls.is_empty());
    let leases_after = world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .leases()
        .count();
    assert_eq!(leases_before, leases_after);
}

#[test]
fn losing_the_control_connection_stops_renewal_and_the_lease_expires() {
    let mut run = Run::running();
    run.adapter.connection_lost();
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::ControlNotLive { .. })
    ));
    assert_eq!(run.adapter.state(), &AdapterState::Running);
    // Frames on the lost session are refused.
    let frame = run.remote(ControlBody::Heartbeat);
    assert!(matches!(
        run.adapter.handle_frame(&frame, &mut run.authority),
        Err(AdapterRefusal::Control {
            refusal: super::control::ControlRefusal::Lost
        })
    ));
    run.advance(10 * MINUTE);
    assert!(!run.coordinator_honours());
    let refusal = run.adapter.check_authority(&mut run.authority).unwrap_err();
    assert!(matches!(
        lease_refusal(&refusal),
        Some(LeaseRefusal::Expired { .. })
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LeaseRefused { .. }
        }
    ));
    assert!(run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::NewAuthorizationsDenied));
}

#[test]
fn a_lease_expired_under_partition_cannot_be_renewed_by_the_remote_side() {
    let mut run = Run::running();
    let lease = run.adapter.lease().unwrap().clone();
    // The partition: nothing reaches the host, which renews nothing.
    run.advance(10 * MINUTE);
    assert!(!run.coordinator_honours());
    // The partition heals and the remote asks for a renewal on its session.
    let refusal = run.renewal_request().unwrap_err();
    assert!(matches!(
        lease_refusal(&refusal),
        Some(LeaseRefusal::Expired { .. })
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));
    assert!(matches!(
        run.renewal_request(),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    // The host's authority refuses it directly too, for good.
    assert!(run.authority.renew(lease.id(), lease.clock()).is_err());
    assert_eq!(
        run.authority.check(lease.id()),
        Err(LifetimeRefusal::Ended { lease: lease.id() })
    );
}

#[test]
fn a_reconnect_never_revives_expired_authority() {
    let mut run = Run::running();
    run.adapter.connection_lost();
    run.advance(11 * MINUTE);
    let refusal = run.connect(2).unwrap_err();
    assert!(matches!(
        lease_refusal(&refusal),
        Some(LeaseRefusal::Expired { .. })
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));
    assert_eq!(run.adapter.control().unwrap().id(), session_id(1));
    assert!(matches!(
        run.connect(3),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
}

#[test]
fn a_reconnect_before_expiry_continues_but_never_past_the_maximum_lifetime() {
    let mut run = Run::running();
    let deadline = run.adapter.lease().unwrap().deadline();
    run.adapter.connection_lost();
    run.advance(2 * MINUTE);
    run.connect(2).unwrap();
    let mut limited = false;
    for _ in 0..20 {
        match run.renewal_request() {
            Ok(FrameOutcome::Renewed { grant }) => {
                let ControlBody::Grant { grant } = grant.frame.body else {
                    panic!("{grant:?}");
                };
                let ttl = Duration::from_nanos(grant.ttl_nanos);
                assert!(run.world.now().saturating_add(ttl) <= deadline);
                run.advance(9 * MINUTE);
            }
            Err(refusal) => {
                assert!(
                    matches!(
                        lease_refusal(&refusal),
                        Some(LeaseRefusal::RenewalLimitReached {
                            limit: RenewalLimit::MaxLifetime,
                            ..
                        })
                    ),
                    "{refusal:?} at {:?}",
                    run.world.now()
                );
                assert_eq!(run.adapter.state(), &AdapterState::Running);
                limited = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(limited);
    assert_eq!(run.adapter.lease().unwrap().expires_at(), deadline);
    run.world.clock.advance_to(deadline);
    assert!(run.adapter.check_authority(&mut run.authority).is_err());
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));
}

#[test]
fn a_stale_identity_is_refused_on_reconnect_and_in_frames() {
    let mut run = Run::running();
    let host = run.adapter.identity().unwrap().host;
    // The host is re-enrolled with another key, such as after a reinstall.
    run.known.retire(&host);
    run.known
        .enroll(
            host,
            &host_key(2),
            EnrollmentEvidence::ProviderApi {
                reported: host_key(2).fingerprint(),
            },
            EnrollmentPolicy::default(),
            run.world.now(),
        )
        .unwrap();
    let session = run.session(2);
    assert!(matches!(
        run.adapter
            .connect(&run.known, &host_key(1), session, &mut run.authority),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
    let renewed = RemoteIdentity::from_enrollment(run.known.enrollment(&host).unwrap());
    let session = ControlSession::open(
        renewed,
        session_id(3),
        session_key(3),
        control_key(3),
        run.world.now(),
    );
    assert_eq!(
        run.adapter
            .connect(&run.known, &host_key(2), session, &mut run.authority),
        Err(AdapterRefusal::StaleIdentity)
    );
    let stale = ControlFrame {
        session: session_id(1),
        identity: identity(99).digest(),
        sequence: 50,
        body: ControlBody::Heartbeat,
    }
    .seal(&control_key(1));
    assert_eq!(
        run.adapter.handle_frame(&stale, &mut run.authority),
        Err(AdapterRefusal::Control {
            refusal: super::control::ControlRefusal::StaleIdentity
        })
    );
}

#[test]
fn a_changed_host_key_is_refused_and_ends_delegated_authority_at_once() {
    let mut run = Run::running();
    let identity = run.adapter.identity().unwrap().clone();
    run.adapter.connection_lost();
    run.advance(MINUTE);
    let session = run.session(2);
    assert!(matches!(
        run.adapter
            .connect(&run.known, &host_key(9), session, &mut run.authority),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
    // Nothing waits for the lease to run out: the host released it at once.
    assert_eq!(
        run.adapter.state(),
        &AdapterState::AuthorityEnded {
            reason: AuthorityEnd::HostKeyRejected {
                host: identity.host,
                generation: identity.enrollment,
                observer: RejectionObserver::ControlConnect,
            }
        }
    );
    assert!(!run.coordinator_honours());
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    assert!(run
        .known
        .rejection(&identity.host, identity.enrollment)
        .is_some());
}

fn status(
    run: &Run,
    skew_seconds: i64,
    remaining_seconds: i64,
    local_unix: i64,
) -> (RemoteExpiry, RemoteObservation) {
    let remote_now = local_unix + skew_seconds;
    let now = run.world.now();
    (
        RemoteExpiry {
            right: run.adapter.delegation_right().unwrap(),
            issued_unix_seconds: remote_now,
            expires_unix_seconds: remote_now + remaining_seconds,
            remote_now_unix_seconds: remote_now,
        },
        RemoteObservation {
            sent_at: now,
            received_at: now,
            local_unix_seconds: local_unix,
        },
    )
}

#[test]
fn the_remote_view_of_its_lease_is_judged_under_the_explicit_skew_policy() {
    let mut run = Run::running();
    let mut guard = WallClockGuard::default();
    let lease = run.adapter.lease().unwrap().clone();
    let now = run.world.now();
    // 20 s of skew is within the 30 s allowance; the usable time is the remote's
    // remaining 600 s less the allowance, counted from when the host asked.
    let (expiry, observation) = status(&run, 20, 600, 1_800_000_000);
    let local = run
        .adapter
        .observe_remote_expiry(&expiry, &observation, &mut guard, &mut run.authority)
        .unwrap();
    assert_eq!(local.deadline, now.saturating_add(570 * SECOND));
    assert!(local.deadline <= lease.expires_at());

    let mut foreign = expiry;
    foreign.right = digest("yougori/test/right/v1", &[b"other"]);
    assert_eq!(
        run.adapter
            .observe_remote_expiry(&foreign, &observation, &mut guard, &mut run.authority),
        Err(AdapterRefusal::UnknownRight)
    );
    assert_eq!(run.adapter.state(), &AdapterState::Running);

    let (expiry, observation) = status(&run, 120, 600, 1_800_000_001);
    assert_eq!(
        run.adapter
            .observe_remote_expiry(&expiry, &observation, &mut guard, &mut run.authority),
        Err(AdapterRefusal::Skew {
            refusal: SkewRefusal::SkewExceeded {
                observed_seconds: 120,
                allowed_seconds: 30
            }
        })
    );
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::SkewRefused { .. }
        }
    ));
    assert!(!run.coordinator_honours());
}

#[test]
fn a_remote_claiming_more_time_than_it_was_granted_ends_delegation() {
    let mut run = Run::running();
    let mut guard = WallClockGuard::default();
    let (expiry, observation) = status(&run, 0, 1_800, 1_800_000_000);
    assert!(matches!(
        run.adapter
            .observe_remote_expiry(&expiry, &observation, &mut guard, &mut run.authority),
        Err(AdapterRefusal::RemoteClaimsLongerLease { .. })
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::RemoteClaimedLongerLease
        }
    ));
    assert!(!run.coordinator_honours());
}

#[test]
fn a_clock_that_goes_back_never_revives_a_lease() {
    let clock = Arc::new(RewindableClock::new(at(1_000)));
    let mut world = HostWorld::on(Arc::clone(&clock), 4 * HOUR);
    let mut authority = world.delegation();
    let ledger = SharedSpendLedger::new(SpendLedger::new());
    ledger
        .with(|book| book.open_account(account(), BUDGET))
        .unwrap();
    let mut provider = FakeProvider::default();
    let mut known = KnownHosts::new();
    let mut adapter = RemoteVmAdapter::plan(
        Arc::clone(&clock),
        attempt(1),
        parent(),
        &vm_request(),
        &[dedicated_offering()],
        config(),
    )
    .ok()
    .unwrap();
    adapter
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 1))
        .unwrap();
    let instance = adapter.provision(&mut provider, &ledger).unwrap();
    adapter
        .enroll(
            &mut known,
            &host_key(1),
            EnrollmentEvidence::ProviderApi {
                reported: host_key(1).fingerprint(),
            },
        )
        .unwrap();
    let offer = world.remote_offer(instance.instance, ExecutionCategory::VmSandbox);
    adapter.confirm_runtime(&offer, None).unwrap();
    let session = ControlSession::open(
        adapter.identity().unwrap().clone(),
        session_id(1),
        session_key(1),
        control_key(1),
        clock.now(),
    );
    adapter
        .connect(&known, &host_key(1), session, &mut authority)
        .unwrap();
    adapter
        .launch(&mut authority, OperationId::new("op-remote").unwrap(), None)
        .unwrap();
    let lease = adapter.lease().unwrap().id();
    clock.set(at(1_300));
    adapter.check_authority(&mut authority).unwrap();
    clock.set(at(1_100));
    assert_eq!(
        adapter.check_authority(&mut authority),
        Err(AdapterRefusal::Authority {
            refusal: LifetimeRefusal::Lease {
                refusal: LeaseRefusal::ClockWentBack {
                    now: at(1_100),
                    high_water: at(1_300)
                }
            }
        })
    );
    clock.set(at(1_400));
    assert_eq!(
        authority.check(lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert!(matches!(
        adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));
}

#[test]
fn the_delegation_guard_never_honours_a_lease_again_after_a_rollback() {
    let clock = Arc::new(RewindableClock::new(at(1_000)));
    let world = HostWorld::on(Arc::clone(&clock), 4 * HOUR);
    let mut authority = world.delegation();
    let lease = authority
        .issue(
            &parent(),
            OperationId::new("op-remote").unwrap(),
            config().terms,
        )
        .unwrap();
    clock.set(at(1_300));
    assert!(authority.check(lease.id()).is_ok());
    clock.set(at(1_100));
    assert_eq!(
        authority.renew(lease.id(), lease.clock()),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::ClockWentBack {
                now: at(1_100),
                high_water: at(1_300)
            }
        })
    );
    clock.set(at(1_400));
    // The coordinator alone would honour the lease again; the guard never does.
    assert!(world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .check_lease(lease.id())
        .is_ok());
    assert_eq!(
        authority.check(lease.id()),
        Err(LifetimeRefusal::Ended { lease: lease.id() })
    );
    assert!(authority.renew(lease.id(), lease.clock()).is_err());
    // A restart restores the persisted guard: the lease stays ended.
    let state = authority.guard_state().clone();
    let mut restored = CoordinatorDelegation::restore(Arc::clone(&world.coordinator), state);
    assert_eq!(
        restored.check(lease.id()),
        Err(LifetimeRefusal::Ended { lease: lease.id() })
    );
}

#[test]
fn revoking_the_parent_ends_delegated_authority() {
    let mut run = Run::running();
    run.world.revoke_parent();
    let refusal = run.adapter.renew(&mut run.authority).unwrap_err();
    assert_eq!(
        lease_refusal(&refusal),
        Some(&LeaseRefusal::Cancelled {
            cause: CancelCause::Revocation
        })
    );
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));
}

#[test]
fn a_remote_enforcement_point_stops_within_ttl_plus_the_skew_allowance() {
    let mut run = Run::running();
    run.advance(3 * MINUTE);
    run.heartbeat().unwrap();
    run.adapter.renew(&mut run.authority).unwrap();
    let (granted_at, grant) = run.adapter.last_grant().unwrap();
    let ttl = Duration::from_nanos(grant.ttl_nanos);
    assert_eq!(ttl, 10 * MINUTE);
    let bound = remote_authority_bound(&grant, granted_at, &config().skew).unwrap();
    assert_eq!(bound.remaining_authorized_time, 10 * MINUTE + 30 * SECOND);
    assert_eq!(
        bound.ends_by,
        granted_at.saturating_add(10 * MINUTE + 30 * SECOND)
    );
    // The remote counts the TTL from receipt on its own clock and cannot renew.
    let remote_start = MonotonicTime::from_nanos(77);
    let mut point = RemoteEnforcementPoint::new(
        RemoteLease {
            ttl,
            effect_budget: 1_000,
        },
        remote_start,
    );
    assert!(!point.enforcement().can_mint_renewals);
    let last = MonotonicTime::from_nanos(remote_start.as_nanos() + grant.ttl_nanos - 1);
    assert!(point.try_effect(last).is_ok());
    assert_eq!(
        point.try_effect(remote_start.saturating_add(ttl)),
        Err(RemoteRefusal::LeaseExpired)
    );
    // Delivered 2 s after it was sent, its last moment in host time is inside the bound.
    let receipt = granted_at.saturating_add(2 * SECOND);
    assert!(receipt.saturating_add(ttl) <= bound.ends_by);
}

#[test]
fn renewal_needs_a_recent_authenticated_frame() {
    let mut run = Run::running();
    run.advance(2 * MINUTE);
    assert_eq!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::ControlNotLive {
            silent_for_nanos: 120_000_000_000
        })
    );
    run.heartbeat().unwrap();
    assert!(run.adapter.renew(&mut run.authority).is_ok());
}

#[test]
fn the_remote_cannot_send_host_frames_or_present_a_foreign_lease() {
    let mut run = Run::running();
    let lease = run.adapter.lease().unwrap().clone();
    for body in [
        ControlBody::Stop,
        ControlBody::Grant {
            grant: LeaseGrant {
                authority: GrantRef::Lease { lease: lease.id() },
                clock: lease.clock(),
                ttl_nanos: u64::MAX,
            },
        },
    ] {
        let frame = run.remote(body);
        assert_eq!(
            run.adapter.handle_frame(&frame, &mut run.authority),
            Err(AdapterRefusal::UnexpectedFrame)
        );
    }
    for presented in [
        GrantRef::Lease {
            lease: LeaseId::new(999),
        },
        GrantRef::Labelled {
            epoch: AuthorizationEpoch::FIRST,
        },
    ] {
        let frame = run.remote(ControlBody::RenewalRequest {
            authority: presented,
            clock: lease.clock(),
        });
        assert_eq!(
            run.adapter.handle_frame(&frame, &mut run.authority),
            Err(AdapterRefusal::ForeignAuthority { presented })
        );
    }
    let mut tampered = run.remote(ControlBody::Heartbeat);
    tampered.frame.sequence = 1_000;
    assert!(matches!(
        run.adapter.handle_frame(&tampered, &mut run.authority),
        Err(AdapterRefusal::Control {
            refusal: super::control::ControlRefusal::Tampered
        })
    ));
    let (expiry, _) = status(&run, 0, 600, 1_800_000_000);
    let frame = run.remote(ControlBody::StatusReport { expiry });
    assert_eq!(
        run.adapter.handle_frame(&frame, &mut run.authority),
        Ok(FrameOutcome::StatusReported { expiry })
    );
}

#[test]
fn steps_out_of_order_are_refused_and_an_unprovisioned_run_cancels_cleanly() {
    let mut run = Run::dedicated();
    assert!(matches!(
        run.adapter
            .launch(&mut run.authority, OperationId::new("op-x").unwrap(), None),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    assert!(matches!(
        run.adapter.provision(&mut run.provider, &run.ledger),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    assert!(matches!(
        run.adapter.terminate_step(&mut run.provider),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    run.reserve();
    run.adapter.cancel(&run.ledger).unwrap();
    assert_eq!(run.adapter.state(), &AdapterState::Cancelled);
    assert_eq!(run.spend().reserved_microunits, 0);
    assert!(run.provider.calls.is_empty());

    let mut run = Run::dedicated();
    run.provision();
    assert!(matches!(
        run.adapter.cancel(&run.ledger),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    assert!(run.adapter.needs_cleanup());
}

#[test]
fn a_confidential_launch_needs_an_accepted_attestation_bound_to_this_session() {
    let mut confidential = config();
    confidential.confidential = Some(ConfidentialLaunch {
        workload: workload(),
        max_record_age_seconds: 300,
    });
    let mut run = Run::with(dedicated_offering(), vm_request(), confidential);
    run.provision();
    run.enroll();
    run.confirm();
    run.connect(1).unwrap();
    let operation = || OperationId::new("op-remote").unwrap();
    assert_eq!(
        run.adapter
            .launch(&mut run.authority, operation(), None)
            .map(|_| ()),
        Err(AdapterRefusal::AttestationRequired)
    );
    let mut book = AttestationBook::new();
    let mut nonces = SeededNonces(SeededRng::new(3));
    let vendor = FakeVendor::new();
    let identity_digest = run.adapter.identity().unwrap().digest();
    let mut attest = |run: &Run, key: u8, debug: bool| {
        let challenge = book
            .challenge(
                &mut nonces,
                identity_digest,
                session_key(key),
                workload(),
                target(),
                run.world.session(),
                run.world.now(),
            )
            .unwrap();
        let mut report = valid_report(&challenge);
        if debug {
            report.body.debug_enabled = true;
            resign(&mut report);
        }
        book.verify(
            &report,
            &policy(),
            &vendor,
            run.world.session(),
            run.world.now(),
        )
    };
    let other_session = attest(&run, 2, false);
    assert_eq!(
        run.adapter
            .launch(&mut run.authority, operation(), Some(&other_session))
            .map(|_| ()),
        Err(AdapterRefusal::AttestationNotUsable {
            reason: super::attestation::AttestationUse::OtherSessionKey
        })
    );
    let refused = attest(&run, 1, true);
    assert_eq!(
        run.adapter
            .launch(&mut run.authority, operation(), Some(&refused))
            .map(|_| ()),
        Err(AdapterRefusal::AttestationNotUsable {
            reason: super::attestation::AttestationUse::NotAccepted
        })
    );
    let good = attest(&run, 1, false);
    assert!(good.result.is_accepted());
    run.adapter
        .launch(&mut run.authority, operation(), Some(&good))
        .unwrap();
    assert_eq!(run.adapter.state(), &AdapterState::Running);
}

#[test]
fn management_launches_the_vm_while_workload_authority_is_the_lease_alone() {
    let mut run = Run::with(metal_offering(), vm_request(), config());
    run.provision();
    let identity = run.enroll();
    let enrollment = run.known.enrollment(&identity.host).unwrap().clone();
    let management = ManagementIdentity::new(
        &enrollment,
        RemoteAccountName::new("yougori").unwrap(),
        mgmt_key(),
        RemoteShellKind::Posix,
        BTreeSet::from([ManagementAction::LaunchVm, ManagementAction::TerminateVm]),
    )
    .unwrap();
    let command = RemoteCommand::new(
        ProgramPath::new("/opt/yougori/bin/yougori-remote").unwrap(),
        OptionTerminator::DoubleDash,
    )
    .flag("--launch-vm")
    .unwrap()
    .flag_value("--vm", "vm-1; reboot")
    .unwrap();
    let shell = ExecutionContext::RemoteHostShell {
        host: identity.host,
    };
    let invocation = RemoteInvocation::new(
        &management,
        &run.known,
        ManagementAction::LaunchVm,
        shell,
        &command,
    )
    .unwrap();
    assert_eq!(
        invocation.command().as_str(),
        "'/opt/yougori/bin/yougori-remote' '--launch-vm' '--vm=vm-1; reboot'"
    );
    // Launching the VM delegated no workload authority.
    assert!(run.adapter.lease().is_none());
    let workload_evidence = RemoteCapabilityEvidence::observed(
        &enrollment,
        ExecutionContext::VmWorkload {
            host: identity.host,
            vm: vm_id(1),
        },
        RemoteCapability::VmRunning {
            hardware_accelerated: true,
        },
        run.world.now(),
    );
    let offer = run
        .world
        .remote_offer(*vm_id(1).digest(), ExecutionCategory::VmSandbox);
    run.adapter
        .confirm_runtime(&offer, Some(&workload_evidence))
        .unwrap();
    run.connect(1).unwrap();
    run.launch();
    let lease = run.adapter.lease().unwrap();
    assert_eq!(lease.kind(), LeaseKind::Service);
    assert_eq!(lease.parent(), &parent());
    let json = serde_json::to_value(&management).unwrap();
    assert!(json.get("lease").is_none());
}

/// VM-P40: under random partitions, reconnects, host-key changes, clock skew, renewal
/// requests, revocations and provider errors, no delegated authority outlives the
/// lease's maximum lifetime or its last grant, and a run never returns to running.
#[test]
fn no_event_sequence_creates_immortal_delegated_authority() {
    for seed in 0..120u64 {
        let mut rng = SeededRng::new(0xa11c_e000 + seed);
        let mut run = Run::running();
        let deadline = run.adapter.lease().unwrap().deadline();
        let mut guard = WallClockGuard::default();
        let mut next_session: u8 = 2;
        let mut ended = false;
        for _ in 0..80 {
            match rng.below(11) {
                0 | 1 => run.advance(Duration::from_secs(rng.below(12 * 60))),
                2 => run.adapter.connection_lost(),
                3 => {
                    next_session = next_session.wrapping_add(1).max(2);
                    let _ = run.connect(next_session);
                }
                4 => {
                    let session = run.session(200);
                    let _ =
                        run.adapter
                            .connect(&run.known, &host_key(9), session, &mut run.authority);
                }
                5 => {
                    let _ = run.heartbeat();
                }
                6 => {
                    if run.adapter.lease().is_some() {
                        let _ = run.renewal_request();
                    }
                }
                7 => {
                    let _ = run.adapter.renew(&mut run.authority);
                }
                8 => {
                    if run.adapter.state() == &AdapterState::Running {
                        let local_unix = 1_800_000_000
                            + i64::try_from(run.world.now().as_nanos() / 1_000_000_000).unwrap();
                        let skew = i64::try_from(rng.below(241)).unwrap() - 120;
                        let remaining = i64::try_from(
                            run.adapter
                                .lease()
                                .unwrap()
                                .expires_at()
                                .saturating_duration_since(run.world.now())
                                .as_secs(),
                        )
                        .unwrap();
                        let (expiry, observation) = status(&run, skew, remaining, local_unix);
                        let _ = run.adapter.observe_remote_expiry(
                            &expiry,
                            &observation,
                            &mut guard,
                            &mut run.authority,
                        );
                    }
                }
                9 => {
                    let _ = run.adapter.check_authority(&mut run.authority);
                    // Provider errors on other calls change nothing about authority.
                    run.provider
                        .terminations
                        .push_back(TerminationOutcome::Failed {
                            error: ProviderError::ProviderUnavailable,
                        });
                }
                _ => {
                    if rng.below(8) == 0 {
                        run.world.revoke_parent();
                    }
                }
            }
            let now = run.world.now();
            let running = run.adapter.state() == &AdapterState::Running;
            if ended {
                assert!(!running, "seed {seed}: a run returned to running");
            }
            ended |= !running;
            let lease = run.adapter.lease().unwrap();
            assert!(lease.expires_at() <= deadline, "seed {seed}");
            if now >= deadline {
                assert!(
                    !run.coordinator_honours(),
                    "seed {seed}: authority past its deadline"
                );
            }
            if let Some((granted_at, grant)) = run.adapter.last_grant() {
                assert!(
                    granted_at.saturating_add(Duration::from_nanos(grant.ttl_nanos)) <= deadline,
                    "seed {seed}: a grant outlives the deadline"
                );
            }
        }
        run.advance(3 * HOUR);
        assert!(!run.coordinator_honours(), "seed {seed}");
        if run.adapter.state() == &AdapterState::Running {
            assert!(run.adapter.check_authority(&mut run.authority).is_err());
        }
        assert_ne!(run.adapter.state(), &AdapterState::Running, "seed {seed}");
    }
}

/// A provider container run to running under its labelled-runtime record (VM-D5).
fn container_running(authority_lifetime: Duration) -> Run {
    let mut run = Run::with(container_offering(), explicit_container(), config());
    let instance = run.provision();
    run.enroll();
    let offer = run.world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
    run.world
        .authorize_labelled(pod_execution(), admitted, authority_lifetime)
        .unwrap();
    run.connect(1).unwrap();
    run.launch();
    run
}

#[test]
fn a_provider_container_runs_under_its_labelled_runtime_record_never_a_lease() {
    let leases_before = run_leases(&Run::dedicated());
    let mut run = container_running(HOUR);
    let Some(Delegation::Labelled { grant }) = run.adapter.delegation().cloned() else {
        panic!("{:?}", run.adapter.delegation());
    };
    assert!(run.adapter.lease().is_none());
    assert_eq!(run_leases(&run), leases_before);
    let record = run
        .world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .labelled_runtime(&pod_execution())
        .unwrap()
        .clone();
    assert_eq!(
        record.runtime().category,
        ExecutionCategory::ProviderContainerRuntime
    );
    assert_eq!(record.authority(), grant);
    // The remote gets one term at a time, within the grant.
    let (_, first) = run.adapter.last_grant().unwrap();
    assert_eq!(
        first.authority,
        GrantRef::Labelled {
            epoch: AuthorizationEpoch::FIRST
        }
    );
    assert_eq!(Duration::from_nanos(first.ttl_nanos), 10 * MINUTE);
    run.advance(55 * MINUTE);
    assert!(matches!(
        run.renewal_request(),
        Ok(FrameOutcome::Renewed { .. })
    ));
    let (_, near_end) = run.adapter.last_grant().unwrap();
    assert_eq!(Duration::from_nanos(near_end.ttl_nanos), 5 * MINUTE);
    run.advance(5 * MINUTE);
    let refusal = run.renewal_request().unwrap_err();
    assert!(matches!(
        refusal,
        AdapterRefusal::Labelled {
            refusal: LeaseRefusal::AuthorityExpired { .. }
        }
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LabelledRefused { .. }
        }
    ));
}

fn run_leases(run: &Run) -> usize {
    run.world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .leases()
        .count()
}

#[test]
fn a_container_launch_needs_the_hosts_labelled_record_for_exactly_its_runtime() {
    let mut run = Run::with(container_offering(), explicit_container(), config());
    let instance = run.provision();
    run.enroll();
    let offer = run.world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    run.adapter.confirm_runtime(&offer, None).unwrap();
    run.connect(1).unwrap();
    assert_eq!(
        run.adapter
            .launch(
                &mut run.authority,
                OperationId::new("op-pod").unwrap(),
                None
            )
            .map(|_| ()),
        Err(AdapterRefusal::Labelled {
            refusal: LeaseRefusal::UnknownExecution {
                execution: pod_execution()
            }
        })
    );
    // A record granted for another container instance does not authorize this one.
    let other = run.world.remote_offer(
        digest("yougori/test/provider-instance/v1", &[b"another-pod"]),
        ExecutionCategory::ProviderContainerRuntime,
    );
    let other = explicit_container().requirement.admit(&other).unwrap();
    run.world
        .authorize_labelled(pod_execution(), other, HOUR)
        .unwrap();
    assert_eq!(
        run.adapter
            .launch(
                &mut run.authority,
                OperationId::new("op-pod").unwrap(),
                None
            )
            .map(|_| ()),
        Err(AdapterRefusal::LabelledRecordForAnotherRuntime)
    );
    assert_eq!(run.adapter.state(), &AdapterState::RuntimeConfirmed);
}

#[test]
fn a_vm_sandbox_execution_never_gets_a_labelled_record() {
    let mut run = Run::with(container_offering(), explicit_container(), config());
    let instance = run.provision();
    run.enroll();
    let offer = run.world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
    // The parent is a VM sandbox: a container cannot be recorded under it.
    assert!(matches!(
        run.world.authorize_labelled(parent(), admitted, HOUR),
        Err(CoordinationError::NotALabelledRuntime { .. })
    ));
}

#[test]
fn revoking_or_replacing_the_labelled_grant_ends_the_container_delegation() {
    let mut run = container_running(HOUR);
    run.world.revoke_labelled(&pod_execution());
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::Labelled {
            refusal: LeaseRefusal::RevokedAuthorization { .. }
        })
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded { .. }
    ));

    // The grant expires and someone authorizes the runtime afresh: the new grant is not
    // adopted, so reconnecting cannot revive the run's authority.
    let mut run = container_running(20 * MINUTE);
    run.adapter.connection_lost();
    run.advance(21 * MINUTE);
    let admitted = run.adapter.runtime().unwrap().clone();
    let fresh = run
        .world
        .authorize_labelled(pod_execution(), admitted, HOUR)
        .unwrap();
    assert_eq!(fresh.epoch, AuthorizationEpoch::FIRST.next().unwrap());
    let refusal = run.connect(2).unwrap_err();
    assert!(matches!(
        refusal,
        AdapterRefusal::LabelledGrantReplaced { current, .. } if current == fresh
    ));
    assert!(matches!(
        run.adapter.state(),
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::GrantReplaced
        }
    ));
}

#[test]
fn terminating_a_container_run_revokes_its_labelled_record() {
    let mut run = container_running(HOUR);
    run.adapter.begin_termination(&mut run.authority).unwrap();
    let record = run
        .world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .labelled_runtime(&pod_execution())
        .unwrap()
        .clone();
    assert_ne!(record.epoch(), record.authority().epoch);
    assert!(run.authority.check_labelled(&pod_execution()).is_err());
    run.adapter.terminate_step(&mut run.provider).unwrap();
    assert_eq!(
        run.settle(),
        Ok(BillingOutcome::Settled {
            charged_microunits: COST
        })
    );
    // A container is not a VM: its termination is not recorded as a VM stopping.
    assert!(!run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::VmStopped));
    assert!(run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
}

#[test]
fn the_final_bill_acknowledges_stopped_billing_on_the_parents_revocation() {
    let mut run = Run::running();
    run.world.revoke_parent();
    assert!(run.adapter.check_authority(&mut run.authority).is_err());
    run.adapter.begin_termination(&mut run.authority).unwrap();
    run.adapter.terminate_step(&mut run.provider).unwrap();
    let before = run
        .world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .revocation(&parent())
        .unwrap()
        .milestones()
        .clone();
    assert!(!before.contains_key(&RevocationMilestone::ProviderStoppedBilling));
    // Without a final bill nothing is acknowledged.
    run.provider.bills.push_back(BillingReport::Unavailable);
    run.settle().unwrap();
    assert!(!run
        .world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .revocation(&parent())
        .unwrap()
        .milestones()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
    run.settle().unwrap();
    let after = run
        .world
        .coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .revocation(&parent())
        .unwrap()
        .milestones()
        .clone();
    assert!(after.contains_key(&RevocationMilestone::ProviderStoppedBilling));
    assert!(run
        .adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
}
