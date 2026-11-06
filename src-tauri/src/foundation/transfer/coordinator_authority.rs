//! The authority port over the CORE-04 coordinator (T09).
//!
//! A transfer's parent execution is a VM sandbox the coordinator launched, and the
//! sandbox lifecycle owns its authorization epoch and its authority (S3.1). Every check
//! reads the coordinator's state at that moment, so a revocation is seen by the
//! transfer's next check: the epoch has advanced and no authority is held under it
//! (INT-02).

use std::sync::{Arc, Mutex, PoisonError};

use super::ports::{AuthorityPort, ParentAuthority, ParentStatus};
use crate::foundation::coordination::{CapacityPort, Coordinator, SandboxState};
use crate::foundation::ids::{Clock, ExecutionId};

/// [`AuthorityPort`] over the host's [`Coordinator`], shared with the VM lifecycle and the
/// model side.
pub struct CoordinatorAuthority<C: Clock, P: CapacityPort> {
    coordinator: Arc<Mutex<Coordinator<C, P>>>,
}

impl<C: Clock, P: CapacityPort> CoordinatorAuthority<C, P> {
    pub fn new(coordinator: Arc<Mutex<Coordinator<C, P>>>) -> Self {
        Self { coordinator }
    }
}

impl<C: Clock, P: CapacityPort + Send> AuthorityPort for CoordinatorAuthority<C, P> {
    /// The sandbox's authority while it holds one under its current epoch; its current
    /// epoch while it holds none, as after a revocation or before a grant; not running
    /// once it stopped, or when the coordinator does not know it.
    fn parent_status(&self, parent: &ExecutionId) -> ParentStatus {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        parent_status_in(&coordinator, parent)
    }
}

/// Where `parent` stands in `coordinator` now, by the rule of [`CoordinatorAuthority`], for
/// a caller that holds the coordinator itself (the VM service's supervisor owns one).
pub fn parent_status_in<C: Clock, P: CapacityPort>(
    coordinator: &Coordinator<C, P>,
    parent: &ExecutionId,
) -> ParentStatus {
    let Some(sandbox) = coordinator.sandbox(parent) else {
        return ParentStatus::NotRunning;
    };
    let state = sandbox.state();
    if state == SandboxState::Stopped {
        return ParentStatus::NotRunning;
    }
    let current = sandbox.generations().authorization;
    match sandbox.authority() {
        Some(grant) if state.holds_authority() && grant.epoch == current => {
            ParentStatus::Authorized {
                authority: ParentAuthority {
                    epoch: grant.epoch,
                    clock: grant.clock,
                    expires_at: grant.expires_at,
                },
            }
        }
        _ => ParentStatus::NoAuthority { current },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::MutexGuard;
    use std::time::Duration;

    use super::*;
    use crate::foundation::coordination::{
        BootRequest, LaunchOutcome, LaunchPlan, LedgerCapacity, ObservedVm, PerimeterId,
        PortFailure, PortOperation, Readiness, ReadinessReport, ReservationPriority, ResourceKind,
        RestoredVmReport, SandboxPort, SnapshotId, SnapshotManifest, VmInstanceId,
    };
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        Backend, BackendRelease, Capability, ConfigurationFingerprint, HostSubject, Observation,
        ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
        SupportDetail,
    };
    use crate::foundation::ids::{
        digest, Digest, ExecutionCategory, ManualClock, PolicyEpoch, SandboxBootGeneration,
    };
    use crate::foundation::ledger::{
        CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
    };
    use crate::foundation::transfer::fakes::{
        download_connection, download_fields, object, parent, range, tenant, test_key, World, GIB,
        HOUR, SECOND, SESSION,
    };
    use crate::foundation::transfer::{StopReason, TransferGate, TransferPorts, TransferRefusal};

    type TestCoordinator = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

    fn handle(kind: &str, request: &BootRequest) -> Digest {
        digest(
            "yougori/test/handle/v1",
            &[
                kind.as_bytes(),
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )
    }

    /// A VM backend whose every boot succeeds and which the host observes ready.
    struct ReadyBackend;

    impl SandboxPort for ReadyBackend {
        fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
            Ok(PerimeterId::new(handle("perimeter", request)))
        }

        fn create_vm(
            &mut self,
            request: &BootRequest,
            _perimeter: &PerimeterId,
        ) -> Result<VmInstanceId, PortFailure> {
            Ok(VmInstanceId::new(handle("vm", request)))
        }

        fn restore_vm(
            &mut self,
            _request: &BootRequest,
            _perimeter: &PerimeterId,
            _snapshot: &SnapshotManifest,
        ) -> Result<VmInstanceId, PortFailure> {
            Err(PortFailure {
                operation: PortOperation::RestoreVm,
                detail: "this backend keeps no snapshots".to_owned(),
            })
        }

        fn observe_readiness(
            &mut self,
            _vm: &VmInstanceId,
            _boot: SandboxBootGeneration,
        ) -> ReadinessReport {
            ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::Ready,
            }
        }

        fn inspect_restored_vm(
            &mut self,
            vm: &VmInstanceId,
            boot: SandboxBootGeneration,
        ) -> RestoredVmReport {
            RestoredVmReport {
                vm: *vm,
                boot,
                snapshot: SnapshotId::new(digest("yougori/test/snapshot/v1", &[b"none"])),
                guest_identity: digest("yougori/test/guest/v1", &[b"none"]),
                actions: BTreeSet::new(),
                attached_volumes: BTreeSet::new(),
                policy: PolicyEpoch::FIRST,
                image_profile: digest("yougori/test/image/v1", &[b"none"]),
                presented_epochs: BTreeSet::new(),
                source: SourceClass::HostProbe,
            }
        }

        fn terminate_vm(&mut self, _vm: &VmInstanceId) -> Result<(), PortFailure> {
            Ok(())
        }

        fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
            Ok(())
        }

        fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
            Ok(Vec::new())
        }
    }

    fn lock(coordinator: &Mutex<TestCoordinator>) -> MutexGuard<'_, TestCoordinator> {
        coordinator.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The coordinator over a real ledger with 64 GiB of host RAM for tenant-a, and the
    /// parent sandbox launched to authority on host evidence that it is a VM sandbox.
    fn launched_parent(world: &World) -> (Arc<Mutex<TestCoordinator>>, ParentAuthority) {
        let ram = ResourceKey::Host(HostResource::Ram);
        let mut ledger = Ledger::new(
            world.clock.clone(),
            HostSubject {
                machine: digest("yougori/test/machine/v1", &[b"host"]),
            },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 4,
                    max_entries_per_tenant: 2,
                    max_wait: Duration::from_secs(60),
                },
                grant_ttl: Duration::from_secs(300),
                unmanaged_usage_max_age: HOUR,
            },
        );
        ledger
            .declare_capacity(
                ram,
                CapacityDeclaration {
                    total: 64 * GIB,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), ram, 64 * GIB).unwrap();
        let coordinator = Arc::new(Mutex::new(Coordinator::new(
            world.clock.clone(),
            SESSION,
            LedgerCapacity::new(ledger),
        )));

        let mut registry = ProbeRegistry::new(world.clock.clone());
        let probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
        };
        let configuration = ConfigurationFingerprint::from_digest(digest(
            "yougori/test/configuration/v1",
            &[b"launch"],
        ));
        let subject = Subject::Runtime(runtime.clone());
        probe.respond(
            &subject,
            Observation::supported(
                configuration,
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer = RuntimeOffer::observe(&registry, runtime, HOUR, configuration).unwrap();
        let plan = LaunchPlan {
            execution: parent(),
            tenant: tenant(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, GIB)]),
            priority: ReservationPriority::Foreground,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        };
        let outcome = lock(&coordinator)
            .launch(plan, &mut ReadyBackend, &registry)
            .unwrap();
        let LaunchOutcome::AuthorityActive { grant, .. } = outcome else {
            panic!("expected authority, got {outcome:?}");
        };
        let authority = ParentAuthority {
            epoch: grant.epoch,
            clock: grant.clock,
            expires_at: grant.expires_at,
        };
        (coordinator, authority)
    }

    /// INT-02 through the real coordinator: a revocation advances the parent's epoch and
    /// ends its authority, and the open transfer stops at its next chunk; the chunk
    /// already in flight does not count.
    #[test]
    fn a_revocation_through_the_coordinator_stops_an_open_transfer_at_its_next_chunk() {
        let world = World::new();
        let (coordinator, granted) = launched_parent(&world);
        let authority = Arc::new(CoordinatorAuthority::new(coordinator.clone()));
        assert_eq!(granted.clock, SESSION);
        assert_eq!(
            authority.parent_status(&parent()),
            ParentStatus::Authorized { authority: granted }
        );
        assert_eq!(
            authority.parent_status(&ExecutionId::new("exe-unknown").unwrap()),
            ParentStatus::NotRunning
        );

        let gate = TransferGate::new(
            test_key(),
            TransferPorts {
                clock: world.clock.clone(),
                clock_session: SESSION,
                authority: authority.clone(),
                budget: world.ledger.clone(),
                extents: world.extents.clone(),
                progress: world.progress.clone(),
            },
        );
        let mut fields = download_fields();
        fields.epoch = granted.epoch;
        let mut session = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        let in_flight = session.admit(&object("weights"), range(0, 40)).unwrap();

        let notice = lock(&coordinator).revoke(&parent()).unwrap();
        assert_eq!(notice.revoked, granted.epoch);
        assert!(notice.current > granted.epoch);
        assert_eq!(
            authority.parent_status(&parent()),
            ParentStatus::NoAuthority {
                current: notice.current
            }
        );

        let refused = session
            .admit(&object("weights"), range(40, 80))
            .unwrap_err();
        assert_eq!(
            refused,
            TransferRefusal::Stopped {
                reason: StopReason::AuthorityNotCurrent {
                    granted: granted.epoch,
                    current: Some(notice.current),
                }
            }
        );
        let TransferRefusal::Stopped { reason } = &refused else {
            unreachable!();
        };
        assert!(reason.is_revocation());
        assert!(matches!(
            session.deliver(in_flight),
            Err(TransferRefusal::NotActive { .. })
        ));
        assert_eq!(session.delivered_bytes(), 0);
        assert_eq!(world.ledger.held_bytes(), 0);
    }
}
