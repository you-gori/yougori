//! Test doubles (rollout plan §15): a catalog with scripted object statuses, a loader, a
//! VM backend that keeps its VMs in memory, a seeded generator, and a VM sandbox host
//! built on the committed CORE-04 coordinator over the committed CORE-03 ledger.
//! Everything stays in memory; nothing on the host is touched.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use super::job::LoadRequest;
use super::ports::{CatalogObjects, Loader, PortError, PortFailure, PortName};
use crate::foundation::catalog::{ObjectId, ObjectStatus, Scope};
use crate::foundation::coordination::{
    BootRequest, Coordinator, GpuAllocationHandle, GpuDemand, LaunchOutcome, LaunchPlan,
    LeaseTerms, LedgerCapacity, ModelId, ObservedVm, PerimeterId, PortFailure as VmPortFailure,
    PortOperation, Readiness, ReadinessReport, RecoveryReport as CoordinatorRecovery,
    ReservationPriority, ResourceKind as CoordinatedResource, RestoredVmReport, SandboxPort,
    SnapshotId, SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    ArtifactVerification, AuthorityGrant, Backend, BackendRelease, Capability, ClockSession,
    ConfigurationFingerprint, HostSubject, Observation, ProbeRegistry, Residency, RuntimeOffer,
    RuntimeRequirement, RuntimeSettings, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionCategory, ExecutionId, GpuDeviceKey, ManualClock, OperationId,
    PolicyEpoch, SandboxBootGeneration, TenantId,
};
use crate::foundation::ledger::{
    CapacityDeclaration, DeviceId, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};

const GB: u64 = 1_000_000_000;
const HOUR: Duration = Duration::from_secs(3_600);

/// A catalog with scripted object statuses, for states a real catalog reaches only
/// through damage, and for an unreachable catalog. An unscripted object is absent.
#[derive(Default)]
pub struct FakeCatalog {
    statuses: BTreeMap<(Scope, ObjectId), ObjectStatus>,
    pub unavailable: bool,
}

impl FakeCatalog {
    pub fn set_status(&mut self, owner: Scope, object: ObjectId, status: ObjectStatus) {
        self.statuses.insert((owner, object), status);
    }
}

impl CatalogObjects for FakeCatalog {
    fn object_status(&self, owner: &Scope, object: ObjectId) -> Result<ObjectStatus, PortError> {
        if self.unavailable {
            return Err(PortError {
                port: PortName::Catalog,
                failure: PortFailure::Unavailable,
            });
        }
        Ok(self
            .statuses
            .get(&(owner.clone(), object))
            .cloned()
            .unwrap_or(ObjectStatus::Absent))
    }
}

/// The normal loader, recording what it was asked.
#[derive(Default)]
pub struct FakeLoader {
    pub submitted: Vec<LoadRequest>,
    pub cancelled: Vec<OperationId>,
    pub refuse_submissions: bool,
    pub refuse_cancellations: bool,
}

impl Loader for FakeLoader {
    fn submit(&mut self, request: LoadRequest) -> Result<(), PortError> {
        if self.refuse_submissions {
            return Err(PortError {
                port: PortName::Loader,
                failure: PortFailure::Unavailable,
            });
        }
        self.submitted.push(request);
        Ok(())
    }

    fn cancel(&mut self, operation: &OperationId) -> Result<(), PortError> {
        if self.refuse_cancellations {
            return Err(PortError {
                port: PortName::Loader,
                failure: PortFailure::Unavailable,
            });
        }
        self.cancelled.push(operation.clone());
        Ok(())
    }
}

/// SplitMix64: the only randomness in these tests, seeded explicitly.
pub struct SeededRng(u64);

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`; `bound` is at least 1.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound.max(1)
    }
}

/// A VM backend whose VMs boot at once, are always ready as the host observes them, and
/// stay alive across a daemon restart until terminated.
#[derive(Default)]
pub struct LiveVms {
    live: BTreeMap<VmInstanceId, ObservedVm>,
}

impl SandboxPort for LiveVms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, VmPortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, VmPortFailure> {
        let vm = VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        ));
        self.live.insert(
            vm,
            ObservedVm {
                vm,
                execution: request.execution.clone(),
                boot: request.generations.boot,
            },
        );
        Ok(vm)
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, VmPortFailure> {
        Err(VmPortFailure {
            operation: PortOperation::RestoreVm,
            detail: "this backend does not restore".to_owned(),
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
            source: SourceClass::Fixture,
        }
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), VmPortFailure> {
        self.live.remove(vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), VmPortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, VmPortFailure> {
        Ok(self.live.values().cloned().collect())
    }
}

/// The CORE-04 coordinator over the CORE-03 ledger, on the test clock.
pub type Host = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

pub fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

pub fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[&[0]]),
    }
}

/// The VM sandbox execution the jobs run under.
pub fn owner() -> ExecutionId {
    ExecutionId::new("exe-1").unwrap()
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-1").unwrap()
}

pub fn model(name: &str) -> ModelId {
    ModelId::new(digest("yougori/test/model-id/v1", &[name.as_bytes()]))
}

/// A lease of one minute, renewable for ten.
pub fn lease_terms() -> LeaseTerms {
    LeaseTerms {
        term: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(600),
        cancel_within: Duration::from_secs(5),
    }
}

/// A session on the test clock, named by `index` rather than drawn at random.
pub fn session(index: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(index))
}

fn vram() -> ResourceKey {
    ResourceKey::Vram(DeviceId::from(gpu()))
}

/// A ledger owning one 32 GB GPU, all of it in the tenant's budget.
fn ledger(clock: &Arc<ManualClock>) -> LedgerCapacity<Arc<ManualClock>> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(60),
            unmanaged_usage_max_age: Duration::from_secs(24 * 3_600),
        },
    );
    ledger
        .declare_capacity(
            vram(),
            CapacityDeclaration {
                total: 32 * GB,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    ledger.set_tenant_budget(tenant(), vram(), 32 * GB).unwrap();
    LedgerCapacity::new(ledger)
}

/// A coordinator with nothing launched, on its own clock `session`, as a host's
/// coordinator is after a restart with nothing to recover.
pub fn idle_host(clock: &Arc<ManualClock>, session: ClockSession) -> Host {
    Coordinator::new(Arc::clone(clock), session, ledger(clock))
}

/// A running VM sandbox on a coordinator, and what relaunching it needs.
pub struct SandboxHost {
    pub host: Host,
    pub vms: LiveVms,
    pub registry: ProbeRegistry<Arc<ManualClock>>,
    pub plan: LaunchPlan,
    /// The settings the sandbox's current authority allows.
    pub settings: RuntimeSettings,
}

impl SandboxHost {
    /// Launches a VM sandbox owning 30 GB of the 32 GB GPU and starts it running.
    pub fn launch(clock: &Arc<ManualClock>) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm-host"]),
        };
        let configuration = ConfigurationFingerprint::from_digest(digest(
            "yougori/test/configuration/v1",
            &[b"vm"],
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
            execution: owner(),
            tenant: tenant(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(
                CoordinatedResource::GpuMemoryBytes { device: gpu() },
                30 * GB,
            )]),
            priority: ReservationPriority::Foreground,
            authority_lifetime: HOUR,
            readiness_max_age: Duration::from_secs(5),
            runtime_evidence_max_age: HOUR,
        };
        let mut host = Coordinator::new(Arc::clone(clock), registry.session(), ledger(clock));
        let mut vms = LiveVms::default();
        let grant = run(&mut host, &plan, &mut vms, &registry);
        let settings = RuntimeSettings {
            execution_category: ExecutionCategory::VmSandbox,
            network: BTreeSet::new(),
            authority: grant,
            artifact_verification: ArtifactVerification::Verified {
                artifacts: BTreeSet::new(),
            },
            loader: BTreeSet::new(),
            batch_size: NonZeroU32::MIN,
            residency: Residency::Device,
        };
        Self {
            host,
            vms,
            registry,
            plan,
            settings,
        }
    }

    /// Continues the launch of a sandbox a restart left without authority, up to running
    /// under fresh authority, which every later activation runs under.
    pub fn authorize(&mut self) {
        self.settings.authority = run(&mut self.host, &self.plan, &mut self.vms, &self.registry);
    }

    /// Begins an activation of `model` holding 4 GB of the GPU; it loads into the
    /// allocation the handle names.
    pub fn activate(&mut self, model: ModelId) -> GpuAllocationHandle {
        self.host
            .begin_activation(
                &owner(),
                model,
                self.settings.clone(),
                GpuDemand {
                    device: gpu(),
                    memory_bytes: 4 * GB,
                },
            )
            .unwrap()
    }

    /// The daemon restarts: the coordinator persists its state and stops, and a new one
    /// recovers it under a new clock session (INT-04). The VM survives, without
    /// authority.
    pub fn restart(self, clock: &Arc<ManualClock>) -> (Self, CoordinatorRecovery) {
        let Self {
            host,
            mut vms,
            registry,
            plan,
            settings,
        } = self;
        let persisted = host.persist();
        let (host, recovered) = Coordinator::recover(
            persisted,
            Arc::clone(clock),
            session(2),
            host.into_capacity(),
            &mut vms,
        )
        .unwrap();
        let sandbox = Self {
            host,
            vms,
            registry,
            plan,
            settings,
        };
        (sandbox, recovered)
    }
}

/// Launches, or continues the launch of, the sandbox in `plan` until it runs, and returns
/// the authority it was granted.
fn run(
    host: &mut Host,
    plan: &LaunchPlan,
    vms: &mut LiveVms,
    registry: &ProbeRegistry<Arc<ManualClock>>,
) -> AuthorityGrant {
    let outcome = host.launch(plan.clone(), vms, registry).unwrap();
    let LaunchOutcome::AuthorityActive { grant, .. } = outcome else {
        panic!("the sandbox did not get authority: {outcome:?}");
    };
    host.start_running(&owner()).unwrap();
    grant
}
