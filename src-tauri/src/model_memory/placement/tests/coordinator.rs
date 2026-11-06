//! A slot driven through the committed CORE-04 coordinator (task T09), with the CORE-03
//! ledger behind it: generations from the coordinator's model activations, leases that
//! carry every generation, weights held apart and counted once across generations, the
//! drain-first handover of a predecessor's own memory, a bounded drain, reactivation,
//! several devices with host memory, and execute-while-load under a preparation lease.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::{
    ActivationState, BootRequest, Coordinator, GpuReservationState, HoldingId, HoldingMemory,
    LaunchOutcome, LaunchPlan, LeaseKind as CoordinatedLeaseKind, LedgerCapacity, ModelActivations,
    ModelId, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness,
    ReadinessReport as VmReadiness, ReservationPriority, ResourceKind as CoordinatedResource,
    RestoredVmReport, RetireReason, SandboxPort, SnapshotId, SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    ArtifactVerification, Backend, BackendRelease, Capability, ConfigurationFingerprint,
    HostSubject, Observation, ProbeRegistry, Residency, RuntimeOffer, RuntimeRequirement,
    RuntimeSettings, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ExecutionCategory, GpuDeviceKey, ManualClock, MonotonicTime,
    PolicyEpoch, SandboxBootGeneration,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::model_memory::identity::AuthorityBinding;
use crate::model_memory::placement::test_support::*;
use crate::model_memory::placement::*;

/// A VM backend that boots at once and is always ready, observed by the host.
struct ReadyVms;

impl SandboxPort for ReadyVms {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        Ok(VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "this backend does not restore".to_owned(),
        })
    }

    fn observe_readiness(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> VmReadiness {
        VmReadiness {
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

type Host = Coordinator<Arc<ManualClock>, LedgerCapacity<Arc<ManualClock>>>;

fn vram_of(device: GpuDeviceKey) -> ResourceKey {
    ResourceKey::Vram(ledger_device(&device))
}

fn host_ram() -> ResourceKey {
    ResourceKey::Host(HostResource::Ram)
}

fn pinned_ram() -> ResourceKey {
    ResourceKey::Host(HostResource::PinnedRam)
}

/// Physical totals and the sandbox's share of each resource.
struct Sizes {
    gpus: Vec<(GpuDeviceKey, u64, u64)>,
    host: Option<(u64, u64)>,
    pinned: Option<(u64, u64)>,
}

fn one_gpu(total: u64, sandbox: u64) -> Sizes {
    Sizes {
        gpus: vec![(gpu(0), total, sandbox)],
        host: None,
        pinned: None,
    }
}

/// A launched VM sandbox, its coordinator over the ledger, and one model slot in it.
struct Sandbox {
    clock: Arc<ManualClock>,
    host: Host,
    state: CoordinatorPlacement,
    slot: PlacementSlot<Arc<ManualClock>>,
    epoch: AuthorizationEpoch,
    model: ModelId,
}

impl Sandbox {
    fn launch(sizes: Sizes) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let mut ledger = Ledger::new(
            Arc::clone(&clock),
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
        let mut demand = BTreeMap::new();
        let mut declare = |resource: ResourceKey, total: u64| {
            ledger
                .declare_capacity(
                    resource,
                    CapacityDeclaration {
                        total,
                        supervisor_reserve: 0,
                        unmanaged_in_use: 0,
                        source: SourceClass::HostProbe,
                    },
                )
                .unwrap();
            ledger.set_tenant_budget(tenant(), resource, total).unwrap();
        };
        for (device, total, sandbox) in &sizes.gpus {
            declare(vram_of(*device), *total);
            demand.insert(
                CoordinatedResource::GpuMemoryBytes { device: *device },
                *sandbox,
            );
        }
        if let Some((total, sandbox)) = sizes.host {
            declare(host_ram(), total);
            demand.insert(CoordinatedResource::HostMemoryBytes, sandbox);
        }
        if let Some((total, sandbox)) = sizes.pinned {
            declare(pinned_ram(), total);
            demand.insert(CoordinatedResource::PinnedHostMemoryBytes, sandbox);
        }

        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
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
        let admitted = RuntimeRequirement::VmSandbox.admit(&offer).unwrap();

        let mut host = Coordinator::new(
            Arc::clone(&clock),
            registry.session(),
            LedgerCapacity::new(ledger),
        );
        let plan = LaunchPlan {
            execution: owner(),
            tenant: tenant(),
            runtime: admitted,
            demand,
            priority: ReservationPriority::Foreground,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        };
        let LaunchOutcome::AuthorityActive { grant, .. } =
            host.launch(plan, &mut ReadyVms, &registry).unwrap()
        else {
            panic!("the sandbox launches");
        };
        host.start_running(&owner()).unwrap();
        let epoch = host.sandbox(&owner()).unwrap().generations().authorization;
        let model = ModelId::new(digest("yougori/test/model-id/v1", &[b"chat"]));
        let state = CoordinatorPlacement::new(CoordinatorBinding {
            execution: owner(),
            model,
            settings: RuntimeSettings {
                execution_category: ExecutionCategory::VmSandbox,
                network: BTreeSet::new(),
                authority: grant,
                artifact_verification: ArtifactVerification::Verified {
                    artifacts: BTreeSet::new(),
                },
                loader: BTreeSet::new(),
                batch_size: NonZeroU32::new(8).unwrap(),
                residency: Residency::Device,
            },
            cancel_within: 5 * SECOND,
            release_source: SourceClass::GuestReport,
        });
        let slot = PlacementSlot::new(
            SlotSpec {
                slot: slot_id(),
                tenant: tenant(),
                authority: AuthorityBinding::new(
                    owner(),
                    ExecutionCategory::VmSandbox,
                    Some(epoch),
                )
                .unwrap(),
            },
            Arc::clone(&clock),
        );
        Self {
            clock,
            host,
            state,
            slot,
            epoch,
            model,
        }
    }

    /// What the sandbox reservation has not carved into children.
    fn room(&self, resource: ResourceKey) -> u64 {
        let key = self.host.sandbox(&owner()).unwrap().reservation().unwrap();
        let capacity = self.host.capacity();
        let id = capacity.record(&key).unwrap().id();
        capacity.ledger().parent_room(id, resource).unwrap()
    }

    fn activations(&self) -> &ModelActivations {
        self.host.model_activations(&owner(), self.model).unwrap()
    }

    fn begin(&mut self, request: &ActivationRequest) -> ActivationStarted {
        self.slot
            .begin_activation(request, &mut self.state.port(&mut self.host))
            .unwrap()
    }

    fn load(&mut self) -> ExtentProgress {
        let progress = self
            .slot
            .prepare_extents(&mut self.state.port(&mut self.host))
            .unwrap();
        for (extent, _) in &progress.allocated {
            self.slot.record_extent_usable(*extent).unwrap();
        }
        self.slot.record_runtime_initialized().unwrap();
        self.slot.materialize().unwrap();
        progress
    }

    fn validate_and_publish(&mut self) -> PublishReport {
        self.slot.begin_activating().unwrap();
        let activation = self.slot.activation().unwrap();
        for waiting in activation.waiting_ranks {
            let mut port = self.state.port(&mut self.host);
            self.slot
                .record_validation(&validation(activation.generation, waiting.get()), &mut port)
                .unwrap();
            self.slot
                .record_readiness(activation.generation, waiting, &ready(), &mut port)
                .unwrap();
        }
        self.slot
            .publish(&mut self.state.port(&mut self.host))
            .unwrap()
    }

    fn activate(&mut self, request: &ActivationRequest) -> PublishReport {
        self.begin(request);
        self.load();
        self.validate_and_publish()
    }

    fn admit(&mut self, name: &str) -> RequestTicket {
        let admission = AdmissionRequest {
            request: op(name),
            execution: owner(),
            epoch: self.epoch,
            shape: RequestShape {
                context_tokens: 1_024,
                batch_sequences: 1,
            },
            adapter: None,
            lease_expires_at: self.clock.now().saturating_add(HOUR),
        };
        self.slot
            .admit(&admission, &mut self.state.port(&mut self.host))
            .unwrap()
    }

    fn park_and_reclaim(&mut self, placement: PlacementKey) -> ReclaimReport {
        self.slot.park(placement).unwrap();
        self.slot
            .reclaim(placement, &mut self.state.port(&mut self.host))
            .unwrap()
    }
}

/// The holding of `name`'s weights in the slot.
fn weights_of(sandbox: &Sandbox, name: &str) -> HoldingId {
    sandbox.state.weights_holding(&extent(name)).unwrap()
}

/// The allocation generation of a GPU holding.
fn allocation_of(holding: HoldingId) -> crate::foundation::ids::GpuAllocationGeneration {
    match holding {
        HoldingId::Gpu { allocation } => allocation,
        HoldingId::Host { .. } => panic!("not GPU memory"),
    }
}

/// The holdings of `activation` that are its own memory, not weights held apart.
fn own_holdings(
    activations: &ModelActivations,
    activation: crate::foundation::ids::ModelActivationGeneration,
) -> BTreeSet<HoldingId> {
    activations
        .activation(activation)
        .unwrap()
        .holdings()
        .iter()
        .copied()
        .filter(|holding| {
            activations
                .holding(*holding)
                .is_some_and(|entry| !entry.holds_weights())
        })
        .collect()
}

/// The weights holdings the coordinator still holds for the model: how many, and their
/// bytes.
fn held_weights(sandbox: &Sandbox) -> (usize, u64) {
    sandbox
        .activations()
        .holdings()
        .iter()
        .filter(|holding| holding.holds_weights() && holding.state() == GpuReservationState::Held)
        .fold((0, 0), |(count, bytes), holding| match holding.memory() {
            HoldingMemory::Gpu { memory_bytes, .. } => (count + 1, bytes + memory_bytes),
            HoldingMemory::Host { .. } => (count, bytes),
        })
}

#[test]
fn shared_weights_count_once_while_versions_overlap() {
    let mut sandbox = Sandbox::launch(one_gpu(32 * GB, 30 * GB));
    let vram = vram_of(gpu(0));
    let first = sandbox.activate(&request("model-a", &model_a(), &[]));
    // A's four extents are the model's weights, 10 GB in a holding each; its own memory is
    // the other 2 GB of its steady state and the 1 GB peak.
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB);
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));
    let shared: BTreeSet<HoldingId> = ["a-embed", "a-layer-0", "a-head"]
        .into_iter()
        .map(|name| weights_of(&sandbox, name))
        .collect();
    let a_layer_1 = weights_of(&sandbox, "a-layer-1");
    let first_own = own_holdings(sandbox.activations(), first.generation);
    assert_eq!(first_own.len(), 1);

    // A request's lease is the coordinator's and carries every generation.
    let old = sandbox.admit("old");
    let record = sandbox.host.lease_record(old.lease).unwrap();
    let binding = record.lease().model().unwrap();
    assert_eq!(binding.generations.activation, first.generation);
    assert_eq!(record.lease().sandbox().authorization, sandbox.epoch);

    // Model B shares three of A's extents: it acquires their weights and reserves only its
    // own layer 1 (4 GB) and its own memory (2 GB + a 1 GB peak), 7 GB. A's own memory, its
    // KV and contexts, is never acquired.
    let started = sandbox.begin(&request("model-b", &model_b(), &[]));
    assert_eq!(started.mode, TransitionMode::Overlap);
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB - 7 * GB);
    let handle = sandbox.state.current().unwrap().clone();
    let b_layer_1 = weights_of(&sandbox, "b-layer-1");
    let mut expected = shared.clone();
    expected.insert(b_layer_1);
    assert_eq!(handle.acquired, expected);
    assert!(!handle.acquired.contains(&a_layer_1));
    assert!(first_own.is_disjoint(&handle.acquired));
    assert_eq!(handle.allocated.len(), 1);
    // The new extent lives in its weights' own allocation.
    let progress = sandbox.load();
    assert_eq!(
        progress.allocated,
        vec![(extent("b-layer-1"), allocation_of(b_layer_1))]
    );
    let second = sandbox.validate_and_publish();
    assert_eq!(
        sandbox
            .activations()
            .activation(first.generation)
            .unwrap()
            .state(),
        ActivationState::Draining
    );
    assert!(sandbox.host.check_lease(old.lease).is_ok());

    // The last old request ends; the coordinator retires the first activation.
    sandbox
        .slot
        .finish(&old, &mut sandbox.state.port(&mut sandbox.host))
        .unwrap();
    assert_eq!(
        sandbox
            .activations()
            .activation(first.generation)
            .unwrap()
            .state(),
        ActivationState::Retired {
            reason: RetireReason::Replaced
        }
    );
    // Reclaiming the first placement releases its own memory and the weights only it read;
    // the weights B reads stay, counted once.
    sandbox.park_and_reclaim(first.placement);
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB);
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));
    for holding in first_own.iter().chain([&a_layer_1]) {
        assert_eq!(
            sandbox.activations().holding(*holding).unwrap().state(),
            GpuReservationState::Released
        );
    }
    for holding in &expected {
        assert_eq!(
            sandbox.activations().holding(*holding).unwrap().state(),
            GpuReservationState::Held
        );
    }
    assert_eq!(sandbox.state.weights_holding(&extent("a-layer-1")), None);

    // Reclaiming the second placement closes everything; its record and the ledger agree
    // that nothing is left.
    sandbox.slot.begin_draining(second.placement).unwrap();
    sandbox.park_and_reclaim(second.placement);
    assert_eq!(sandbox.room(vram), 30 * GB);
    assert!(sandbox
        .activations()
        .holdings()
        .iter()
        .all(|holding| holding.state() == GpuReservationState::Released));
    assert!(sandbox.state.weights().is_empty());
}

#[test]
fn weights_count_once_across_a_b_a() {
    let mut sandbox = Sandbox::launch(one_gpu(32 * GB, 30 * GB));
    let vram = vram_of(gpu(0));
    let a = sandbox.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB);
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));

    // B, an update of A's layer 1, adds only that layer's weights beside its own memory.
    let b = sandbox.activate(&request("model-b", &model_b(), &[]));
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB - 7 * GB);
    assert_eq!(held_weights(&sandbox), (5, 14 * GB));

    // Back to A while A's first placement still drains: every extent of A is resident, so
    // its weights are acquired and none is reserved again; only its own memory is new.
    let again = sandbox.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB - 7 * GB - 3 * GB);
    assert_eq!(held_weights(&sandbox), (5, 14 * GB));
    assert_eq!(sandbox.state.current().unwrap().allocated.len(), 1);
    for name in ["a-embed", "a-layer-0", "a-layer-1", "a-head"] {
        assert!(sandbox
            .activations()
            .activation(again.generation)
            .unwrap()
            .holdings()
            .contains(&weights_of(&sandbox, name)));
    }

    // Reclaiming A's first placement and B leaves A's weights once with the last
    // placement's own memory.
    sandbox.park_and_reclaim(a.placement);
    assert_eq!(held_weights(&sandbox), (5, 14 * GB));
    sandbox.park_and_reclaim(b.placement);
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));
    assert_eq!(sandbox.room(vram), 30 * GB - 13 * GB);
    assert_eq!(
        sandbox
            .activations()
            .serving()
            .unwrap()
            .generations()
            .activation,
        again.generation
    );
}

#[test]
fn drain_first_hands_the_old_own_memory_over_and_shares_the_weights() {
    // A takes 10 GB of weights, 4 GB of its own and a 1 GB peak: 15 of the sandbox's 20 GB.
    let mut sandbox = Sandbox::launch(one_gpu(24 * GB, 20 * GB));
    let vram = vram_of(gpu(0));
    let mut a = request("model-a", &model_a(), &[]);
    a.steady.vram_bytes.insert(gpu(0), 14 * GB);
    let first = sandbox.activate(&a);
    assert_eq!(sandbox.room(vram), 5 * GB);

    // B shares three extents and adds 4 GB of weights. Beside A it would need 4 GB of
    // weights and 5 GB of its own; only 5 GB is free, so A drains first.
    let mut b = request("model-b", &model_b(), &[]);
    b.steady.vram_bytes.insert(gpu(0), 14 * GB);
    let started = sandbox.begin(&b);
    assert_eq!(started.mode, TransitionMode::DrainFirst);
    assert!(started.pause.is_some());
    // B's own layer is reserved now; its own memory is A's, handed over once A is
    // reclaimed, so nothing more is reserved.
    assert_eq!(sandbox.room(vram), GB);
    assert_eq!(
        sandbox
            .activations()
            .activation(started.generation)
            .unwrap()
            .awaiting_handover(),
        Some(first.generation)
    );

    // Until the handover, nothing computes early on memory not yet the successor's.
    let pending = AssignedRequest {
        request: op("pending"),
        execution: owner(),
        epoch: sandbox.epoch,
        required: [at(0, Component::Layer(0))].into_iter().collect(),
        lease_expires_at: sandbox.clock.now().saturating_add(HOUR),
    };
    assert_eq!(
        sandbox
            .slot
            .assign_early_request(&pending, &mut sandbox.state.port(&mut sandbox.host)),
        Err(EarlyRefusal::LeaseRefused {
            refusal: CoordinationRefusal::HandoverPending {
                predecessor: first.generation
            }
        })
    );

    // The shared extents are acquired at once; the new one waits for A's reclamation.
    let waiting = sandbox
        .slot
        .prepare_extents(&mut sandbox.state.port(&mut sandbox.host))
        .unwrap();
    assert_eq!(waiting.acquired.len(), 3);
    assert_eq!(waiting.waiting_for_predecessor, vec![extent("b-layer-1")]);
    // A's own memory passes to B without returning to the ledger; A's layer 1, which only
    // A read, is released.
    sandbox.park_and_reclaim(first.placement);
    assert_eq!(sandbox.room(vram), 5 * GB);
    assert_eq!(
        sandbox
            .activations()
            .activation(started.generation)
            .unwrap()
            .awaiting_handover(),
        None
    );
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));

    let progress = sandbox.load();
    assert_eq!(
        progress.allocated,
        vec![(
            extent("b-layer-1"),
            allocation_of(weights_of(&sandbox, "b-layer-1"))
        )]
    );
    let report = sandbox.validate_and_publish();
    assert_eq!(
        report.pause.unwrap().outcome,
        Some(PauseOutcome::Resumed {
            generation: started.generation
        })
    );
    assert_eq!(
        sandbox
            .activations()
            .serving()
            .unwrap()
            .generations()
            .activation,
        started.generation
    );
    assert_eq!(sandbox.room(vram), 5 * GB);
}

#[test]
fn weights_only_a_successor_reads_must_fit_beside_its_predecessor() {
    // Model C shares nothing with A: its 10 GB of weights are the model's and never handed
    // over, so they must fit beside A even when A would drain first. They do not; the
    // activation is refused at step 1, nothing stays reserved and A keeps serving.
    let mut sandbox = Sandbox::launch(one_gpu(24 * GB, 20 * GB));
    let vram = vram_of(gpu(0));
    let first = sandbox.activate(&request("model-a", &model_a(), &[]));
    assert_eq!(sandbox.room(vram), 7 * GB);
    let other = [
        part(Component::Embedding, "c-embed", GB),
        part(Component::Layer(0), "c-layer-0", 4 * GB),
        part(Component::Layer(1), "c-layer-1", 4 * GB),
        part(Component::OutputHead, "c-head", GB),
    ];
    let refused = sandbox
        .slot
        .begin_activation(
            &request("model-c", &other, &[]),
            &mut sandbox.state.port(&mut sandbox.host),
        )
        .unwrap_err();
    assert!(
        matches!(
            refused,
            ActivationError::Reservation {
                refusal: ReservationRefusal::Capacity { .. },
                mode: TransitionMode::DrainFirst,
            }
        ),
        "{refused:?}"
    );
    assert_eq!(sandbox.room(vram), 7 * GB);
    assert_eq!(held_weights(&sandbox), (4, 10 * GB));
    assert!(sandbox
        .state
        .weights_holding(&extent("c-layer-0"))
        .is_none());
    assert_eq!(
        sandbox.slot.published().unwrap().generation,
        first.generation
    );
    assert!(sandbox.slot.active_pause().is_none());
}

#[test]
fn several_devices_and_host_memory_reserve_as_one_activation() {
    let mut sandbox = Sandbox::launch(Sizes {
        gpus: vec![(gpu(0), 24 * GB, 16 * GB), (gpu(1), 24 * GB, 16 * GB)],
        host: Some((64 * GB, 8 * GB)),
        pinned: Some((8 * GB, 2 * GB)),
    });
    let parts = [
        part_on(0, Component::Embedding, "m-embed", GB),
        part_on(0, Component::Layer(0), "m-layer-0", 4 * GB),
        part_on(1, Component::Layer(1), "m-layer-1", 4 * GB),
        part_on(1, Component::OutputHead, "m-head", GB),
    ];
    let mut request = request("model-m", &parts, &[]);
    request.steady.host_ram_bytes = 4 * GB;
    request.steady.pinned_host_bytes = GB;

    let started = sandbox.begin(&request);
    let handle = sandbox.state.current().unwrap().clone();
    assert_eq!(handle.allocated.len(), 2);
    assert_ne!(handle.allocated[&gpu(0)], handle.allocated[&gpu(1)]);
    let holdings = sandbox
        .activations()
        .activation(started.generation)
        .unwrap()
        .holdings()
        .clone();
    assert_eq!(
        holdings.len(),
        7,
        "a weights holding per extent, its own GPU allocation per device and host memory"
    );
    assert!(holdings
        .iter()
        .any(|holding| matches!(holding, HoldingId::Host { .. })));
    // Per device: 5 GB of weights + 2 GB + a 1 GB peak.
    assert_eq!(sandbox.room(vram_of(gpu(0))), 16 * GB - 8 * GB);
    assert_eq!(sandbox.room(vram_of(gpu(1))), 16 * GB - 8 * GB);
    // Pinned bytes are host RAM too (decisions T08 and P02): 4 GB pageable + 1 GB pinned.
    assert_eq!(sandbox.room(host_ram()), 8 * GB - 5 * GB);
    assert_eq!(sandbox.room(pinned_ram()), 2 * GB - GB);

    // Each extent lives in its own weights' allocation, on its rank's device.
    let progress = sandbox.load();
    for (extent, allocation) in &progress.allocated {
        assert_eq!(
            *allocation,
            allocation_of(sandbox.state.weights_holding(extent).unwrap())
        );
    }
    let report = sandbox.validate_and_publish();
    let identities = sandbox
        .slot
        .placement_identities(report.generation)
        .unwrap();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[&rank(0)], identities[&rank(1)]);
}

#[test]
fn a_parked_placement_reactivates_without_a_new_reservation() {
    let mut sandbox = Sandbox::launch(one_gpu(32 * GB, 30 * GB));
    let memory = vram_of(gpu(0));
    let first = sandbox.activate(&request("model-a", &model_a(), &[]));
    sandbox.slot.begin_draining(first.placement).unwrap();
    sandbox.slot.park(first.placement).unwrap();
    let room = sandbox.room(memory);
    let open = sandbox.host.capacity().ledger().open_reservations().count();

    // The placement's memory already holds its steady state and a 1 GB transition peak.
    let again = reuse(request("model-a", &model_a(), &[]), first.placement);
    let started = sandbox.begin(&again);
    assert_eq!(sandbox.room(memory), room);
    assert_eq!(
        sandbox.host.capacity().ledger().open_reservations().count(),
        open
    );
    let handle = sandbox.state.current().unwrap().clone();
    assert!(handle.allocated.is_empty());
    assert_eq!(
        &handle.acquired,
        sandbox
            .activations()
            .activation(first.generation)
            .unwrap()
            .holdings()
    );

    let progress = sandbox.load();
    assert!(progress.allocated.is_empty() && progress.acquired.is_empty());
    let report = sandbox.validate_and_publish();
    assert_eq!(report.placement, first.placement);
    assert_eq!(
        sandbox
            .activations()
            .serving()
            .unwrap()
            .generations()
            .activation,
        started.generation
    );
    assert_eq!(
        sandbox
            .activations()
            .activation(first.generation)
            .unwrap()
            .state(),
        ActivationState::Retired {
            reason: RetireReason::Replaced
        }
    );

    // A larger transition peak than the placement holds reserves only the difference.
    sandbox.slot.begin_draining(first.placement).unwrap();
    sandbox.slot.park(first.placement).unwrap();
    let room = sandbox.room(memory);
    let mut larger = reuse(request("model-a", &model_a(), &[]), first.placement);
    larger.transition_peak = vram(gpu(0), 3 * GB);
    sandbox.begin(&larger);
    assert_eq!(sandbox.room(memory), room - 2 * GB);
    let handle = sandbox.state.current().unwrap();
    assert_eq!(handle.allocated.len(), 1);
    assert!(handle.acquired.contains(&HoldingId::Gpu {
        allocation: first_allocation(&sandbox, first.generation)
    }));
}

/// The GPU allocation an activation reserved first.
fn first_allocation(
    sandbox: &Sandbox,
    activation: crate::foundation::ids::ModelActivationGeneration,
) -> crate::foundation::ids::GpuAllocationGeneration {
    sandbox
        .activations()
        .activation(activation)
        .unwrap()
        .holdings()
        .iter()
        .find_map(|holding| match holding {
            HoldingId::Gpu { allocation } => Some(*allocation),
            HoldingId::Host { .. } => None,
        })
        .unwrap()
}

#[test]
fn execute_while_load_runs_under_a_preparation_lease_and_publishes_after_activation() {
    let mut sandbox = Sandbox::launch(one_gpu(32 * GB, 30 * GB));
    let parts = [
        part(Component::Layer(0), "c-layer-0", 2 * GB),
        part(Component::Layer(1), "c-layer-1", 2 * GB),
        part(Component::OutputHead, "c-head", GB),
    ];
    let chain = [
        at(0, Component::Layer(0)),
        at(0, Component::Layer(1)),
        at(0, Component::OutputHead),
    ];
    let started = sandbox.begin(&request("model-c", &parts, &[]));
    let progress = sandbox
        .slot
        .prepare_extents(&mut sandbox.state.port(&mut sandbox.host))
        .unwrap();
    let assigned = AssignedRequest {
        request: op("pending"),
        execution: owner(),
        epoch: sandbox.epoch,
        required: chain.into_iter().collect(),
        lease_expires_at: sandbox.clock.now().saturating_add(HOUR),
    };
    let ticket = sandbox
        .slot
        .assign_early_request(&assigned, &mut sandbox.state.port(&mut sandbox.host))
        .unwrap();
    let record = sandbox.host.lease_record(ticket.lease).unwrap();
    assert_eq!(record.lease().kind(), CoordinatedLeaseKind::Preparation);
    assert_eq!(
        record.lease().model().unwrap().generations.activation,
        started.generation
    );

    for (extent, _) in &progress.allocated {
        sandbox.slot.record_extent_usable(*extent).unwrap();
    }
    for position in chain {
        sandbox
            .slot
            .start_early_compute(&op("pending"), position)
            .unwrap();
        sandbox
            .slot
            .finish_early_compute(&op("pending"), position)
            .unwrap();
    }
    assert_eq!(
        sandbox
            .slot
            .release_early_result(&op("pending"), &sandbox.state.port(&mut sandbox.host)),
        Err(EarlyRefusal::AwaitingPublication)
    );
    assert!(sandbox.host.check_result_publication(ticket.lease).is_err());

    sandbox.slot.record_runtime_initialized().unwrap();
    sandbox.slot.materialize().unwrap();
    sandbox.validate_and_publish();
    let result = sandbox
        .slot
        .release_early_result(&op("pending"), &sandbox.state.port(&mut sandbox.host))
        .unwrap();
    assert_eq!(result.generation, started.generation);
    assert!(sandbox.host.check_result_publication(ticket.lease).is_ok());
}

#[test]
fn a_drain_deadline_ends_the_old_generations_leases() {
    let mut sandbox = Sandbox::launch(one_gpu(32 * GB, 30 * GB));
    let vram = vram_of(gpu(0));
    let first = sandbox.activate(&request("model-a", &model_a(), &[]));
    let old = sandbox.admit("old");

    // A serving placement's leases are never ended this way.
    assert_eq!(
        sandbox
            .slot
            .end_leases(first.placement, &mut sandbox.state.port(&mut sandbox.host)),
        Err(SlotError::NotDraining {
            placement: first.placement,
            state: StateKind::Serving
        })
    );

    // Once it drains and its deadline has passed, every lease still held ends: the
    // request may publish nothing more, and the placement is drained.
    sandbox.slot.begin_draining(first.placement).unwrap();
    let ended = sandbox
        .slot
        .end_leases(first.placement, &mut sandbox.state.port(&mut sandbox.host))
        .unwrap();
    assert_eq!(
        ended,
        vec![EndedLease {
            request: op("old"),
            generation: first.generation,
            lease: old.lease,
            status: LeaseStatus::Released,
        }]
    );
    assert!(sandbox.host.check_result_publication(old.lease).is_err());
    assert!(sandbox
        .slot
        .drain_status(first.placement, &sandbox.state.port(&mut sandbox.host))
        .unwrap()
        .is_drained());
    sandbox.park_and_reclaim(first.placement);
    assert_eq!(sandbox.room(vram), 30 * GB);
}
