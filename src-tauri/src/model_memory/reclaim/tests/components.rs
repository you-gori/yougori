//! The sources over real components, on the real ledger: idle pinned staging rings of a
//! pinned host tier, and idle placements of real placement slots.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::foundation::ids::{AuthorizationEpoch, ContentKey};
use crate::model_memory::identity::{
    AdapterRecipe, ArtifactIdentity, AuthorityBinding, CodePolicy, CommitId, CompileConfiguration,
    Dtype, ExecutionIdentity, ExecutionSpec, ImmutableRevision, Label, LogicalModelSpec,
    Quantization, RankTopology, RelativePath, SourceFile, SourceLocation, SourceSpec,
    VersionedName,
};
use crate::model_memory::placement::fakes::FakeCoordination;
use crate::model_memory::placement::{
    ActivationIdentity, ActivationRequest, AdmissionRequest, ArtifactProblem, ArtifactValidity,
    Component, ExtentKey, ExtentSpec, LedgerPlacementConfig,
    LedgerReservations as PlacementReservations, PlacementChoice, PlacementKey, PlacementSlot,
    PlacementView, Ports, ProcessInstance, Rank, ReadinessReport, RequestShape, ResourceDemand,
    SlotId, SlotSpec, StateKind, SupportedShape, TransitionPreference, ValidationReport,
    WeightPosition,
};

/// A pinned host tier of a 4 GiB cap under 64 GiB of host RAM, where `owner` may lock
/// memory without limit.
pub(super) fn pinned_tier(owner: &Consumer) -> PinnedHostTier {
    let scope = |name: &str, kind, bytes, reserve| HostScope {
        name: name.to_string(),
        kind,
        parent: None,
        capacity: Capacity::Physical { bytes },
        safety_reserve_bytes: reserve,
        occupancy: ScopeOccupancy::default(),
    };
    let mut tier = PinnedHostTier::new(PinnedLimits {
        host_ram: scope("host-ram", HostScopeKind::HostRam, 64 * GIB, 2 * GIB),
        wsl: WslLimit::NotWsl,
        host_wide_cap: scope("pinned-cap", HostScopeKind::PinnedRam, 4 * GIB, 128 * MIB),
        memlock_reserve_bytes: MIB,
        max_ring_bytes: 256 * MIB,
    });
    tier.register_execution(owner.execution.clone(), MemlockLimit::Unlimited);
    tier
}

#[test]
fn the_scratch_step_unpins_only_idle_rings_of_a_real_pinned_tier() {
    let clock = start();
    let mut host = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        config(),
    );
    declare(&mut host, RAM, 8 * GIB);
    declare(&mut host, PINNED, 512 * MIB);
    let ledger = Arc::new(Mutex::new(host));
    let owner = Consumer {
        tenant: tenant(),
        execution: ExecutionId::new("exe-runtime").unwrap(),
        trust: TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "alpha"),
    };
    let mut tier = pinned_tier(&owner);
    let charge = LedgerCharge {
        operation: OperationId::new("op-rings").unwrap(),
        priority: Priority::Foreground,
        retry_number: 0,
    };
    let (idle, busy) = {
        let mut host = ledger.lock().unwrap();
        let idle = tier
            .pin_ring(&owner, 200 * MIB, &charge, &mut host, clock.as_ref())
            .unwrap();
        let busy = tier
            .pin_ring(&owner, 200 * MIB, &charge, &mut host, clock.as_ref())
            .unwrap();
        (idle, busy)
    };
    let idle_reservation = tier.reservation(idle).unwrap();
    let busy_reservation = tier.reservation(busy).unwrap();
    let rings = [
        RingUse {
            pin: busy,
            in_use: true,
        },
        RingUse {
            pin: idle,
            in_use: false,
        },
    ];
    let mut scratch = ReclaimUnusedScratch::new(Requester::ModelPlacement);
    let survey = scratch
        .prepare(&mut PinnedRings::new(
            &mut tier,
            &rings,
            Arc::clone(&ledger),
        ))
        .unwrap();
    assert_eq!(
        survey,
        Survey {
            free: 1,
            pinned: 0,
            leased: 1
        }
    );

    let request = ReservationRequest::new(
        provenance(Requester::Transfer, "staging"),
        Priority::Foreground,
        Amounts::new().with(PINNED, 150 * MIB).with(RAM, 150 * MIB),
    );
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut scratch as &mut dyn ModelReclaimer]);
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(request, &mut ladder)
    };
    let settlement = scratch
        .settle(
            &admission.report,
            &mut PinnedRings::new(&mut tier, &rings, Arc::clone(&ledger)),
        )
        .unwrap();

    // The idle ring is unpinned; its pinned memory counts until the host sees it freed,
    // so the request is refused for now.
    assert!(admission.admission.is_err());
    assert_eq!(settlement.awaiting_release(), [idle_reservation]);
    assert!(tier.reservation(idle).is_err());
    assert_eq!(tier.reservation(busy), Ok(busy_reservation));
    let mut host = ledger.lock().unwrap();
    assert_eq!(
        state(&host, idle_reservation),
        Some(ReservationState::Releasing)
    );
    assert_eq!(
        state(&host, busy_reservation),
        Some(ReservationState::InUse)
    );
    assert_eq!(host.reserved(PINNED), 400 * MIB);
    host.confirm_release(idle_reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(host.reserved(PINNED), 200 * MIB);
}

const GB: u64 = 1 << 30;
const SHAPE: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 4,
};

fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/gpu/v1", &[&[0]]),
    }
}

fn owner() -> ExecutionId {
    ExecutionId::new("exe-owner").unwrap()
}

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

/// The execution identity of a published single-rank model named `model`.
fn execution_of(model: &str) -> ExecutionIdentity {
    let source = SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(&format!("example-org/{model}")),
        },
        revision: ImmutableRevision::Commit(
            CommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1_000,
            content: ContentKey::of(model.as_bytes()),
        }],
        configuration: digest("yougori/test/configuration/v1", &[model.as_bytes()]),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap();
    let logical = LogicalModelSpec {
        source,
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: digest("yougori/test/tokenizer/v1", &[model.as_bytes()]),
        generation_config: digest("yougori/test/generation/v1", &[model.as_bytes()]),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
    .identity();
    ExecutionSpec {
        logical,
        runner: versioned("vllm", "0.31.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned("flash-attn", "2.7.4"),
        gpu_architectures: BTreeSet::from([label("sm_90a")]),
        topology: RankTopology::new(1, 1, 1).unwrap(),
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

fn artifact_of(model: &str) -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&digest("yougori/test/manifest/v1", &[model.as_bytes()]))
}

/// One rank of `model`, verified: 10 GB of weights, a 12 GB steady state and a 1 GB
/// transition peak.
fn activation_of(model: &str) -> ActivationRequest {
    let demand = |bytes| ResourceDemand {
        vram_bytes: [(device(), bytes)].into_iter().collect(),
        host_ram_bytes: 0,
        pinned_host_bytes: 0,
    };
    ActivationRequest {
        operation: OperationId::new(format!("activate-{model}")).unwrap(),
        identity: ActivationIdentity {
            execution: execution_of(model),
            artifact: artifact_of(model),
            adapters: BTreeMap::new(),
        },
        placement: PlacementChoice::New {
            process: ProcessInstance::new(1),
        },
        artifact: ArtifactValidity::Verified {
            artifact: artifact_of(model),
        },
        layout: BTreeMap::from([(Rank::new(0), device())]),
        components: vec![ExtentSpec {
            position: WeightPosition::new(Rank::new(0), Component::Layer(0)),
            extent: ExtentKey {
                content: ContentKey::of(format!("{model}-weights").as_bytes()),
                device: device(),
            },
            bytes: 10 * GB,
        }],
        steady: demand(12 * GB),
        transition_peak: demand(GB),
        declared_shape: SHAPE,
        preference: TransitionPreference::OverlapOrPause,
    }
}

type SharedHost = Arc<Mutex<Ledger<Arc<ManualClock>>>>;

/// A slot serving one model, whose reservations are filed at host level in the shared
/// ledger and confirmed by a host probe when the slot releases them.
struct Serving {
    slot: PlacementSlot<Arc<ManualClock>>,
    reservations: PlacementReservations,
    coordination: FakeCoordination,
    placement: PlacementKey,
}

impl Serving {
    /// Activates `model` through steps 1–5 and publishes it.
    fn activate(model: &str, clock: &Arc<ManualClock>, ledger: &SharedHost) -> Self {
        let mut reservations = PlacementReservations::new(LedgerPlacementConfig {
            tenant: tenant(),
            priority: Priority::Foreground,
            parent: None,
            release_source: SourceClass::HostProbe,
        });
        let mut coordination = FakeCoordination::new();
        coordination.authorize(&owner(), AuthorizationEpoch::FIRST);
        let spec = SlotSpec {
            slot: SlotId::new(digest("yougori/test/slot/v1", &[model.as_bytes()])),
            tenant: tenant(),
            authority: AuthorityBinding::new(
                owner(),
                ExecutionCategory::VmSandbox,
                Some(AuthorizationEpoch::FIRST),
            )
            .unwrap(),
        };
        let mut slot = PlacementSlot::new(spec, Arc::clone(clock));
        let placement = {
            let mut host = ledger.lock().unwrap();
            let mut port = reservations.port(&mut host);
            let mut ports = Ports {
                reservations: &mut port,
                coordination: &mut coordination,
            };
            let started = slot
                .begin_activation(&activation_of(model), &mut ports)
                .unwrap();
            let progress = slot.prepare_extents(&mut ports).unwrap();
            for (extent, _) in &progress.allocated {
                slot.record_extent_usable(*extent).unwrap();
            }
            slot.record_runtime_initialized().unwrap();
            slot.materialize().unwrap();
            slot.begin_activating().unwrap();
            let validation = ValidationReport {
                generation: started.generation,
                rank: Rank::new(0),
                weights_verified: true,
                buffers_ready: true,
                graphs_compatible: true,
                coordination: digest("yougori/test/communicator/v1", &[b"nccl"]),
            };
            slot.record_validation(&validation, &mut ports).unwrap();
            slot.record_readiness(
                started.generation,
                Rank::new(0),
                &ReadinessReport::Ready { supported: SHAPE },
                &mut ports,
            )
            .unwrap();
            slot.publish(&mut ports).unwrap().placement
        };
        Self {
            slot,
            reservations,
            coordination,
            placement,
        }
    }

    /// Admits one request, which holds a lease on the serving generation.
    fn admit(&mut self, clock: &ManualClock, name: &str) {
        let admission = AdmissionRequest {
            request: OperationId::new(name).unwrap(),
            execution: owner(),
            epoch: AuthorizationEpoch::FIRST,
            shape: RequestShape {
                context_tokens: 4_096,
                batch_sequences: 1,
            },
            adapter: None,
            lease_expires_at: clock.now().saturating_add(Duration::from_secs(3_600)),
        };
        self.slot.admit(&admission, &mut self.coordination).unwrap();
    }

    /// Records that the model's artifact went missing: it keeps serving from weights
    /// verified when loaded, but nothing can rebuild them any more.
    fn lose_artifact(&mut self, ledger: &SharedHost) {
        let mut host = ledger.lock().unwrap();
        let mut port = self.reservations.port(&mut host);
        let mut ports = Ports {
            reservations: &mut port,
            coordination: &mut self.coordination,
        };
        self.slot
            .record_artifact_invalid(self.placement, ArtifactProblem::Missing, &mut ports)
            .unwrap();
    }

    fn view(&self) -> PlacementView {
        self.slot.placement(self.placement).unwrap()
    }

    fn source(
        &mut self,
        ledger: &SharedHost,
    ) -> SlotParking<'_, Arc<ManualClock>, Arc<ManualClock>> {
        SlotParking::new(&mut self.slot, &mut self.reservations, Arc::clone(ledger))
    }
}

#[test]
fn parking_a_real_slot_never_touches_a_leased_model() {
    let clock = start();
    let mut host = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        config(),
    );
    declare(&mut host, gpu(), 38 * GB);
    let ledger = Arc::new(Mutex::new(host));
    // Three models of 12 GB each: one serving a request, one idle, and one idle whose
    // artifact went missing, so nothing can rebuild it.
    let mut leased = Serving::activate("leased", &clock, &ledger);
    let mut idle = Serving::activate("idle", &clock, &ledger);
    let mut unverified = Serving::activate("unverified", &clock, &ledger);
    unverified.lose_artifact(&ledger);
    leased.admit(&clock, "request-1");
    assert_eq!(leased.view().leases, 1);
    assert_eq!(ledger.lock().unwrap().reserved(gpu()), 36 * GB);

    let mut steps: Vec<ParkEligibleIdleModels<IdlePlacement>> = (0..3)
        .map(|_| ParkEligibleIdleModels::new(Requester::ModelPlacement))
        .collect();
    let surveys: Vec<Survey> = [&mut leased, &mut idle, &mut unverified]
        .into_iter()
        .zip(steps.iter_mut())
        .map(|(serving, step)| step.prepare(&mut serving.source(&ledger)).unwrap())
        .collect();
    assert_eq!(
        surveys,
        [
            Survey {
                free: 0,
                pinned: 0,
                leased: 1
            },
            Survey {
                free: 1,
                pinned: 0,
                leased: 0
            },
            Survey {
                free: 0,
                pinned: 1,
                leased: 0
            },
        ]
    );

    // A 12 GB load does not fit in the 2 GB left.
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(
            &mut ladder,
            steps.iter_mut().map(|step| step as &mut dyn ModelReclaimer),
        );
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("needs-12", 12 * GB), &mut ladder)
    };
    // The idle model's steady state is in use: it only begins releasing, so the load is
    // refused for now.
    assert!(admission.admission.is_err());
    let parking: Vec<StepOutcome> = admission
        .report
        .steps()
        .iter()
        .filter(|step| step.step == ReclaimStep::ParkEligibleIdleModels)
        .map(|step| step.outcome.clone())
        .collect();
    assert_eq!(parking.len(), 3);
    assert_eq!(
        parking[0],
        StepOutcome::Declined(DeclineReason::Held {
            pinned: 0,
            leased: 1
        })
    );
    assert!(
        matches!(&parking[1], StepOutcome::Released { refused, .. } if refused.is_empty()),
        "{:?}",
        parking[1]
    );
    assert_eq!(
        parking[2],
        StepOutcome::Declined(DeclineReason::Held {
            pinned: 1,
            leased: 0
        })
    );

    let settlements: Vec<Settlement> = [&mut leased, &mut idle, &mut unverified]
        .into_iter()
        .zip(steps.iter_mut())
        .map(|(serving, step)| {
            step.settle(&admission.report, &mut serving.source(&ledger))
                .unwrap()
        })
        .collect();
    assert!(settlements[0].is_empty() && settlements[2].is_empty());
    assert_eq!(settlements[1].stopped.len(), 1, "{:?}", settlements[1]);
    assert!(settlements[1].not_stopped.is_empty());

    // The idle model was drained, parked and reclaimed; the slot's own port confirmed
    // the release with the host probe its configuration names.
    let parked = idle.view();
    assert_eq!(parked.state.kind(), StateKind::Parked);
    assert_eq!(parked.steady_reservation, None);
    assert!(!parked.gpu.is_resident());
    // The leased model and the one nothing can rebuild still serve, untouched.
    for kept in [&leased, &unverified] {
        let view = kept.view();
        assert_eq!(view.state.kind(), StateKind::Serving);
        assert!(view.steady_reservation.is_some());
        assert!(view.gpu.is_resident());
    }
    assert_eq!(leased.view().leases, 1);
    let mut host = ledger.lock().unwrap();
    assert_eq!(host.reserved(gpu()), 24 * GB);
    assert!(matches!(
        host.reserve(load("needs-12-again", 12 * GB)),
        Ok(Admission::Granted(_))
    ));
}
