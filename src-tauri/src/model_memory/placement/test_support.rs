//! Fixtures for the slot scenario tests: devices, T07 identities, models, activation
//! requests and a world of fake ports driven by a manual clock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{FakePorts, FakeReservations};
use super::*;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId,
    GpuDeviceKey, ManualClock, ModelActivationGeneration, MonotonicTime, OperationId, TenantId,
};
use crate::model_memory::identity::{
    AdapterIdentity, AdapterRecipe, AdapterSpec, ArtifactIdentity, AuthorityBinding, CodePolicy,
    CommitId, CompileConfiguration, Dtype, ExecutionIdentity, ExecutionSpec, ImmutableRevision,
    Label, LogicalModelSpec, Quantization, RankTopology, RelativePath, SourceFile, SourceIdentity,
    SourceLocation, SourceSpec, VersionedName,
};

pub(super) const GB: u64 = 1 << 30;
pub(super) const SECOND: Duration = Duration::from_secs(1);
pub(super) const HOUR: Duration = Duration::from_secs(3_600);
pub(super) const SHAPE: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 4,
};
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

pub(super) fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

pub(super) fn gpu(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[&[index]]),
    }
}

pub(super) fn owner() -> ExecutionId {
    ExecutionId::new("exe-owner").unwrap()
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

/// The slot's binding: a VM sandbox under authorization epoch 1.
pub(super) fn authority() -> AuthorityBinding {
    AuthorityBinding::new(
        owner(),
        ExecutionCategory::VmSandbox,
        Some(AuthorizationEpoch::FIRST),
    )
    .unwrap()
}

pub(super) fn slot_id() -> SlotId {
    SlotId::new(digest("yougori/test/slot/v1", &[b"chat"]))
}

pub(super) fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

/// The T07 source identity of a published model or adapter named `name`.
fn source_of(name: &str) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(&format!("example-org/{name}")),
        },
        revision: ImmutableRevision::Commit(CommitId::new(COMMIT).unwrap()),
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: 1_000,
            content: ContentKey::of(name.as_bytes()),
        }],
        configuration: digest("yougori/test/configuration/v1", &[name.as_bytes()]),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap()
}

/// The T07 execution identity of `model` run over `ranks` tensor-parallel ranks.
pub(super) fn execution_of(model: &str, ranks: u32) -> ExecutionIdentity {
    let logical = LogicalModelSpec {
        source: source_of(model),
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
        topology: RankTopology::new(ranks, 1, 1).unwrap(),
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

pub(super) fn artifact_of(model: &str) -> ArtifactIdentity {
    ArtifactIdentity::from_manifest_digest(&digest("yougori/test/manifest/v1", &[model.as_bytes()]))
}

pub(super) fn adapter_of(adapter: &str) -> AdapterIdentity {
    AdapterSpec {
        source: source_of(adapter),
        method: versioned("lora", "1"),
        dtype: Dtype::BFloat16,
    }
    .identity()
}

pub(super) fn extent_on(content: &str, device: GpuDeviceKey) -> ExtentKey {
    ExtentKey {
        content: ContentKey::of(content.as_bytes()),
        device,
    }
}

pub(super) fn extent(content: &str) -> ExtentKey {
    extent_on(content, gpu(0))
}

pub(super) fn rank(value: u64) -> Rank {
    Rank::new(value)
}

pub(super) fn at(rank_value: u64, component: Component) -> WeightPosition {
    WeightPosition::new(rank(rank_value), component)
}

pub(super) fn vram(device: GpuDeviceKey, bytes: u64) -> ResourceDemand {
    ResourceDemand {
        vram_bytes: [(device, bytes)].into_iter().collect(),
        host_ram_bytes: 0,
        pinned_host_bytes: 0,
    }
}

/// One part of a model on one rank.
#[derive(Clone, Debug)]
pub(super) struct Part {
    pub(super) rank: u64,
    pub(super) component: Component,
    pub(super) content: String,
    pub(super) bytes: u64,
}

pub(super) fn part(component: Component, content: &str, bytes: u64) -> Part {
    Part {
        rank: 0,
        component,
        content: content.to_owned(),
        bytes,
    }
}

pub(super) fn part_on(rank_value: u64, component: Component, content: &str, bytes: u64) -> Part {
    Part {
        rank: rank_value,
        ..part(component, content, bytes)
    }
}

/// Model A: 10 GB of weights in four parts.
pub(super) fn model_a() -> Vec<Part> {
    vec![
        part(Component::Embedding, "a-embed", GB),
        part(Component::Layer(0), "a-layer-0", 4 * GB),
        part(Component::Layer(1), "a-layer-1", 4 * GB),
        part(Component::OutputHead, "a-head", GB),
    ]
}

/// A weight update of model A: layer 1 changed, the other parts shared.
pub(super) fn model_b() -> Vec<Part> {
    let mut parts = model_a();
    parts[2] = part(Component::Layer(1), "b-layer-1", 4 * GB);
    parts
}

/// Model A's base with one adapter of 1 GB as `Component::Adapter(0)`.
pub(super) fn with_adapter(adapter: &str) -> Vec<Part> {
    let mut parts = model_a();
    parts.push(part(
        Component::Adapter(0),
        &format!("{adapter}-weights"),
        GB,
    ));
    parts
}

/// An activation request for `model` on the GPUs its parts name, with steady state of
/// the weights plus 2 GB per device and a 1 GB transition peak per device. Adapter `i`
/// of `adapters` is `Component::Adapter(i)`.
pub(super) fn request(model: &str, parts: &[Part], adapters: &[&str]) -> ActivationRequest {
    let layout: BTreeMap<Rank, GpuDeviceKey> = parts
        .iter()
        .map(|part| (rank(part.rank), gpu(part.rank as u8)))
        .collect();
    let components: Vec<ExtentSpec> = parts
        .iter()
        .map(|part| ExtentSpec {
            position: at(part.rank, part.component),
            extent: extent_on(&part.content, gpu(part.rank as u8)),
            bytes: part.bytes,
        })
        .collect();
    let mut steady = ResourceDemand::default();
    let mut peak = ResourceDemand::default();
    let mut seen = BTreeSet::new();
    for spec in &components {
        let device = spec.extent.device;
        if seen.insert(spec.extent) {
            *steady.vram_bytes.entry(device).or_insert(2 * GB) += spec.bytes;
        }
        peak.vram_bytes.insert(device, GB);
    }
    ActivationRequest {
        operation: op(&format!("activate-{model}")),
        identity: ActivationIdentity {
            execution: execution_of(model, layout.len() as u32),
            artifact: artifact_of(model),
            adapters: adapters
                .iter()
                .zip(0u32..)
                .map(|(name, index)| (index, adapter_of(name)))
                .collect(),
        },
        placement: PlacementChoice::New {
            process: ProcessInstance::new(1),
        },
        artifact: ArtifactValidity::Verified {
            artifact: artifact_of(model),
        },
        layout,
        components,
        steady,
        transition_peak: peak,
        declared_shape: SHAPE,
        preference: TransitionPreference::OverlapOrPause,
    }
}

pub(super) fn reuse(mut request: ActivationRequest, placement: PlacementKey) -> ActivationRequest {
    request.placement = PlacementChoice::Reuse { placement };
    request
}

pub(super) fn communicator() -> Digest {
    digest("yougori/test/communicator/v1", &[b"nccl"])
}

pub(super) fn validation(
    generation: ModelActivationGeneration,
    rank_value: u64,
) -> ValidationReport {
    ValidationReport {
        generation,
        rank: rank(rank_value),
        weights_verified: true,
        buffers_ready: true,
        graphs_compatible: true,
        coordination: communicator(),
    }
}

pub(super) fn ready() -> ReadinessReport {
    ReadinessReport::Ready { supported: SHAPE }
}

pub(super) fn slot_spec() -> SlotSpec {
    SlotSpec {
        slot: slot_id(),
        tenant: tenant(),
        authority: authority(),
    }
}

/// A slot on fake ports with a manual clock starting at zero.
pub(super) struct World {
    pub(super) clock: Arc<ManualClock>,
    pub(super) slot: PlacementSlot<Arc<ManualClock>>,
    pub(super) fakes: FakePorts,
}

impl World {
    /// One GPU with `vram_bytes`.
    pub(super) fn new(vram_bytes: u64) -> Self {
        Self::with_gpus(1, vram_bytes)
    }

    pub(super) fn with_gpus(count: u8, vram_bytes: u64) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let reservations = (0..count).fold(FakeReservations::new(), |fake, index| {
            fake.with_vram(gpu(index), vram_bytes)
        });
        let mut fakes = FakePorts {
            reservations,
            ..FakePorts::default()
        };
        fakes
            .coordination
            .authorize(&owner(), AuthorizationEpoch::FIRST);
        Self {
            slot: PlacementSlot::new(slot_spec(), Arc::clone(&clock)),
            clock,
            fakes,
        }
    }

    pub(super) fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    pub(super) fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    pub(super) fn vram_used(&self, index: u8) -> u64 {
        self.fakes
            .reservations
            .used(ResourceKind::Vram { device: gpu(index) })
    }

    pub(super) fn begin(&mut self, request: &ActivationRequest) -> ActivationStarted {
        self.slot
            .begin_activation(request, &mut self.fakes.ports())
            .unwrap()
    }

    /// Step 2 to the end: acquires and allocates, marks every allocated extent usable,
    /// initializes runtime state and materializes.
    pub(super) fn load(&mut self) -> ExtentProgress {
        let progress = self.slot.prepare_extents(&mut self.fakes.ports()).unwrap();
        for (extent, _) in &progress.allocated {
            self.slot.record_extent_usable(*extent).unwrap();
        }
        self.slot.record_runtime_initialized().unwrap();
        self.slot.materialize().unwrap();
        progress
    }

    /// Steps 3 and 4 on every rank.
    pub(super) fn validate_and_ready(&mut self) {
        self.slot.begin_activating().unwrap();
        let activation = self.slot.activation().unwrap();
        for waiting in activation.waiting_ranks {
            self.slot
                .record_validation(
                    &validation(activation.generation, waiting.get()),
                    &mut self.fakes.ports(),
                )
                .unwrap();
            self.slot
                .record_readiness(
                    activation.generation,
                    waiting,
                    &ready(),
                    &mut self.fakes.ports(),
                )
                .unwrap();
        }
    }

    pub(super) fn publish(&mut self) -> PublishReport {
        self.slot.publish(&mut self.fakes.ports()).unwrap()
    }

    /// Steps 1–5 when nothing has to drain first.
    pub(super) fn activate(&mut self, request: &ActivationRequest) -> PublishReport {
        let started = self.begin(request);
        assert_ne!(started.mode, TransitionMode::DrainFirst);
        self.load();
        self.validate_and_ready();
        self.publish()
    }

    pub(super) fn admission(&self, name: &str) -> AdmissionRequest {
        AdmissionRequest {
            request: op(name),
            execution: owner(),
            epoch: AuthorizationEpoch::FIRST,
            shape: RequestShape {
                context_tokens: 4_096,
                batch_sequences: 1,
            },
            adapter: None,
            lease_expires_at: self.now().saturating_add(HOUR),
        }
    }

    pub(super) fn admit(&mut self, name: &str) -> RequestTicket {
        let admission = self.admission(name);
        self.slot
            .admit(&admission, &mut self.fakes.coordination)
            .unwrap()
    }

    pub(super) fn finish(&mut self, ticket: &RequestTicket) {
        self.slot
            .finish(ticket, &mut self.fakes.coordination)
            .unwrap();
    }

    /// Drains a placement that no longer admits, parks it and reclaims it.
    pub(super) fn park_and_reclaim(&mut self, placement: PlacementKey) -> ReclaimReport {
        assert!(self
            .slot
            .drain_status(placement, &self.fakes.coordination)
            .unwrap()
            .is_drained());
        self.slot.park(placement).unwrap();
        self.slot
            .reclaim(placement, &mut self.fakes.reservations)
            .unwrap()
    }

    pub(super) fn state(&self, placement: PlacementKey) -> StateKind {
        self.slot.placement(placement).unwrap().state.kind()
    }

    pub(super) fn published_generation(&self) -> Option<ModelActivationGeneration> {
        self.slot.published().map(|content| content.generation)
    }
}

pub(super) fn keys(extents: &[ExtentKey]) -> BTreeSet<ExtentKey> {
    extents.iter().copied().collect()
}
