//! Fixtures shared by the streaming tests.

use std::sync::Arc;
use std::time::Duration;

use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, EvidencePolicy, Observation,
    ProbeRegistry, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, ContentKey, ExecutionCategory, ManualClock, MonotonicTime};
use crate::foundation::report::{RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON};
use crate::model_memory::graph::granularity::{Granularities, MappingUnitReport};
use crate::model_memory::graph::scatter_gather::ByteRange;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::overlap::ExpertId;

use super::architecture::{
    ArchitectureFamily, ArchitectureSpec, BufferSpec, ComputeCost, ExecuteWhileLoadEvidence,
    ExecutionMode, GroupRole, GroupSpec, PrefillRouting, RequestShape, StreamingModel, TensorName,
    TensorSpec,
};
use super::deadline::{ReadCostModel, StreamingBudget};

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * KIB;
pub const GB: u64 = 1_000_000_000;
pub const MAX_PROMPT: u64 = 4096;

/// How tensors are laid out in storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// Sorted by name, as safetensors headers sort keys: layer 10 precedes layer 2.
    Lexicographic,
    /// In execution order.
    Execution,
}

pub fn shape(prompt_tokens: u64) -> RequestShape {
    RequestShape {
        prompt_tokens,
        batch_sequences: 1,
    }
}

fn tensor(name: String, length_bytes: u64, index: u64, expert: Option<ExpertId>) -> TensorSpec {
    TensorSpec {
        content: ContentKey::of(name.as_bytes()),
        name: TensorName::new(name).unwrap(),
        stored: ByteRange {
            offset_bytes: 0,
            length_bytes,
        },
        extents: vec![index],
        expert,
    }
}

/// Assigns stored offsets: contiguous, in the order the layout gives.
fn lay_out(tensors: &mut [TensorSpec], layout: Layout) {
    let mut order: Vec<usize> = (0..tensors.len()).collect();
    if layout == Layout::Lexicographic {
        order.sort_by(|a, b| tensors[*a].name.cmp(&tensors[*b].name));
    }
    let mut offset = 0;
    for index in order {
        tensors[index].stored.offset_bytes = offset;
        offset += tensors[index].stored.length_bytes;
    }
}

fn layer_compute() -> ComputeCost {
    ComputeCost {
        fixed_seconds: 0.000_5,
        per_token_seconds: 0.000_02,
    }
}

/// A dense decoder: a tied embedding (tensor 0), two tensors per layer, a final norm, and
/// one rotary buffer every layer reads. Each layer stores `layer_bytes`.
pub fn dense_spec_with(layers: usize, layer_bytes: u64, layout: Layout) -> ArchitectureSpec {
    let mut tensors = vec![tensor(
        "model.embed_tokens.weight".into(),
        layer_bytes,
        0,
        None,
    )];
    for layer in 0..layers {
        for part in ["attn", "mlp"] {
            let index = tensors.len() as u64;
            tensors.push(tensor(
                format!("model.layers.{layer}.{part}.weight"),
                layer_bytes / 2,
                index,
                None,
            ));
        }
    }
    let norm = tensors.len();
    tensors.push(tensor(
        "model.norm.weight".into(),
        4 * KIB,
        norm as u64,
        None,
    ));
    lay_out(&mut tensors, layout);
    let mut groups = vec![GroupSpec {
        role: GroupRole::Embedding,
        reads: vec![0],
        experts: vec![],
        buffers: vec![],
        compute: ComputeCost {
            fixed_seconds: 0.000_1,
            per_token_seconds: 0.000_001,
        },
        activation_bytes_per_token: 8 * KIB,
    }];
    for layer in 0..layers {
        groups.push(GroupSpec {
            role: GroupRole::Layer,
            reads: vec![1 + 2 * layer, 2 + 2 * layer],
            experts: vec![],
            buffers: vec![0],
            compute: layer_compute(),
            activation_bytes_per_token: 8 * KIB,
        });
    }
    groups.push(GroupSpec {
        role: GroupRole::OutputHead,
        reads: vec![norm, 0],
        experts: vec![],
        buffers: vec![],
        compute: ComputeCost {
            fixed_seconds: 0.000_5,
            per_token_seconds: 0.000_01,
        },
        activation_bytes_per_token: 4 * KIB,
    });
    ArchitectureSpec {
        family: ArchitectureFamily::DenseDecoder,
        mode: ExecutionMode::Eager,
        extra_state: vec![],
        tensors,
        buffers: vec![BufferSpec {
            name: TensorName::new("rotary.cache").unwrap(),
            fixed_bytes: 64 * KIB,
            bytes_per_token: 256,
            init: ComputeCost {
                fixed_seconds: 0.000_1,
                per_token_seconds: 0.000_000_1,
            },
        }],
        groups,
        max_prompt_tokens: MAX_PROMPT,
    }
}

pub fn dense_spec(layers: usize, layer_bytes: u64) -> ArchitectureSpec {
    dense_spec_with(layers, layer_bytes, Layout::Execution)
}

/// An MoE decoder: a tied embedding, per layer one attention tensor and `experts` expert
/// tensors of `expert_bytes` each, and a final norm. Stored in execution order.
pub fn moe_spec(layers: usize, experts: usize, expert_bytes: u64) -> ArchitectureSpec {
    let mut tensors = vec![tensor(
        "model.embed_tokens.weight".into(),
        expert_bytes,
        0,
        None,
    )];
    let mut groups = vec![GroupSpec {
        role: GroupRole::Embedding,
        reads: vec![0],
        experts: vec![],
        buffers: vec![],
        compute: ComputeCost {
            fixed_seconds: 0.000_1,
            per_token_seconds: 0.000_001,
        },
        activation_bytes_per_token: 8 * KIB,
    }];
    for layer in 0..layers {
        let attention = tensors.len();
        tensors.push(tensor(
            format!("model.layers.{layer}.attn.weight"),
            expert_bytes,
            attention as u64,
            None,
        ));
        let mut expert_tensors = Vec::new();
        for expert in 0..experts {
            let index = tensors.len();
            tensors.push(tensor(
                format!("model.layers.{layer}.experts.{expert}.weight"),
                expert_bytes,
                index as u64,
                Some(ExpertId {
                    layer: layer as u32,
                    expert: expert as u32,
                }),
            ));
            expert_tensors.push(index);
        }
        groups.push(GroupSpec {
            role: GroupRole::Layer,
            reads: vec![attention],
            experts: expert_tensors,
            buffers: vec![],
            compute: layer_compute(),
            activation_bytes_per_token: 8 * KIB,
        });
    }
    let norm = tensors.len();
    tensors.push(tensor(
        "model.norm.weight".into(),
        4 * KIB,
        norm as u64,
        None,
    ));
    lay_out(&mut tensors, Layout::Execution);
    groups.push(GroupSpec {
        role: GroupRole::OutputHead,
        reads: vec![norm, 0],
        experts: vec![],
        buffers: vec![],
        compute: ComputeCost {
            fixed_seconds: 0.000_5,
            per_token_seconds: 0.000_01,
        },
        activation_bytes_per_token: 4 * KIB,
    });
    ArchitectureSpec {
        family: ArchitectureFamily::MoeDecoder,
        mode: ExecutionMode::Eager,
        extra_state: vec![],
        tensors,
        buffers: vec![],
        groups,
        max_prompt_tokens: MAX_PROMPT,
    }
}

/// Routes every MoE group to the experts at these positions of its expert list.
pub fn moe_routing(model: &StreamingModel, positions: &[usize]) -> PrefillRouting {
    model
        .groups()
        .iter()
        .enumerate()
        .filter(|(_, group)| !group.experts.is_empty())
        .fold(PrefillRouting::new(), |routing, (index, group)| {
            routing.route(index, positions.iter().map(|p| group.experts[*p]))
        })
}

/// A measured read path: `alpha` seconds per request and `bytes_per_second`.
pub fn read_path(alpha_seconds: f64, bytes_per_second: f64) -> ReadCostModel {
    ReadCostModel::new(
        alpha_seconds,
        &BandwidthRating::measured_directional(bytes_per_second).unwrap(),
    )
    .unwrap()
}

pub fn granularities(transport_batch_bytes: u64) -> Granularities {
    Granularities::new(
        MIB,
        128 * KIB,
        MappingUnitReport::from_driver(
            crate::foundation::ids::digest("yougori/test/streaming/allocation/v1", &[b"a"]),
            2 * MIB,
        )
        .unwrap(),
        transport_batch_bytes,
    )
    .unwrap()
}

pub fn budget(transport_batch_bytes: u64) -> StreamingBudget {
    StreamingBudget::new(&granularities(transport_batch_bytes), u64::MAX).unwrap()
}

/// CORE-08's golden record on the fake substrate: the matched configuration template.
pub fn fake_template() -> RunRecord {
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = RunSubstrate::FakeTimeControlled;
    record
}

fn runtime_named(instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/streaming/runtime/v1", &[instance.as_bytes()]),
    }
}

/// The runtime the load runs on.
pub fn runtime() -> RuntimeSubject {
    runtime_named("wsl")
}

/// Another runtime instance of the same release.
pub fn other_runtime() -> RuntimeSubject {
    runtime_named("wsl-2")
}

pub fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", "580.1"), ("profile", "p1")]).unwrap()
}

pub fn other_configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", "581.0"), ("profile", "p1")]).unwrap()
}

/// A probe registry on a manual clock, with or without ExecuteWhileLoad evidence.
pub struct EvidenceWorld {
    pub clock: Arc<ManualClock>,
    pub registry: ProbeRegistry<Arc<ManualClock>>,
    pub runtime: RuntimeSubject,
}

impl EvidenceWorld {
    /// No ExecuteWhileLoad evidence was ever observed.
    pub fn unobserved() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        Self {
            registry: ProbeRegistry::new(Arc::clone(&clock)),
            clock,
            runtime: runtime(),
        }
    }

    /// Execute-while-load observed working on [`runtime`] by `source`, fresh for an hour.
    pub fn supported(source: SourceClass) -> Self {
        let mut world = Self::unobserved();
        let probe = Arc::new(FakeProbe::new(Capability::ExecuteWhileLoad, source));
        world
            .registry
            .register(Box::new(Arc::clone(&probe)))
            .unwrap();
        let subject = Subject::Runtime(world.runtime.clone());
        probe.respond(
            &subject,
            Observation::supported(
                configuration(),
                Duration::from_secs(3_600),
                SupportDetail::ExecuteWhileLoad,
            ),
        );
        world
            .registry
            .refresh(Capability::ExecuteWhileLoad, &subject)
            .unwrap();
        world
    }

    /// What the decision reads, under a guest-report policy of one hour.
    pub fn evidence(&self) -> ExecuteWhileLoadEvidence<'_, Arc<ManualClock>> {
        ExecuteWhileLoadEvidence {
            registry: &self.registry,
            runtime: &self.runtime,
            policy: EvidencePolicy {
                minimum_source: SourceClass::GuestReport,
                max_age: Duration::from_secs(3_600),
            },
            configuration: configuration(),
        }
    }
}
