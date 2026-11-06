//! FAST-02 profile choice (S13 line 242).
//!
//! The selector chooses the graph mode, concurrent-sequence limit, batched-token budget,
//! KV representation and context from checkpoint compatibility evidence, measured free
//! GPU capacity and the request mix. Context and concurrency are exactly what the mix
//! needs and are never reduced to fit: a shortfall is a capacity refusal naming the
//! limiting GPU, not a silent downgrade. A lossy KV representation is used only where the
//! request's fidelity configuration lists it (T07, §1.3) and line 248's checks passed for
//! this model. CUDA graphs and more than one sequence go beyond today's `--enforce-eager`
//! and `--max-num-seqs 1`, and run only where the backend gate admits them for the exact
//! runtime (GPU part §3.8 later experiments); otherwise eager execution stays, and a mix
//! that needs concurrency is refused. For several GPUs, measured peer topology comes before
//! the per-process NCCL choice. Nothing is looked up by card name; every piece of evidence
//! is bound to the full hardware class.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::formats::{
    admit_kv_representation, feed_kv, kv_fidelity, KvFormatQualification, KvFormatRefusal,
};
use super::guard::{admit_runtime, admit_technique};
use super::observed::{EvidenceGap, EvidenceSource};
use super::settings::{
    CommunicationRefusal, CommunicationScope, EngineRef, GraphMode, HardwareClass, MemoryFraction,
    NcclChoice, PeerTopology, ServingSettings, SettingsError,
};
use crate::foundation::evidence::{
    AdmittedRuntime, BackendRelease, CategoryRefusal, ConfigurationFingerprint, EvidencePolicy,
    GpuDeviceSubject, ModelCheckpointSubject, ProbeRegistry, RuntimeOffer, RuntimeRequirement,
    Subject,
};
use crate::foundation::ids::{Clock, Digest, DigestBuilder};
use crate::model_memory::backends::{
    AdmittedTechnique, BackendRuntime, ExperimentApproval, Technique, TechniqueRefusal,
};
use crate::model_memory::identity::{
    Dtype, FidelityCategory, FidelityConfiguration, KvRepresentation, LogicalModelIdentity,
    LogicalModelSpec,
};

const COMPATIBILITY_RECORD_DOMAIN: &str =
    "yougori/model_memory/profiles/checkpoint-compatibility/v1";

/// What the requests a profile serves need (FAST-02 "request mix").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestMix {
    /// The longest request, prompt and output together. The chosen context is exactly this.
    pub max_request_tokens: u32,
    /// Sequences that must run at once. The chosen concurrent-sequence limit is exactly
    /// this.
    pub concurrent_sequences: u32,
    /// Requests call tools, whose semantics must be preserved.
    pub tool_calls: bool,
    /// The requester's explicit fidelity configuration (T07, §1.3). A lossy KV
    /// representation is used only where it lists that approximation with its accuracy
    /// evaluation; lossy modes are not defaults (FAST-06).
    pub fidelity: FidelityConfiguration,
}

/// Measured GPU memory outside the KV cache for one graph mode and batched-token budget:
/// weights, activation peak, captured graphs and other allocations, per GPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfiledFootprint {
    pub graph_mode: GraphMode,
    pub max_num_batched_tokens: u32,
    pub non_kv_bytes_per_device: u64,
}

/// A KV representation the engine supports for this checkpoint, with its measured size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvCacheSupport {
    pub representation: KvRepresentation,
    pub bytes_per_token_per_device: u64,
}

strict_tagged_enum! {
/// Whether tool calls keep their semantics with this checkpoint on this engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolCalls (tag = "tool_calls", wire = ToolCallsWire, wire_name = "ToolCallsWire") {
    /// Tool calls work through this parser for the model's family.
    Preserved { parser: String },
    NotSupported,
}
}

/// What one checkpoint supports on one pinned engine and hardware class (FAST-02
/// "checkpoint compatibility"). Graph modes appear only through footprints measured
/// starting, and KV representations only with a measured size per token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointCompatibility {
    pub max_position_tokens: u32,
    pub footprints: Vec<ProfiledFootprint>,
    pub kv_caches: Vec<KvCacheSupport>,
    pub tool_calls: ToolCalls,
}

impl CheckpointCompatibility {
    /// The CORE-01 subject a compatibility observation is about: the exact logical model,
    /// the pinned engine's release and image and the whole hardware class, never a card
    /// name alone.
    pub fn subject(
        model: &LogicalModelIdentity,
        engine: &EngineRef,
        hardware: &HardwareClass,
    ) -> ModelCheckpointSubject {
        ModelCheckpointSubject {
            checkpoint: *model.digest(),
            release: engine.release.clone(),
            image: engine.image,
            hardware: hardware.identity(),
        }
    }

    /// The record's identity, which CORE-01's compatibility evidence names: its positions,
    /// every measured footprint and KV representation and its tool calls. Footprints and
    /// KV representations are hashed in a fixed order, so the order they were listed in
    /// does not matter.
    pub fn digest(&self) -> Digest {
        let count = |length: usize| u64::try_from(length).unwrap_or(u64::MAX);
        let mut footprints: Vec<&ProfiledFootprint> = self.footprints.iter().collect();
        footprints.sort_by_key(|footprint| {
            (
                footprint.graph_mode,
                footprint.max_num_batched_tokens,
                footprint.non_kv_bytes_per_device,
            )
        });
        let builder = DigestBuilder::new(COMPATIBILITY_RECORD_DOMAIN)
            .u64(u64::from(self.max_position_tokens))
            .u64(count(footprints.len()));
        let builder = footprints.iter().fold(builder, |builder, footprint| {
            builder
                .str(footprint.graph_mode.tag())
                .u64(u64::from(footprint.max_num_batched_tokens))
                .u64(footprint.non_kv_bytes_per_device)
        });
        let mut supports: Vec<&KvCacheSupport> = self.kv_caches.iter().collect();
        supports.sort_by(|one, other| {
            one.representation.cmp(&other.representation).then(
                one.bytes_per_token_per_device
                    .cmp(&other.bytes_per_token_per_device),
            )
        });
        let builder =
            supports
                .iter()
                .fold(builder.u64(count(supports.len())), |builder, support| {
                    feed_kv(builder, &support.representation)
                        .u64(support.bytes_per_token_per_device)
                });
        match &self.tool_calls {
            ToolCalls::Preserved { parser } => builder.str("tool_calls_preserved").str(parser),
            ToolCalls::NotSupported => builder.str("tool_calls_not_supported"),
        }
        .finish()
    }

    /// Refuses evidence with zero sizes or repeated measurements.
    pub fn check(&self) -> Result<(), CompatibilityError> {
        if self.max_position_tokens == 0 {
            return Err(CompatibilityError::ZeroPositions);
        }
        let mut measured = BTreeSet::new();
        for footprint in &self.footprints {
            if footprint.max_num_batched_tokens == 0 || footprint.non_kv_bytes_per_device == 0 {
                return Err(CompatibilityError::ZeroFootprint {
                    graph_mode: footprint.graph_mode,
                    max_num_batched_tokens: footprint.max_num_batched_tokens,
                });
            }
            if !measured.insert((footprint.graph_mode, footprint.max_num_batched_tokens)) {
                return Err(CompatibilityError::RepeatedFootprint {
                    graph_mode: footprint.graph_mode,
                    max_num_batched_tokens: footprint.max_num_batched_tokens,
                });
            }
        }
        let mut representations = BTreeSet::new();
        for support in &self.kv_caches {
            let dtype = support.representation.dtype();
            if support.bytes_per_token_per_device == 0 {
                return Err(CompatibilityError::ZeroKvBytes { dtype });
            }
            if !representations.insert(&support.representation) {
                return Err(CompatibilityError::RepeatedKvCache { dtype });
            }
        }
        Ok(())
    }

    fn preserves_tool_calls(&self) -> bool {
        matches!(self.tool_calls, ToolCalls::Preserved { .. })
    }
}

/// Why compatibility evidence was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityError {
    ZeroPositions,
    ZeroFootprint {
        graph_mode: GraphMode,
        max_num_batched_tokens: u32,
    },
    /// Two measurements of the same graph mode and budget; neither is chosen over the
    /// other.
    RepeatedFootprint {
        graph_mode: GraphMode,
        max_num_batched_tokens: u32,
    },
    ZeroKvBytes {
        dtype: Dtype,
    },
    /// The same KV representation measured twice.
    RepeatedKvCache {
        dtype: Dtype,
    },
}

/// Measured memory of one assigned GPU, as CORE-01's free-memory evidence carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMemory {
    pub device: GpuDeviceSubject,
    pub total_bytes: u64,
    pub free_bytes: u64,
}

/// Measured free capacity of the assigned GPUs, in tensor-parallel rank order (FAST-02
/// "measured free capacity"), read device by device from CORE-01.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredCapacity {
    pub devices: Vec<DeviceMemory>,
}

impl MeasuredCapacity {
    /// Refuses a measurement of other GPUs, of zero memory, or with more free than total.
    pub fn check(&self, devices: &[GpuDeviceSubject]) -> Result<(), CapacityError> {
        if self.devices.len() != devices.len()
            || self
                .devices
                .iter()
                .zip(devices)
                .any(|(measured, assigned)| measured.device != *assigned)
        {
            return Err(CapacityError::OtherDevices);
        }
        for (index, device) in self.devices.iter().enumerate() {
            if device.total_bytes == 0 || device.free_bytes > device.total_bytes {
                return Err(CapacityError::Implausible {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                    free_bytes: device.free_bytes,
                    total_bytes: device.total_bytes,
                });
            }
        }
        Ok(())
    }
}

/// Why a capacity measurement was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityError {
    /// The measurement does not cover exactly the assigned GPUs, in order.
    OtherDevices,
    Implausible {
        index: u32,
        free_bytes: u64,
        total_bytes: u64,
    },
}

/// One profile choice to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRequest {
    /// The logical model (T07): source, dtype and quantization, tokenizer and generation
    /// configuration. KV fidelity is judged against it.
    pub model: LogicalModelSpec,
    pub engine: EngineRef,
    pub hardware: HardwareClass,
    /// The assigned GPUs, in tensor-parallel rank order; the tensor-parallel size is
    /// their count.
    pub devices: Vec<GpuDeviceSubject>,
    /// What the request allows of the runtime's execution category (INT-07).
    pub requirement: RuntimeRequirement,
    /// The runtime the profile runs in, with CORE-01 evidence of its category; a profile
    /// never changes that category (S13 line 252).
    pub runtime: RuntimeOffer,
    /// The same runtime as the backend gate knows it (GPU part §3.8).
    pub backend: BackendRuntime,
    /// Approved later experiments, such as CUDA graphs or concurrency, each for one exact
    /// release.
    pub approvals: Vec<ExperimentApproval>,
    /// The configuration in force; evidence observed under another no longer applies.
    pub configuration: ConfigurationFingerprint,
    pub mix: RequestMix,
    /// The most of each GPU's memory the engine may take (today 0.90).
    pub memory_target: MemoryFraction,
}

impl ProfileRequest {
    /// Refuses a request that cannot describe a run.
    pub fn check(&self) -> Result<(), RequestError> {
        if self.mix.concurrent_sequences == 0 {
            return Err(RequestError::ZeroSequences);
        }
        if self.mix.max_request_tokens == 0 {
            return Err(RequestError::ZeroTokens);
        }
        let count = u32::try_from(self.devices.len()).map_err(|_| RequestError::TooManyDevices)?;
        if count == 0 {
            return Err(RequestError::NoDevices);
        }
        if count != self.hardware.gpu_count {
            return Err(RequestError::DeviceCountMismatch {
                devices: count,
                gpu_count: self.hardware.gpu_count,
            });
        }
        let distinct: BTreeSet<Digest> = self
            .devices
            .iter()
            .map(|device| Subject::GpuDevice(*device).identity())
            .collect();
        if distinct.len() != self.devices.len() {
            return Err(RequestError::RepeatedDevice);
        }
        if count == 1 && self.hardware.topology != PeerTopology::single().identity() {
            return Err(RequestError::SingleGpuWithPeers);
        }
        Ok(())
    }
}

/// Why a request was refused before any evidence was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    ZeroSequences,
    ZeroTokens,
    NoDevices,
    TooManyDevices,
    DeviceCountMismatch {
        devices: u32,
        gpu_count: u32,
    },
    RepeatedDevice,
    /// One GPU whose hardware class names a multi-GPU topology.
    SingleGpuWithPeers,
}

/// The evidence one choice reads (FAST-02): the CORE-01 registry that judges checkpoint
/// compatibility, each assigned GPU's free memory and the runtime's peer topology, the
/// checkpoint's measured compatibility record, which the registry's evidence names by
/// [digest](CheckpointCompatibility::digest), and line 248's KV qualifications.
pub struct ServingEvidence<'a, C: Clock> {
    pub registry: &'a ProbeRegistry<C>,
    pub compatibility: &'a CheckpointCompatibility,
    /// Line 248 qualifications for lossy KV representations.
    pub kv_qualifications: &'a [KvFormatQualification],
}

/// Source and age each serving fact needs; CORE-01 raises a source below a capability's
/// floor to it, so free memory comes only from a host probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicy {
    pub compatibility: EvidencePolicy,
    pub capacity: EvidencePolicy,
    pub topology: EvidencePolicy,
}

/// One combination the selector tried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub graph_mode: GraphMode,
    pub max_num_batched_tokens: u32,
    pub kv: KvRepresentation,
}

/// Something the selector tried before its choice, and why it could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PassedOver {
    /// A backend technique the gate did not admit; every candidate needing it was skipped
    /// (GPU part §3.8).
    Technique { refusal: TechniqueRefusal },
    /// A KV representation that could not be used at all.
    KvCache {
        kv: KvRepresentation,
        refusal: KvFormatRefusal,
    },
    /// One combination that could not be used.
    Candidate {
        candidate: Candidate,
        reason: CandidateRejection,
    },
}

/// Why one combination could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateRejection {
    /// The budget cannot hold one token of every concurrent sequence.
    BudgetBelowSequences,
    /// Non-KV memory plus KV for every sequence at full context exceeds the budget of the
    /// limiting GPU.
    Memory {
        needed_bytes_per_device: u64,
        budget_bytes_per_device: u64,
    },
}

/// The selector's choice.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileChoice {
    pub settings: ServingSettings,
    pub runtime: AdmittedRuntime,
    /// Every technique the settings need beyond today's flags, in the order of
    /// [`ServingSettings::techniques`], each admitted by the backend gate for this exact
    /// runtime (GPU part §3.8), so the two gates agree.
    pub techniques: Vec<AdmittedTechnique>,
    /// Lossless representation unless a lossy KV representation the request configured
    /// was needed to fit (T07 categories; line 250).
    pub fidelity: FidelityCategory,
    pub needed_bytes_per_device: u64,
    /// The memory fraction's share of the limiting GPU.
    pub budget_bytes_per_device: u64,
    pub limiting_device: GpuDeviceSubject,
    /// Everything tried before the choice, each with its reason; nothing is skipped
    /// silently.
    pub passed_over: Vec<PassedOver>,
}

/// The mix does not fit the measured capacity with any supported combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityShortfall {
    /// The GPU whose budget is smallest.
    pub device: GpuDeviceSubject,
    /// The least any combination needs per GPU.
    pub needed_bytes_per_device: u64,
    pub budget_bytes_per_device: u64,
    pub free_bytes: u64,
    pub passed_over: Vec<PassedOver>,
}

/// Why no profile was chosen. Each is a refusal; none is followed by a weaker profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileRefusal {
    InvalidRequest {
        error: RequestError,
    },
    /// The request does not allow the runtime's category (INT-07, S13 line 252).
    Category {
        refusal: CategoryRefusal,
    },
    /// The offered runtime runs another backend release than the pinned engine.
    RuntimeForOtherEngine {
        runtime: BackendRelease,
        engine: BackendRelease,
    },
    /// The backend runtime is not the offered runtime.
    BackendForOtherRuntime,
    /// The mix needs more than one sequence, and the backend gate did not admit
    /// concurrency: the single sequence stays, and these requests are refused (GPU part
    /// §3.8).
    TechniqueNotAdmitted {
        refusal: TechniqueRefusal,
    },
    Evidence {
        gap: EvidenceGap,
    },
    InvalidCompatibility {
        error: CompatibilityError,
    },
    InvalidCapacity {
        error: CapacityError,
    },
    /// The measured topology is not the one the hardware class names.
    TopologyMismatch {
        measured: Digest,
        hardware_class: Digest,
    },
    Communication {
        refusal: CommunicationRefusal,
    },
    /// The mix needs a longer context than the checkpoint supports.
    ContextBeyondCheckpoint {
        requested_tokens: u32,
        max_position_tokens: u32,
    },
    /// The mix calls tools and this checkpoint and engine do not preserve them.
    ToolSemantics,
    Capacity {
        shortfall: CapacityShortfall,
    },
    /// No combination is supported for reasons other than memory.
    NoSupportedCandidate {
        passed_over: Vec<PassedOver>,
    },
    Settings {
        error: SettingsError,
    },
}

impl fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { error } => {
                write!(f, "the profile request is invalid: {error:?}")
            }
            Self::Category { refusal } => write!(f, "{refusal}"),
            Self::RuntimeForOtherEngine { runtime, engine } => write!(
                f,
                "the runtime runs {runtime}, and this profile is for {engine}"
            ),
            Self::BackendForOtherRuntime => {
                f.write_str("the backend gate describes another runtime than the one offered")
            }
            Self::TechniqueNotAdmitted { refusal } => write!(f, "{refusal}"),
            Self::Evidence { gap } => write!(f, "{gap}"),
            Self::InvalidCompatibility { error } => {
                write!(f, "the compatibility evidence is invalid: {error:?}")
            }
            Self::InvalidCapacity { error } => {
                write!(f, "the capacity measurement is invalid: {error:?}")
            }
            Self::TopologyMismatch { .. } => f.write_str(
                "the measured peer topology differs from this hardware class; settings are not \
                 carried between topologies",
            ),
            Self::Communication { refusal } => write!(f, "{refusal}"),
            Self::ContextBeyondCheckpoint {
                requested_tokens,
                max_position_tokens,
            } => write!(
                f,
                "the requests need {requested_tokens} tokens of context, and this checkpoint \
                 supports {max_position_tokens}"
            ),
            Self::ToolSemantics => f.write_str(
                "the requests call tools, and this checkpoint on this engine does not preserve \
                 tool calls; nothing is served without them",
            ),
            Self::Capacity { shortfall } => write!(
                f,
                "the requests need {} bytes on each GPU and the limiting GPU allows {} bytes \
                 ({} free); context and concurrency are not reduced to fit",
                shortfall.needed_bytes_per_device,
                shortfall.budget_bytes_per_device,
                shortfall.free_bytes
            ),
            Self::NoSupportedCandidate { .. } => f.write_str(
                "no measured graph mode, budget and KV representation supports these requests",
            ),
            Self::Settings { error } => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ProfileRefusal {}

/// FAST-02 profile choice under one evidence policy.
#[derive(Clone, Copy, Debug)]
pub struct ProfileSelector {
    policy: SelectionPolicy,
}

impl ProfileSelector {
    /// A selector reading every serving fact from CORE-01 under `policy`.
    pub fn new(policy: SelectionPolicy) -> Self {
        Self { policy }
    }

    /// Chooses settings for `request`, or refuses.
    ///
    /// In order: the evidenced runtime must be admitted, run the pinned engine's release
    /// and be the backend gate's runtime; CORE-01 must hold checkpoint-compatibility
    /// evidence about this logical model, engine and hardware class that names the given
    /// record, and host-measured free memory of each assigned GPU; for several GPUs, the
    /// runtime's measured peer topology must match the hardware class before the
    /// per-process NCCL choice; the checkpoint must support the context and, when needed,
    /// tool calls; more than one sequence needs the gate to admit concurrency. Combinations
    /// are then tried lossless KV first, captured graphs before eager where the gate admits
    /// CUDA graphs, larger measured budgets first, and the first that fits is chosen. The
    /// memory fraction is the target lowered to what every GPU has free, and the choice
    /// carries the techniques the gate admitted for it.
    pub fn select<C: Clock>(
        &self,
        request: &ProfileRequest,
        evidence: &ServingEvidence<'_, C>,
    ) -> Result<ProfileChoice, ProfileRefusal> {
        request
            .check()
            .map_err(|error| ProfileRefusal::InvalidRequest { error })?;
        let runtime = admit_runtime(&request.requirement, &request.runtime)
            .map_err(|refusal| ProfileRefusal::Category { refusal })?;
        if runtime.runtime().release != request.engine.release {
            return Err(ProfileRefusal::RuntimeForOtherEngine {
                runtime: runtime.runtime().release.clone(),
                engine: request.engine.release.clone(),
            });
        }
        if request.backend.plan().runtime() != runtime.runtime() {
            return Err(ProfileRefusal::BackendForOtherRuntime);
        }
        let source = EvidenceSource {
            registry: evidence.registry,
            configuration: request.configuration,
        };
        let model = request.model.identity();
        let compatibility = evidence.compatibility;
        source
            .compatibility(
                CheckpointCompatibility::subject(&model, &request.engine, &request.hardware),
                compatibility.digest(),
                self.policy.compatibility,
            )
            .map_err(|gap| ProfileRefusal::Evidence { gap })?;
        compatibility
            .check()
            .map_err(|error| ProfileRefusal::InvalidCompatibility { error })?;
        let devices = request
            .devices
            .iter()
            .map(|device| {
                source.free_memory(*device, self.policy.capacity).map(
                    |(free_bytes, total_bytes)| DeviceMemory {
                        device: *device,
                        total_bytes,
                        free_bytes,
                    },
                )
            })
            .collect::<Result<Vec<DeviceMemory>, EvidenceGap>>()
            .map_err(|gap| ProfileRefusal::Evidence { gap })?;
        let capacity = MeasuredCapacity { devices };
        capacity
            .check(&request.devices)
            .map_err(|error| ProfileRefusal::InvalidCapacity { error })?;
        let nccl = self.nccl_choice(request, &source, &runtime)?;

        let mix = &request.mix;
        if mix.max_request_tokens > compatibility.max_position_tokens {
            return Err(ProfileRefusal::ContextBeyondCheckpoint {
                requested_tokens: mix.max_request_tokens,
                max_position_tokens: compatibility.max_position_tokens,
            });
        }
        if mix.tool_calls && !compatibility.preserves_tool_calls() {
            return Err(ProfileRefusal::ToolSemantics);
        }

        // More than today's single sequence needs the gate's approval; without it the
        // requests are refused, never served one at a time.
        let concurrency = if mix.concurrent_sequences > 1 {
            let admitted =
                admit_technique(&request.backend, Technique::Concurrency, &request.approvals)
                    .map_err(|refusal| ProfileRefusal::TechniqueNotAdmitted { refusal })?;
            Some(admitted)
        } else {
            None
        };

        let budget = Budget::of(&capacity.devices, request.memory_target).ok_or(
            ProfileRefusal::InvalidCapacity {
                error: CapacityError::OtherDevices,
            },
        )?;
        let mut passed_over = Vec::new();
        let mut footprints = ordered_footprints(&compatibility.footprints);
        let mut graphs = None;
        if footprints
            .iter()
            .any(|footprint| footprint.graph_mode.technique().is_some())
        {
            match admit_technique(&request.backend, Technique::CudaGraphs, &request.approvals) {
                Ok(admitted) => graphs = Some(admitted),
                Err(refusal) => {
                    footprints.retain(|footprint| footprint.graph_mode.technique().is_none());
                    passed_over.push(PassedOver::Technique { refusal });
                }
            }
        }
        let mut least_needed: Option<u64> = None;
        for support in ordered_kv(&request.model, &compatibility.kv_caches) {
            let kv = &support.representation;
            let fidelity = match admit_kv_representation(
                &mix.fidelity,
                &request.model,
                &request.engine,
                kv,
                evidence.kv_qualifications,
            ) {
                Ok(fidelity) => fidelity,
                Err(refusal) => {
                    passed_over.push(PassedOver::KvCache {
                        kv: kv.clone(),
                        refusal,
                    });
                    continue;
                }
            };
            for footprint in footprints.iter().copied() {
                let candidate = Candidate {
                    graph_mode: footprint.graph_mode,
                    max_num_batched_tokens: footprint.max_num_batched_tokens,
                    kv: kv.clone(),
                };
                if footprint.max_num_batched_tokens < mix.concurrent_sequences {
                    passed_over.push(PassedOver::Candidate {
                        candidate,
                        reason: CandidateRejection::BudgetBelowSequences,
                    });
                    continue;
                }
                let needed =
                    needed_bytes_per_device(footprint, support.bytes_per_token_per_device, mix);
                let fraction = match budget.fraction {
                    Some(fraction) if needed <= budget.bytes => fraction,
                    _ => {
                        least_needed = Some(least_needed.map_or(needed, |least| least.min(needed)));
                        passed_over.push(PassedOver::Candidate {
                            candidate,
                            reason: CandidateRejection::Memory {
                                needed_bytes_per_device: needed,
                                budget_bytes_per_device: budget.bytes,
                            },
                        });
                        continue;
                    }
                };
                let settings = ServingSettings {
                    graph_mode: footprint.graph_mode,
                    max_num_seqs: mix.concurrent_sequences,
                    max_num_batched_tokens: footprint.max_num_batched_tokens,
                    kv_cache: kv.clone(),
                    context_tokens: mix.max_request_tokens,
                    tensor_parallel_size: request.hardware.gpu_count,
                    gpu_memory: fraction,
                    nccl,
                    drafting: None,
                };
                settings
                    .check()
                    .map_err(|error| ProfileRefusal::Settings { error })?;
                // A captured graph mode is left only when the gate admitted CUDA graphs.
                let techniques = footprint
                    .graph_mode
                    .technique()
                    .and(graphs)
                    .into_iter()
                    .chain(concurrency)
                    .collect();
                return Ok(ProfileChoice {
                    settings,
                    runtime,
                    techniques,
                    fidelity,
                    needed_bytes_per_device: needed,
                    budget_bytes_per_device: budget.bytes,
                    limiting_device: budget.device,
                    passed_over,
                });
            }
        }
        match least_needed {
            Some(needed) => Err(ProfileRefusal::Capacity {
                shortfall: CapacityShortfall {
                    device: budget.device,
                    needed_bytes_per_device: needed,
                    budget_bytes_per_device: budget.bytes,
                    free_bytes: budget.free_bytes,
                    passed_over,
                },
            }),
            None => Err(ProfileRefusal::NoSupportedCandidate { passed_over }),
        }
    }

    fn nccl_choice<C: Clock>(
        &self,
        request: &ProfileRequest,
        source: &EvidenceSource<'_, C>,
        runtime: &AdmittedRuntime,
    ) -> Result<Option<NcclChoice>, ProfileRefusal> {
        if request.devices.len() < 2 {
            return Ok(None);
        }
        let topology = source
            .topology(runtime.runtime(), self.policy.topology)
            .map_err(|gap| ProfileRefusal::Evidence { gap })?;
        let measured = topology.identity();
        if measured != request.hardware.topology {
            return Err(ProfileRefusal::TopologyMismatch {
                measured,
                hardware_class: request.hardware.topology,
            });
        }
        NcclChoice::from_topology(&topology, CommunicationScope::EngineProcess)
            .map(Some)
            .map_err(|refusal| ProfileRefusal::Communication { refusal })
    }
}

/// The memory fraction and the smallest per-GPU budget it gives.
struct Budget {
    /// `None` when some GPU has less than a thousandth free.
    fraction: Option<MemoryFraction>,
    bytes: u64,
    device: GpuDeviceSubject,
    free_bytes: u64,
}

impl Budget {
    /// A GPU with under a thousandth free is the limit outright. Otherwise the fraction
    /// is the target lowered to what every GPU has free, and the limit is the GPU with
    /// the smallest share, the one with less free memory on a tie.
    fn of(devices: &[DeviceMemory], target: MemoryFraction) -> Option<Self> {
        let largest_free = |device: &DeviceMemory| {
            MemoryFraction::largest_free(device.free_bytes, device.total_bytes)
        };
        if let Some(starved) = devices.iter().find(|device| largest_free(device).is_none()) {
            return Some(Self {
                fraction: None,
                bytes: 0,
                device: starved.device,
                free_bytes: starved.free_bytes,
            });
        }
        let fraction = devices
            .iter()
            .filter_map(largest_free)
            .fold(target, Ord::min);
        devices
            .iter()
            .map(|device| (fraction.of_bytes(device.total_bytes), device))
            .min_by_key(|(bytes, device)| (*bytes, device.free_bytes))
            .map(|(bytes, device)| Self {
                fraction: Some(fraction),
                bytes,
                device: device.device,
                free_bytes: device.free_bytes,
            })
    }
}

/// KV representations in trial order: lossless ones first, then lossy ones from the most
/// bits to the fewest, in a fixed order on a tie.
fn ordered_kv<'a>(
    model: &LogicalModelSpec,
    supports: &'a [KvCacheSupport],
) -> Vec<&'a KvCacheSupport> {
    let rank = |support: &KvCacheSupport| {
        (
            kv_fidelity(model, &support.representation) != FidelityCategory::LosslessRepresentation,
            Reverse(support.representation.dtype().bits()),
        )
    };
    let mut ordered: Vec<&KvCacheSupport> = supports.iter().collect();
    ordered.sort_by(|one, other| {
        rank(one)
            .cmp(&rank(other))
            .then_with(|| one.representation.cmp(&other.representation))
    });
    ordered
}

/// Footprints in trial order: graph modes by [`GraphMode::PREFERENCE`], larger budgets
/// first.
fn ordered_footprints(footprints: &[ProfiledFootprint]) -> Vec<&ProfiledFootprint> {
    let rank = |mode: GraphMode| {
        GraphMode::PREFERENCE
            .iter()
            .position(|preferred| *preferred == mode)
            .unwrap_or(GraphMode::PREFERENCE.len())
    };
    let mut ordered: Vec<&ProfiledFootprint> = footprints.iter().collect();
    ordered.sort_by(|one, other| {
        rank(one.graph_mode).cmp(&rank(other.graph_mode)).then(
            other
                .max_num_batched_tokens
                .cmp(&one.max_num_batched_tokens),
        )
    });
    ordered
}

/// Measured non-KV memory plus KV for every concurrent sequence at full context, so the
/// mix runs without preempting a sequence.
fn needed_bytes_per_device(
    footprint: &ProfiledFootprint,
    kv_bytes_per_token: u64,
    mix: &RequestMix,
) -> u64 {
    let kv = u128::from(kv_bytes_per_token)
        .saturating_mul(u128::from(mix.concurrent_sequences))
        .saturating_mul(u128::from(mix.max_request_tokens));
    let needed = kv.saturating_add(u128::from(footprint.non_kv_bytes_per_device));
    u64::try_from(needed).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{
        Backend, Capability, EvidenceRefusal, Observation, SourceClass, Staleness, UnknownReason,
        UnsupportedReason,
    };
    use crate::foundation::ids::ExecutionCategory;
    use crate::model_memory::identity::{FidelityRefusal, Quantization};
    use crate::model_memory::profiles::formats::{CheckResult, KvCheck};
    use crate::model_memory::profiles::observed::ServingFact;
    use crate::model_memory::profiles::settings::{PeerAccess, PeerToPeer};
    use crate::model_memory::profiles::testkit::{
        allowing, approval, approvals, backend_for, backend_runtime, compatibility,
        compatibility_script, configuration, d, device, engine, fp4_kv, fp8_kv, free_memory_script,
        kv, labelled_requirement, logical_spec, mix, model_kv, offer, offer_for, qualification,
        registry_with, runtime, single_gpu, start_clock, topology_script, two_gpu_topology,
        two_gpus, Script, GIB,
    };
    use std::time::Duration;

    const MINUTE: Duration = Duration::from_secs(60);
    /// 0.90 of 24 GiB, rounded down.
    const BUDGET: u64 = 23_192_823_398;

    fn policy() -> SelectionPolicy {
        let fresh = EvidencePolicy {
            minimum_source: SourceClass::GuestReport,
            max_age: MINUTE,
        };
        SelectionPolicy {
            compatibility: fresh,
            capacity: fresh,
            topology: fresh,
        }
    }

    /// One or two 24 GiB GPUs, a BF16 checkpoint with 32,768 positions whose measured
    /// footprints are 18 GiB (piecewise graphs, 8,192 tokens), 17 GiB (piecewise, 2,048)
    /// and 15 GiB (eager, 2,048), KV of 128 KiB per token in BF16 and 64 KiB in FP8, and
    /// a mix of 2 sequences of 8,192 tokens under a lossless configuration. CORE-01 holds
    /// host-probe evidence of the record, each GPU's memory and, for two GPUs, the
    /// runtime's topology.
    struct Fixture {
        request: ProfileRequest,
        compatibility: CheckpointCompatibility,
        /// The hardware class the compatibility evidence is about.
        compatibility_hardware: HardwareClass,
        capacity: MeasuredCapacity,
        topology: Option<PeerTopology>,
        qualifications: Vec<KvFormatQualification>,
    }

    impl Fixture {
        fn request(hardware: HardwareClass, devices: Vec<GpuDeviceSubject>) -> ProfileRequest {
            ProfileRequest {
                model: logical_spec(),
                engine: engine(),
                hardware,
                devices,
                requirement: labelled_requirement(),
                runtime: offer(ExecutionCategory::SharedKernelGpuRuntime),
                backend: backend_runtime(),
                approvals: approvals(),
                configuration: configuration(),
                mix: mix(8_192, 2),
                memory_target: MemoryFraction::new(900).unwrap(),
            }
        }

        fn single() -> Self {
            Self::for_request(
                Self::request(single_gpu(), vec![device(0)]),
                free(&[24 * GIB]),
            )
        }

        fn two_with(topology: PeerTopology) -> Self {
            let request = Self::request(two_gpus(&topology), vec![device(0), device(1)]);
            let mut fixture = Self::for_request(request, free(&[24 * GIB, 24 * GIB]));
            fixture.topology = Some(topology);
            fixture
        }

        fn two() -> Self {
            Self::two_with(two_gpu_topology(PeerAccess::Verified))
        }

        fn for_request(request: ProfileRequest, capacity: MeasuredCapacity) -> Self {
            Self {
                compatibility: compatibility(),
                compatibility_hardware: request.hardware.clone(),
                capacity,
                topology: None,
                qualifications: Vec::new(),
                request,
            }
        }

        /// What CORE-01 holds: the compatibility evidence naming this fixture's record,
        /// each measured GPU's memory and the runtime's topology.
        fn scripts(&self) -> Vec<Script> {
            let mut scripts = vec![compatibility_script(
                &self.compatibility_hardware,
                self.compatibility.digest(),
            )];
            scripts.extend(self.capacity.devices.iter().map(|measured| {
                free_memory_script(measured.device, measured.free_bytes, measured.total_bytes)
            }));
            if let Some(topology) = &self.topology {
                scripts.push(topology_script(
                    runtime(ExecutionCategory::SharedKernelGpuRuntime),
                    topology,
                ));
            }
            scripts
        }

        /// Chooses with a registry holding `scripts`, `elapsed` after they were observed.
        fn select_with(
            &self,
            scripts: &[Script],
            elapsed: Duration,
        ) -> Result<ProfileChoice, ProfileRefusal> {
            let clock = start_clock();
            let registry = registry_with(clock.clone(), scripts);
            clock.advance(elapsed);
            ProfileSelector::new(policy()).select(
                &self.request,
                &ServingEvidence {
                    registry: &registry,
                    compatibility: &self.compatibility,
                    kv_qualifications: &self.qualifications,
                },
            )
        }

        fn select(&self) -> Result<ProfileChoice, ProfileRefusal> {
            self.select_with(&self.scripts(), Duration::ZERO)
        }

        fn shortfall(&self) -> CapacityShortfall {
            match self.select() {
                Err(ProfileRefusal::Capacity { shortfall }) => shortfall,
                other => panic!("expected a capacity refusal, got {other:?}"),
            }
        }

        /// Adds a measured KV representation of `bytes` per token.
        fn support(&mut self, representation: KvRepresentation, bytes: u64) {
            self.compatibility.kv_caches.push(KvCacheSupport {
                representation,
                bytes_per_token_per_device: bytes,
            });
        }
    }

    /// The selection refused for `fact` with CORE-01's `refusal`.
    fn refused(
        fact: ServingFact,
        refusal: EvidenceRefusal,
    ) -> Result<ProfileChoice, ProfileRefusal> {
        Err(ProfileRefusal::Evidence {
            gap: EvidenceGap::Refused { fact, refusal },
        })
    }

    /// Fully free GPUs of these sizes, as devices 0, 1, ...
    fn free(totals: &[u64]) -> MeasuredCapacity {
        MeasuredCapacity {
            devices: totals
                .iter()
                .enumerate()
                .map(|(index, total)| DeviceMemory {
                    device: device(u32::try_from(index).unwrap()),
                    total_bytes: *total,
                    free_bytes: *total,
                })
                .collect(),
        }
    }

    fn candidates(passed_over: &[PassedOver]) -> Vec<Candidate> {
        passed_over
            .iter()
            .filter_map(|passed| match passed {
                PassedOver::Candidate { candidate, .. } => Some(candidate.clone()),
                PassedOver::KvCache { .. } | PassedOver::Technique { .. } => None,
            })
            .collect()
    }

    fn refused_kv(
        passed_over: &[PassedOver],
        wanted: &KvRepresentation,
    ) -> Option<KvFormatRefusal> {
        passed_over.iter().find_map(|passed| match passed {
            PassedOver::KvCache { kv, refusal } if kv == wanted => Some(refusal.clone()),
            _ => None,
        })
    }

    fn candidate(graph_mode: GraphMode, budget: u32, kv: KvRepresentation) -> Candidate {
        Candidate {
            graph_mode,
            max_num_batched_tokens: budget,
            kv,
        }
    }

    /// The techniques the backend gate admitted for a choice.
    fn admitted_techniques(choice: &ProfileChoice) -> Vec<Technique> {
        choice
            .techniques
            .iter()
            .map(AdmittedTechnique::technique)
            .collect()
    }

    #[test]
    fn chooses_from_compatibility_capacity_and_mix() {
        let choice = Fixture::single().select().unwrap();
        let settings = &choice.settings;
        // Full graphs were not measured for this checkpoint; piecewise graphs were.
        assert_eq!(settings.graph_mode, GraphMode::PiecewiseCudaGraphs);
        // The largest measured budget that fits.
        assert_eq!(settings.max_num_batched_tokens, 8_192);
        assert_eq!(settings.max_num_seqs, 2);
        assert_eq!(settings.context_tokens, 8_192);
        assert_eq!(settings.kv_cache, model_kv());
        assert_eq!(choice.fidelity, FidelityCategory::LosslessRepresentation);
        assert_eq!(settings.tensor_parallel_size, 1);
        assert_eq!(settings.gpu_memory.permille(), 900);
        assert_eq!(settings.nccl, None);
        assert_eq!(settings.drafting, None);
        // 18 GiB of footprint plus 128 KiB x 2 sequences x 8,192 tokens of KV.
        assert_eq!(choice.needed_bytes_per_device, 20 * GIB);
        assert_eq!(choice.budget_bytes_per_device, BUDGET);
        assert_eq!(choice.limiting_device, device(0));
        assert_eq!(
            choice.runtime.category(),
            ExecutionCategory::SharedKernelGpuRuntime
        );
        // Captured graphs and two sequences, each admitted by the backend gate on the
        // pinned release.
        assert_eq!(
            admitted_techniques(&choice),
            vec![Technique::CudaGraphs, Technique::Concurrency]
        );
        assert_eq!(admitted_techniques(&choice), settings.techniques());
        assert!(choice
            .techniques
            .iter()
            .all(|admitted| *admitted.release() == engine().release));
        assert!(choice.passed_over.is_empty());
    }

    #[test]
    fn a_larger_mix_takes_a_smaller_budget_or_eager_rather_than_less_context() {
        // 2 x 16,384 tokens is 4 GiB of KV: 22 GiB at the 8,192 budget does not fit the
        // 21.6 GiB budget, 21 GiB at 2,048 does.
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(16_384, 2);
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::PiecewiseCudaGraphs);
        assert_eq!(choice.settings.max_num_batched_tokens, 2_048);
        assert_eq!(choice.settings.context_tokens, 16_384);
        assert_eq!(
            choice.passed_over,
            vec![PassedOver::Candidate {
                candidate: candidate(GraphMode::PiecewiseCudaGraphs, 8_192, model_kv()),
                reason: CandidateRejection::Memory {
                    needed_bytes_per_device: 22 * GIB,
                    budget_bytes_per_device: BUDGET,
                },
            }]
        );
        // 3 x 16,384 tokens is 6 GiB of KV: only eager (15 GiB) fits.
        fixture.request.mix = mix(16_384, 3);
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::Eager);
        assert_eq!(choice.settings.max_num_seqs, 3);
        assert_eq!(choice.needed_bytes_per_device, 21 * GIB);
        assert_eq!(candidates(&choice.passed_over).len(), 2);
    }

    #[test]
    fn capacity_shortfall_is_a_refusal_not_a_downgrade() {
        // 4 x 16,384 tokens is 8 GiB of KV; even eager needs 23 GiB against 21.6 GiB. A
        // shorter context, fewer sequences or FP8 KV would fit, and none is chosen.
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(16_384, 4);
        let shortfall = fixture.shortfall();
        assert_eq!(shortfall.device, device(0));
        assert_eq!(shortfall.needed_bytes_per_device, 23 * GIB);
        assert_eq!(shortfall.budget_bytes_per_device, BUDGET);
        assert_eq!(shortfall.free_bytes, 24 * GIB);
        assert_eq!(
            candidates(&shortfall.passed_over),
            vec![
                candidate(GraphMode::PiecewiseCudaGraphs, 8_192, model_kv()),
                candidate(GraphMode::PiecewiseCudaGraphs, 2_048, model_kv()),
                candidate(GraphMode::Eager, 2_048, model_kv()),
            ]
        );
        // FP8 KV was not configured, so T07 refused it.
        assert!(matches!(
            refused_kv(&shortfall.passed_over, &fp8_kv()),
            Some(KvFormatRefusal::Fidelity {
                refusal: FidelityRefusal::NotExplicitlyConfigured { .. }
            })
        ));
        assert!(ProfileRefusal::Capacity { shortfall }
            .to_string()
            .contains("context and concurrency are not reduced to fit"));
    }

    #[test]
    fn memory_fraction_follows_measured_free_memory() {
        // 20 of 24 GiB free: the fraction drops from 0.90 to 0.833, and the 8,192 budget
        // (20 GiB) no longer fits its 21,466,246,545 bytes.
        let mut fixture = Fixture::single();
        fixture.capacity.devices[0].free_bytes = 20 * GIB;
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.gpu_memory.permille(), 833);
        assert_eq!(choice.budget_bytes_per_device, 21_466_246_545);
        assert_eq!(choice.settings.max_num_batched_tokens, 2_048);
        // The fraction never rises above the target, however much is free.
        let mut capped = Fixture::single();
        capped.request.memory_target = MemoryFraction::new(500).unwrap();
        assert_eq!(capped.shortfall().budget_bytes_per_device, 12 * GIB);
        // A GPU with under a thousandth free is named as the limit.
        let mut full = Fixture::two();
        full.capacity.devices[1].free_bytes = 1024;
        let shortfall = full.shortfall();
        assert_eq!(shortfall.device, device(1));
        assert_eq!(shortfall.budget_bytes_per_device, 0);
        assert_eq!(shortfall.free_bytes, 1024);
        // Equal budgets name the GPU with less free memory.
        let mut uneven = Fixture::two();
        uneven.capacity.devices[1].free_bytes = 23 * GIB;
        uneven.request.mix = mix(16_384, 4);
        assert_eq!(uneven.shortfall().device, device(1));
    }

    #[test]
    fn lossy_kv_only_when_configured_and_qualified() {
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(16_384, 4);
        fixture.request.mix.fidelity = allowing(&fp8_kv());
        // Configured with its accuracy evaluation, but not qualified for this model.
        assert_eq!(
            refused_kv(&fixture.shortfall().passed_over, &fp8_kv()),
            Some(KvFormatRefusal::NotQualified {
                kv: Box::new(fp8_kv())
            })
        );
        // Qualified: FP8 halves the KV to 4 GiB, and 21 GiB fits at the 2,048 budget.
        fixture.qualifications = vec![qualification(fp8_kv())];
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.kv_cache, fp8_kv());
        assert_eq!(choice.fidelity, FidelityCategory::ApproximateInference);
        assert_eq!(choice.settings.context_tokens, 16_384);
        assert_eq!(choice.settings.max_num_seqs, 4);
        assert_eq!(choice.settings.max_num_batched_tokens, 2_048);
        // Every lossless combination was tried first.
        let tried = candidates(&choice.passed_over);
        assert_eq!(
            tried.iter().filter(|tried| tried.kv == model_kv()).count(),
            3
        );
        assert_eq!(tried.len(), 4);
        // Where lossless KV fits, a configured lossy representation is not used.
        let mut roomy = Fixture::single();
        roomy.request.mix.fidelity = allowing(&fp8_kv());
        roomy.qualifications = vec![qualification(fp8_kv())];
        let choice = roomy.select().unwrap();
        assert_eq!(choice.settings.kv_cache, model_kv());
        assert_eq!(choice.fidelity, FidelityCategory::LosslessRepresentation);
    }

    #[test]
    fn fp4_kv_is_refused_without_per_model_support() {
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(16_384, 4);
        fixture.request.mix.fidelity = allowing(&fp4_kv());
        fixture.support(fp4_kv(), 32 * 1024);
        let mut unsupported = qualification(fp4_kv());
        unsupported.per_model_support = CheckResult::NotChecked;
        fixture.qualifications = vec![unsupported];
        assert_eq!(
            refused_kv(&fixture.shortfall().passed_over, &fp4_kv()),
            Some(KvFormatRefusal::CheckNotPassed {
                kv: Box::new(fp4_kv()),
                check: KvCheck::PerModelSupport,
                result: CheckResult::NotChecked,
            })
        );
        // FP4 without its exact scheme is refused by T07 before any per-model check.
        let unscaled = kv(Dtype::Float4E2M1, Quantization::None);
        fixture.support(unscaled.clone(), 32 * 1024);
        assert!(matches!(
            refused_kv(&fixture.shortfall().passed_over, &unscaled),
            Some(KvFormatRefusal::Fidelity {
                refusal: FidelityRefusal::NarrowDtypeWithoutScheme { .. }
            })
        ));
        // With per-model support and the other checks passed, 2 GiB of FP4 KV fits.
        fixture.qualifications = vec![qualification(fp4_kv())];
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.kv_cache, fp4_kv());
        assert_eq!(choice.settings.max_num_batched_tokens, 8_192);
    }

    #[test]
    fn unmeasured_modes_and_budgets_are_not_assumed() {
        // Without any measured footprint there is nothing to choose.
        let mut unmeasured = Fixture::single();
        unmeasured.compatibility.footprints.clear();
        let Err(ProfileRefusal::NoSupportedCandidate { passed_over }) = unmeasured.select() else {
            panic!("expected no supported candidate");
        };
        assert!(candidates(&passed_over).is_empty());
        // A concurrency above every measured budget.
        let mut wide = Fixture::single();
        wide.request.mix = mix(16, 10_000);
        let Err(ProfileRefusal::NoSupportedCandidate { passed_over }) = wide.select() else {
            panic!("expected no supported candidate");
        };
        assert_eq!(candidates(&passed_over).len(), 3);
        assert!(passed_over.iter().all(|passed| !matches!(
            passed,
            PassedOver::Candidate {
                reason: CandidateRejection::Memory { .. },
                ..
            }
        )));
        // A KV representation the evidence does not list is never a candidate.
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(16_384, 4);
        fixture.request.mix.fidelity = allowing(&fp4_kv());
        fixture.qualifications = vec![qualification(fp4_kv())];
        assert_eq!(
            refused_kv(&fixture.shortfall().passed_over, &fp4_kv()),
            None
        );
    }

    #[test]
    fn context_beyond_the_checkpoint_refuses() {
        let mut fixture = Fixture::single();
        fixture.request.mix = mix(65_536, 1);
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::ContextBeyondCheckpoint {
                requested_tokens: 65_536,
                max_position_tokens: 32_768,
            })
        );
    }

    #[test]
    fn a_tool_semantics_gap_refuses() {
        let mut fixture = Fixture::single();
        fixture.request.mix.tool_calls = true;
        fixture.compatibility.tool_calls = ToolCalls::NotSupported;
        assert_eq!(fixture.select(), Err(ProfileRefusal::ToolSemantics));
        fixture.compatibility.tool_calls = ToolCalls::Preserved {
            parser: "hermes".to_owned(),
        };
        assert!(fixture.select().is_ok());
    }

    #[test]
    fn several_gpus_need_topology_evidence_before_nccl() {
        let mut fixture = Fixture::two();
        let choice = fixture.select().unwrap();
        let nccl = choice.settings.nccl.unwrap();
        assert_eq!(nccl.peer_to_peer(), PeerToPeer::Direct);
        assert_eq!(nccl.device_count(), 2);
        assert_eq!(choice.settings.tensor_parallel_size, 2);

        fixture.topology = None;
        assert_eq!(
            fixture.select(),
            refused(
                ServingFact::PeerTopology,
                EvidenceRefusal::Missing {
                    capability: Capability::PeerTopology
                }
            )
        );
        // The topology is the runtime's: one measured for another runtime does not answer.
        let mut scripts = Fixture::two().scripts();
        scripts.pop();
        scripts.push(topology_script(
            runtime(ExecutionCategory::ProviderContainerRuntime),
            &two_gpu_topology(PeerAccess::Verified),
        ));
        assert_eq!(
            Fixture::two().select_with(&scripts, Duration::ZERO),
            refused(
                ServingFact::PeerTopology,
                EvidenceRefusal::Missing {
                    capability: Capability::PeerTopology
                }
            )
        );
    }

    #[test]
    fn unavailable_peer_access_disables_p2p_for_the_engine_process_only() {
        let fixture = Fixture::two_with(two_gpu_topology(PeerAccess::Unavailable));
        let nccl = fixture.select().unwrap().settings.nccl.unwrap();
        assert_eq!(nccl.peer_to_peer(), PeerToPeer::Disabled);
        assert_eq!(nccl.process_environment(), vec![("NCCL_P2P_DISABLE", "1")]);
    }

    #[test]
    fn the_same_card_name_on_another_topology_is_not_portable() {
        // The hardware class says the peers were verified; the measurement says otherwise.
        let mut fixture = Fixture::two();
        let measured = two_gpu_topology(PeerAccess::Unavailable);
        fixture.topology = Some(measured.clone());
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::TopologyMismatch {
                measured: measured.identity(),
                hardware_class: fixture.request.hardware.topology,
            })
        );
        // Compatibility measured on one GPU of the same card does not answer for two.
        let mut two = Fixture::two();
        two.compatibility_hardware = single_gpu();
        assert_eq!(
            two.select(),
            refused(
                ServingFact::CheckpointCompatibility,
                EvidenceRefusal::Missing {
                    capability: Capability::CheckpointCompatibility
                }
            )
        );
    }

    #[test]
    fn evidence_for_another_model_or_engine_does_not_answer() {
        let missing = refused(
            ServingFact::CheckpointCompatibility,
            EvidenceRefusal::Missing {
                capability: Capability::CheckpointCompatibility,
            },
        );
        let mut other_model = Fixture::single();
        other_model.request.model.tokenizer = d("other tokenizer");
        assert_eq!(other_model.select(), missing);
        let mut other_image = Fixture::single();
        other_image.request.engine.image = d("upgraded image");
        assert_eq!(other_image.select(), missing);
    }

    #[test]
    fn the_compatibility_record_must_be_the_measured_one() {
        // CORE-01's evidence names the record it measured; another record, such as one
        // with an extra KV representation, is not that measurement.
        let fixture = Fixture::single();
        let mut edited = Fixture::single();
        edited.support(fp4_kv(), 32 * 1024);
        assert_eq!(
            edited.select_with(&fixture.scripts(), Duration::ZERO),
            Err(ProfileRefusal::Evidence {
                gap: EvidenceGap::OtherRecord {
                    measured: compatibility().digest(),
                    given: edited.compatibility.digest(),
                }
            })
        );
        // The record's identity ignores the order it lists its measurements in.
        let mut reordered = compatibility();
        reordered.footprints.reverse();
        reordered.kv_caches.reverse();
        assert_eq!(reordered.digest(), compatibility().digest());
        assert_ne!(edited.compatibility.digest(), compatibility().digest());
    }

    #[test]
    fn stale_weak_or_changed_evidence_refuses() {
        // Stale on the registry's clock: a minute is the policy's limit.
        let fixture = Fixture::single();
        assert!(matches!(
            fixture.select_with(&fixture.scripts(), Duration::from_secs(61)),
            Err(ProfileRefusal::Evidence {
                gap: EvidenceGap::Refused {
                    fact: ServingFact::CheckpointCompatibility,
                    refusal: EvidenceRefusal::Stale {
                        staleness: Staleness::TooOld { .. },
                        ..
                    }
                }
            })
        ));
        // A declaration is no measurement, and free memory needs a host probe: a guest's
        // own report of it is not enough (CORE-01's floor), whatever the policy asks.
        for source in [SourceClass::RecordedDeclaration, SourceClass::GuestReport] {
            let mut scripts = fixture.scripts();
            scripts[1].source = source;
            assert_eq!(
                fixture.select_with(&scripts, Duration::ZERO),
                refused(
                    ServingFact::FreeCapacity,
                    EvidenceRefusal::SourceTooWeak {
                        capability: Capability::GpuFreeMemory,
                        observed: source,
                        required: SourceClass::HostProbe,
                    }
                )
            );
        }
        // Evidence observed under another configuration no longer applies.
        let mut changed = Fixture::single();
        changed.request.configuration = ConfigurationFingerprint::from_digest(d("new config"));
        assert_eq!(
            changed.select(),
            refused(
                ServingFact::CheckpointCompatibility,
                EvidenceRefusal::FingerprintChanged {
                    capability: Capability::CheckpointCompatibility,
                    observed_under: configuration(),
                    current: changed.request.configuration,
                }
            )
        );
    }

    #[test]
    fn inconclusive_or_unsupported_evidence_refuses() {
        let fixture = Fixture::single();
        // A compatibility probe that could not decide.
        let mut inconclusive = fixture.scripts();
        inconclusive[0].observation = Observation::unknown(
            configuration(),
            Duration::from_secs(3600),
            UnknownReason::NotTested,
        );
        assert_eq!(
            fixture.select_with(&inconclusive, Duration::ZERO),
            refused(
                ServingFact::CheckpointCompatibility,
                EvidenceRefusal::Unknown {
                    capability: Capability::CheckpointCompatibility,
                    reason: UnknownReason::NotTested,
                }
            )
        );
        // A checkpoint that did not run on this engine and hardware.
        let mut unsupported = fixture.scripts();
        unsupported[0].observation = Observation::unsupported(
            configuration(),
            Duration::from_secs(3600),
            UnsupportedReason::OperationFailed,
        );
        assert_eq!(
            fixture.select_with(&unsupported, Duration::ZERO),
            refused(
                ServingFact::CheckpointCompatibility,
                EvidenceRefusal::Unsupported {
                    capability: Capability::CheckpointCompatibility,
                    reason: UnsupportedReason::OperationFailed,
                }
            )
        );
    }

    #[test]
    fn a_vm_required_request_never_gets_a_labelled_runtime() {
        let mut fixture = Fixture::single();
        fixture.request.requirement = RuntimeRequirement::VmSandbox;
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::Category {
                refusal: CategoryRefusal::VmSandboxRequired {
                    offered: ExecutionCategory::SharedKernelGpuRuntime
                }
            })
        );
        fixture.request.requirement =
            RuntimeRequirement::explicit([ExecutionCategory::ProviderContainerRuntime]).unwrap();
        assert!(matches!(
            fixture.select(),
            Err(ProfileRefusal::Category {
                refusal: CategoryRefusal::NotExplicitlyAllowed { .. }
            })
        ));
        // A VM sandbox runtime is admitted only by a VM-required request.
        fixture.request.requirement = RuntimeRequirement::VmSandbox;
        fixture.request.runtime = offer(ExecutionCategory::VmSandbox);
        fixture.request.backend = backend_for(runtime(ExecutionCategory::VmSandbox));
        assert!(fixture.select().unwrap().runtime.is_vm_sandbox());
    }

    #[test]
    fn the_runtime_must_run_the_pinned_engine() {
        let mut fixture = Fixture::single();
        let mut upgraded = runtime(ExecutionCategory::SharedKernelGpuRuntime);
        upgraded.release = BackendRelease::new(Backend::Vllm, "0.31.0").unwrap();
        fixture.request.runtime = offer_for(upgraded);
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::RuntimeForOtherEngine {
                runtime: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                engine: engine().release,
            })
        );
    }

    #[test]
    fn cuda_graphs_need_an_approved_experiment() {
        // Without the approval, eager execution stays and the refusal is recorded.
        let mut fixture = Fixture::single();
        fixture.request.approvals = vec![approval(Technique::Concurrency)];
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::Eager);
        assert_eq!(
            choice.passed_over,
            vec![PassedOver::Technique {
                refusal: TechniqueRefusal::ExperimentNotApproved {
                    technique: Technique::CudaGraphs,
                    release: engine().release,
                }
            }]
        );
        assert_eq!(admitted_techniques(&choice), vec![Technique::Concurrency]);
        // An approval for another release does not count.
        let mut other_release = approval(Technique::CudaGraphs);
        other_release.release = BackendRelease::new(Backend::Vllm, "0.31.0").unwrap();
        fixture.request.approvals.push(other_release);
        assert_eq!(
            fixture.select().unwrap().settings.graph_mode,
            GraphMode::Eager
        );
        // With it, captured graphs are chosen.
        fixture
            .request
            .approvals
            .push(approval(Technique::CudaGraphs));
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::PiecewiseCudaGraphs);
        assert_eq!(
            admitted_techniques(&choice),
            vec![Technique::CudaGraphs, Technique::Concurrency]
        );
        // Approved but not needed: where only eager fits, CUDA graphs are not carried.
        fixture.request.mix = mix(16_384, 3);
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::Eager);
        assert_eq!(admitted_techniques(&choice), vec![Technique::Concurrency]);
        // Where eager was never measured, nothing is left to choose.
        let mut graphs_only = Fixture::single();
        graphs_only.request.approvals = vec![approval(Technique::Concurrency)];
        graphs_only
            .compatibility
            .footprints
            .retain(|footprint| footprint.graph_mode != GraphMode::Eager);
        assert!(matches!(
            graphs_only.select(),
            Err(ProfileRefusal::NoSupportedCandidate { passed_over })
                if passed_over.iter().any(|passed| matches!(passed, PassedOver::Technique { .. }))
        ));
    }

    #[test]
    fn concurrency_needs_an_approved_experiment() {
        // Two sequences without the approval are refused, never served as one.
        let mut fixture = Fixture::single();
        fixture.request.approvals = vec![approval(Technique::CudaGraphs)];
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::TechniqueNotAdmitted {
                refusal: TechniqueRefusal::ExperimentNotApproved {
                    technique: Technique::Concurrency,
                    release: engine().release,
                }
            })
        );
        // One sequence, today's --max-num-seqs 1, needs no approval.
        fixture.request.mix = mix(8_192, 1);
        let choice = fixture.select().unwrap();
        assert_eq!(choice.settings.max_num_seqs, 1);
        assert_eq!(admitted_techniques(&choice), vec![Technique::CudaGraphs]);
        // With the approval, two sequences are chosen.
        fixture.request.mix = mix(8_192, 2);
        fixture
            .request
            .approvals
            .push(approval(Technique::Concurrency));
        assert_eq!(fixture.select().unwrap().settings.max_num_seqs, 2);
        // Today's eager, single-sequence settings need nothing from the gate.
        let mut today = Fixture::single();
        today.request.approvals.clear();
        today.request.mix = mix(8_192, 1);
        let choice = today.select().unwrap();
        assert_eq!(choice.settings.graph_mode, GraphMode::Eager);
        assert!(choice.settings.techniques().is_empty());
        assert!(choice.techniques.is_empty());
    }

    #[test]
    fn the_backend_gate_must_describe_the_offered_runtime() {
        let mut fixture = Fixture::single();
        fixture.request.backend = backend_for(runtime(ExecutionCategory::ProviderContainerRuntime));
        assert_eq!(
            fixture.select(),
            Err(ProfileRefusal::BackendForOtherRuntime)
        );
    }

    #[test]
    fn malformed_requests_and_measurements_refuse() {
        let mut zero = Fixture::single();
        zero.request.mix = mix(8_192, 0);
        assert_eq!(
            zero.select(),
            Err(ProfileRefusal::InvalidRequest {
                error: RequestError::ZeroSequences
            })
        );
        let mut count = Fixture::single();
        count.request.hardware.gpu_count = 2;
        assert_eq!(
            count.select(),
            Err(ProfileRefusal::InvalidRequest {
                error: RequestError::DeviceCountMismatch {
                    devices: 1,
                    gpu_count: 2
                }
            })
        );
        let mut repeated = Fixture::two();
        repeated.request.devices[1] = device(0);
        assert_eq!(
            repeated.select(),
            Err(ProfileRefusal::InvalidRequest {
                error: RequestError::RepeatedDevice
            })
        );
        let mut peers = Fixture::single();
        peers.request.hardware.topology = two_gpu_topology(PeerAccess::Verified).identity();
        assert_eq!(
            peers.select(),
            Err(ProfileRefusal::InvalidRequest {
                error: RequestError::SingleGpuWithPeers
            })
        );
        // More free memory than the GPU has is an inconsistent report, which CORE-01
        // records as inconclusive.
        let mut implausible = Fixture::single();
        implausible.capacity.devices[0].free_bytes = 25 * GIB;
        assert_eq!(
            implausible.select(),
            refused(
                ServingFact::FreeCapacity,
                EvidenceRefusal::Unknown {
                    capability: Capability::GpuFreeMemory,
                    reason: UnknownReason::InconsistentReport,
                }
            )
        );
        // Memory measured on another GPU says nothing about the assigned one.
        let mut other_devices = Fixture::single();
        other_devices.capacity.devices[0].device = device(7);
        assert_eq!(
            other_devices.select(),
            refused(
                ServingFact::FreeCapacity,
                EvidenceRefusal::Missing {
                    capability: Capability::GpuFreeMemory
                }
            )
        );
        // A measurement that omits a path between two GPUs is inconclusive too.
        let mut one_way = two_gpu_topology(PeerAccess::Verified);
        one_way.paths.truncate(1);
        let mut partial = Fixture::two();
        partial.topology = Some(one_way);
        assert_eq!(
            partial.select(),
            refused(
                ServingFact::PeerTopology,
                EvidenceRefusal::Unknown {
                    capability: Capability::PeerTopology,
                    reason: UnknownReason::InconsistentReport,
                }
            )
        );
        let mut duplicate = Fixture::single();
        let first = duplicate.compatibility.footprints[0];
        duplicate.compatibility.footprints.push(first);
        assert!(matches!(
            duplicate.select(),
            Err(ProfileRefusal::InvalidCompatibility {
                error: CompatibilityError::RepeatedFootprint { .. }
            })
        ));
        let mut zero_kv = Fixture::single();
        zero_kv.support(kv(Dtype::Float32, Quantization::None), 0);
        assert_eq!(
            zero_kv.select(),
            Err(ProfileRefusal::InvalidCompatibility {
                error: CompatibilityError::ZeroKvBytes {
                    dtype: Dtype::Float32
                }
            })
        );
        let mut repeated_kv = Fixture::single();
        repeated_kv.support(model_kv(), 64 * 1024);
        assert_eq!(
            repeated_kv.select(),
            Err(ProfileRefusal::InvalidCompatibility {
                error: CompatibilityError::RepeatedKvCache {
                    dtype: Dtype::BFloat16
                }
            })
        );
    }

    #[test]
    fn the_same_inputs_give_the_same_choice() {
        let fixture = Fixture::two();
        assert_eq!(fixture.select(), fixture.select());
        let mut shuffled = Fixture::two();
        shuffled.compatibility.footprints.reverse();
        shuffled.compatibility.kv_caches.reverse();
        assert_eq!(shuffled.select(), fixture.select());
    }

    #[test]
    fn tool_call_support_refuses_unknown_fields() {
        let unit: ToolCalls = serde_json::from_str(r#"{"tool_calls":"not_supported"}"#).unwrap();
        assert_eq!(unit, ToolCalls::NotSupported);
        assert_eq!(
            serde_json::to_string(&ToolCalls::NotSupported).unwrap(),
            r#"{"tool_calls":"not_supported"}"#
        );
        assert!(serde_json::from_str::<ToolCalls>(
            r#"{"tool_calls":"not_supported","parser":"hermes"}"#
        )
        .is_err());
    }
}
