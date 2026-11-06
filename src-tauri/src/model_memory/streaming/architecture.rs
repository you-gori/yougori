//! One explicit architecture for execute-while-load (GPU-W07 items 1, 2, 5, 6 and 8;
//! GPU §2.6 lines 419–434, §4.4 lines 689–697).
//!
//! An [`ArchitectureSpec`] lists the stored tensors, the nonpersistent buffers the model
//! builds at load, and the execution groups in exact model order with the tensors and
//! buffers each reads. Validation turns it into a [`StreamingModel`]. A tensor that more
//! than one group reads, such as an embedding tied to the output head, is one dependency
//! read once and required by every group that uses it. Request shapes are dynamic:
//! compute durations, activation sizes and buffer sizes follow the request, so a plan is
//! made for one [`RequestShape`].
//!
//! [`choose_loader`] runs execute-while-load only for an explicitly supported
//! architecture in eager mode, and only on fresh CORE-01 evidence that execute-while-load
//! works on the actual runtime ([`Capability::ExecuteWhileLoad`], evaluated by the probe
//! registry). Anything else uses the normal loader with a typed reason: graph capture
//! (GPU-W07 item 5), a second architecture before the first has a reproducible gain
//! (item 8), and evidence that is missing, stale, from a weaker source than the policy
//! needs, observed under another configuration, unsupported or inconclusive.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, ProbeRegistry,
    Requirement, RuntimeSubject, Satisfied, Subject, SupportDetail,
};
use crate::foundation::ids::{validate_identifier, Clock, ContentKey, Digest};
use crate::foundation::report::{
    BaselineOutcome, BaselineRole, ComparisonReport, ImprovementClaim, Measured, NotMeasuredReason,
    Objective, VerdictStatus,
};
use crate::model_memory::executor::{DependencyId, DependencySpec};
use crate::model_memory::graph::scatter_gather::ByteRange;
use crate::model_memory::math::overlap::ExpertId;

use super::{add_bytes, non_negative, ReadSetProblem, StreamingError};

/// A tensor or buffer name as the checkpoint writes it, under the shared identifier
/// grammar (letters, digits, '.', '_', ':' and '-').
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TensorName(String);

impl TensorName {
    /// Refuses a name outside the shared identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, StreamingError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// The name as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TensorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One stored tensor (GPU-W07 item 1): its byte range in the stored representation, its
/// content identity, the manifest extents that carry it, and the expert it belongs to
/// in an MoE layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorSpec {
    pub name: TensorName,
    pub stored: ByteRange,
    pub content: ContentKey,
    /// Manifest extent indices, as the transfer executor names them.
    pub extents: Vec<u64>,
    pub expert: Option<ExpertId>,
}

/// Compute time for a request: `fixed_seconds + per_token_seconds × tokens`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComputeCost {
    pub fixed_seconds: f64,
    pub per_token_seconds: f64,
}

impl ComputeCost {
    /// The duration for `tokens` tokens.
    pub fn seconds_for(&self, tokens: u64) -> f64 {
        self.fixed_seconds + self.per_token_seconds * tokens as f64
    }

    fn check(&self, field: &'static str) -> Result<(), StreamingError> {
        non_negative(field, self.fixed_seconds)?;
        non_negative(field, self.per_token_seconds)?;
        Ok(())
    }
}

/// A nonpersistent buffer (GPU §2.6 line 432, GPU-W07 item 2): built on the device at
/// load, never read from storage, and sized by the request shape, such as a rotary or
/// mask cache. Buffers are built one after another on a separate initialization stream
/// from the start of the load.
#[derive(Clone, Debug, PartialEq)]
pub struct BufferSpec {
    pub name: TensorName,
    pub fixed_bytes: u64,
    pub bytes_per_token: u64,
    pub init: ComputeCost,
}

/// What an execution group is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupRole {
    Embedding,
    Layer,
    OutputHead,
}

/// One execution group in exact model order (GPU-W07 item 1).
#[derive(Clone, Debug, PartialEq)]
pub struct GroupSpec {
    pub role: GroupRole,
    /// Tensors every request needs, by index into [`ArchitectureSpec::tensors`].
    pub reads: Vec<usize>,
    /// For an MoE layer: the experts it may route to. A request needs exactly the ones
    /// its routing names.
    pub experts: Vec<usize>,
    pub buffers: Vec<usize>,
    pub compute: ComputeCost,
    /// Activation bytes the group produces per token.
    pub activation_bytes_per_token: u64,
}

/// The model family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchitectureFamily {
    /// The first supported architecture (§4.4: "one supported dense architecture").
    DenseDecoder,
    /// The second architecture, an MoE adapter with explicit expert dependencies.
    MoeDecoder,
    /// Anything without an explicit description here; it uses the normal loader.
    Unsupported { name: String },
}

/// How the model executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Eager,
    /// Evaluated only after dependency correctness (GPU-W07 item 5).
    GraphCapture,
}

/// State a group may need beyond weights and buffers (GPU §2.6 line 432) that this first
/// architecture does not describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraState {
    RecurrentState,
    MultimodalEncoder,
}

/// Everything an architecture description declares.
#[derive(Clone, Debug, PartialEq)]
pub struct ArchitectureSpec {
    pub family: ArchitectureFamily,
    pub mode: ExecutionMode,
    pub extra_state: Vec<ExtraState>,
    pub tensors: Vec<TensorSpec>,
    pub buffers: Vec<BufferSpec>,
    /// In exact execution order: one embedding, layers, one output head.
    pub groups: Vec<GroupSpec>,
    pub max_prompt_tokens: u64,
}

/// A request's dynamic shape (GPU-W07 item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestShape {
    pub prompt_tokens: u64,
    pub batch_sequences: u64,
}

impl RequestShape {
    /// `prompt_tokens × batch_sequences`; `None` on overflow.
    pub fn tokens(&self) -> Option<u64> {
        self.prompt_tokens.checked_mul(self.batch_sequences)
    }
}

/// The exact experts a request's prefill routes to, per MoE group (§2.6 line 434).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefillRouting {
    experts: BTreeMap<usize, BTreeSet<usize>>,
}

impl PrefillRouting {
    /// No routing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Routes group `group` to exactly these expert tensors.
    pub fn route(mut self, group: usize, experts: impl IntoIterator<Item = usize>) -> Self {
        self.experts.insert(group, experts.into_iter().collect());
        self
    }

    /// The expert tensors routed for `group`, if any.
    pub fn experts(&self, group: usize) -> Option<&BTreeSet<usize>> {
        self.experts.get(&group)
    }
}

/// One execution group of a planned request.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedGroup {
    /// Index into the model's groups.
    pub group: usize,
    pub role: GroupRole,
    /// Tensors only this group reads, including its routed experts.
    pub weights: Vec<usize>,
    /// Tensors several groups read, such as a tied embedding: dependencies beyond the
    /// group's own weights (§2.6 line 432).
    pub tied: Vec<usize>,
    pub buffers: Vec<usize>,
    pub compute_seconds: f64,
    pub activation_bytes: u64,
}

impl PlannedGroup {
    /// Every tensor the group reads.
    pub fn tensors(&self) -> impl Iterator<Item = usize> + '_ {
        self.weights.iter().chain(self.tied.iter()).copied()
    }
}

/// A nonpersistent buffer sized for a request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlannedBuffer {
    pub bytes: u64,
    pub init_seconds: f64,
}

/// One request's groups, buffers and background tensors for one shape.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedRequest {
    pub shape: RequestShape,
    pub groups: Vec<PlannedGroup>,
    pub buffers: Vec<PlannedBuffer>,
    /// Tensors no group of this request reads, such as experts its routing does not name.
    /// They load after the first-token dependencies.
    pub background: Vec<usize>,
}

impl PlannedRequest {
    /// Whether a tensor is a first-token dependency of this request.
    pub fn needs(&self, tensor: usize) -> bool {
        self.groups
            .iter()
            .any(|group| group.tensors().any(|read| read == tensor))
    }

    /// The first group that reads `tensor`.
    pub fn first_consumer(&self, tensor: usize) -> Option<usize> {
        self.groups
            .iter()
            .position(|group| group.tensors().any(|read| read == tensor))
    }
}

/// The result of comparing the streamed read set with the ordinary loader's (GPU-W07
/// item 6).
#[derive(Clone, Debug, PartialEq)]
pub struct ReadSetCheck {
    pub tensors: usize,
    pub bytes: u64,
    /// Numerical agreement needs both loaders run on a GPU; never measured here.
    pub numerical_agreement: Measured<Digest>,
}

/// A validated architecture.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamingModel {
    spec: ArchitectureSpec,
    /// Tensors more than one group reads.
    shared: BTreeSet<usize>,
    /// The group that owns each tensor for execution order: its first reader.
    owner: Vec<usize>,
}

impl StreamingModel {
    /// Validates an explicit description (GPU-W07 items 1 and 2).
    pub fn new(spec: ArchitectureSpec) -> Result<Self, StreamingError> {
        let moe = match &spec.family {
            ArchitectureFamily::DenseDecoder => false,
            ArchitectureFamily::MoeDecoder => true,
            ArchitectureFamily::Unsupported { .. } => {
                return Err(StreamingError::Invalid {
                    field: "family",
                    reason: "an unsupported architecture has no streaming description",
                })
            }
        };
        if spec.max_prompt_tokens == 0 {
            return Err(StreamingError::Invalid {
                field: "max_prompt_tokens",
                reason: "must be more than zero",
            });
        }
        check_tensors(&spec.tensors)?;
        check_buffers(&spec)?;
        check_group_order(&spec.groups)?;
        let (shared, owner) = check_reads(&spec, moe)?;
        Ok(Self {
            spec,
            shared,
            owner,
        })
    }

    /// The model family.
    pub fn family(&self) -> &ArchitectureFamily {
        &self.spec.family
    }

    /// Stored tensors, indexed as the groups name them.
    pub fn tensors(&self) -> &[TensorSpec] {
        &self.spec.tensors
    }

    /// Nonpersistent buffers, indexed as the groups name them.
    pub fn buffers(&self) -> &[BufferSpec] {
        &self.spec.buffers
    }

    /// Execution groups in exact model order.
    pub fn groups(&self) -> &[GroupSpec] {
        &self.spec.groups
    }

    /// The longest prompt a plan may be made for.
    pub fn max_prompt_tokens(&self) -> u64 {
        self.spec.max_prompt_tokens
    }

    /// Tensors that several groups read, such as an embedding tied to the output head.
    pub fn tied_tensors(&self) -> Vec<usize> {
        self.shared.iter().copied().collect()
    }

    /// The first group that reads a tensor; the execution order loads it there.
    pub fn owner_group(&self, tensor: usize) -> Option<usize> {
        self.owner.get(tensor).copied()
    }

    /// Bytes of every stored tensor: what the ordinary loader reads.
    pub fn total_weight_bytes(&self) -> Result<u64, StreamingError> {
        self.spec.tensors.iter().try_fold(0u64, |total, tensor| {
            add_bytes("total weight bytes", total, tensor.stored.length_bytes)
        })
    }

    /// Plans one request: compute times, activation and buffer sizes for its shape, and
    /// for an MoE model exactly the routed experts (§2.6 line 434). A dense model refuses
    /// routing; an MoE model refuses a group without exact routing.
    pub fn plan_request(
        &self,
        shape: RequestShape,
        routing: Option<&PrefillRouting>,
    ) -> Result<PlannedRequest, StreamingError> {
        if shape.prompt_tokens == 0 || shape.batch_sequences == 0 {
            return Err(StreamingError::Invalid {
                field: "RequestShape",
                reason: "prompt tokens and batch sequences must be more than zero",
            });
        }
        if shape.prompt_tokens > self.spec.max_prompt_tokens {
            return Err(StreamingError::ShapeTooLarge {
                prompt_tokens: shape.prompt_tokens,
                max_prompt_tokens: self.spec.max_prompt_tokens,
            });
        }
        let tokens = shape.tokens().ok_or(StreamingError::Invalid {
            field: "RequestShape",
            reason: "token count does not fit in 64 bits",
        })?;
        let moe = self.spec.family == ArchitectureFamily::MoeDecoder;
        if let Some(routing) = routing {
            if !moe {
                let group = routing.experts.keys().next().copied().unwrap_or(0);
                return Err(StreamingError::Routing {
                    group,
                    reason: "a dense model has no experts to route",
                });
            }
            if let Some(group) = routing.experts.keys().find(|group| {
                self.spec
                    .groups
                    .get(**group)
                    .is_none_or(|g| g.experts.is_empty())
            }) {
                return Err(StreamingError::Routing {
                    group: *group,
                    reason: "routing names a group without experts",
                });
            }
        }
        let mut routed_all = BTreeSet::new();
        let mut groups = Vec::with_capacity(self.spec.groups.len());
        for (index, spec) in self.spec.groups.iter().enumerate() {
            let mut weights = Vec::new();
            let mut tied = Vec::new();
            for &tensor in &spec.reads {
                if self.shared.contains(&tensor) {
                    tied.push(tensor);
                } else {
                    weights.push(tensor);
                }
            }
            if !spec.experts.is_empty() {
                let routed = routing.and_then(|routing| routing.experts(index)).ok_or(
                    StreamingError::Routing {
                        group: index,
                        reason: "an MoE group needs the exact experts its routing names",
                    },
                )?;
                if routed.is_empty() {
                    return Err(StreamingError::Routing {
                        group: index,
                        reason: "routing names no expert",
                    });
                }
                for expert in routed {
                    if !spec.experts.contains(expert) {
                        return Err(StreamingError::Routing {
                            group: index,
                            reason:
                                "routing names a tensor that is not one of this group's experts",
                        });
                    }
                    weights.push(*expert);
                    routed_all.insert(*expert);
                }
            }
            let compute_seconds = spec.compute.seconds_for(tokens);
            if !(compute_seconds.is_finite() && compute_seconds > 0.0) {
                return Err(StreamingError::Invalid {
                    field: "GroupSpec.compute",
                    reason: "every group computes for more than zero seconds",
                });
            }
            let activation_bytes = spec.activation_bytes_per_token.checked_mul(tokens).ok_or(
                StreamingError::Invalid {
                    field: "activation bytes",
                    reason: "does not fit in 64 bits",
                },
            )?;
            groups.push(PlannedGroup {
                group: index,
                role: spec.role,
                weights,
                tied,
                buffers: spec.buffers.clone(),
                compute_seconds,
                activation_bytes,
            });
        }
        let buffers = self
            .spec
            .buffers
            .iter()
            .map(|buffer| {
                let bytes = buffer
                    .bytes_per_token
                    .checked_mul(tokens)
                    .and_then(|bytes| bytes.checked_add(buffer.fixed_bytes))
                    .ok_or(StreamingError::Invalid {
                        field: "buffer bytes",
                        reason: "does not fit in 64 bits",
                    })?;
                Ok(PlannedBuffer {
                    bytes,
                    init_seconds: buffer.init.seconds_for(tokens),
                })
            })
            .collect::<Result<Vec<_>, StreamingError>>()?;
        let background = self
            .spec
            .groups
            .iter()
            .flat_map(|group| group.experts.iter().copied())
            .filter(|expert| !routed_all.contains(expert))
            .collect();
        Ok(PlannedRequest {
            shape,
            groups,
            buffers,
            background,
        })
    }

    /// Checks that streaming loads exactly the tensors the ordinary loader loads, with the
    /// same content identities (GPU-W07 item 6: exact weights). Numerical agreement needs
    /// both loaders on a GPU and is reported as not measured.
    pub fn verify_against_ordinary_loader(
        &self,
        ordinary: &[(TensorName, ContentKey)],
    ) -> Result<ReadSetCheck, StreamingError> {
        let mut theirs: BTreeMap<&TensorName, &ContentKey> = BTreeMap::new();
        for (name, content) in ordinary {
            if theirs.insert(name, content).is_some() {
                return Err(StreamingError::ReadSetMismatch {
                    tensor: name.to_string(),
                    problem: ReadSetProblem::Repeated,
                });
            }
        }
        for tensor in &self.spec.tensors {
            match theirs.remove(&tensor.name) {
                None => {
                    return Err(StreamingError::ReadSetMismatch {
                        tensor: tensor.name.to_string(),
                        problem: ReadSetProblem::NotInOrdinaryLoader,
                    })
                }
                Some(content) if *content != tensor.content => {
                    return Err(StreamingError::ReadSetMismatch {
                        tensor: tensor.name.to_string(),
                        problem: ReadSetProblem::ContentDiffers,
                    })
                }
                Some(_) => {}
            }
        }
        if let Some(name) = theirs.keys().next() {
            return Err(StreamingError::ReadSetMismatch {
                tensor: name.to_string(),
                problem: ReadSetProblem::MissingFromStream,
            });
        }
        Ok(ReadSetCheck {
            tensors: self.spec.tensors.len(),
            bytes: self.total_weight_bytes()?,
            numerical_agreement: Measured::not_measured(NotMeasuredReason::ReferenceUnavailable),
        })
    }

    /// Transfer-executor dependencies (GPU §3.5 step 7): one per tensor, identified by the
    /// tensor's index. A tied tensor is one dependency that every group using it requires,
    /// so its two uses never load it twice or split it.
    pub fn dependency_specs(&self) -> Vec<DependencySpec> {
        self.spec
            .tensors
            .iter()
            .enumerate()
            .map(|(index, tensor)| DependencySpec {
                id: dependency_id(index),
                extents: tensor.extents.clone(),
                requires: Vec::new(),
            })
            .collect()
    }

    /// The executor dependencies a planned group waits for.
    pub fn group_dependencies(group: &PlannedGroup) -> Vec<DependencyId> {
        group.tensors().map(dependency_id).collect()
    }
}

/// The executor dependency of a tensor.
pub fn dependency_id(tensor: usize) -> DependencyId {
    DependencyId(tensor as u64)
}

fn check_tensors(tensors: &[TensorSpec]) -> Result<(), StreamingError> {
    if tensors.is_empty() {
        return Err(StreamingError::Invalid {
            field: "tensors",
            reason: "an architecture stores at least one tensor",
        });
    }
    let mut names = BTreeSet::new();
    let mut experts = BTreeSet::new();
    for tensor in tensors {
        if !names.insert(&tensor.name) {
            return Err(StreamingError::Duplicate {
                field: "tensors",
                name: tensor.name.to_string(),
            });
        }
        if tensor.stored.length_bytes == 0 {
            return Err(StreamingError::Invalid {
                field: "TensorSpec.stored",
                reason: "a stored tensor has at least one byte",
            });
        }
        if tensor
            .stored
            .offset_bytes
            .checked_add(tensor.stored.length_bytes)
            .is_none()
        {
            return Err(StreamingError::Invalid {
                field: "TensorSpec.stored",
                reason: "the range ends past 64 bits",
            });
        }
        if tensor.extents.is_empty() {
            return Err(StreamingError::Invalid {
                field: "TensorSpec.extents",
                reason: "a tensor is carried by at least one manifest extent",
            });
        }
        let unique: BTreeSet<u64> = tensor.extents.iter().copied().collect();
        if unique.len() != tensor.extents.len() {
            return Err(StreamingError::Duplicate {
                field: "TensorSpec.extents",
                name: tensor.name.to_string(),
            });
        }
        if let Some(expert) = tensor.expert {
            if !experts.insert(expert) {
                return Err(StreamingError::Duplicate {
                    field: "TensorSpec.expert",
                    name: expert.to_string(),
                });
            }
        }
    }
    let mut by_offset: Vec<&TensorSpec> = tensors.iter().collect();
    by_offset.sort_by_key(|tensor| tensor.stored.offset_bytes);
    for pair in by_offset.windows(2) {
        if let [first, second] = pair {
            if first.stored.end_bytes() > second.stored.offset_bytes {
                return Err(StreamingError::OverlappingTensors {
                    first: first.name.to_string(),
                    second: second.name.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn check_buffers(spec: &ArchitectureSpec) -> Result<(), StreamingError> {
    let mut names: BTreeSet<&TensorName> = spec.tensors.iter().map(|tensor| &tensor.name).collect();
    for buffer in &spec.buffers {
        if !names.insert(&buffer.name) {
            return Err(StreamingError::Duplicate {
                field: "buffers",
                name: buffer.name.to_string(),
            });
        }
        buffer.init.check("BufferSpec.init")?;
    }
    Ok(())
}

fn check_group_order(groups: &[GroupSpec]) -> Result<(), StreamingError> {
    if groups.len() < 3 {
        return Err(StreamingError::GroupOrder {
            reason: "an embedding, at least one layer and an output head are required",
        });
    }
    let last = groups.len() - 1;
    for (index, group) in groups.iter().enumerate() {
        let expected = match index {
            0 => GroupRole::Embedding,
            i if i == last => GroupRole::OutputHead,
            _ => GroupRole::Layer,
        };
        if group.role != expected {
            return Err(StreamingError::GroupOrder {
                reason: "groups must be one embedding, then layers, then one output head",
            });
        }
        group.compute.check("GroupSpec.compute")?;
        if group.compute.fixed_seconds <= 0.0 && group.compute.per_token_seconds <= 0.0 {
            return Err(StreamingError::Invalid {
                field: "GroupSpec.compute",
                reason: "every group computes for more than zero seconds",
            });
        }
        if group.reads.is_empty() && group.experts.is_empty() {
            return Err(StreamingError::Invalid {
                field: "GroupSpec.reads",
                reason: "every execution group reads at least one tensor",
            });
        }
        if !group.experts.is_empty() && group.role != GroupRole::Layer {
            return Err(StreamingError::GroupOrder {
                reason: "only layers route to experts",
            });
        }
    }
    Ok(())
}

/// Checks every read and returns the shared tensors and each tensor's first reader.
fn check_reads(
    spec: &ArchitectureSpec,
    moe: bool,
) -> Result<(BTreeSet<usize>, Vec<usize>), StreamingError> {
    let tensor_count = spec.tensors.len();
    let mut readers: Vec<Vec<usize>> = vec![Vec::new(); tensor_count];
    let mut expert_reader: Vec<Option<usize>> = vec![None; tensor_count];
    let mut buffer_used = vec![false; spec.buffers.len()];
    let mut any_experts = false;
    for (index, group) in spec.groups.iter().enumerate() {
        let mut seen = BTreeSet::new();
        for &tensor in group.reads.iter().chain(group.experts.iter()) {
            if tensor >= tensor_count {
                return Err(StreamingError::Unknown {
                    field: "GroupSpec.reads",
                    index: tensor,
                });
            }
            if !seen.insert(tensor) {
                return Err(StreamingError::Duplicate {
                    field: "GroupSpec.reads",
                    name: spec.tensors[tensor].name.to_string(),
                });
            }
        }
        for &tensor in &group.reads {
            if spec.tensors[tensor].expert.is_some() {
                return Err(StreamingError::Invalid {
                    field: "GroupSpec.reads",
                    reason: "an expert tensor is read only through routing",
                });
            }
            readers[tensor].push(index);
        }
        for &tensor in &group.experts {
            any_experts = true;
            if spec.tensors[tensor].expert.is_none() {
                return Err(StreamingError::Invalid {
                    field: "GroupSpec.experts",
                    reason: "every routable tensor names its expert",
                });
            }
            if expert_reader[tensor].replace(index).is_some() {
                return Err(StreamingError::Duplicate {
                    field: "GroupSpec.experts",
                    name: spec.tensors[tensor].name.to_string(),
                });
            }
        }
        let mut seen_buffers = BTreeSet::new();
        for &buffer in &group.buffers {
            let used = buffer_used.get_mut(buffer).ok_or(StreamingError::Unknown {
                field: "GroupSpec.buffers",
                index: buffer,
            })?;
            if !seen_buffers.insert(buffer) {
                return Err(StreamingError::Duplicate {
                    field: "GroupSpec.buffers",
                    name: spec.buffers[buffer].name.to_string(),
                });
            }
            *used = true;
        }
    }
    if moe && !any_experts {
        return Err(StreamingError::Invalid {
            field: "family",
            reason: "an MoE decoder has at least one layer with experts",
        });
    }
    if !moe && (any_experts || spec.tensors.iter().any(|tensor| tensor.expert.is_some())) {
        return Err(StreamingError::Invalid {
            field: "family",
            reason: "a dense decoder has no experts",
        });
    }
    let mut owner = Vec::with_capacity(tensor_count);
    for (tensor, spec_tensor) in spec.tensors.iter().enumerate() {
        let first = readers[tensor]
            .first()
            .copied()
            .or(expert_reader[tensor])
            .ok_or_else(|| StreamingError::Unread {
                name: spec_tensor.name.to_string(),
            })?;
        owner.push(first);
    }
    if let Some(unused) = buffer_used.iter().position(|used| !used) {
        return Err(StreamingError::Unread {
            name: spec.buffers[unused].name.to_string(),
        });
    }
    let shared = readers
        .iter()
        .enumerate()
        .filter(|(_, groups)| groups.len() > 1)
        .map(|(tensor, _)| tensor)
        .collect();
    Ok((shared, owner))
}

/// Evidence that the first architecture's overlap improved end-to-end first-token time
/// against the ordinary loader (GPU-W07 acceptance and item 8). Built only from a
/// comparison whose sides carry Yougori evidence, so a fake run never unlocks a second
/// architecture.
#[derive(Clone, Debug, PartialEq)]
pub struct ReproducibleGain {
    family: ArchitectureFamily,
    evidence: Digest,
}

impl ReproducibleGain {
    /// Requires an [`ImprovementClaim`] against the ordinary workflow (which refuses fake
    /// or unreproduced evidence), first-token time as the declared objective, and a
    /// verdict of [`VerdictStatus::Improved`]: no regression and nothing unmeasured.
    pub fn from_report(
        report: &ComparisonReport,
        family: ArchitectureFamily,
    ) -> Result<Self, StreamingError> {
        if family != ArchitectureFamily::DenseDecoder {
            return Err(StreamingError::Invalid {
                field: "ReproducibleGain.family",
                reason: "the dense decoder is the first architecture",
            });
        }
        let evidence = report.candidate().provenance.yougori_evidence()?;
        ImprovementClaim::from_report(report, BaselineRole::OrdinaryWorkflow)?;
        match report.ordinary_workflow() {
            BaselineOutcome::Compared { verdict, .. }
                if verdict.declared.objective == Objective::TimeToFirstToken
                    && verdict.status == VerdictStatus::Improved =>
            {
                Ok(Self { family, evidence })
            }
            _ => Err(StreamingError::Invalid {
                field: "ReproducibleGain",
                reason: "needs an improved end-to-end first-token time with nothing \
                         regressed or unmeasured",
            }),
        }
    }

    /// The architecture whose gain was reproduced.
    pub fn family(&self) -> &ArchitectureFamily {
        &self.family
    }

    /// The Yougori evidence digest of the comparison.
    pub fn evidence(&self) -> Digest {
        self.evidence
    }
}

/// What may run with execute-while-load.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ArchitectureGate {
    dense_gain: Option<ReproducibleGain>,
}

impl ArchitectureGate {
    /// Only the first architecture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the first architecture's reproducible gain, which admits the second.
    pub fn with_dense_gain(mut self, gain: ReproducibleGain) -> Self {
        self.dense_gain = Some(gain);
        self
    }
}

/// Why the normal loader runs instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalLoaderReason {
    UnsupportedFamily {
        name: String,
    },
    /// GPU-W07 item 5: eager execution first; graph capture only after dependency
    /// correctness is established.
    GraphCaptureNotEvaluated,
    UnsupportedState(ExtraState),
    /// GPU-W07 item 8.
    FirstArchitectureGainNotReproduced,
    /// CORE-01 does not show execute-while-load working on this runtime now: the evidence
    /// is missing, stale, from a weaker source than the policy needs (such as a guest
    /// report where a host probe is required), observed under another configuration,
    /// unsupported or inconclusive.
    EvidenceRefused(EvidenceRefusal),
}

/// What the execute-while-load decision reads from CORE-01: the probe registry, the
/// runtime the load actually runs on, the evidence policy of its profile and the
/// configuration in force now.
pub struct ExecuteWhileLoadEvidence<'a, C: Clock> {
    pub registry: &'a ProbeRegistry<C>,
    pub runtime: &'a RuntimeSubject,
    pub policy: EvidencePolicy,
    pub configuration: ConfigurationFingerprint,
}

impl<C: Clock> ExecuteWhileLoadEvidence<'_, C> {
    /// The fresh evidence for the actual runtime, or CORE-01's refusal.
    fn evaluate(&self) -> Result<Result<Satisfied, EvidenceRefusal>, StreamingError> {
        let subject = Subject::Runtime(self.runtime.clone());
        let requirement = Requirement::new(
            Capability::ExecuteWhileLoad,
            subject.clone(),
            self.policy.minimum_source,
            self.policy.max_age,
            self.configuration,
        );
        let satisfied = match self.registry.evaluate(&requirement) {
            Ok(satisfied) => satisfied,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if satisfied.capability() != Capability::ExecuteWhileLoad
            || satisfied.subject() != subject.identity()
            || *satisfied.detail() != SupportDetail::ExecuteWhileLoad
        {
            return Err(StreamingError::Invalid {
                field: "ExecuteWhileLoad evidence",
                reason: "the registry answered for another capability or subject",
            });
        }
        Ok(Ok(satisfied))
    }
}

/// The loader for one architecture.
#[derive(Clone, Debug, PartialEq)]
pub enum LoaderChoice {
    /// Streams `model`. `evidence` is the CORE-01 result it rests on; the choice holds
    /// only until [`Satisfied::fresh_until`], after which the caller chooses again.
    ExecuteWhileLoad {
        model: StreamingModel,
        evidence: Satisfied,
    },
    NormalLoader {
        reason: NormalLoaderReason,
    },
}

/// Chooses the loader (GPU-W07 acceptance: "unsupported architectures use the normal
/// loader"). Execute-while-load also needs a fresh CORE-01 [`Satisfied`] for
/// [`Capability::ExecuteWhileLoad`] on the actual runtime; any refusal sends the load to
/// the normal loader with that refusal as the reason. A supported architecture with an
/// invalid description is refused, never streamed and never silently treated as
/// unsupported.
pub fn choose_loader<C: Clock>(
    spec: ArchitectureSpec,
    gate: &ArchitectureGate,
    evidence: &ExecuteWhileLoadEvidence<'_, C>,
) -> Result<LoaderChoice, StreamingError> {
    let normal = |reason| Ok(LoaderChoice::NormalLoader { reason });
    match &spec.family {
        ArchitectureFamily::Unsupported { name } => {
            return normal(NormalLoaderReason::UnsupportedFamily { name: name.clone() })
        }
        ArchitectureFamily::MoeDecoder if gate.dense_gain.is_none() => {
            return normal(NormalLoaderReason::FirstArchitectureGainNotReproduced)
        }
        _ => {}
    }
    if spec.mode == ExecutionMode::GraphCapture {
        return normal(NormalLoaderReason::GraphCaptureNotEvaluated);
    }
    if let Some(state) = spec.extra_state.first() {
        return normal(NormalLoaderReason::UnsupportedState(*state));
    }
    let model = StreamingModel::new(spec)?;
    match evidence.evaluate()? {
        Ok(satisfied) => Ok(LoaderChoice::ExecuteWhileLoad {
            model,
            evidence: satisfied,
        }),
        Err(refusal) => normal(NormalLoaderReason::EvidenceRefused(refusal)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::SourceClass;
    use crate::model_memory::streaming::test_support::*;

    #[test]
    fn groups_and_read_sets_are_explicit() {
        let model = StreamingModel::new(dense_spec(3, MIB)).unwrap();
        // Embedding, three layers, output head.
        assert_eq!(model.groups().len(), 5);
        assert_eq!(model.groups()[0].role, GroupRole::Embedding);
        assert_eq!(model.groups()[4].role, GroupRole::OutputHead);
        let request = model.plan_request(shape(16), None).unwrap();
        assert_eq!(request.groups.len(), 5);
        // Layer 1 reads its own tensors and the rotary buffer.
        let layer = &request.groups[1];
        assert_eq!(layer.weights.len(), 2);
        assert!(layer.tied.is_empty());
        assert_eq!(layer.buffers, vec![0]);
        // The head reads the final norm and the tied embedding.
        assert_eq!(request.groups[4].tied, vec![0]);
        assert!(request.background.is_empty());
    }

    #[test]
    fn a_tied_embedding_and_head_keep_both_uses_in_one_dependency() {
        let model = StreamingModel::new(dense_spec(3, MIB)).unwrap();
        assert_eq!(model.tied_tensors(), vec![0]);
        let specs = model.dependency_specs();
        // One dependency per tensor; the tied tensor's extents appear exactly once.
        assert_eq!(specs.len(), model.tensors().len());
        let tied_extents = &model.tensors()[0].extents;
        let carrying: Vec<_> = specs
            .iter()
            .filter(|spec| spec.extents.iter().any(|e| tied_extents.contains(e)))
            .collect();
        assert_eq!(carrying.len(), 1);
        let request = model.plan_request(shape(16), None).unwrap();
        let embedding = StreamingModel::group_dependencies(&request.groups[0]);
        let head = StreamingModel::group_dependencies(&request.groups[4]);
        assert!(embedding.contains(&dependency_id(0)));
        assert!(head.contains(&dependency_id(0)));
        // Both uses are the same dependency, owned by its first reader.
        assert_eq!(model.owner_group(0), Some(0));
    }

    #[test]
    fn request_shapes_change_compute_activations_and_buffers() {
        let model = StreamingModel::new(dense_spec(2, MIB)).unwrap();
        let short = model.plan_request(shape(8), None).unwrap();
        let long = model
            .plan_request(
                RequestShape {
                    prompt_tokens: 32,
                    batch_sequences: 2,
                },
                None,
            )
            .unwrap();
        assert!(long.groups[1].compute_seconds > short.groups[1].compute_seconds);
        assert_eq!(
            long.groups[1].activation_bytes,
            8 * short.groups[1].activation_bytes
        );
        assert!(long.buffers[0].bytes > short.buffers[0].bytes);
        assert!(long.buffers[0].init_seconds > short.buffers[0].init_seconds);
        assert_eq!(
            model.plan_request(shape(MAX_PROMPT + 1), None),
            Err(StreamingError::ShapeTooLarge {
                prompt_tokens: MAX_PROMPT + 1,
                max_prompt_tokens: MAX_PROMPT
            })
        );
        assert!(model.plan_request(shape(0), None).is_err());
    }

    #[test]
    fn descriptions_are_refused_rather_than_repaired() {
        let mut spec = dense_spec(2, MIB);
        spec.tensors[2].stored.offset_bytes = spec.tensors[1].stored.offset_bytes;
        assert!(matches!(
            StreamingModel::new(spec),
            Err(StreamingError::OverlappingTensors { .. })
        ));
        let mut spec = dense_spec(2, MIB);
        spec.groups[1].reads.retain(|tensor| *tensor != 1);
        assert!(matches!(
            StreamingModel::new(spec),
            Err(StreamingError::Unread { .. })
        ));
        let mut spec = dense_spec(2, MIB);
        spec.groups.swap(0, 1);
        assert!(matches!(
            StreamingModel::new(spec),
            Err(StreamingError::GroupOrder { .. })
        ));
        let mut spec = dense_spec(2, MIB);
        spec.groups[1].reads.push(99);
        assert!(matches!(
            StreamingModel::new(spec),
            Err(StreamingError::Unknown { .. })
        ));
        let mut spec = dense_spec(2, MIB);
        spec.groups[2].compute = ComputeCost {
            fixed_seconds: 0.0,
            per_token_seconds: 0.0,
        };
        assert!(StreamingModel::new(spec).is_err());
        assert!(TensorName::new("layers 0").is_err());
    }

    #[test]
    fn moe_routing_must_be_exact() {
        let model = StreamingModel::new(moe_spec(2, 4, MIB)).unwrap();
        // Missing routing is refused, never assumed.
        assert!(matches!(
            model.plan_request(shape(4), None),
            Err(StreamingError::Routing { group: 1, .. })
        ));
        let experts = model.groups()[1].experts.clone();
        let routing = moe_routing(&model, &[0, 2]);
        let request = model.plan_request(shape(4), Some(&routing)).unwrap();
        assert!(request.groups[1].weights.contains(&experts[0]));
        assert!(request.groups[1].weights.contains(&experts[2]));
        assert!(!request.needs(experts[1]));
        assert!(request.background.contains(&experts[1]));
        // An expert of another layer cannot stand in.
        let wrong = PrefillRouting::new()
            .route(1, [model.groups()[2].experts[0]])
            .route(2, [model.groups()[2].experts[0]]);
        assert!(matches!(
            model.plan_request(shape(4), Some(&wrong)),
            Err(StreamingError::Routing { group: 1, .. })
        ));
        let dense = StreamingModel::new(dense_spec(2, MIB)).unwrap();
        assert!(matches!(
            dense.plan_request(shape(4), Some(&routing)),
            Err(StreamingError::Routing { .. })
        ));
    }

    #[test]
    fn streaming_reads_exactly_what_the_ordinary_loader_reads() {
        let model = StreamingModel::new(dense_spec(2, MIB)).unwrap();
        let ordinary: Vec<(TensorName, ContentKey)> = model
            .tensors()
            .iter()
            .map(|tensor| (tensor.name.clone(), tensor.content))
            .collect();
        let check = model.verify_against_ordinary_loader(&ordinary).unwrap();
        assert_eq!(check.tensors, model.tensors().len());
        assert_eq!(check.bytes, model.total_weight_bytes().unwrap());
        assert!(!check.numerical_agreement.is_measured());

        let mut changed = ordinary.clone();
        changed[1].1 = ContentKey::of(b"different weights");
        assert_eq!(
            model.verify_against_ordinary_loader(&changed),
            Err(StreamingError::ReadSetMismatch {
                tensor: ordinary[1].0.to_string(),
                problem: ReadSetProblem::ContentDiffers
            })
        );
        let mut extra = ordinary.clone();
        extra.push((
            TensorName::new("unused.weight").unwrap(),
            ContentKey::of(b"x"),
        ));
        assert!(matches!(
            model.verify_against_ordinary_loader(&extra),
            Err(StreamingError::ReadSetMismatch {
                problem: ReadSetProblem::MissingFromStream,
                ..
            })
        ));
        assert!(matches!(
            model.verify_against_ordinary_loader(&ordinary[1..]),
            Err(StreamingError::ReadSetMismatch {
                problem: ReadSetProblem::NotInOrdinaryLoader,
                ..
            })
        ));
    }

    #[test]
    fn unsupported_architectures_use_the_normal_loader() {
        let world = EvidenceWorld::supported(SourceClass::GuestReport);
        let gate = ArchitectureGate::new();
        let mut spec = dense_spec(2, MIB);
        spec.family = ArchitectureFamily::Unsupported {
            name: "state-space".into(),
        };
        assert_eq!(
            choose_loader(spec, &gate, &world.evidence()),
            Ok(LoaderChoice::NormalLoader {
                reason: NormalLoaderReason::UnsupportedFamily {
                    name: "state-space".into()
                }
            })
        );
        let mut spec = dense_spec(2, MIB);
        spec.mode = ExecutionMode::GraphCapture;
        assert_eq!(
            choose_loader(spec, &gate, &world.evidence()),
            Ok(LoaderChoice::NormalLoader {
                reason: NormalLoaderReason::GraphCaptureNotEvaluated
            })
        );
        let mut spec = dense_spec(2, MIB);
        spec.extra_state.push(ExtraState::MultimodalEncoder);
        assert!(matches!(
            choose_loader(spec, &gate, &world.evidence()),
            Ok(LoaderChoice::NormalLoader {
                reason: NormalLoaderReason::UnsupportedState(ExtraState::MultimodalEncoder)
            })
        ));
        // The second architecture waits for a reproducible gain on the first.
        assert_eq!(
            choose_loader(moe_spec(2, 4, MIB), &gate, &world.evidence()),
            Ok(LoaderChoice::NormalLoader {
                reason: NormalLoaderReason::FirstArchitectureGainNotReproduced
            })
        );
        assert!(matches!(
            choose_loader(dense_spec(2, MIB), &gate, &world.evidence()),
            Ok(LoaderChoice::ExecuteWhileLoad { .. })
        ));
        // A broken description of a supported family is refused, not streamed.
        let mut broken = dense_spec(2, MIB);
        broken.tensors.clear();
        assert!(choose_loader(broken, &gate, &world.evidence()).is_err());
    }

    fn refusal(choice: Result<LoaderChoice, StreamingError>) -> EvidenceRefusal {
        match choice {
            Ok(LoaderChoice::NormalLoader {
                reason: NormalLoaderReason::EvidenceRefused(refusal),
            }) => refusal,
            other => panic!("expected an evidence refusal, got {other:?}"),
        }
    }

    #[test]
    fn execute_while_load_needs_fresh_evidence_for_the_actual_runtime() {
        let gate = ArchitectureGate::new();
        // No evidence at all.
        let missing = EvidenceWorld::unobserved();
        assert!(matches!(
            refusal(choose_loader(
                dense_spec(2, MIB),
                &gate,
                &missing.evidence()
            )),
            EvidenceRefusal::Missing {
                capability: Capability::ExecuteWhileLoad
            }
        ));
        // Fresh evidence for this runtime: streaming, carrying the evidence.
        let world = EvidenceWorld::supported(SourceClass::GuestReport);
        match choose_loader(dense_spec(2, MIB), &gate, &world.evidence()).unwrap() {
            LoaderChoice::ExecuteWhileLoad { evidence, .. } => {
                assert_eq!(evidence.capability(), Capability::ExecuteWhileLoad);
                assert_eq!(evidence.subject(), Subject::Runtime(runtime()).identity());
            }
            other => panic!("expected streaming, got {other:?}"),
        }
        // Evidence about another runtime instance does not count for this one.
        let other = other_runtime();
        let mut elsewhere = world.evidence();
        elsewhere.runtime = &other;
        assert!(matches!(
            refusal(choose_loader(dense_spec(2, MIB), &gate, &elsewhere)),
            EvidenceRefusal::Missing { .. }
        ));
        // A guest report where the profile's policy needs a host probe.
        let mut strict = world.evidence();
        strict.policy.minimum_source = SourceClass::HostProbe;
        assert!(matches!(
            refusal(choose_loader(dense_spec(2, MIB), &gate, &strict)),
            EvidenceRefusal::SourceTooWeak {
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
                ..
            }
        ));
        // The configuration changed since the check.
        let mut changed = world.evidence();
        changed.configuration = other_configuration();
        assert!(matches!(
            refusal(choose_loader(dense_spec(2, MIB), &gate, &changed)),
            EvidenceRefusal::FingerprintChanged { .. }
        ));
        // Two hours later the one-hour evidence is stale.
        world
            .clock
            .advance(std::time::Duration::from_secs(2 * 3_600));
        assert!(matches!(
            refusal(choose_loader(dense_spec(2, MIB), &gate, &world.evidence())),
            EvidenceRefusal::Stale { .. }
        ));
    }
}
