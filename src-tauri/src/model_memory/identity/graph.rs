//! The CUDA graph execution key (§1.1, line 305: "Validate an execution key and every
//! graph resource. Addresses alone do not establish correctness").
//!
//! A captured graph replays fixed kernels against fixed memory. Reuse is valid only when
//! the execution identity, device, capture shape and every resource the graph touches
//! are the same, each with its content identity, allocation generation, address, length
//! and layout. Stable addresses are necessary and never sufficient.

use std::collections::BTreeMap;
use std::fmt;

use crate::foundation::ids::{Digest, GpuAllocationGeneration, GpuDeviceKey};

use super::encoding::{identity_type, Encode, Encoding, GRAPH_DOMAIN};
use super::error::IdentityError;
use super::fields::Label;
use super::layers::ExecutionIdentity;

identity_type!(
    /// The key a captured CUDA graph is valid for (§1.1, line 305). Built only by
    /// [`GraphCaptureSpec::key`].
    GraphExecutionKey
);

/// What a graph resource is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GraphResourceKind {
    Weights,
    KvCache,
    Workspace,
    Input,
    Output,
    AdapterSlot,
    Communicator,
    RandomState,
    MemoryPool,
}

impl GraphResourceKind {
    const fn tag(self) -> &'static str {
        match self {
            Self::Weights => "weights",
            Self::KvCache => "kv_cache",
            Self::Workspace => "workspace",
            Self::Input => "input",
            Self::Output => "output",
            Self::AdapterSlot => "adapter_slot",
            Self::Communicator => "communicator",
            Self::RandomState => "random_state",
            Self::MemoryPool => "memory_pool",
        }
    }
}

/// One resource a captured graph touches (§1.1, line 305 "every graph resource").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GraphResource {
    /// The resource's role, unique within the graph, such as `kv_cache.layer.0`.
    pub role: Label,
    pub kind: GraphResourceKind,
    /// The identity of what the resource holds: an artifact, adapter or buffer
    /// specification digest.
    pub content: Digest,
    pub allocation: GpuAllocationGeneration,
    pub device_address: u64,
    pub length_bytes: u64,
    /// Dtype, shape and stride layout.
    pub layout: Label,
}

impl Encode for GraphResource {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.role)
            .tag(self.kind.tag())
            .item(&self.content)
            .item(&self.allocation)
            .u64(self.device_address)
            .u64(self.length_bytes)
            .item(&self.layout);
    }
}

/// The batch shape a graph was captured for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CaptureShape {
    pub sequences: u32,
    pub tokens: u32,
}

/// Everything a captured graph depends on (§1.1, line 305).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphCaptureSpec {
    pub execution: ExecutionIdentity,
    pub device: GpuDeviceKey,
    pub shape: CaptureShape,
    /// In any order; the key sorts them by role, and a role may appear once. At least
    /// one.
    pub resources: Vec<GraphResource>,
}

/// A field of a [`GraphResource`] that differs between capture and replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GraphResourceField {
    Kind,
    Content,
    Allocation,
    DeviceAddress,
    Length,
    Layout,
}

/// One difference between a captured graph and the current state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphDifference {
    Execution,
    Device,
    Shape,
    ResourceMissing {
        role: Label,
    },
    ResourceAdded {
        role: Label,
    },
    ResourceChanged {
        role: Label,
        fields: Vec<GraphResourceField>,
    },
}

/// Why a captured graph may not be replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphReuseRefusal {
    InvalidCapture(IdentityError),
    InvalidCurrent(IdentityError),
    /// The keys differ; `differences` names every input that changed.
    Mismatch {
        differences: Vec<GraphDifference>,
    },
}

impl fmt::Display for GraphReuseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapture(error) => write!(f, "the captured graph is invalid: {error}"),
            Self::InvalidCurrent(error) => write!(f, "the current graph state is invalid: {error}"),
            Self::Mismatch { differences } => write!(
                f,
                "the graph execution key differs in {} input(s); recapture instead of replaying",
                differences.len()
            ),
        }
    }
}

impl std::error::Error for GraphReuseRefusal {}

impl GraphCaptureSpec {
    /// §1.1, line 305: the key over the execution identity, device, shape and every
    /// resource. Refuses an empty or duplicated resource list.
    pub fn key(&self) -> Result<GraphExecutionKey, IdentityError> {
        Ok(GraphExecutionKey(self.canonical()?.finish(GRAPH_DOMAIN)))
    }

    /// Replay is allowed only when the current key equals the captured key, which covers
    /// every resource (§1.1, line 305). Otherwise the refusal lists what differs.
    pub fn check_reuse(
        &self,
        current: &GraphCaptureSpec,
    ) -> Result<GraphExecutionKey, GraphReuseRefusal> {
        let captured = self.key().map_err(GraphReuseRefusal::InvalidCapture)?;
        let now = current.key().map_err(GraphReuseRefusal::InvalidCurrent)?;
        if captured == now {
            return Ok(captured);
        }
        Err(GraphReuseRefusal::Mismatch {
            differences: self.differences(current),
        })
    }

    pub(crate) fn canonical(&self) -> Result<Encoding, IdentityError> {
        let resources = sorted_resources(&self.resources)?;
        let mut out = Encoding::new();
        out.item(&self.execution)
            .item(&self.device)
            .u64(self.shape.sequences.into())
            .u64(self.shape.tokens.into())
            .list(resources);
        Ok(out)
    }

    fn differences(&self, current: &GraphCaptureSpec) -> Vec<GraphDifference> {
        let mut differences = Vec::new();
        if self.execution != current.execution {
            differences.push(GraphDifference::Execution);
        }
        if self.device != current.device {
            differences.push(GraphDifference::Device);
        }
        if self.shape != current.shape {
            differences.push(GraphDifference::Shape);
        }
        let captured = by_role(&self.resources);
        let now = by_role(&current.resources);
        for (role, resource) in &captured {
            match now.get(role) {
                None => differences.push(GraphDifference::ResourceMissing {
                    role: (*role).clone(),
                }),
                Some(other) => {
                    let fields = changed_fields(resource, other);
                    if !fields.is_empty() {
                        differences.push(GraphDifference::ResourceChanged {
                            role: (*role).clone(),
                            fields,
                        });
                    }
                }
            }
        }
        for role in now.keys().filter(|role| !captured.contains_key(*role)) {
            differences.push(GraphDifference::ResourceAdded {
                role: (*role).clone(),
            });
        }
        differences
    }
}

fn sorted_resources(resources: &[GraphResource]) -> Result<Vec<&GraphResource>, IdentityError> {
    if resources.is_empty() {
        return Err(IdentityError::NoGraphResources);
    }
    let mut sorted: Vec<&GraphResource> = resources.iter().collect();
    sorted.sort_by(|left, right| left.role.cmp(&right.role));
    let duplicate = sorted.windows(2).find_map(|pair| match pair {
        [left, right] if left.role == right.role => Some(left.role.as_str().to_owned()),
        _ => None,
    });
    match duplicate {
        Some(role) => Err(IdentityError::DuplicateGraphResource { role }),
        None => Ok(sorted),
    }
}

fn by_role(resources: &[GraphResource]) -> BTreeMap<&Label, &GraphResource> {
    resources
        .iter()
        .map(|resource| (&resource.role, resource))
        .collect()
}

fn changed_fields(captured: &GraphResource, current: &GraphResource) -> Vec<GraphResourceField> {
    [
        (GraphResourceField::Kind, captured.kind != current.kind),
        (
            GraphResourceField::Content,
            captured.content != current.content,
        ),
        (
            GraphResourceField::Allocation,
            captured.allocation != current.allocation,
        ),
        (
            GraphResourceField::DeviceAddress,
            captured.device_address != current.device_address,
        ),
        (
            GraphResourceField::Length,
            captured.length_bytes != current.length_bytes,
        ),
        (
            GraphResourceField::Layout,
            captured.layout != current.layout,
        ),
    ]
    .into_iter()
    .filter_map(|(field, changed)| changed.then_some(field))
    .collect()
}
