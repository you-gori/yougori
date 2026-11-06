//! What a runner adapter declares a request needs (GPU §3.1 row 4: "exact execution
//! dependencies"), and the security partition planning stays inside (S3.6).

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::catalog::ExtentRef;
use crate::foundation::ids::{Digest, OperationId, TrustScope};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::ArtifactIdentity;

/// One node of a runner's dependency declaration, unique within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(u32);

impl NodeId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node {}", self.0)
    }
}

/// The semantic identity of one piece of required state. Two declarations share state
/// only when these are equal, as a base shared by two adapter variants (GPU §1 path 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateIdentity(Digest);

impl StateIdentity {
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }
}

/// How a missing node becomes usable (GPU §1 path 2: transfer or reconstruct only the
/// missing state).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum Materialization {
    /// The transfer executor reads, verifies, decodes and copies these extents.
    Transfer { extents: Vec<ExtentRef> },
    /// The runner rebuilds it, as with engine initialization or a graph capture.
    Reconstruct,
}

/// One piece of state a request needs. `depends_on` lists the nodes it is made from or
/// needs usable first. Its kind is a state kind of the request graph (T06), never
/// compute or response work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub identity: StateIdentity,
    pub scope: TrustScope,
    /// Device memory the node holds once usable.
    pub device_bytes: u64,
    /// Expected time to make it usable; more than zero.
    pub estimate: Duration,
    pub depends_on: Vec<NodeId>,
    pub materialization: Materialization,
}

/// One group of the request's computation, in execution order, and the nodes it reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComputeGroup {
    pub requires: Vec<NodeId>,
    pub compute: Duration,
}

/// A runner's exact execution dependencies for one model and request shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionDependencies {
    /// The artifact a residency of this model is recorded under (GPU §3.2 item 5).
    pub artifact: ArtifactIdentity,
    pub nodes: Vec<DependencyNode>,
    pub compute: Vec<ComputeGroup>,
    /// Expected time from the last compute group to the first token at the client; more
    /// than zero.
    pub response: Duration,
    /// The KV pool an activation for this shape reserves on the device for its whole
    /// life (GPU §2.7: bounded KV; T08: the KV bound is held for the process lifetime).
    pub session_device_bytes: u64,
    /// Device memory needed only while the activation is made, such as activations alive
    /// while later weights load (§3.6 step 1 "transition peaks", §2.6).
    pub transition_peak_device_bytes: u64,
}

impl ExecutionDependencies {
    pub fn node(&self, id: NodeId) -> Option<&DependencyNode> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

/// A piece of request state a runner holds: shared required state, or one request's
/// session KV.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StateRef {
    Node { identity: StateIdentity },
    Session { operation: OperationId },
}

/// The data boundary of one request, fixed by security policy before any memory
/// scheduling (S3.6): its own scope plus the scopes it holds a read-only grant for
/// (S3.3). Memory scheduling optimizes only inside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecurityPartition {
    own: TrustScope,
    granted: BTreeSet<TrustScope>,
}

impl SecurityPartition {
    pub fn new(own: TrustScope) -> Self {
        Self {
            own,
            granted: BTreeSet::new(),
        }
    }

    /// Adds a read-only grant for another scope. The grant is decided by the security
    /// layer; this only records it.
    pub fn with_read_grant(mut self, scope: TrustScope) -> Self {
        self.granted.insert(scope);
        self
    }

    pub fn own(&self) -> TrustScope {
        self.own
    }

    pub fn allows(&self, scope: &TrustScope) -> bool {
        *scope == self.own || self.granted.contains(scope)
    }
}
