//! Handles and positions local to placement (§3.6). Generations, epochs and execution
//! identifiers come from `foundation::ids`; nothing here duplicates them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{ContentKey, Digest, GpuDeviceKey};

macro_rules! digest_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            /// Names the value by `digest`.
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            /// The digest that names the value.
            pub const fn digest(self) -> Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! handle {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// The handle numbered `value`, as its issuer numbers it.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// The handle's number.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

digest_name!(
    /// One serving target owned by one parent execution. Activation generations are
    /// allocated per slot, and the slot's request router publishes one of them (§3.6
    /// step 5).
    SlotId
);

handle!(
    /// A placement record inside one slot, numbered from 1 in creation order and never
    /// reused within the slot.
    PlacementKey
);
handle!(
    /// One rank of a single- or multi-rank activation (§3.6 line 599).
    Rank
);
handle!(
    /// One instance of a runtime process; a restarted process is a new instance (§3.6
    /// line 585: process liveness is its own field).
    ProcessInstance
);
handle!(
    /// A reservation granted through the reservation port (CORE-03, task T04).
    ReservationId
);
handle!(
    /// A GPU completion event for work enqueued on a placement's memory (§3.6 step 7).
    CompletionEventId
);
handle!(
    /// A process reference to a placement's memory, such as a mapping, an import or a
    /// captured graph (§3.6 step 7).
    ReferenceId
);

/// One immutable extent resident on one GPU: the content key of its bytes and the
/// device. The same content on two devices is two extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentKey {
    pub content: ContentKey,
    pub device: GpuDeviceKey,
}

/// A part of the model a request's computation depends on (§2.6: layers, the output
/// head, tied embeddings, recurrent state, nonpersistent buffers, multimodal encoders,
/// graph capture and, for MoE, exact experts). Named parts carry an index the manifest
/// assigns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Layer(u32),
    /// One exact expert of one MoE layer; another expert never stands in for it (§2.6).
    Expert {
        layer: u32,
        expert: u32,
    },
    Embedding,
    OutputHead,
    RecurrentState(u32),
    Buffer(u32),
    Encoder(u32),
    Graph(u32),
    /// The weights of one applied adapter.
    Adapter(u32),
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layer(layer) => write!(f, "layer {layer}"),
            Self::Expert { layer, expert } => write!(f, "expert {expert} of layer {layer}"),
            Self::Embedding => f.write_str("embedding"),
            Self::OutputHead => f.write_str("output head"),
            Self::RecurrentState(index) => write!(f, "recurrent state {index}"),
            Self::Buffer(index) => write!(f, "buffer {index}"),
            Self::Encoder(index) => write!(f, "encoder {index}"),
            Self::Graph(index) => write!(f, "graph {index}"),
            Self::Adapter(index) => write!(f, "adapter {index}"),
        }
    }
}

/// A component on one rank: the unit a generation's content maps to an extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeightPosition {
    pub rank: Rank,
    pub component: Component,
}

impl WeightPosition {
    /// `component` on `rank`.
    pub const fn new(rank: Rank, component: Component) -> Self {
        Self { rank, component }
    }
}

impl fmt::Display for WeightPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on rank {}", self.component, self.rank)
    }
}
