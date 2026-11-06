//! The model-side demand of one activation, computed by the T08 residency module
//! (GPU §2.7; §3.1 line 491).
//!
//! The state an activation holds becomes one T08 [`VramPlan`] for its device: artifact
//! extents and rank layouts are immutable weight allocations, adapters the adapters term,
//! engine initialization, tokenizer state and communicators the runner's context, graph
//! captures its graph pool, KV blocks and the declared KV pool a reserved KV bound, and
//! the transition peak the activation-overlap term. T08 admits the plan model-side
//! against the runtime's device budget with the governor's safety reserve, and its
//! [`peak_demand`] (every term but the reserve, which the ledger keeps itself) is what
//! the ledger is asked for. A fit is the content of a request, never a grant; only the
//! ledger reserves.
//!
//! The demand counts every node the activation holds, ready ones included, as P04's
//! steady state must: the placement's slot then reserves only what extents resident in
//! its own placements do not cover, and state resident under another model's activation
//! counts twice while both live, so it is never left uncounted when the other retires.

use std::fmt;
use std::time::Duration;

use serde::{Serialize, Serializer};

use super::declaration::{ExecutionDependencies, NodeId};
use crate::foundation::ids::{GpuDeviceKey, MonotonicTime, TrustScope};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::residency::reservation::{peak_demand, vram_resource, PlacementError};
use crate::model_memory::residency::vram::{
    admit_vram, ImmutableAllocation, ImmutableKind, KvBound, ProcessVram, TransientDemand,
    TransientKind, VramBreakdown, VramPlan,
};
use crate::model_memory::residency::{Capacity, InputError, Interval};

/// Every term of an activation is held from the moment it is admitted for the whole of
/// its life, so a window of any length gives the same peak; one second is used.
pub const DEMAND_WINDOW: Duration = Duration::from_secs(1);

/// The device sub-budget of one runtime, as the CORE-03 ledger granted it (line 491),
/// and the room the §2.7 inequality keeps for GPU consumers outside managed allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceBudget {
    pub device: GpuDeviceKey,
    pub usable_bytes: u64,
    pub safety_reserve_bytes: u64,
}

/// The §2.7 demand of one activation on its device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ActivationDemand {
    pub device: GpuDeviceKey,
    /// T08's peak of every term but the safety reserve: the bytes the ledger reserves.
    pub device_bytes: u64,
    /// The terms at the peak, the safety reserve included.
    pub peak: VramBreakdown,
}

/// Why the demand could not be computed or does not fit model-side. Serialized as its
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemandError {
    /// T08 refused the plan: it does not fit, keeps no safety reserve, declares no
    /// context, or another §2.7 rule.
    Residency(PlacementError),
    Input(InputError),
    /// A node the activation holds is not declared.
    UnknownNode {
        node: NodeId,
    },
    /// A node of request work was declared as state.
    NotState {
        node: NodeId,
    },
}

impl fmt::Display for DemandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Residency(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::UnknownNode { node } => write!(f, "{node} is not declared"),
            Self::NotState { node } => write!(f, "{node} is request work, not state"),
        }
    }
}

impl std::error::Error for DemandError {}

impl Serialize for DemandError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl From<PlacementError> for DemandError {
    fn from(error: PlacementError) -> Self {
        Self::Residency(error)
    }
}

impl From<InputError> for DemandError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

/// The §2.7 demand of an activation holding `held` of `dependencies` in `scope`, judged
/// against `budget` at `at`.
pub fn activation_demand(
    dependencies: &ExecutionDependencies,
    held: &[NodeId],
    scope: TrustScope,
    budget: &DeviceBudget,
    at: MonotonicTime,
) -> Result<ActivationDemand, DemandError> {
    let end = at.checked_add(DEMAND_WINDOW).ok_or(InputError::Overflow {
        field: "demand window",
    })?;
    let window = Interval::new(at, end)?;
    let mut allocations = Vec::new();
    let mut context_bytes = 0u64;
    let mut graph_pool_bytes = 0u64;
    let mut kv_bytes = dependencies.session_device_bytes;
    let add = |field: &'static str, total: u64, bytes: u64| {
        total
            .checked_add(bytes)
            .ok_or(InputError::Overflow { field })
    };
    for id in held {
        let node = dependencies
            .node(*id)
            .ok_or(DemandError::UnknownNode { node: *id })?;
        let allocation = |kind| ImmutableAllocation {
            key: format!("state-{}", node.identity.digest().to_hex()),
            kind,
            bytes: node.device_bytes,
            sharing_domain: scope,
            resident: window,
        };
        match node.kind {
            NodeKind::ArtifactExtent | NodeKind::RankLayout => {
                if node.device_bytes > 0 {
                    allocations.push(allocation(ImmutableKind::Weights));
                }
            }
            NodeKind::Adapter => {
                if node.device_bytes > 0 {
                    allocations.push(allocation(ImmutableKind::Adapter));
                }
            }
            NodeKind::EngineInitialization
            | NodeKind::TokenizerConfiguration
            | NodeKind::Communicator => {
                context_bytes = add("context bytes", context_bytes, node.device_bytes)?;
            }
            NodeKind::GraphCapture => {
                graph_pool_bytes = add("graph pool bytes", graph_pool_bytes, node.device_bytes)?;
            }
            NodeKind::KvBlock => {
                kv_bytes = add("KV bytes", kv_bytes, node.device_bytes)?;
            }
            NodeKind::Compute | NodeKind::NetworkResponse => {
                return Err(DemandError::NotState { node: *id });
            }
        }
    }
    let transients = if dependencies.transition_peak_device_bytes > 0 {
        vec![TransientDemand {
            kind: TransientKind::ActivationOverlap,
            bytes: dependencies.transition_peak_device_bytes,
            during: window,
        }]
    } else {
        Vec::new()
    };
    let plan = VramPlan {
        device: budget.device,
        usable_vram: Capacity::Physical {
            bytes: budget.usable_bytes,
        },
        safety_reserve_bytes: budget.safety_reserve_bytes,
        processes: vec![ProcessVram {
            process: "runner".to_owned(),
            sharing_domain: scope,
            lifetime: window,
            maps: allocations
                .iter()
                .map(|allocation| allocation.key.clone())
                .collect(),
            context_bytes,
            graph_pool_bytes,
            kv: KvBound::Reserved { bytes: kv_bytes },
            transients,
        }],
        allocations,
    };
    let peak = admit_vram(&plan)
        .map_err(PlacementError::Vram)?
        .peak()
        .map(|piece| piece.demand)
        .unwrap_or_default();
    let device_bytes =
        peak_demand(std::slice::from_ref(&plan), None)?.get(vram_resource(budget.device));
    Ok(ActivationDemand {
        device: budget.device,
        device_bytes,
        peak,
    })
}
