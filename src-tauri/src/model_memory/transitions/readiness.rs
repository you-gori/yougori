//! Stage readiness (GPU §4.15 lines 850 and 864): how long after a stage's request its
//! first correct token arrives, given which of its state is already resident.
//!
//! Each stage becomes a request graph (§2.3) scheduled by
//! [`crate::model_memory::graph::paths::plan`]: resident state is ready and skipped (§1
//! path 1), missing state is loaded on the one host-to-device link or rebuilt on the GPU
//! (path 2), and independent work overlaps (path 3). Readiness is an estimate with an
//! uncertainty interval, never a guarantee (line 864).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::ids::{DigestBuilder, MonotonicTime, ResourceId};
use crate::model_memory::graph::dag::{GraphBuilder, Policy};
use crate::model_memory::graph::heuristic::WorkBound;
use crate::model_memory::graph::node::{
    CancellationBoundary, CompletionEvent, DemandProfile, DemandSegment, DurationEstimate,
    NodeKind, NodeSpec, ResourceUnit,
};
use crate::model_memory::graph::paths::{plan, ReadyState};
use crate::model_memory::graph::schedule::Capacities;
use crate::model_memory::graph::NodeId;
use crate::model_memory::residency::retention::ObjectKind;

use super::declaration::CheckedWorkflow;
use super::{ResourceSet, TransitionError};

/// Digest domain of the identities of a stage's compute and response nodes.
pub const STAGE_WORK_DOMAIN: &str = "yougori/model-memory/transitions/stage-work/v1";

/// A readiness estimate in seconds with its uncertainty interval (line 864: an
/// estimate rather than a guarantee).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ReadinessEstimate {
    pub expected_seconds: f64,
    pub low_seconds: f64,
    pub high_seconds: f64,
}

impl ReadinessEstimate {
    /// The same estimate delayed by `seconds` on every end.
    pub fn delayed_by(self, seconds: f64) -> Self {
        Self {
            expected_seconds: self.expected_seconds + seconds,
            low_seconds: self.low_seconds + seconds,
            high_seconds: self.high_seconds + seconds,
        }
    }
}

/// Work that makes one missing resource ready.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Work {
    /// A transfer on the host-to-device link.
    Load { seconds: f64 },
    /// Computation on the GPU (a derive or a recompute).
    Compute { seconds: f64 },
}

/// One stage's readiness question.
pub(crate) struct StageQuestion<'q> {
    pub(crate) stage: usize,
    /// Required resources already resident.
    pub(crate) ready: ResourceSet,
    /// Resident derive sources outside the requirement.
    pub(crate) extra_ready: ResourceSet,
    pub(crate) demand: &'q [(usize, Work)],
    pub(crate) derive_edges: &'q [(usize, usize)],
    /// The timing-drift correction applied to stage durations.
    pub(crate) scale: f64,
}

fn duration(seconds: f64) -> Result<Duration, TransitionError> {
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| TransitionError::DurationOutOfRange { seconds })
}

fn estimate(seconds: f64, spread: f64) -> Result<DurationEstimate, TransitionError> {
    let expected = duration(seconds)?.max(Duration::from_nanos(1));
    let low = duration(seconds * (1.0 - spread))?.min(expected);
    let high = duration(seconds * (1.0 + spread))?.max(expected);
    Ok(DurationEstimate::new(low, expected, high)?)
}

fn node_id(value: String) -> Result<NodeId, TransitionError> {
    Ok(NodeId::new(value)?)
}

fn resource_id(name: &str) -> Result<ResourceId, TransitionError> {
    Ok(ResourceId::new(name)?)
}

/// The readiness of one stage (§2.3 objective: the first correct token), scheduled by the
/// request graph.
pub(crate) fn stage_readiness(
    workflow: &CheckedWorkflow,
    question: &StageQuestion<'_>,
    clock: &dyn crate::foundation::ids::Clock,
) -> Result<ReadinessEstimate, TransitionError> {
    let stage = workflow
        .stages
        .get(question.stage)
        .ok_or(TransitionError::Internal {
            what: "stage index out of range",
        })?;
    let spread = workflow.curves.relative_spread;
    let link = resource_id("transitions.h2d-link")?;
    let gpu = resource_id("transitions.gpu-compute")?;
    let scope = workflow.trust_scope;
    let members = stage.requires.union(question.extra_ready);
    let mut builder = GraphBuilder::new();
    let mut ready_states = Vec::new();
    let forever = MonotonicTime::from_nanos(u64::MAX);
    for at in members.iter() {
        let resource = &workflow.resources[at];
        let (kind, completion) = match resource.kind {
            ObjectKind::BaseWeights | ObjectKind::MergedVariant => {
                (NodeKind::ArtifactExtent, CompletionEvent::ExtentVerified)
            }
            ObjectKind::Adapter => (NodeKind::Adapter, CompletionEvent::AdapterActivated),
            ObjectKind::SessionKv => (NodeKind::KvBlock, CompletionEvent::KvBlockPublished),
            ObjectKind::GraphPool => (NodeKind::GraphCapture, CompletionEvent::GraphKeyValidated),
        };
        let work = question
            .demand
            .iter()
            .find(|(index, _)| *index == at)
            .map(|(_, work)| *work);
        let spec = match work {
            None if !question.ready.union(question.extra_ready).contains(at) => {
                return Err(TransitionError::Internal {
                    what: "required state is neither resident nor materialized",
                })
            }
            None => {
                ready_states.push(ReadyState::new(resource.digest, scope, forever));
                NodeSpec::new(
                    node_id(format!("r{at}"))?,
                    kind,
                    resource.digest,
                    scope,
                    DurationEstimate::exact(Duration::from_nanos(1))?,
                    completion,
                )
            }
            Some(Work::Load { seconds }) => {
                let estimate = estimate(seconds, spread)?;
                let demand = DemandSegment::transient(
                    link.clone(),
                    ResourceUnit::Slots,
                    1,
                    Duration::ZERO,
                    estimate.expected(),
                )?;
                NodeSpec::new(
                    node_id(format!("r{at}"))?,
                    kind,
                    resource.digest,
                    scope,
                    estimate,
                    completion,
                )
                .with_demand(DemandProfile::new(vec![demand]))
                .with_cancellation(CancellationBoundary::Boundaries {
                    max_interval: duration(workflow.curves.load_cancellation_interval_seconds)?,
                })
            }
            Some(Work::Compute { seconds }) => {
                let estimate = estimate(seconds, spread)?;
                let demand = DemandSegment::transient(
                    gpu.clone(),
                    ResourceUnit::Slots,
                    1,
                    Duration::ZERO,
                    estimate.expected(),
                )?;
                NodeSpec::new(
                    node_id(format!("r{at}"))?,
                    kind,
                    resource.digest,
                    scope,
                    estimate,
                    completion,
                )
                .with_demand(DemandProfile::new(vec![demand]))
            }
        };
        builder = builder.node(spec);
    }
    let prefill = estimate(stage.prefill_seconds * question.scale, spread)?;
    let prefill_demand = DemandSegment::transient(
        gpu.clone(),
        ResourceUnit::Slots,
        1,
        Duration::ZERO,
        prefill.expected(),
    )?;
    let compute_id = node_id("prefill".to_string())?;
    let response_id = node_id("first-token".to_string())?;
    let work_identity = |part: &str| {
        DigestBuilder::new(STAGE_WORK_DOMAIN)
            .str(stage.id.as_str())
            .str(part)
            .finish()
    };
    builder = builder
        .node(
            NodeSpec::new(
                compute_id.clone(),
                NodeKind::Compute,
                work_identity("prefill"),
                scope,
                prefill,
                CompletionEvent::ComputeCompleted,
            )
            .with_demand(DemandProfile::new(vec![prefill_demand])),
        )
        .node(NodeSpec::new(
            response_id.clone(),
            NodeKind::NetworkResponse,
            work_identity("first-token"),
            scope,
            estimate(stage.response_seconds * question.scale, spread)?,
            CompletionEvent::FirstTokenDelivered,
        ));
    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for at in members.iter() {
        for prerequisite in workflow.resources[at].closure.without(at).iter() {
            if members.contains(prerequisite) {
                edges.insert((prerequisite, at));
            }
        }
    }
    for (source, target) in question.derive_edges {
        if members.contains(*source) && members.contains(*target) {
            edges.insert((*source, *target));
        }
    }
    for (from, to) in &edges {
        builder = builder.edge(&node_id(format!("r{from}"))?, &node_id(format!("r{to}"))?);
    }
    for at in stage.requires.iter() {
        builder = builder.edge(&node_id(format!("r{at}"))?, &compute_id);
    }
    builder = builder.edge(&compute_id, &response_id);
    let graph = builder.build(Policy::new())?;
    let capacities =
        Capacities::new()
            .with(link, ResourceUnit::Slots, 1)?
            .with(gpu, ResourceUnit::Slots, 1)?;
    let planned = plan(
        &graph,
        &ready_states,
        clock,
        &capacities,
        WorkBound::for_graph(&graph),
    )?;
    let expected = planned
        .first_token_at()
        .saturating_duration_since(planned.planned_at());
    let (low, high) = planned.schedule().first_token_interval();
    Ok(ReadinessEstimate {
        expected_seconds: expected.as_secs_f64(),
        low_seconds: low.as_secs_f64(),
        high_seconds: high.as_secs_f64(),
    })
}
