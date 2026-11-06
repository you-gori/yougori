//! A streaming schedule as a request DAG (GPU §2.3 lines 379–395).
//!
//! Every read request becomes an artifact-extent node, every buffer build an
//! engine-initialization node, every execution group a compute node, and the first token a
//! response node. Reads contend for one read-path slot and buffer builds for one
//! initialization stream, so consecutive ones are joined by resource-conflict edges.
//! [`evaluate_fixed`] then gives the first-correct-token finish by
//! `finish(v) = duration(v) + max(finish(u))`, which must agree with the §2.6 recurrence
//! the schedule was planned with: two committed models of the same plan, checked against
//! each other.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::foundation::ids::{DigestBuilder, TrustScope};
use crate::model_memory::graph::dag::{GraphBuilder, Policy, RequestGraph};
use crate::model_memory::graph::node::{
    CompletionEvent, DemandProfile, DemandSegment, DurationEstimate, NodeKind, NodeSpec,
    ResourceUnit,
};
use crate::model_memory::graph::schedule::{evaluate_fixed, Capacities};
use crate::model_memory::graph::{NodeId, ResourceId};

use super::architecture::PlannedRequest;
use super::deadline::{OrderPolicy, StreamingSchedule};
use super::StreamingError;

/// The response node's duration: the graph needs every node to take time.
pub const RESPONSE_NANOS: u64 = 1;

/// A schedule as a request graph with its resources and conflict edges.
#[derive(Clone, Debug)]
pub struct ScheduleGraph {
    pub graph: RequestGraph,
    pub capacities: Capacities,
    pub conflict_edges: Vec<(NodeId, NodeId)>,
}

impl ScheduleGraph {
    /// The first token by the §2.3 finish recurrence, without the response node.
    pub fn first_token_seconds(&self) -> Result<f64, StreamingError> {
        let evaluated = evaluate_fixed(&self.graph, &self.capacities, &self.conflict_edges)?;
        let nanos = evaluated
            .first_token()
            .saturating_sub(Duration::from_nanos(RESPONSE_NANOS));
        Ok(nanos.as_secs_f64())
    }
}

fn nanos(seconds: f64) -> Result<Duration, StreamingError> {
    if !(seconds.is_finite() && seconds > 0.0) {
        return Err(StreamingError::Invalid {
            field: "node duration",
            reason: "every node takes more than zero seconds",
        });
    }
    Ok(Duration::from_nanos((seconds * 1e9).round().max(1.0) as u64))
}

fn node(
    id: &NodeId,
    kind: NodeKind,
    completion: CompletionEvent,
    index: u64,
    duration: Duration,
    scope: TrustScope,
) -> Result<NodeSpec, StreamingError> {
    let identity = DigestBuilder::new("yougori/model-memory/streaming/dag-node/v1")
        .str(id.as_str())
        .u64(index)
        .finish();
    Ok(NodeSpec::new(
        id.clone(),
        kind,
        identity,
        scope,
        DurationEstimate::exact(duration)?,
        completion,
    ))
}

fn slot(resource: &ResourceId, duration: Duration) -> Result<DemandProfile, StreamingError> {
    Ok(DemandProfile::new(vec![DemandSegment::transient(
        resource.clone(),
        ResourceUnit::Slots,
        1,
        Duration::ZERO,
        duration,
    )?]))
}

/// Builds the DAG of one planned load (GPU §2.3).
pub fn schedule_graph(
    request: &PlannedRequest,
    schedule: &StreamingSchedule,
    scope: TrustScope,
) -> Result<ScheduleGraph, StreamingError> {
    let read_path = ResourceId::new("streaming-read-path")?;
    let init_stream = ResourceId::new("streaming-init-stream")?;
    let mut builder = GraphBuilder::new();
    let mut conflicts = Vec::new();
    let mut reads = Vec::with_capacity(schedule.requests.len());
    for (index, read) in schedule.requests.iter().enumerate() {
        let id = NodeId::new(format!("read-{index}"))?;
        let duration = nanos(read.end_seconds - read.start_seconds)?;
        builder = builder.node(
            node(
                &id,
                NodeKind::ArtifactExtent,
                CompletionEvent::ExtentVerified,
                index as u64,
                duration,
                scope,
            )?
            .with_demand(slot(&read_path, duration)?),
        );
        if let Some(previous) = reads.last() {
            conflicts.push((NodeId::clone(previous), id.clone()));
        }
        reads.push(id);
    }
    let mut buffers = Vec::with_capacity(request.buffers.len());
    for (index, buffer) in request.buffers.iter().enumerate() {
        let id = NodeId::new(format!("buffer-{index}"))?;
        let duration = nanos(buffer.init_seconds)?;
        builder = builder.node(
            node(
                &id,
                NodeKind::EngineInitialization,
                CompletionEvent::EngineReady,
                index as u64,
                duration,
                scope,
            )?
            .with_demand(slot(&init_stream, duration)?),
        );
        if let Some(previous) = buffers.last() {
            conflicts.push((NodeId::clone(previous), id.clone()));
        }
        buffers.push(id);
    }
    let mut computes = Vec::with_capacity(request.groups.len());
    for (index, group) in request.groups.iter().enumerate() {
        let id = NodeId::new(format!("compute-{index}"))?;
        builder = builder.node(node(
            &id,
            NodeKind::Compute,
            CompletionEvent::ComputeCompleted,
            index as u64,
            nanos(group.compute_seconds)?,
            scope,
        )?);
        computes.push(id);
    }
    let response = NodeId::new("first-token")?;
    builder = builder.node(node(
        &response,
        NodeKind::NetworkResponse,
        CompletionEvent::FirstTokenDelivered,
        0,
        Duration::from_nanos(RESPONSE_NANOS),
        scope,
    )?);

    for (index, group) in request.groups.iter().enumerate() {
        let needed: BTreeSet<usize> = group.tensors().collect();
        let compute = &computes[index];
        for (read_index, read) in schedule.requests.iter().enumerate() {
            if read.tensors.iter().any(|tensor| needed.contains(tensor)) {
                builder = builder.edge(&reads[read_index], compute);
            }
        }
        for buffer in &group.buffers {
            let producer = buffers.get(*buffer).ok_or(StreamingError::Unknown {
                field: "buffers",
                index: *buffer,
            })?;
            builder = builder.edge(producer, compute);
        }
        if index > 0 {
            builder = builder.edge(&computes[index - 1], compute);
        }
    }
    if schedule.policy == OrderPolicy::OrdinaryLoader {
        // The ordinary loader computes nothing before its last read.
        if let (Some(last), Some(first)) = (reads.last(), computes.first()) {
            builder = builder.edge(last, first);
        }
    }
    if let Some(last) = computes.last() {
        builder = builder.edge(last, &response);
    }
    let graph = builder.build(Policy::new())?;
    let capacities = Capacities::new()
        .with(read_path, ResourceUnit::Slots, 1)?
        .with(init_stream, ResourceUnit::Slots, 1)?;
    Ok(ScheduleGraph {
        graph,
        capacities,
        conflict_edges: conflicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ExecutionCategory;
    use crate::model_memory::streaming::architecture::StreamingModel;
    use crate::model_memory::streaming::deadline::plan_streaming;
    use crate::model_memory::streaming::test_support::*;

    #[test]
    fn the_request_graph_agrees_with_the_recurrence_for_every_order() {
        let model =
            StreamingModel::new(dense_spec_with(12, 4 * MIB, Layout::Lexicographic)).unwrap();
        let request = model.plan_request(shape(32), None).unwrap();
        let path = read_path(0.000_05, 6e9);
        let scope = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-a");
        for policy in [
            OrderPolicy::OrdinaryLoader,
            OrderPolicy::FileOrder,
            OrderPolicy::ExecutionOrder,
            OrderPolicy::DeadlineOrder { lookahead_steps: 1 },
        ] {
            let schedule =
                plan_streaming(&model, &request, &path, &budget(32 * MIB), policy).unwrap();
            let graph = schedule_graph(&request, &schedule, scope).unwrap();
            let by_graph = graph.first_token_seconds().unwrap();
            let by_recurrence = schedule.first_token.first_token_seconds;
            // Nanosecond rounding per node is the only difference.
            let nodes = graph.graph.len() as f64;
            assert!(
                (by_graph - by_recurrence).abs() <= nodes * 1e-9,
                "{policy:?}: {by_graph} against {by_recurrence}"
            );
            // The first token needs every compute node: all groups and the output head.
            for index in 0..request.groups.len() {
                let id = NodeId::new(format!("compute-{index}")).unwrap();
                assert!(graph.graph.on_objective_path(&id));
            }
        }
    }
}
