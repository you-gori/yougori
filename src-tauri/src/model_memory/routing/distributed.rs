//! GPU §4.8, temporary distributed execution while replicas load (lines 732–738): "nodes
//! holding complementary layers can serve collaboratively while full replicas are being
//! formed."
//!
//! A [`PipelinePlan`] puts complementary layer ranges on nodes joined by measured links.
//! The model covers per-layer activation traffic (hidden size × activation bytes per
//! token at each stage boundary), link latency, microbatch fill, temporary KV placement
//! on each stage and the transition from the pipeline to independent replicas.
//! [`serve_window`] plays a loading window out under one of three strategies: the
//! temporary pipeline, waiting for full replicas, and routing to the donor (line 738).
//! Requests are admitted when a unit starts them, and the transition is replayed through
//! [`PlanEpochs`] so every request finishes on the plan it was admitted to. A slow LAN can
//! erase the benefit; RDMA results are never assumed.

use std::collections::BTreeMap;
use std::fmt;

use crate::foundation::ids::{AuthorizationEpoch, ModelActivationGeneration, OperationId};
use crate::model_memory::identity::ExecutionIdentity;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::{non_negative, positive, InputError};

use super::epochs::{EpochRefusal, PlanEpochs, PlanKind, PlanPublication, PlanTicket};
use super::joint::RequestedModel;
use super::numbers::{approx_f64, index_u32};
use super::replication::NodeId;

/// The model dimensions that size activation traffic and KV (§4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelShape {
    pub layers: u32,
    pub hidden_size: u32,
    pub activation_bytes_per_element: u32,
    pub kv_bytes_per_token_per_layer: u64,
}

impl ModelShape {
    /// Bytes one token's activations carry across a stage boundary: hidden size ×
    /// bytes per element.
    pub fn activation_bytes_per_token(&self) -> u64 {
        u64::from(self.hidden_size).saturating_mul(u64::from(self.activation_bytes_per_element))
    }

    /// Activation bytes of `tokens` tokens at one boundary.
    pub fn boundary_bytes(&self, tokens: u64) -> Result<u64, InputError> {
        self.activation_bytes_per_token()
            .checked_mul(tokens)
            .ok_or(InputError::Overflow {
                field: "boundary_bytes",
            })
    }
}

/// One stage: a node holding a contiguous range of layers.
#[derive(Clone, Debug, PartialEq)]
pub struct PipelineStage {
    pub node: NodeId,
    pub first_layer: u32,
    pub layer_count: u32,
    /// Prefill time per prompt token through this stage's layers.
    pub prefill_seconds_per_token: f64,
    /// One decode token through this stage's layers.
    pub decode_step_seconds: f64,
    /// GPU memory free for temporary KV on this stage.
    pub free_kv_bytes: u64,
}

/// A measured link between stages.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PipelineLink {
    pub bandwidth: BandwidthRating,
    pub latency_seconds: f64,
}

impl PipelineLink {
    /// Latency plus `bytes` at the measured usable bandwidth.
    pub fn seconds(&self, bytes: f64) -> Result<f64, DistributedError> {
        let bytes_per_second = self
            .bandwidth
            .usable_bytes_per_second()
            .map_err(|unusable| DistributedError::UnmeasuredLink {
                basis: unusable.basis,
            })?;
        Ok(self.latency_seconds + bytes / bytes_per_second)
    }
}

/// Why a pipeline, placement or window was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum DistributedError {
    Input(InputError),
    /// The stages do not hold complementary layers covering the model exactly once.
    LayersNotComplementary,
    /// A link figure is not a measured directional bandwidth.
    UnmeasuredLink {
        basis: crate::model_memory::math::bounds::BandwidthBasis,
    },
    /// Temporary KV does not fit a stage.
    KvDoesNotFit {
        stage: usize,
        needed_bytes: u64,
        free_bytes: u64,
    },
    /// The donor strategy needs a donor.
    NoDonor,
    /// The epoch replay refused a step.
    Epoch(EpochRefusal),
}

impl From<InputError> for DistributedError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<EpochRefusal> for DistributedError {
    fn from(error: EpochRefusal) -> Self {
        Self::Epoch(error)
    }
}

impl fmt::Display for DistributedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::LayersNotComplementary => {
                f.write_str("the stages do not hold each layer exactly once, in order")
            }
            Self::UnmeasuredLink { basis } => {
                write!(f, "a link has a {basis:?} figure, not a measured bandwidth")
            }
            Self::KvDoesNotFit {
                stage,
                needed_bytes,
                free_bytes,
            } => write!(
                f,
                "stage {stage} needs {needed_bytes} bytes of temporary KV and has {free_bytes}"
            ),
            Self::NoDonor => f.write_str("no donor is available"),
            Self::Epoch(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DistributedError {}

/// `M / (M + P − 1)`: the busy fraction of a `P`-stage pipeline over `M` microbatches in
/// one pass (§4.8 "microbatch fill").
pub fn microbatch_fill(stages: u32, microbatches: u32) -> Result<f64, InputError> {
    if stages == 0 {
        return Err(InputError::NotPositive { field: "stages" });
    }
    if microbatches == 0 {
        return Err(InputError::NotPositive {
            field: "microbatches",
        });
    }
    let microbatches = f64::from(microbatches);
    Ok(microbatches / (microbatches + f64::from(stages) - 1.0))
}

/// Temporary KV on each stage (§4.8 "temporary KV placement").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvPlacement {
    pub stage_bytes: Vec<u64>,
}

/// Complementary layers on several nodes (§4.8).
#[derive(Clone, Debug, PartialEq)]
pub struct PipelinePlan {
    shape: ModelShape,
    stages: Vec<PipelineStage>,
    links: Vec<PipelineLink>,
    return_link: PipelineLink,
    token_id_bytes: u64,
}

impl PipelinePlan {
    /// Refuses fewer than two stages, layers that are not each held exactly once in
    /// order, a link count other than stages − 1 and unmeasured or negative figures.
    /// `links[i]` joins stage `i` to stage `i + 1`; `return_link` carries the sampled
    /// token from the last stage back to the first.
    pub fn new(
        shape: ModelShape,
        stages: Vec<PipelineStage>,
        links: Vec<PipelineLink>,
        return_link: PipelineLink,
        token_id_bytes: u64,
    ) -> Result<Self, DistributedError> {
        if stages.len() < 2 {
            return Err(InputError::OutOfRange { field: "stages" }.into());
        }
        let expected_links = stages.len().saturating_sub(1);
        if links.len() != expected_links {
            return Err(InputError::LengthMismatch {
                field: "links",
                expected: expected_links,
                actual: links.len(),
            }
            .into());
        }
        let mut next_layer = 0u32;
        for stage in &stages {
            if stage.first_layer != next_layer || stage.layer_count == 0 {
                return Err(DistributedError::LayersNotComplementary);
            }
            next_layer = next_layer
                .checked_add(stage.layer_count)
                .ok_or(DistributedError::LayersNotComplementary)?;
            non_negative("prefill_seconds_per_token", stage.prefill_seconds_per_token)?;
            non_negative("decode_step_seconds", stage.decode_step_seconds)?;
        }
        if next_layer != shape.layers {
            return Err(DistributedError::LayersNotComplementary);
        }
        for link in links.iter().chain(std::iter::once(&return_link)) {
            non_negative("latency_seconds", link.latency_seconds)?;
            link.seconds(0.0)?;
        }
        Ok(Self {
            shape,
            stages,
            links,
            return_link,
            token_id_bytes,
        })
    }

    pub fn stages(&self) -> &[PipelineStage] {
        &self.stages
    }

    pub fn shape(&self) -> &ModelShape {
        &self.shape
    }

    /// Prefill of `prompt_tokens` split into `microbatches` equal microbatches. Stages
    /// and links pipeline: `T(M) = Σ_s t_s + (M − 1) × max_s t_s`, where a compute stage
    /// takes its per-token time × the microbatch's tokens and a link its latency plus the
    /// microbatch's boundary bytes over the measured bandwidth.
    pub fn prefill_seconds(
        &self,
        prompt_tokens: u64,
        microbatches: u32,
    ) -> Result<f64, DistributedError> {
        if microbatches == 0 {
            return Err(InputError::NotPositive {
                field: "microbatches",
            }
            .into());
        }
        let tokens = approx_f64(prompt_tokens) / f64::from(microbatches);
        let bytes = tokens * approx_f64(self.shape.activation_bytes_per_token());
        let mut times = Vec::with_capacity(self.stages.len().saturating_add(self.links.len()));
        for (index, stage) in self.stages.iter().enumerate() {
            times.push(stage.prefill_seconds_per_token * tokens);
            if let Some(link) = self.links.get(index) {
                times.push(link.seconds(bytes)?);
            }
        }
        let total: f64 = times.iter().sum();
        let slowest = times.iter().copied().fold(0.0, f64::max);
        Ok(total + f64::from(microbatches.saturating_sub(1)) * slowest)
    }

    /// One decode token of one sequence: every stage, every forward link carrying one
    /// token's activations, and the return link carrying the sampled token id.
    pub fn decode_step_seconds(&self) -> Result<f64, DistributedError> {
        let activation = approx_f64(self.shape.activation_bytes_per_token());
        let mut total: f64 = self
            .stages
            .iter()
            .map(|stage| stage.decode_step_seconds)
            .sum();
        for link in &self.links {
            total += link.seconds(activation)?;
        }
        Ok(total + self.return_link.seconds(approx_f64(self.token_id_bytes))?)
    }

    /// Activation bytes each boundary carries for one request: the prompt's prefill plus
    /// one token per decode step after the first.
    pub fn activation_traffic_bytes(
        &self,
        prompt_tokens: u64,
        output_tokens: u64,
    ) -> Result<Vec<u64>, DistributedError> {
        let tokens = prompt_tokens
            .checked_add(output_tokens.saturating_sub(1))
            .ok_or(InputError::Overflow {
                field: "activation tokens",
            })?;
        let bytes = self.shape.boundary_bytes(tokens)?;
        Ok(vec![bytes; self.links.len()])
    }

    /// Temporary KV for sequences of `context_tokens` in flight: each stage holds its
    /// layers' KV for every token, and must have room for it.
    pub fn kv_placement(&self, context_tokens: &[u64]) -> Result<KvPlacement, DistributedError> {
        let tokens = context_tokens
            .iter()
            .try_fold(0u64, |total, tokens| total.checked_add(*tokens))
            .ok_or(InputError::Overflow {
                field: "context_tokens",
            })?;
        let mut stage_bytes = Vec::with_capacity(self.stages.len());
        for (index, stage) in self.stages.iter().enumerate() {
            let needed_bytes = u64::from(stage.layer_count)
                .checked_mul(self.shape.kv_bytes_per_token_per_layer)
                .and_then(|per_token| per_token.checked_mul(tokens))
                .ok_or(InputError::Overflow { field: "kv bytes" })?;
            if needed_bytes > stage.free_kv_bytes {
                return Err(DistributedError::KvDoesNotFit {
                    stage: index,
                    needed_bytes,
                    free_bytes: stage.free_kv_bytes,
                });
            }
            stage_bytes.push(needed_bytes);
        }
        Ok(KvPlacement { stage_bytes })
    }
}

/// Serving the whole model on one node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplicaService {
    pub prefill_seconds_per_token: f64,
    pub decode_step_seconds: f64,
}

impl ReplicaService {
    fn first_token_seconds(&self, prompt_tokens: u64) -> f64 {
        approx_f64(prompt_tokens) * self.prefill_seconds_per_token
    }
}

/// The donor that already holds the full model (line 738 "routing to the donor").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DonorRoute {
    /// Work the donor has already admitted.
    pub backlog_seconds: f64,
    pub service: ReplicaService,
    /// Extra network time to and from the donor.
    pub network_tail_seconds: f64,
}

/// The loading window (§4.8).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoadingWindow {
    /// When the complementary layers are resident, so the pipeline can serve.
    pub pipeline_ready_seconds: f64,
    /// When every node holds a full replica.
    pub replicas_ready_seconds: f64,
    pub replica_nodes: u32,
    pub replica_service: ReplicaService,
    pub donor: Option<DonorRoute>,
    pub client_tail_seconds: f64,
    pub microbatches: u32,
    /// The pipeline's and the replicas' executions and plan generations.
    pub pipeline_execution: ExecutionIdentity,
    pub replica_execution: ExecutionIdentity,
    pub pipeline_generation: ModelActivationGeneration,
    pub replica_generation: ModelActivationGeneration,
}

/// One request arriving in the window.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowRequest {
    pub arrival_seconds: f64,
    pub prompt_tokens: u64,
    pub output_tokens: u64,
}

/// The strategies compared (line 738).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowStrategy {
    /// Serve on the temporary pipeline until replicas are ready (the candidate).
    TemporaryPipeline,
    /// Wait for full replicas (the ordinary workflow).
    WaitForReplicas,
    /// Serve on the donor until replicas are ready.
    RouteToDonor,
}

/// Which unit served a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServingUnit {
    Pipeline,
    Replica(u32),
    Donor,
}

/// How one request was served.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowServed {
    pub index: usize,
    pub unit: ServingUnit,
    /// The plan generation it ran on; the donor's own plan is outside this model.
    pub plan: Option<ModelActivationGeneration>,
    pub arrival_seconds: f64,
    pub start_seconds: f64,
    /// Client-side.
    pub first_token_seconds: f64,
    /// Client-side.
    pub completion_seconds: f64,
    /// Activation bytes over the pipeline's links.
    pub activation_bytes: u64,
}

impl WindowServed {
    pub fn time_to_first_token_seconds(&self) -> f64 {
        self.first_token_seconds - self.arrival_seconds
    }
}

fn check_window(window: &LoadingWindow, requests: &[WindowRequest]) -> Result<(), InputError> {
    non_negative("pipeline_ready_seconds", window.pipeline_ready_seconds)?;
    non_negative("replicas_ready_seconds", window.replicas_ready_seconds)?;
    if window.replica_nodes == 0 {
        return Err(InputError::NotPositive {
            field: "replica_nodes",
        });
    }
    non_negative(
        "replica prefill_seconds_per_token",
        window.replica_service.prefill_seconds_per_token,
    )?;
    positive(
        "replica decode_step_seconds",
        window.replica_service.decode_step_seconds,
    )?;
    non_negative("client_tail_seconds", window.client_tail_seconds)?;
    if let Some(donor) = &window.donor {
        non_negative("donor backlog_seconds", donor.backlog_seconds)?;
        non_negative("donor network_tail_seconds", donor.network_tail_seconds)?;
        non_negative(
            "donor prefill_seconds_per_token",
            donor.service.prefill_seconds_per_token,
        )?;
        positive(
            "donor decode_step_seconds",
            donor.service.decode_step_seconds,
        )?;
    }
    if window.pipeline_generation >= window.replica_generation {
        return Err(InputError::OutOfRange {
            field: "replica_generation",
        });
    }
    let mut previous = 0.0;
    for request in requests {
        let arrival = non_negative("arrival_seconds", request.arrival_seconds)?;
        if arrival < previous {
            return Err(InputError::OutOfRange {
                field: "arrival_seconds",
            });
        }
        previous = arrival;
        if request.output_tokens == 0 {
            return Err(InputError::NotPositive {
                field: "output_tokens",
            });
        }
    }
    Ok(())
}

/// Plays the window out under `strategy`. Requests are dispatched in arrival order to the
/// first unit that can start them; a request the pipeline (or donor) would start before
/// the replicas are ready goes there, any other to the replica that frees first. The
/// pipeline's temporary KV must fit every stage. The pipeline-to-replica transition is
/// then replayed through [`PlanEpochs`].
pub fn serve_window(
    plan: &PipelinePlan,
    window: &LoadingWindow,
    requests: &[WindowRequest],
    strategy: WindowStrategy,
    model: &RequestedModel,
    epoch: AuthorizationEpoch,
) -> Result<Vec<WindowServed>, DistributedError> {
    check_window(window, requests)?;
    if strategy == WindowStrategy::RouteToDonor && window.donor.is_none() {
        return Err(DistributedError::NoDonor);
    }
    let decode_step = plan.decode_step_seconds()?;
    let mut pipeline_free = window.pipeline_ready_seconds;
    let mut donor_free = window.donor.map_or(0.0, |donor| donor.backlog_seconds);
    let replica_nodes =
        usize::try_from(window.replica_nodes).map_err(|_| InputError::Overflow {
            field: "replica_nodes",
        })?;
    let mut replica_free = vec![window.replicas_ready_seconds; replica_nodes];
    let mut served = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        let arrival = request.arrival_seconds;
        let decode_after_first = approx_f64(request.output_tokens.saturating_sub(1));
        let early = match strategy {
            WindowStrategy::TemporaryPipeline => {
                let start = arrival.max(pipeline_free);
                (start < window.replicas_ready_seconds).then_some((ServingUnit::Pipeline, start))
            }
            WindowStrategy::RouteToDonor => {
                let start = arrival.max(donor_free);
                (start < window.replicas_ready_seconds).then_some((ServingUnit::Donor, start))
            }
            WindowStrategy::WaitForReplicas => None,
        };
        let entry = match early {
            Some((ServingUnit::Pipeline, start)) => {
                plan.kv_placement(&[request.prompt_tokens.saturating_add(request.output_tokens)])?;
                let first =
                    start + plan.prefill_seconds(request.prompt_tokens, window.microbatches)?;
                let completion = first + decode_after_first * decode_step;
                pipeline_free = completion;
                WindowServed {
                    index,
                    unit: ServingUnit::Pipeline,
                    plan: Some(window.pipeline_generation),
                    arrival_seconds: arrival,
                    start_seconds: start,
                    first_token_seconds: first + window.client_tail_seconds,
                    completion_seconds: completion + window.client_tail_seconds,
                    activation_bytes: plan
                        .activation_traffic_bytes(request.prompt_tokens, request.output_tokens)?
                        .iter()
                        .fold(0u64, |total, bytes| total.saturating_add(*bytes)),
                }
            }
            Some((_, start)) => {
                let donor = window.donor.ok_or(DistributedError::NoDonor)?;
                let first = start + donor.service.first_token_seconds(request.prompt_tokens);
                let completion = first + decode_after_first * donor.service.decode_step_seconds;
                donor_free = completion;
                let tail = window.client_tail_seconds + donor.network_tail_seconds;
                WindowServed {
                    index,
                    unit: ServingUnit::Donor,
                    plan: None,
                    arrival_seconds: arrival,
                    start_seconds: start,
                    first_token_seconds: first + tail,
                    completion_seconds: completion + tail,
                    activation_bytes: 0,
                }
            }
            None => {
                let (replica, free_at) = replica_free
                    .iter()
                    .copied()
                    .enumerate()
                    .min_by(|left, right| left.1.total_cmp(&right.1).then(left.0.cmp(&right.0)))
                    .ok_or(InputError::NotPositive {
                        field: "replica_nodes",
                    })?;
                let start = arrival.max(free_at);
                let service = window.replica_service;
                let first = start + service.first_token_seconds(request.prompt_tokens);
                let completion = first + decode_after_first * service.decode_step_seconds;
                let slot = replica_free
                    .get_mut(replica)
                    .ok_or(InputError::OutOfRange { field: "replica" })?;
                *slot = completion;
                WindowServed {
                    index,
                    unit: ServingUnit::Replica(index_u32(replica)),
                    plan: Some(window.replica_generation),
                    arrival_seconds: arrival,
                    start_seconds: start,
                    first_token_seconds: first + window.client_tail_seconds,
                    completion_seconds: completion + window.client_tail_seconds,
                    activation_bytes: 0,
                }
            }
        };
        served.push(entry);
    }
    let stages = u32::try_from(plan.stages().len()).unwrap_or(u32::MAX);
    replay_epochs(window, stages, &served, model, epoch)?;
    Ok(served)
}

/// Replays the window's plan events in time order through [`PlanEpochs`]: the pipeline
/// is published when it is ready and the replicas when they are, each request is
/// admitted when it starts and finishes on its own plan, and the pipeline is retired
/// once its last request finishes. Finishes come before a publication at the same time,
/// and publications before starts.
fn replay_epochs(
    window: &LoadingWindow,
    stages: u32,
    served: &[WindowServed],
    model: &RequestedModel,
    epoch: AuthorizationEpoch,
) -> Result<(), DistributedError> {
    #[derive(Clone, Copy)]
    enum Event {
        Finish(usize),
        PublishPipeline,
        PublishReplicas,
        Start(usize, ModelActivationGeneration),
    }
    let rank = |event: &Event| match event {
        Event::Finish(_) => 0,
        Event::PublishPipeline | Event::PublishReplicas => 1,
        Event::Start(..) => 2,
    };
    let uses_pipeline = served
        .iter()
        .any(|entry| entry.unit == ServingUnit::Pipeline);
    let mut events: Vec<(f64, Event)> = Vec::new();
    if uses_pipeline {
        events.push((window.pipeline_ready_seconds, Event::PublishPipeline));
    }
    events.push((window.replicas_ready_seconds, Event::PublishReplicas));
    for (index, entry) in served.iter().enumerate() {
        if let Some(plan) = entry.plan {
            events.push((entry.start_seconds, Event::Start(index, plan)));
            events.push((
                entry.completion_seconds - window.client_tail_seconds,
                Event::Finish(index),
            ));
        }
    }
    events.sort_by(|left, right| {
        left.0
            .total_cmp(&right.0)
            .then_with(|| rank(&left.1).cmp(&rank(&right.1)))
    });
    let mut epochs = PlanEpochs::new(model.clone(), epoch);
    let mut tickets: BTreeMap<usize, PlanTicket> = BTreeMap::new();
    for (_, event) in events {
        match event {
            Event::PublishPipeline => {
                epochs.publish(PlanPublication {
                    generation: window.pipeline_generation,
                    execution: window.pipeline_execution,
                    kind: PlanKind::Pipeline { stages },
                })?;
            }
            Event::PublishReplicas => {
                let previous = epochs.publish(PlanPublication {
                    generation: window.replica_generation,
                    execution: window.replica_execution,
                    kind: PlanKind::Replicas {
                        nodes: window.replica_nodes,
                    },
                })?;
                if let Some(previous) = previous {
                    if epochs.in_flight(previous) == 0 {
                        epochs.retire(previous)?;
                    }
                }
            }
            Event::Start(index, planned) => {
                let request = OperationId::new(format!("op-window-{index}"))
                    .map_err(|_| InputError::OutOfRange { field: "request" })?;
                let ticket = epochs.admit(request, epoch)?;
                if ticket.plan != planned {
                    return Err(EpochRefusal::PlanChanged {
                        admitted: ticket.plan,
                        offered: planned,
                    }
                    .into());
                }
                tickets.insert(index, ticket);
            }
            Event::Finish(index) => {
                let ticket = tickets.remove(&index).ok_or(EpochRefusal::UnknownTicket)?;
                let report = epochs.finish(&ticket)?;
                if report.drained {
                    epochs.retire(report.plan)?;
                }
            }
        }
    }
    Ok(())
}

/// Each strategy's served requests, for comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct WindowComparison {
    pub strategies: Vec<(WindowStrategy, Vec<WindowServed>)>,
}

impl WindowComparison {
    /// The strategy with the lowest worst time to first token; ties go to the earlier
    /// strategy.
    pub fn best_by_worst_first_token(&self) -> Option<WindowStrategy> {
        self.strategies
            .iter()
            .map(|(strategy, served)| {
                let worst = served
                    .iter()
                    .map(WindowServed::time_to_first_token_seconds)
                    .fold(0.0, f64::max);
                (*strategy, worst)
            })
            .min_by(|left, right| left.1.total_cmp(&right.1).then(left.0.cmp(&right.0)))
            .map(|(strategy, _)| strategy)
    }
}

/// Plays the window under every available strategy; the donor strategy only with a
/// donor.
pub fn compare_window(
    plan: &PipelinePlan,
    window: &LoadingWindow,
    requests: &[WindowRequest],
    model: &RequestedModel,
    epoch: AuthorizationEpoch,
) -> Result<WindowComparison, DistributedError> {
    let mut strategies = Vec::new();
    for strategy in [
        WindowStrategy::TemporaryPipeline,
        WindowStrategy::WaitForReplicas,
        WindowStrategy::RouteToDonor,
    ] {
        if strategy == WindowStrategy::RouteToDonor && window.donor.is_none() {
            continue;
        }
        strategies.push((
            strategy,
            serve_window(plan, window, requests, strategy, model, epoch)?,
        ));
    }
    Ok(WindowComparison { strategies })
}
