//! Deadline-aware layer streaming (GPU §4.4 lines 689–697; GPU-W07 item 4).
//!
//! Each execution group's latest useful arrival comes from the compute schedule: with the
//! first group usable at `a_1`, group `i` is useful no later than `a_1 + sum_(j<i) t_j`,
//! the §2.6 no-stall deadline. Its slack is that deadline minus its arrival; a negative
//! slack is a stall.
//!
//! One read path serves one request at a time. A request is a contiguous range of whole
//! tensors of at most g_t bytes (a single larger tensor is read in `ceil(len / g_t)`
//! chunks), costs `chunks × alpha + bytes / B` by the fitted path model of §2.5, and makes
//! every tensor in it usable when it completes. Coalescing adjacent tensors amortizes
//! `alpha`; it delays the first tensor in the request. Four orders are compared:
//!
//! - [`OrderPolicy::OrdinaryLoader`]: file order, and no group computes before the whole
//!   load completes (the baseline every overlap must beat end to end);
//! - [`OrderPolicy::FileOrder`]: stored order, coalesced;
//! - [`OrderPolicy::ExecutionOrder`]: each tensor with its first reader, layer by layer,
//!   coalesced where adjacent (the PipeSwitch formulation);
//! - [`OrderPolicy::DeadlineOrder`]: first-token dependencies by deadline, then everything
//!   else. With no lookahead it sends the least-slack tensor alone. With a lookahead of
//!   1–3 steps it weighs four candidates (the least-slack and the earliest-deadline
//!   tensor, each alone or coalesced forward into a contiguous bulk read) by the
//!   first-token time the §2.6 recurrence predicts after rolling out the rest with each
//!   base rule.
//!
//! Group arrivals become [`GroupRequirement`]s with tied tensors as
//! [`DependencyKind::TiedEmbeddings`] and buffers as
//! [`DependencyKind::NonPersistentBuffers`], and the first token comes from
//! [`first_token`]: the output head runs after every required layer (§2.6 line 432).

use std::collections::BTreeSet;

use crate::model_memory::graph::granularity::Granularities;
use crate::model_memory::graph::scatter_gather::ByteRange;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::chunking::LinearServiceFit;
use crate::model_memory::math::overlap::{
    finish_after, finish_times, first_token, no_stall, Dependency, DependencyKind, FirstToken,
    GroupRequirement, GroupTiming, NoStall,
};

use super::architecture::{PlannedRequest, StreamingModel};
use super::{add_bytes, non_negative, StreamingError};

/// The largest lookahead: §4.4 asks for a small one.
pub const MAX_LOOKAHEAD_STEPS: usize = 3;

/// The most first-token dependencies the exhaustive order oracle accepts (§2.3 line 395:
/// an exhaustive search is an offline oracle for tiny traces only).
pub const ORDER_ORACLE_MAX_TENSORS: usize = 6;

/// The fitted read path `t(c) = alpha + c/B` (GPU §2.5) with a measured directional
/// bandwidth (GPU §2.2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReadCostModel {
    overhead_seconds: f64,
    bandwidth_bytes_per_second: f64,
}

impl ReadCostModel {
    /// Refuses an advertised or bidirectional bandwidth figure: only a measured
    /// directional bandwidth is usable (GPU §2.2).
    pub fn new(overhead_seconds: f64, bandwidth: &BandwidthRating) -> Result<Self, StreamingError> {
        let bandwidth_bytes_per_second =
            bandwidth
                .usable_bytes_per_second()
                .map_err(|_| StreamingError::Invalid {
                    field: "bandwidth",
                    reason: "only a measured directional bandwidth is usable (GPU §2.2)",
                })?;
        Ok(Self {
            overhead_seconds: non_negative("overhead_seconds", overhead_seconds)?,
            bandwidth_bytes_per_second,
        })
    }

    /// The path a least-squares fit of measurements describes.
    pub fn from_fit(fit: &LinearServiceFit) -> Self {
        Self {
            overhead_seconds: fit.overhead_seconds(),
            bandwidth_bytes_per_second: fit.bandwidth_bytes_per_second(),
        }
    }

    /// `alpha`: per-request overhead.
    pub fn overhead_seconds(&self) -> f64 {
        self.overhead_seconds
    }

    /// `B`.
    pub fn bandwidth_bytes_per_second(&self) -> f64 {
        self.bandwidth_bytes_per_second
    }

    /// `chunks × alpha + bytes / B`.
    pub fn read_seconds(&self, bytes: u64, chunks: u64) -> f64 {
        chunks as f64 * self.overhead_seconds + bytes as f64 / self.bandwidth_bytes_per_second
    }

    /// `bytes / B`: the time the bytes occupy the path.
    pub fn data_seconds(&self, bytes: u64) -> f64 {
        bytes as f64 / self.bandwidth_bytes_per_second
    }
}

/// Resource budgets a plan respects: g_t bounds every request, so cancellation and the
/// non-preemptible stretch stay bounded (§2.4, §2.5), and the destination reservation
/// bounds the bytes loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamingBudget {
    transport_batch_bytes: u64,
    destination_bytes: u64,
}

impl StreamingBudget {
    /// g_t from the recorded granularities and the destination reservation's bytes.
    pub fn new(
        granularities: &Granularities,
        destination_bytes: u64,
    ) -> Result<Self, StreamingError> {
        if destination_bytes == 0 {
            return Err(StreamingError::Invalid {
                field: "destination_bytes",
                reason: "must be more than zero",
            });
        }
        Ok(Self {
            transport_batch_bytes: granularities.transport_batch_bytes(),
            destination_bytes,
        })
    }

    /// g_t.
    pub fn transport_batch_bytes(&self) -> u64 {
        self.transport_batch_bytes
    }

    /// The destination reservation's bytes.
    pub fn destination_bytes(&self) -> u64 {
        self.destination_bytes
    }
}

/// One read request: contiguous whole tensors, usable together at `end_seconds`.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadRequest {
    pub tensors: Vec<usize>,
    pub range: ByteRange,
    pub chunks: u64,
    pub start_seconds: f64,
    pub end_seconds: f64,
}

/// The transfer order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderPolicy {
    OrdinaryLoader,
    FileOrder,
    ExecutionOrder,
    /// `lookahead_steps` 0 sends the least-slack tensor alone; 1–3 weigh bulk against
    /// scattered reads.
    DeadlineOrder {
        lookahead_steps: usize,
    },
    /// The offline oracle of §2.3 line 395 for tiny requests: every sequence of reads of
    /// the first-token dependencies, each read any contiguous run of unread tensors that
    /// starts at one of them and fits in g_t; the earliest first token wins.
    ExhaustiveOracle,
}

/// One group's latest useful arrival, arrival and slack.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GroupSlack {
    pub latest_useful_arrival_seconds: f64,
    pub usable_at_seconds: f64,
    /// Latest useful arrival minus arrival; negative means the group stalls compute.
    pub slack_seconds: f64,
}

/// The latest useful arrival `a_1 + sum_(j<i) t_j` and slack of every group (GPU §4.4,
/// the §2.6 no-stall deadline).
pub fn group_slack(timings: &[GroupTiming]) -> Result<Vec<GroupSlack>, StreamingError> {
    let first = timings.first().ok_or(StreamingError::Invalid {
        field: "timings",
        reason: "at least one group",
    })?;
    let mut deadline = non_negative("usable_at_seconds", first.usable_at_seconds)?;
    let mut slack = Vec::with_capacity(timings.len());
    for timing in timings {
        let usable = non_negative("usable_at_seconds", timing.usable_at_seconds)?;
        slack.push(GroupSlack {
            latest_useful_arrival_seconds: deadline,
            usable_at_seconds: usable,
            slack_seconds: deadline - usable,
        });
        deadline += non_negative("compute_seconds", timing.compute_seconds)?;
    }
    Ok(slack)
}

/// A planned load: its requests, arrivals and the first token they allow.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamingSchedule {
    pub policy: OrderPolicy,
    pub requests: Vec<ReadRequest>,
    /// Per tensor: when it is usable.
    pub tensor_usable_seconds: Vec<f64>,
    /// Per buffer: when its initialization finishes.
    pub buffer_usable_seconds: Vec<f64>,
    pub requirements: Vec<GroupRequirement>,
    pub timings: Vec<GroupTiming>,
    pub finish_seconds: Vec<f64>,
    pub first_token: FirstToken,
    pub no_stall: NoStall,
    pub slack: Vec<GroupSlack>,
    /// When every first-token dependency is usable.
    pub dependencies_usable_seconds: f64,
    /// When every tensor is usable.
    pub load_complete_seconds: f64,
    pub transferred_bytes: u64,
}

impl StreamingSchedule {
    /// The windows in which bytes occupy the read path: the last `bytes / B` of each
    /// request.
    pub fn busy_intervals(&self, cost: &ReadCostModel) -> Vec<(f64, f64)> {
        self.requests
            .iter()
            .map(|request| {
                let start = request.end_seconds - cost.data_seconds(request.range.length_bytes);
                (start.max(request.start_seconds), request.end_seconds)
            })
            .collect()
    }

    /// The first group with negative slack, as [`no_stall`] names it.
    pub fn first_stall(&self) -> Option<usize> {
        match self.no_stall {
            NoStall::Holds => None,
            NoStall::Stalls { group, .. } => Some(group - 1),
        }
    }
}

/// Everything the order and the prediction need about one request.
struct Context<'a> {
    model: &'a StreamingModel,
    request: &'a PlannedRequest,
    cost: &'a ReadCostModel,
    batch_bytes: u64,
    /// The tensor stored right after each one, if any.
    next_adjacent: Vec<Option<usize>>,
    buffer_usable: Vec<f64>,
    /// Per tensor: the deadline of its first consumer; `None` for background tensors.
    deadline: Vec<Option<f64>>,
}

/// Plans one request's load under `policy` (GPU §4.4).
pub fn plan_streaming(
    model: &StreamingModel,
    request: &PlannedRequest,
    cost: &ReadCostModel,
    budget: &StreamingBudget,
    policy: OrderPolicy,
) -> Result<StreamingSchedule, StreamingError> {
    let total = model.total_weight_bytes()?;
    if total > budget.destination_bytes {
        return Err(StreamingError::OverDestinationBudget {
            needed_bytes: total,
            budget_bytes: budget.destination_bytes,
        });
    }
    if let OrderPolicy::DeadlineOrder { lookahead_steps } = policy {
        if lookahead_steps > MAX_LOOKAHEAD_STEPS {
            return Err(StreamingError::Invalid {
                field: "lookahead_steps",
                reason: "the lookahead is at most three steps",
            });
        }
    }
    check_request(model, request)?;
    let context = Context::new(model, request, cost, budget.transport_batch_bytes)?;
    let order: Vec<Vec<usize>> = match policy {
        OrderPolicy::OrdinaryLoader | OrderPolicy::FileOrder => {
            let mut all: Vec<usize> = (0..model.tensors().len()).collect();
            all.sort_by_key(|tensor| model.tensors()[*tensor].stored.offset_bytes);
            context.coalesce(&all)
        }
        OrderPolicy::ExecutionOrder => {
            let mut all: Vec<usize> = (0..model.tensors().len()).collect();
            all.sort_by_key(|tensor| {
                (
                    model.owner_group(*tensor).unwrap_or(usize::MAX),
                    model.tensors()[*tensor].stored.offset_bytes,
                )
            });
            context.coalesce(&all)
        }
        OrderPolicy::DeadlineOrder { lookahead_steps } => {
            context.deadline_order(lookahead_steps)?
        }
        OrderPolicy::ExhaustiveOracle => context.oracle_order()?,
    };
    context.schedule(policy, &order)
}

/// A request's fields are public, so every index is checked against the model before
/// it is used.
fn check_request(model: &StreamingModel, request: &PlannedRequest) -> Result<(), StreamingError> {
    if request.groups.is_empty() {
        return Err(StreamingError::Invalid {
            field: "groups",
            reason: "a request has groups",
        });
    }
    let tensors = model.tensors().len();
    for group in &request.groups {
        if let Some(tensor) = group.tensors().find(|tensor| *tensor >= tensors) {
            return Err(StreamingError::Unknown {
                field: "PlannedGroup.tensors",
                index: tensor,
            });
        }
        if let Some(buffer) = group.buffers.iter().find(|b| **b >= request.buffers.len()) {
            return Err(StreamingError::Unknown {
                field: "PlannedGroup.buffers",
                index: *buffer,
            });
        }
        let compute = non_negative("compute_seconds", group.compute_seconds)?;
        if compute <= 0.0 {
            return Err(StreamingError::Invalid {
                field: "compute_seconds",
                reason: "every group computes for more than zero seconds",
            });
        }
    }
    if let Some(tensor) = request.background.iter().find(|tensor| **tensor >= tensors) {
        return Err(StreamingError::Unknown {
            field: "PlannedRequest.background",
            index: *tensor,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    LeastSlack,
    EarliestDeadline,
}

/// A partial deadline-order plan.
#[derive(Clone, Debug)]
struct State {
    pending: BTreeSet<usize>,
    background: BTreeSet<usize>,
    link_free: f64,
    usable: Vec<Option<f64>>,
    order: Vec<Vec<usize>>,
}

/// Predicted first token, then predicted completion of the first-token dependencies.
type Value = (f64, f64);

fn better(left: Value, right: Value) -> bool {
    left.0 < right.0 || (left.0 == right.0 && left.1 < right.1)
}

impl<'a> Context<'a> {
    fn new(
        model: &'a StreamingModel,
        request: &'a PlannedRequest,
        cost: &'a ReadCostModel,
        batch_bytes: u64,
    ) -> Result<Self, StreamingError> {
        let tensors = model.tensors();
        let mut by_offset: Vec<usize> = (0..tensors.len()).collect();
        by_offset.sort_by_key(|tensor| tensors[*tensor].stored.offset_bytes);
        let mut next_adjacent = vec![None; tensors.len()];
        for pair in by_offset.windows(2) {
            if let [left, right] = pair {
                if tensors[*left].stored.end_bytes() == tensors[*right].stored.offset_bytes {
                    next_adjacent[*left] = Some(*right);
                }
            }
        }
        let mut buffer_usable = Vec::with_capacity(request.buffers.len());
        let mut init_end = 0.0;
        for buffer in &request.buffers {
            init_end += non_negative("buffer init_seconds", buffer.init_seconds)?;
            buffer_usable.push(init_end);
        }
        let mut context = Self {
            model,
            request,
            cost,
            batch_bytes,
            next_adjacent,
            buffer_usable,
            deadline: vec![None; tensors.len()],
        };
        // The compute schedule starts when the first group could be usable at the
        // earliest: its tensors read alone from time zero, and its buffers built.
        let first = request.groups.first().ok_or(StreamingError::Invalid {
            field: "groups",
            reason: "a request has groups",
        })?;
        let mut first_usable = first
            .tensors()
            .map(|tensor| context.read_alone_seconds(tensor))
            .sum::<f64>();
        for buffer in &first.buffers {
            first_usable = first_usable.max(context.buffer_at(*buffer)?);
        }
        let mut group_deadline = Vec::with_capacity(request.groups.len());
        let mut deadline = first_usable;
        for group in &request.groups {
            group_deadline.push(deadline);
            deadline += group.compute_seconds;
        }
        for tensor in 0..tensors.len() {
            context.deadline[tensor] = request
                .first_consumer(tensor)
                .and_then(|group| group_deadline.get(group).copied());
        }
        Ok(context)
    }

    fn length(&self, tensor: usize) -> u64 {
        self.model.tensors()[tensor].stored.length_bytes
    }

    fn chunks(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.batch_bytes).max(1)
    }

    fn read_alone_seconds(&self, tensor: usize) -> f64 {
        let bytes = self.length(tensor);
        self.cost.read_seconds(bytes, self.chunks(bytes))
    }

    fn buffer_at(&self, buffer: usize) -> Result<f64, StreamingError> {
        self.buffer_usable
            .get(buffer)
            .copied()
            .ok_or(StreamingError::Unknown {
                field: "buffers",
                index: buffer,
            })
    }

    /// Splits an ordered tensor list into requests: consecutive tensors that are adjacent
    /// in storage share a request while it stays within g_t.
    fn coalesce(&self, ordered: &[usize]) -> Vec<Vec<usize>> {
        let mut requests: Vec<Vec<usize>> = Vec::new();
        let mut bytes = 0u64;
        for &tensor in ordered {
            let length = self.length(tensor);
            let joins = requests
                .last()
                .and_then(|last| last.last())
                .is_some_and(|previous| {
                    self.next_adjacent[*previous] == Some(tensor)
                        && bytes.saturating_add(length) <= self.batch_bytes
                });
            if joins {
                bytes += length;
                if let Some(last) = requests.last_mut() {
                    last.push(tensor);
                }
            } else {
                bytes = length;
                requests.push(vec![tensor]);
            }
        }
        requests
    }

    /// Bytes and chunks of one request.
    fn request_size(&self, tensors: &[usize]) -> (u64, u64) {
        let bytes = tensors
            .iter()
            .map(|tensor| self.length(*tensor))
            .sum::<u64>();
        (bytes, self.chunks(bytes))
    }

    fn apply(&self, state: &State, tensors: Vec<usize>) -> State {
        let mut next = state.clone();
        let (bytes, chunks) = self.request_size(&tensors);
        let end = next.link_free + self.cost.read_seconds(bytes, chunks);
        for tensor in &tensors {
            next.usable[*tensor] = Some(end);
            next.pending.remove(tensor);
            next.background.remove(tensor);
        }
        next.link_free = end;
        next.order.push(tensors);
        next
    }

    fn urgent(&self, state: &State, rule: Rule) -> Option<usize> {
        let key = |tensor: usize| -> f64 {
            let deadline = self.deadline[tensor].unwrap_or(f64::INFINITY);
            match rule {
                Rule::EarliestDeadline => deadline,
                Rule::LeastSlack => deadline - (state.link_free + self.read_alone_seconds(tensor)),
            }
        };
        state
            .pending
            .iter()
            .copied()
            .fold(None, |best, tensor| match best {
                Some(current) if key(current) <= key(tensor) => Some(current),
                _ => Some(tensor),
            })
    }

    /// The urgent tensor extended forward over unread adjacent tensors within g_t.
    fn bulk(&self, state: &State, start: usize) -> Vec<usize> {
        let mut tensors = vec![start];
        let mut bytes = self.length(start);
        let mut at = start;
        while let Some(next) = self.next_adjacent[at] {
            let unread = state.pending.contains(&next) || state.background.contains(&next);
            let length = self.length(next);
            if !unread || bytes.saturating_add(length) > self.batch_bytes {
                break;
            }
            bytes += length;
            tensors.push(next);
            at = next;
        }
        tensors
    }

    fn candidates(&self, state: &State) -> Vec<Vec<usize>> {
        let mut candidates: Vec<Vec<usize>> = Vec::new();
        for rule in [Rule::EarliestDeadline, Rule::LeastSlack] {
            if let Some(tensor) = self.urgent(state, rule) {
                for candidate in [self.bulk(state, tensor), vec![tensor]] {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
        }
        candidates
    }

    /// The predicted first token and dependency completion of a finished prefix.
    fn evaluate(&self, state: &State) -> Result<Value, StreamingError> {
        let mut finish = 0.0;
        for group in &self.request.groups {
            let mut usable = 0.0f64;
            for tensor in group.tensors() {
                usable = usable.max(state.usable[tensor].ok_or(StreamingError::Invalid {
                    field: "deadline order",
                    reason: "a first-token dependency was never read",
                })?);
            }
            for buffer in &group.buffers {
                usable = usable.max(self.buffer_at(*buffer)?);
            }
            finish = finish_after(
                finish,
                GroupTiming {
                    usable_at_seconds: usable,
                    compute_seconds: group.compute_seconds,
                },
            )?;
        }
        Ok((finish, state.link_free))
    }

    fn rollout(&self, state: &State, rule: Rule) -> Result<Value, StreamingError> {
        let mut state = state.clone();
        while let Some(tensor) = self.urgent(&state, rule) {
            state = self.apply(&state, vec![tensor]);
        }
        self.evaluate(&state)
    }

    fn value(&self, state: &State, depth: usize) -> Result<Value, StreamingError> {
        if state.pending.is_empty() {
            return self.evaluate(state);
        }
        let mut best: Option<Value> = None;
        if depth == 0 {
            for rule in [Rule::EarliestDeadline, Rule::LeastSlack] {
                let value = self.rollout(state, rule)?;
                if best.is_none_or(|current| better(value, current)) {
                    best = Some(value);
                }
            }
        } else {
            for candidate in self.candidates(state) {
                let value = self.value(&self.apply(state, candidate), depth - 1)?;
                if best.is_none_or(|current| better(value, current)) {
                    best = Some(value);
                }
            }
        }
        best.ok_or(StreamingError::Invalid {
            field: "deadline order",
            reason: "no candidate",
        })
    }

    /// Nothing read yet: first-token dependencies pending, every other tensor background.
    fn start(&self) -> State {
        let tensors = self.model.tensors().len();
        State {
            pending: (0..tensors)
                .filter(|t| self.deadline[*t].is_some())
                .collect(),
            background: (0..tensors)
                .filter(|t| self.deadline[*t].is_none())
                .collect(),
            link_free: 0.0,
            usable: vec![None; tensors],
            order: Vec::new(),
        }
    }

    /// Appends the background tensors, coalesced in stored order, to a finished prefix.
    fn finish_order(&self, state: State) -> Vec<Vec<usize>> {
        let mut order = state.order;
        let mut rest: Vec<usize> = state.background.into_iter().collect();
        rest.sort_by_key(|tensor| self.model.tensors()[*tensor].stored.offset_bytes);
        order.extend(self.coalesce(&rest));
        order
    }

    fn search(
        &self,
        state: &State,
        best: &mut Option<(Value, Vec<Vec<usize>>)>,
    ) -> Result<(), StreamingError> {
        if state.pending.is_empty() {
            let value = self.evaluate(state)?;
            if best
                .as_ref()
                .is_none_or(|(current, _)| better(value, *current))
            {
                *best = Some((value, state.order.clone()));
            }
            return Ok(());
        }
        for tensor in &state.pending {
            let run = self.bulk(state, *tensor);
            for length in 1..=run.len() {
                let read = run.get(..length).map(<[usize]>::to_vec).unwrap_or_default();
                self.search(&self.apply(state, read), best)?;
            }
        }
        Ok(())
    }

    fn oracle_order(&self) -> Result<Vec<Vec<usize>>, StreamingError> {
        let start = self.start();
        if start.pending.len() > ORDER_ORACLE_MAX_TENSORS {
            return Err(StreamingError::OracleTooLarge {
                ops: self.request.groups.len(),
                tensors: start.pending.len(),
                max_ops: usize::MAX,
                max_tensors: ORDER_ORACLE_MAX_TENSORS,
            });
        }
        let mut best = None;
        self.search(&start, &mut best)?;
        let (_, order) = best.ok_or(StreamingError::Invalid {
            field: "order oracle",
            reason: "no order",
        })?;
        let mut state = start;
        for read in order {
            state = self.apply(&state, read);
        }
        Ok(self.finish_order(state))
    }

    fn deadline_order(&self, lookahead_steps: usize) -> Result<Vec<Vec<usize>>, StreamingError> {
        let mut state = self.start();
        while !state.pending.is_empty() {
            let choice = if lookahead_steps == 0 {
                self.urgent(&state, Rule::LeastSlack)
                    .map(|tensor| vec![tensor])
            } else {
                let mut best: Option<(Value, Vec<usize>)> = None;
                for candidate in self.candidates(&state) {
                    let value =
                        self.value(&self.apply(&state, candidate.clone()), lookahead_steps - 1)?;
                    if best
                        .as_ref()
                        .is_none_or(|(current, _)| better(value, *current))
                    {
                        best = Some((value, candidate));
                    }
                }
                best.map(|(_, candidate)| candidate)
            };
            let choice = choice.ok_or(StreamingError::Invalid {
                field: "deadline order",
                reason: "no candidate",
            })?;
            state = self.apply(&state, choice);
        }
        Ok(self.finish_order(state))
    }

    /// Times the requests in order and derives the groups' arrivals and first token.
    fn schedule(
        &self,
        policy: OrderPolicy,
        order: &[Vec<usize>],
    ) -> Result<StreamingSchedule, StreamingError> {
        let tensors = self.model.tensors();
        let mut usable: Vec<Option<f64>> = vec![None; tensors.len()];
        let mut requests = Vec::with_capacity(order.len());
        let mut link_free = 0.0;
        let mut transferred_bytes = 0u64;
        for tensors_in_request in order {
            let first = *tensors_in_request.first().ok_or(StreamingError::Invalid {
                field: "requests",
                reason: "a request reads at least one tensor",
            })?;
            let (bytes, chunks) = self.request_size(tensors_in_request);
            let start = link_free;
            let end = start + self.cost.read_seconds(bytes, chunks);
            for tensor in tensors_in_request {
                if usable[*tensor].replace(end).is_some() {
                    return Err(StreamingError::Duplicate {
                        field: "requests",
                        name: tensors[*tensor].name.to_string(),
                    });
                }
            }
            transferred_bytes = add_bytes("transferred bytes", transferred_bytes, bytes)?;
            requests.push(ReadRequest {
                tensors: tensors_in_request.clone(),
                range: ByteRange {
                    offset_bytes: tensors[first].stored.offset_bytes,
                    length_bytes: bytes,
                },
                chunks,
                start_seconds: start,
                end_seconds: end,
            });
            link_free = end;
        }
        let tensor_usable_seconds = usable
            .iter()
            .enumerate()
            .map(|(tensor, at)| {
                at.ok_or_else(|| StreamingError::Unread {
                    name: tensors[tensor].name.to_string(),
                })
            })
            .collect::<Result<Vec<f64>, StreamingError>>()?;
        let load_complete_seconds = link_free;
        let mut requirements = Vec::with_capacity(self.request.groups.len());
        let mut dependencies_usable_seconds = 0.0f64;
        for group in &self.request.groups {
            let weights = group
                .weights
                .iter()
                .map(|tensor| tensor_usable_seconds[*tensor])
                .fold(0.0f64, f64::max);
            let mut dependencies: Vec<Dependency> = group
                .tied
                .iter()
                .map(|tensor| Dependency {
                    kind: DependencyKind::TiedEmbeddings,
                    usable_at_seconds: tensor_usable_seconds[*tensor],
                })
                .collect();
            for buffer in &group.buffers {
                dependencies.push(Dependency {
                    kind: DependencyKind::NonPersistentBuffers,
                    usable_at_seconds: self.buffer_at(*buffer)?,
                });
            }
            let mut requirement = GroupRequirement {
                weights_usable_at_seconds: weights,
                compute_seconds: group.compute_seconds,
                dependencies,
            };
            dependencies_usable_seconds = requirement
                .dependencies
                .iter()
                .map(|dependency| dependency.usable_at_seconds)
                .fold(dependencies_usable_seconds.max(weights), f64::max);
            if policy == OrderPolicy::OrdinaryLoader {
                // The ordinary loader computes nothing before the whole load completes.
                requirement.weights_usable_at_seconds = load_complete_seconds;
            }
            requirements.push(requirement);
        }
        let timings: Vec<GroupTiming> = requirements
            .iter()
            .map(|requirement| GroupTiming {
                usable_at_seconds: requirement
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.usable_at_seconds)
                    .fold(requirement.weights_usable_at_seconds, f64::max),
                compute_seconds: requirement.compute_seconds,
            })
            .collect();
        let (head, layers) = requirements.split_last().ok_or(StreamingError::Invalid {
            field: "groups",
            reason: "a request has groups",
        })?;
        let first_token = first_token(layers, head)?;
        if policy == OrderPolicy::OrdinaryLoader {
            dependencies_usable_seconds = load_complete_seconds;
        }
        Ok(StreamingSchedule {
            policy,
            requests,
            tensor_usable_seconds,
            buffer_usable_seconds: self.buffer_usable.clone(),
            finish_seconds: finish_times(&timings)?,
            no_stall: no_stall(&timings)?,
            slack: group_slack(&timings)?,
            requirements,
            timings,
            first_token,
            dependencies_usable_seconds,
            load_complete_seconds,
            transferred_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::math::bounds::{transfer_lower_bound, ResourceTable, TransferDemand};
    use crate::model_memory::math::chunking::ServiceSample;
    use crate::model_memory::math::overlap::{GroupRef, WaitCause};
    use crate::model_memory::math::ResourceId;
    use crate::model_memory::streaming::test_support::*;

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[test]
    fn slack_on_a_hand_worked_schedule() {
        // Compute (1, 10, 2, 3) and arrivals (1, 11, 12, 13). Latest useful arrivals are
        // a_1 + sum_(j<i) t_j = (1, 2, 12, 14), so the slack is (0, -9, 0, 1).
        let timings: Vec<GroupTiming> = [(1.0, 1.0), (11.0, 10.0), (12.0, 2.0), (13.0, 3.0)]
            .into_iter()
            .map(|(usable_at_seconds, compute_seconds)| GroupTiming {
                usable_at_seconds,
                compute_seconds,
            })
            .collect();
        let slack = group_slack(&timings).unwrap();
        let deadlines: Vec<f64> = slack
            .iter()
            .map(|s| s.latest_useful_arrival_seconds)
            .collect();
        let slacks: Vec<f64> = slack.iter().map(|s| s.slack_seconds).collect();
        assert_eq!(deadlines, vec![1.0, 2.0, 12.0, 14.0]);
        assert_eq!(slacks, vec![0.0, -9.0, 0.0, 1.0]);
        // The first negative slack is the group §2.6's no-stall check names.
        assert_eq!(
            no_stall(&timings).unwrap(),
            NoStall::Stalls {
                group: 2,
                usable_at_seconds: 11.0,
                deadline_seconds: 2.0
            }
        );
        // The 9-second deficit is the stall: finish 26 against the ideal 17.
        assert_eq!(finish_times(&timings).unwrap().last(), Some(&26.0));
        assert!(group_slack(&[]).is_err());
    }

    #[test]
    fn the_read_path_comes_from_a_fit_or_a_measured_bandwidth() {
        let fit = LinearServiceFit::fit(&[
            ServiceSample {
                chunk_bytes: MIB,
                seconds: 0.002 + MIB as f64 / 2e9,
            },
            ServiceSample {
                chunk_bytes: 64 * MIB,
                seconds: 0.002 + 64.0 * MIB as f64 / 2e9,
            },
        ])
        .unwrap();
        let path = ReadCostModel::from_fit(&fit);
        assert!((path.overhead_seconds() - 0.002).abs() < 1e-12);
        assert!((path.bandwidth_bytes_per_second() - 2e9).abs() < 1.0);
        // Three chunks pay alpha three times.
        assert!(close(path.read_seconds(4_000_000, 3), 0.006 + 0.002));
        // An advertised figure is never usable bandwidth.
        assert!(ReadCostModel::new(0.0, &BandwidthRating::advertised(32e9).unwrap()).is_err());
        assert!(
            ReadCostModel::new(-1.0, &BandwidthRating::measured_directional(1e9).unwrap()).is_err()
        );
    }

    /// Seventeen contiguous 4 MB tensors (a 4 MB embedding and eight layers of two) and a
    /// 4 KiB norm.
    fn bulk_case() -> (StreamingModel, PlannedRequest) {
        let mut spec = dense_spec(8, 8 * 1_000_000);
        spec.buffers.clear();
        for group in &mut spec.groups {
            group.buffers.clear();
        }
        spec.tensors[0].stored.length_bytes = 4_000_000;
        let mut offset = 0;
        for tensor in &mut spec.tensors {
            tensor.stored.offset_bytes = offset;
            offset += tensor.stored.length_bytes;
        }
        let model = StreamingModel::new(spec).unwrap();
        let request = model.plan_request(shape(1), None).unwrap();
        (model, request)
    }

    #[test]
    fn bulk_versus_scattered_on_worked_numbers() {
        let (model, request) = bulk_case();
        // g_t = 64 MB holds sixteen of the 4 MB tensors.
        let g_t = 64_000_000;
        // alpha = 2 ms at 2 GB/s: one 64 MB bulk read takes 2 + 32 = 34 ms; sixteen
        // scattered reads take 16 × (2 + 2) = 64 ms. The first tensor alone arrives at 4 ms.
        let nvme = read_path(0.002, 2e9);
        let file = plan_streaming(
            &model,
            &request,
            &nvme,
            &budget(g_t),
            OrderPolicy::FileOrder,
        )
        .unwrap();
        let scattered = plan_streaming(
            &model,
            &request,
            &nvme,
            &budget(g_t),
            OrderPolicy::DeadlineOrder { lookahead_steps: 0 },
        )
        .unwrap();
        assert_eq!(scattered.requests.len(), model.tensors().len());
        assert!(close(scattered.requests[0].end_seconds, 0.004));
        assert!(close(file.requests[0].end_seconds, 0.034));
        assert_eq!(file.requests[0].tensors.len(), 16);
        // Compute per layer is 0.52 ms, far below 4 ms per read, so the load bounds the
        // first token: about 39.0 ms after the bulk read against about 70.5 ms scattered.
        assert!(close(file.first_token.first_token_seconds, 0.039_032_048));
        assert!(close(
            scattered.first_token.first_token_seconds,
            0.070_512_048
        ));
        let look = plan_streaming(
            &model,
            &request,
            &nvme,
            &budget(g_t),
            OrderPolicy::DeadlineOrder { lookahead_steps: 2 },
        )
        .unwrap();
        // The lookahead chooses the bulk read here.
        assert!(look.requests.len() < 4);
        assert!(
            look.first_token.first_token_seconds <= file.first_token.first_token_seconds + 1e-12
        );

        // With no per-request overhead, scattering costs nothing and the urgent tensor
        // arrives 30 ms sooner, so the lookahead streams each tensor as it is needed:
        // about 35.0 ms against 36.8 ms for the bulk read.
        let free = read_path(0.0, 2e9);
        let bulk = plan_streaming(
            &model,
            &request,
            &free,
            &budget(g_t),
            OrderPolicy::FileOrder,
        )
        .unwrap();
        let look = plan_streaming(
            &model,
            &request,
            &free,
            &budget(g_t),
            OrderPolicy::DeadlineOrder { lookahead_steps: 2 },
        )
        .unwrap();
        assert!(close(bulk.first_token.first_token_seconds, 0.036_771));
        assert!(close(look.first_token.first_token_seconds, 0.035_03));
        assert!(close(look.requests[0].end_seconds, 0.002));
    }

    #[test]
    fn the_bulk_read_never_exceeds_the_transport_batch() {
        let (model, request) = bulk_case();
        let path = read_path(0.002, 2e9);
        let small = plan_streaming(
            &model,
            &request,
            &path,
            &budget(16 * MIB),
            OrderPolicy::DeadlineOrder { lookahead_steps: 2 },
        )
        .unwrap();
        assert!(small
            .requests
            .iter()
            .all(|request| request.range.length_bytes <= 16 * MIB));
        let over = StreamingBudget::new(&granularities(16 * MIB), MIB).unwrap();
        assert!(matches!(
            plan_streaming(&model, &request, &path, &over, OrderPolicy::FileOrder),
            Err(StreamingError::OverDestinationBudget { .. })
        ));
        assert!(plan_streaming(
            &model,
            &request,
            &path,
            &budget(MIB),
            OrderPolicy::DeadlineOrder { lookahead_steps: 4 }
        )
        .is_err());
    }

    /// Twelve layers stored by name: layers 10 and 11 sit between 1 and 2.
    fn lexicographic() -> (StreamingModel, PlannedRequest) {
        let model =
            StreamingModel::new(dense_spec_with(12, 8 * MIB, Layout::Lexicographic)).unwrap();
        let request = model.plan_request(shape(64), None).unwrap();
        (model, request)
    }

    #[test]
    fn deadline_order_beats_file_order_on_a_lexicographic_layout() {
        let (model, request) = lexicographic();
        // Layer 10 is stored before layer 2.
        let tensors = model.tensors();
        assert!(tensors[1 + 2 * 10].stored.offset_bytes < tensors[1 + 2 * 2].stored.offset_bytes);
        let path = read_path(0.000_05, 6e9);
        let plan =
            |policy| plan_streaming(&model, &request, &path, &budget(64 * MIB), policy).unwrap();
        let ordinary = plan(OrderPolicy::OrdinaryLoader);
        let file = plan(OrderPolicy::FileOrder);
        let execution = plan(OrderPolicy::ExecutionOrder);
        let deadline = plan(OrderPolicy::DeadlineOrder { lookahead_steps: 2 });
        let ttft = |schedule: &StreamingSchedule| schedule.first_token.first_token_seconds;
        assert!(ttft(&deadline) < ttft(&file));
        assert!(ttft(&file) < ttft(&ordinary));
        assert!(ttft(&deadline) <= ttft(&execution) + 1e-12);
        // Every order moves the same bytes; the order changes when they arrive.
        assert_eq!(deadline.transferred_bytes, file.transferred_bytes);
        assert_eq!(
            deadline.transferred_bytes,
            model.total_weight_bytes().unwrap()
        );
        // File order's first bulk read also carries layers 10 and 11, so even the
        // embedding waits behind them.
        assert!(file.timings[0].usable_at_seconds > deadline.timings[0].usable_at_seconds);
        // The first token never precedes the GPU §2.2 bound for the bytes moved.
        let mut table = ResourceTable::new();
        let link = ResourceId::new("nvme0-read").unwrap();
        table
            .add(
                link.clone(),
                BandwidthRating::measured_directional(6e9).unwrap(),
            )
            .unwrap();
        let compute: f64 = request.groups.iter().map(|g| g.compute_seconds).sum();
        let bound = transfer_lower_bound(
            &table,
            &[TransferDemand {
                bytes: deadline.transferred_bytes,
                resources: vec![link],
            }],
            compute,
        )
        .unwrap();
        for schedule in [&ordinary, &file, &execution, &deadline] {
            bound.check_claim(ttft(schedule)).unwrap();
        }
    }

    #[test]
    fn least_slack_alone_loses_to_earliest_deadline_and_the_lookahead_weighs_both() {
        // The claim record's counterexample, as a model: the embedding is large and its
        // compute long, so the first layer's tensors have the earlier deadline but more
        // slack once their transfer is subtracted.
        let mut spec = dense_spec(2, 2 * MIB);
        spec.buffers.clear();
        for group in &mut spec.groups {
            group.buffers.clear();
        }
        spec.tensors[0].stored.length_bytes = 16 * MIB;
        let mut offset = 0;
        for tensor in &mut spec.tensors {
            tensor.stored.offset_bytes = offset;
            offset += tensor.stored.length_bytes;
        }
        spec.groups[0].compute.fixed_seconds = 0.000_1;
        let model = StreamingModel::new(spec).unwrap();
        let request = model.plan_request(shape(1), None).unwrap();
        let path = read_path(0.0, 1e9);
        let plan = |policy| {
            plan_streaming(&model, &request, &path, &budget(64 * MIB), policy)
                .unwrap()
                .first_token
                .first_token_seconds
        };
        let slack_only = plan(OrderPolicy::DeadlineOrder { lookahead_steps: 0 });
        let with_lookahead = plan(OrderPolicy::DeadlineOrder { lookahead_steps: 1 });
        let execution = plan(OrderPolicy::ExecutionOrder);
        assert!(with_lookahead <= slack_only + 1e-12);
        assert!(with_lookahead <= execution + 1e-12);
    }

    #[test]
    fn no_order_beats_the_exhaustive_oracle_on_seeded_tiny_requests() {
        use crate::model_memory::bench::rng::SeededRng;
        let mut rng = SeededRng::new(404);
        let mut deadline_gaps = 0;
        for _ in 0..40 {
            // Two layers: six first-token tensors, shuffled in storage, random sizes.
            let mut spec = dense_spec(2, MIB);
            for tensor in &mut spec.tensors {
                tensor.stored.length_bytes = (1 + rng.below(8)) * MIB;
            }
            let mut order: Vec<usize> = (0..spec.tensors.len()).collect();
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let mut offset = 0;
            for index in order {
                spec.tensors[index].stored.offset_bytes = offset;
                offset += spec.tensors[index].stored.length_bytes;
            }
            let model = StreamingModel::new(spec).unwrap();
            let request = model.plan_request(shape(1 + rng.below(512)), None).unwrap();
            let path = read_path(rng.below(3) as f64 * 0.001, 2e9);
            let g_t = (4 + rng.below(16)) * MIB;
            let ttft = |policy| {
                plan_streaming(&model, &request, &path, &budget(g_t), policy)
                    .unwrap()
                    .first_token
                    .first_token_seconds
            };
            let oracle = ttft(OrderPolicy::ExhaustiveOracle);
            let slack_only = ttft(OrderPolicy::DeadlineOrder { lookahead_steps: 0 });
            for policy in [OrderPolicy::FileOrder, OrderPolicy::ExecutionOrder] {
                assert!(oracle <= ttft(policy) + 1e-12, "{policy:?}");
            }
            for lookahead_steps in 0..=MAX_LOOKAHEAD_STEPS {
                let deadline = ttft(OrderPolicy::DeadlineOrder { lookahead_steps });
                assert!(oracle <= deadline + 1e-12);
                // The rollout never loses to its own base rule.
                assert!(deadline <= slack_only + 1e-12);
            }
            if oracle + 1e-9 < ttft(OrderPolicy::DeadlineOrder { lookahead_steps: 2 }) {
                deadline_gaps += 1;
            }
        }
        // The bounded lookahead is a heuristic: report, not hide, where it falls short.
        assert!(deadline_gaps < 40);
        let big = StreamingModel::new(dense_spec(3, MIB)).unwrap();
        let request = big.plan_request(shape(1), None).unwrap();
        assert!(matches!(
            plan_streaming(
                &big,
                &request,
                &read_path(0.0, 1e9),
                &budget(MIB),
                OrderPolicy::ExhaustiveOracle
            ),
            Err(StreamingError::OracleTooLarge { .. })
        ));
    }

    #[test]
    fn a_tied_head_waits_for_its_dependency_and_buffers_count() {
        let model = StreamingModel::new(dense_spec(2, MIB)).unwrap();
        let request = model.plan_request(shape(16), None).unwrap();
        let path = read_path(0.000_01, 1e9);
        let schedule = plan_streaming(
            &model,
            &request,
            &path,
            &budget(64 * MIB),
            OrderPolicy::FileOrder,
        )
        .unwrap();
        let head = schedule.requirements.last().unwrap();
        assert!(head
            .dependencies
            .iter()
            .any(|d| d.kind == DependencyKind::TiedEmbeddings));
        let layer = &schedule.requirements[1];
        assert!(layer
            .dependencies
            .iter()
            .any(|d| d.kind == DependencyKind::NonPersistentBuffers));
        // A slow buffer build becomes the critical input of the first layer.
        let mut slow = request.clone();
        slow.buffers[0].init_seconds = 1.0;
        let schedule = plan_streaming(
            &model,
            &slow,
            &path,
            &budget(64 * MIB),
            OrderPolicy::FileOrder,
        )
        .unwrap();
        assert_eq!(
            schedule
                .first_token
                .critical_input
                .map(|c| (c.group, c.cause)),
            Some((
                GroupRef::Layer(2),
                WaitCause::Dependency(DependencyKind::NonPersistentBuffers)
            ))
        );
        assert!(schedule.first_token.first_token_seconds > 1.0);
    }

    #[test]
    fn the_ordinary_loader_computes_only_after_the_whole_load() {
        let model = StreamingModel::new(dense_spec(3, MIB)).unwrap();
        let request = model.plan_request(shape(8), None).unwrap();
        let path = read_path(0.000_01, 1e9);
        let ordinary = plan_streaming(
            &model,
            &request,
            &path,
            &budget(64 * MIB),
            OrderPolicy::OrdinaryLoader,
        )
        .unwrap();
        let compute: f64 = request.groups.iter().map(|g| g.compute_seconds).sum();
        assert!(close(
            ordinary.first_token.first_token_seconds,
            ordinary.load_complete_seconds + compute
        ));
        assert!(close(
            ordinary.dependencies_usable_seconds,
            ordinary.load_complete_seconds
        ));
    }
}
