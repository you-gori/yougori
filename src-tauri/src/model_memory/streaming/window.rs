//! Memory-limited exact execution (GPU §4.11 lines 760–768).
//!
//! A [`WindowProblem`] is a fixed sequence of exact operations, each reading a set of
//! tensors, under a physical device budget. The live range of every weight and activation
//! is an interval of operations ([`LiveRange`]); a tied embedding and output head make one
//! long interval with a gap in the middle.
//!
//! A [`ResidencyPlan`] names the set `S_k` resident while operation `k` computes; it must
//! contain the operation's read set `R_k`. Transfers are double-buffered: the tensors new
//! in `S_(k+1)` load while operation `k` computes, and those `S_k` drops are freed only
//! after operation `k` finished (§3.7: unmapping requires quiescence). So for every `k`:
//!
//! ```text
//! bytes(S_k ∪ S_(k+1)) + activations live at k <= device budget
//! a_k = start_(k-1) + load(S_k \ S_(k-1)),     start_(-1) = 0
//! f_k = max(a_k, f_(k-1)) + t_k                (the §2.6 recurrence)
//! ```
//!
//! [`layer_window`] keeps the read sets of the next `w` operations, optionally holding a
//! tensor across its whole live range. [`oracle`] is the small exhaustive offline oracle
//! (§2.3 line 395): it enumerates every residency set at every operation; the future
//! depends only on the current set and finish time, and the finish is monotone, so keeping
//! the earliest finish per set loses nothing. The window's sets lie inside the oracle's
//! search space, so the window never beats the oracle.
//!
//! [`decode_reload_cost`] shows the price of reloading weights every token, and the budget
//! is physical: unified-memory oversubscription is refused as capacity (line 768).

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ids::TrustScope;
use crate::model_memory::math::bounds::{transfer_lower_bound, ResourceTable, TransferDemand};
use crate::model_memory::math::overlap::{finish_after, GroupTiming};
use crate::model_memory::math::ResourceId;
use crate::model_memory::residency::host::{HostBacking, HostDemand};
use crate::model_memory::residency::vram::{KvBound, ProcessVram, TransientDemand, TransientKind};
use crate::model_memory::residency::{Capacity, Interval};

use super::deadline::ReadCostModel;
use super::{add_bytes, non_negative, ExecutionRefusal, StreamingError};

/// The most operations the exhaustive oracle accepts (§2.3 line 395: tiny traces only).
pub const ORACLE_MAX_OPS: usize = 16;
/// The most tensors the exhaustive oracle accepts.
pub const ORACLE_MAX_TENSORS: usize = 10;

/// The physical device bytes a window may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowBudget {
    device_bytes: u64,
}

impl WindowBudget {
    /// The physical capacity minus what other terms already hold. An address reservation,
    /// such as an oversubscribed unified-memory range, supplies no physical capacity and
    /// is refused (§4.11 line 768, §2.7).
    pub fn from_capacity(capacity: Capacity, held_bytes: u64) -> Result<Self, StreamingError> {
        let physical = capacity
            .physical_bytes()
            .ok_or(StreamingError::UnifiedMemoryIsNotCapacity)?;
        let device_bytes =
            physical
                .checked_sub(held_bytes)
                .filter(|b| *b > 0)
                .ok_or(StreamingError::Invalid {
                    field: "WindowBudget",
                    reason: "nothing is left for the window",
                })?;
        Ok(Self { device_bytes })
    }

    /// Physical bytes the window may use.
    pub fn device_bytes(&self) -> u64 {
        self.device_bytes
    }
}

/// One exact operation.
#[derive(Clone, Debug, PartialEq)]
pub struct ExactOp {
    pub reads: Vec<usize>,
    pub compute_seconds: f64,
    /// The activation it produces, consumed by the next operation.
    pub output_activation_bytes: u64,
}

/// What a live range keeps alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LiveItem {
    Weight { tensor: usize },
    Activation { op: usize },
}

/// An interval of operations over which an item must exist (§4.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveRange {
    pub item: LiveItem,
    pub first_op: usize,
    pub last_op: usize,
    pub bytes: u64,
    /// Operations that use the item inside the interval.
    pub uses: usize,
}

impl LiveRange {
    /// Whether the interval spans operations that do not use the item, as a tied
    /// embedding and output head do.
    pub fn is_long(&self) -> bool {
        self.last_op - self.first_op + 1 > self.uses
    }
}

/// Tensor sizes, exact operations, a device budget and the read path.
#[derive(Clone, Debug, PartialEq)]
pub struct WindowProblem {
    tensor_bytes: Vec<u64>,
    ops: Vec<ExactOp>,
    budget: WindowBudget,
    cost: ReadCostModel,
}

/// The resident set during every operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidencyPlan {
    pub sets: Vec<BTreeSet<usize>>,
}

/// A plan's timing and traffic.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanEvaluation {
    pub finish_seconds: f64,
    pub op_finish_seconds: Vec<f64>,
    /// `a_k`: when operation k's new tensors are resident.
    pub arrivals_seconds: Vec<f64>,
    pub loads: Vec<Vec<usize>>,
    pub transferred_bytes: u64,
    pub peak_device_bytes: u64,
    pub peak_weight_bytes: u64,
    pub peak_activation_bytes: u64,
    /// Time the operations waited for loads after the first.
    pub stall_seconds: f64,
    /// Windows in which bytes occupied the read path: the last `bytes / B` of each load.
    pub busy_intervals: Vec<(f64, f64)>,
}

/// Which window won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowChoice {
    pub window_ops: usize,
    pub pinned_live_ranges: bool,
}

impl WindowProblem {
    /// Refuses no operations, an empty tensor and an unknown read.
    pub fn new(
        tensor_bytes: Vec<u64>,
        ops: Vec<ExactOp>,
        budget: WindowBudget,
        cost: ReadCostModel,
    ) -> Result<Self, StreamingError> {
        if ops.is_empty() {
            return Err(StreamingError::Invalid {
                field: "ops",
                reason: "at least one operation",
            });
        }
        if tensor_bytes.contains(&0) {
            return Err(StreamingError::Invalid {
                field: "tensor_bytes",
                reason: "every tensor has at least one byte",
            });
        }
        // Every subset sum below then fits in 64 bits.
        tensor_bytes.iter().try_fold(0u64, |total, bytes| {
            add_bytes("tensor_bytes", total, *bytes)
        })?;
        for op in &ops {
            non_negative("compute_seconds", op.compute_seconds)?;
            add_bytes(
                "output_activation_bytes",
                op.output_activation_bytes,
                op.output_activation_bytes,
            )?;
            if let Some(tensor) = op.reads.iter().find(|t| **t >= tensor_bytes.len()) {
                return Err(StreamingError::Unknown {
                    field: "ExactOp.reads",
                    index: *tensor,
                });
            }
        }
        Ok(Self {
            tensor_bytes,
            ops,
            budget,
            cost,
        })
    }

    /// The exact operations, in order.
    pub fn ops(&self) -> &[ExactOp] {
        &self.ops
    }

    /// The physical device budget.
    pub fn budget(&self) -> WindowBudget {
        self.budget
    }

    /// Weight and activation live ranges (§4.11).
    pub fn live_ranges(&self) -> Vec<LiveRange> {
        let mut weights: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new();
        for (index, op) in self.ops.iter().enumerate() {
            for tensor in op.reads.iter().collect::<BTreeSet<_>>() {
                let entry = weights.entry(*tensor).or_insert((index, index, 0));
                entry.1 = index;
                entry.2 += 1;
            }
        }
        let mut ranges: Vec<LiveRange> = weights
            .into_iter()
            .map(|(tensor, (first_op, last_op, uses))| LiveRange {
                item: LiveItem::Weight { tensor },
                first_op,
                last_op,
                bytes: self.tensor_bytes[tensor],
                uses,
            })
            .collect();
        let last = self.ops.len() - 1;
        for (index, op) in self.ops.iter().enumerate() {
            if op.output_activation_bytes > 0 {
                let last_op = (index + 1).min(last);
                ranges.push(LiveRange {
                    item: LiveItem::Activation { op: index },
                    first_op: index,
                    last_op,
                    bytes: op.output_activation_bytes,
                    uses: last_op - index + 1,
                });
            }
        }
        ranges
    }

    /// Activation bytes live during operation `k`: its input and its output.
    pub fn activation_bytes_at(&self, k: usize) -> u64 {
        let own = self.ops.get(k).map_or(0, |op| op.output_activation_bytes);
        let input = k
            .checked_sub(1)
            .and_then(|previous| self.ops.get(previous))
            .map_or(0, |op| op.output_activation_bytes);
        own.saturating_add(input)
    }

    fn set_bytes<'a>(
        &self,
        mut set: impl Iterator<Item = &'a usize>,
    ) -> Result<u64, StreamingError> {
        set.try_fold(0u64, |total, tensor| {
            add_bytes("resident bytes", total, self.tensor_bytes[*tensor])
        })
    }

    fn load_seconds(&self, tensors: &[usize]) -> f64 {
        tensors
            .iter()
            .map(|tensor| self.cost.read_seconds(self.tensor_bytes[*tensor], 1))
            .sum()
    }

    /// Checks a plan's shape: one set per operation, known tensors only, and every
    /// operation's read set resident while it computes.
    pub fn check_plan(&self, plan: &ResidencyPlan) -> Result<(), StreamingError> {
        if plan.sets.len() != self.ops.len() {
            return Err(StreamingError::Invalid {
                field: "ResidencyPlan",
                reason: "one resident set per operation",
            });
        }
        for (op, set) in self.ops.iter().zip(&plan.sets) {
            if let Some(tensor) = set.iter().find(|t| **t >= self.tensor_bytes.len()) {
                return Err(StreamingError::Unknown {
                    field: "ResidencyPlan",
                    index: *tensor,
                });
            }
            if op.reads.iter().any(|tensor| !set.contains(tensor)) {
                return Err(StreamingError::Invalid {
                    field: "ResidencyPlan",
                    reason: "an operation's read set must be resident while it computes",
                });
            }
        }
        Ok(())
    }

    /// Times a plan and checks it against the budget (§4.11).
    pub fn evaluate(&self, plan: &ResidencyPlan) -> Result<PlanEvaluation, StreamingError> {
        self.check_plan(plan)?;
        let empty = BTreeSet::new();
        let mut peak_device_bytes = 0u64;
        let mut peak_weight_bytes = 0u64;
        let mut peak_activation_bytes = 0u64;
        for (k, set) in plan.sets.iter().enumerate() {
            let next = plan.sets.get(k + 1).unwrap_or(&empty);
            let weights = self.set_bytes(set.union(next))?;
            let activations = self.activation_bytes_at(k);
            let needed = add_bytes("device bytes", weights, activations)?;
            if needed > self.budget.device_bytes {
                return Err(StreamingError::OverDeviceBudget {
                    op: k,
                    needed_bytes: needed,
                    budget_bytes: self.budget.device_bytes,
                });
            }
            peak_device_bytes = peak_device_bytes.max(needed);
            peak_weight_bytes = peak_weight_bytes.max(weights);
            peak_activation_bytes = peak_activation_bytes.max(activations);
        }
        let mut previous: &BTreeSet<usize> = &empty;
        let mut start_previous = 0.0;
        let mut finish = 0.0;
        let mut op_finish_seconds = Vec::with_capacity(self.ops.len());
        let mut arrivals_seconds = Vec::with_capacity(self.ops.len());
        let mut loads = Vec::with_capacity(self.ops.len());
        let mut transferred_bytes = 0u64;
        let mut stall_seconds = 0.0;
        let mut busy_intervals = Vec::new();
        for (k, set) in plan.sets.iter().enumerate() {
            let load: Vec<usize> = set.difference(previous).copied().collect();
            let load_bytes = self.set_bytes(load.iter())?;
            transferred_bytes = add_bytes("transferred bytes", transferred_bytes, load_bytes)?;
            let arrival = start_previous + self.load_seconds(&load);
            if load_bytes > 0 {
                busy_intervals.push((arrival - self.cost.data_seconds(load_bytes), arrival));
            }
            if k > 0 && arrival > finish {
                stall_seconds += arrival - finish;
            }
            let compute = self.ops[k].compute_seconds;
            finish = finish_after(
                finish,
                GroupTiming {
                    usable_at_seconds: arrival,
                    compute_seconds: compute,
                },
            )?;
            start_previous = finish - compute;
            arrivals_seconds.push(arrival);
            op_finish_seconds.push(finish);
            loads.push(load);
            previous = set;
        }
        Ok(PlanEvaluation {
            finish_seconds: finish,
            op_finish_seconds,
            arrivals_seconds,
            loads,
            transferred_bytes,
            peak_device_bytes,
            peak_weight_bytes,
            peak_activation_bytes,
            stall_seconds,
            busy_intervals,
        })
    }

    /// Serial offload, the baseline without overlap: each operation's read set loads
    /// after the previous operation finished, into memory it freed.
    pub fn serial_offload(&self) -> Result<PlanEvaluation, StreamingError> {
        let mut finish = 0.0;
        let mut previous: BTreeSet<usize> = BTreeSet::new();
        let mut op_finish_seconds = Vec::new();
        let mut arrivals_seconds = Vec::new();
        let mut loads = Vec::new();
        let mut transferred_bytes = 0u64;
        let mut peak_device_bytes = 0u64;
        let mut peak_weight_bytes = 0u64;
        let mut peak_activation_bytes = 0u64;
        let mut stall_seconds = 0.0;
        let mut busy_intervals = Vec::new();
        for (k, op) in self.ops.iter().enumerate() {
            let set: BTreeSet<usize> = op.reads.iter().copied().collect();
            let weights = self.set_bytes(set.iter())?;
            let activations = self.activation_bytes_at(k);
            let needed = add_bytes("device bytes", weights, activations)?;
            if needed > self.budget.device_bytes {
                return Err(StreamingError::OverDeviceBudget {
                    op: k,
                    needed_bytes: needed,
                    budget_bytes: self.budget.device_bytes,
                });
            }
            peak_device_bytes = peak_device_bytes.max(needed);
            peak_weight_bytes = peak_weight_bytes.max(weights);
            peak_activation_bytes = peak_activation_bytes.max(activations);
            let load: Vec<usize> = set.difference(&previous).copied().collect();
            let load_bytes = self.set_bytes(load.iter())?;
            transferred_bytes = add_bytes("transferred bytes", transferred_bytes, load_bytes)?;
            let arrival = finish + self.load_seconds(&load);
            if load_bytes > 0 {
                busy_intervals.push((arrival - self.cost.data_seconds(load_bytes), arrival));
            }
            if k > 0 {
                stall_seconds += arrival - finish;
            }
            finish = finish_after(
                finish,
                GroupTiming {
                    usable_at_seconds: arrival,
                    compute_seconds: op.compute_seconds,
                },
            )?;
            arrivals_seconds.push(arrival);
            op_finish_seconds.push(finish);
            loads.push(load);
            previous = set;
        }
        Ok(PlanEvaluation {
            finish_seconds: finish,
            op_finish_seconds,
            arrivals_seconds,
            loads,
            transferred_bytes,
            peak_device_bytes,
            peak_weight_bytes,
            peak_activation_bytes,
            stall_seconds,
            busy_intervals,
        })
    }
}

/// The simple layer window: the read sets of operations `k..k+w`, and with
/// `pin_live_ranges` every tensor from its first to its last use (a tied embedding and
/// head stay resident between their uses).
pub fn layer_window(
    problem: &WindowProblem,
    window_ops: usize,
    pin_live_ranges: bool,
) -> Result<ResidencyPlan, StreamingError> {
    if window_ops == 0 {
        return Err(StreamingError::Invalid {
            field: "window_ops",
            reason: "the window holds at least the current operation",
        });
    }
    let ranges = problem.live_ranges();
    let m = problem.ops.len();
    let sets = (0..m)
        .map(|k| {
            let mut set: BTreeSet<usize> = problem.ops[k..(k + window_ops).min(m)]
                .iter()
                .flat_map(|op| op.reads.iter().copied())
                .collect();
            if pin_live_ranges {
                for range in &ranges {
                    if let LiveItem::Weight { tensor } = range.item {
                        if range.first_op <= k && k <= range.last_op {
                            set.insert(tensor);
                        }
                    }
                }
            }
            set
        })
        .collect();
    Ok(ResidencyPlan { sets })
}

/// The best feasible window of at most `max_window_ops` operations, with and without
/// pinned live ranges; earliest finish, then fewest bytes.
pub fn best_window(
    problem: &WindowProblem,
    max_window_ops: usize,
) -> Result<(WindowChoice, ResidencyPlan, PlanEvaluation), StreamingError> {
    let mut best: Option<(WindowChoice, ResidencyPlan, PlanEvaluation)> = None;
    let mut last_error = StreamingError::Invalid {
        field: "max_window_ops",
        reason: "at least one window size",
    };
    for window_ops in 1..=max_window_ops {
        for pinned_live_ranges in [false, true] {
            let plan = layer_window(problem, window_ops, pinned_live_ranges)?;
            match problem.evaluate(&plan) {
                Ok(evaluation) => {
                    let wins = best.as_ref().is_none_or(|(_, _, current)| {
                        evaluation.finish_seconds < current.finish_seconds
                            || (evaluation.finish_seconds == current.finish_seconds
                                && evaluation.transferred_bytes < current.transferred_bytes)
                    });
                    if wins {
                        let choice = WindowChoice {
                            window_ops,
                            pinned_live_ranges,
                        };
                        best = Some((choice, plan, evaluation));
                    }
                }
                Err(error) => last_error = error,
            }
        }
    }
    best.ok_or(last_error)
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    finish: f64,
    bytes: u64,
    parent: u64,
}

/// The exhaustive offline oracle (§2.3 line 395, §4.11): the plan with the earliest
/// finish, then the fewest bytes moved, over every residency set at every operation.
pub fn oracle(problem: &WindowProblem) -> Result<(ResidencyPlan, PlanEvaluation), StreamingError> {
    let m = problem.ops.len();
    let n = problem.tensor_bytes.len();
    if m > ORACLE_MAX_OPS || n > ORACLE_MAX_TENSORS {
        return Err(StreamingError::OracleTooLarge {
            ops: m,
            tensors: n,
            max_ops: ORACLE_MAX_OPS,
            max_tensors: ORACLE_MAX_TENSORS,
        });
    }
    let mask_of = |tensors: &mut dyn Iterator<Item = usize>| -> u64 {
        tensors.fold(0u64, |mask, tensor| mask | (1u64 << tensor))
    };
    let required: Vec<u64> = problem
        .ops
        .iter()
        .map(|op| mask_of(&mut op.reads.iter().copied()))
        .collect();
    let mut future = vec![0u64; m];
    for k in (0..m.saturating_sub(1)).rev() {
        future[k] = future[k + 1] | required[k + 1];
    }
    let bytes_of = |mask: u64| -> u64 {
        (0..n)
            .filter(|tensor| mask & (1u64 << tensor) != 0)
            .map(|tensor| problem.tensor_bytes[tensor])
            .sum()
    };
    let seconds_of = |mask: u64| -> f64 {
        (0..n)
            .filter(|tensor| mask & (1u64 << tensor) != 0)
            .map(|tensor| problem.cost.read_seconds(problem.tensor_bytes[tensor], 1))
            .sum()
    };
    let subsets = |free: u64| -> Vec<u64> {
        let mut all = Vec::new();
        let mut sub = free;
        loop {
            all.push(sub);
            if sub == 0 {
                break;
            }
            sub = (sub - 1) & free;
        }
        all
    };
    let better = |finish: f64, bytes: u64, current: &Entry| {
        finish < current.finish || (finish == current.finish && bytes < current.bytes)
    };
    let budget = problem.budget.device_bytes;
    let mut layers: Vec<BTreeMap<u64, Entry>> = Vec::with_capacity(m);
    let mut first = BTreeMap::new();
    for extra in subsets(future[0] & !required[0]) {
        let set = required[0] | extra;
        let finish = finish_after(
            0.0,
            GroupTiming {
                usable_at_seconds: seconds_of(set),
                compute_seconds: problem.ops[0].compute_seconds,
            },
        )?;
        first.insert(
            set,
            Entry {
                finish,
                bytes: bytes_of(set),
                parent: 0,
            },
        );
    }
    layers.push(first);
    for k in 1..m {
        let mut next: BTreeMap<u64, Entry> = BTreeMap::new();
        let activations = problem.activation_bytes_at(k - 1);
        let candidates = subsets(future[k] & !required[k]);
        for (&previous, entry) in &layers[k - 1] {
            let start = entry.finish - problem.ops[k - 1].compute_seconds;
            for extra in &candidates {
                let set = required[k] | extra;
                if bytes_of(previous | set).saturating_add(activations) > budget {
                    continue;
                }
                let load = set & !previous;
                let finish = finish_after(
                    entry.finish,
                    GroupTiming {
                        usable_at_seconds: start + seconds_of(load),
                        compute_seconds: problem.ops[k].compute_seconds,
                    },
                )?;
                let bytes = entry.bytes.saturating_add(bytes_of(load));
                let wins = next
                    .get(&set)
                    .is_none_or(|current| better(finish, bytes, current));
                if wins {
                    next.insert(
                        set,
                        Entry {
                            finish,
                            bytes,
                            parent: previous,
                        },
                    );
                }
            }
        }
        layers.push(next);
    }
    let last_activations = problem.activation_bytes_at(m - 1);
    let mut best: Option<(u64, Entry)> = None;
    if let Some(last) = layers.last() {
        for (&set, entry) in last {
            if bytes_of(set).saturating_add(last_activations) > budget {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(_, current)| better(entry.finish, entry.bytes, current))
            {
                best = Some((set, *entry));
            }
        }
    }
    let (mut set, _) = best.ok_or(StreamingError::OverDeviceBudget {
        op: 0,
        needed_bytes: bytes_of(required.iter().fold(0, |all, r| all | r)),
        budget_bytes: budget,
    })?;
    let mut masks = vec![0u64; m];
    for k in (0..m).rev() {
        masks[k] = set;
        let entry = layers[k].get(&set).ok_or(StreamingError::Invalid {
            field: "oracle",
            reason: "lost a parent while reconstructing the plan",
        })?;
        set = entry.parent;
    }
    let plan = ResidencyPlan {
        sets: masks
            .iter()
            .map(|mask| (0..n).filter(|t| mask & (1u64 << t) != 0).collect())
            .collect(),
    };
    let evaluation = problem.evaluate(&plan)?;
    Ok((plan, evaluation))
}

/// The bandwidth price of reloading weights every token (§4.11 line 766).
#[derive(Clone, Debug, PartialEq)]
pub struct DecodeReloadCost {
    pub streamed_bytes_per_token: u64,
    /// `max(compute, streamed / B)` by the GPU §2.2 bound.
    pub seconds_per_token_lower_bound: f64,
    pub tokens_per_second_upper_bound: f64,
    /// Whether the read path, not compute, sets the bound.
    pub link_bound: bool,
}

impl DecodeReloadCost {
    /// Whether the bound allows the per-token latency objective at all.
    pub fn can_meet(&self, objective_seconds_per_token: f64) -> bool {
        self.seconds_per_token_lower_bound <= objective_seconds_per_token
    }

    /// The read bandwidth the streamed bytes would need to meet the objective.
    pub fn bandwidth_needed_bytes_per_second(&self, objective_seconds_per_token: f64) -> f64 {
        self.streamed_bytes_per_token as f64 / objective_seconds_per_token
    }
}

/// Dense decoding with `resident_weight_bytes` kept on the device: every other weight byte
/// crosses `link` once per token.
pub fn decode_reload_cost(
    total_weight_bytes: u64,
    resident_weight_bytes: u64,
    compute_seconds_per_token: f64,
    table: &ResourceTable,
    link: &ResourceId,
) -> Result<DecodeReloadCost, StreamingError> {
    let streamed_bytes_per_token = total_weight_bytes
        .checked_sub(resident_weight_bytes)
        .ok_or(StreamingError::Invalid {
            field: "resident_weight_bytes",
            reason: "more resident than the model holds",
        })?;
    let bound = transfer_lower_bound(
        table,
        &[TransferDemand {
            bytes: streamed_bytes_per_token,
            resources: vec![link.clone()],
        }],
        compute_seconds_per_token,
    )?;
    let seconds = bound.lower_bound_seconds;
    Ok(DecodeReloadCost {
        streamed_bytes_per_token,
        seconds_per_token_lower_bound: seconds,
        tokens_per_second_upper_bound: if seconds > 0.0 {
            1.0 / seconds
        } else {
            f64::INFINITY
        },
        link_bound: bound.critical_path_minimum_seconds < seconds,
    })
}

/// The window's device demand as one process of the §2.7 admission check: the streamed
/// weight buffers as staging and the activations as activation overlap, for the whole
/// lifetime. The caller adds the process to a [`crate::model_memory::residency::vram::VramPlan`]
/// and admits it; the ledger stays the capacity authority.
pub fn process_vram(
    process: String,
    sharing_domain: TrustScope,
    lifetime: Interval,
    context_bytes: u64,
    kv: KvBound,
    evaluation: &PlanEvaluation,
) -> ProcessVram {
    let mut transients = Vec::new();
    if evaluation.peak_weight_bytes > 0 {
        transients.push(TransientDemand {
            kind: TransientKind::Staging,
            bytes: evaluation.peak_weight_bytes,
            during: lifetime,
        });
    }
    if evaluation.peak_activation_bytes > 0 {
        transients.push(TransientDemand {
            kind: TransientKind::ActivationOverlap,
            bytes: evaluation.peak_activation_bytes,
            during: lifetime,
        });
    }
    ProcessVram {
        process,
        sharing_domain,
        lifetime,
        maps: Vec::new(),
        context_bytes,
        graph_pool_bytes: 0,
        kv,
        transients,
    }
}

/// The host copy the window streams from: pinned, so copies are asynchronous, and charged
/// to host RAM and the pinned cap (§2.7). Page cache would not be guaranteed residency.
pub fn host_source_demand(
    weight_bytes: u64,
    during: Interval,
    memory_scope: String,
    pinned_scope: String,
) -> HostDemand {
    HostDemand {
        label: "streamed weights".into(),
        backing: HostBacking::Pinned,
        bytes: weight_bytes,
        during,
        memory_scope,
        pinned_scope: Some(pinned_scope),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Residency {
    Loading,
    Resident,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    bytes: u64,
    state: Residency,
    users: u32,
}

/// Runtime device accounting for a window (§3.7 lines 605–607): a tensor is used only
/// while resident, evicted only when no running operation uses it, and nothing loads past
/// the physical budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceWindow {
    budget_bytes: u64,
    activation_bytes: u64,
    used_bytes: u64,
    peak_bytes: u64,
    slots: BTreeMap<usize, Slot>,
}

impl DeviceWindow {
    /// An empty window under a physical budget.
    pub fn new(budget: WindowBudget) -> Self {
        Self {
            budget_bytes: budget.device_bytes,
            activation_bytes: 0,
            used_bytes: 0,
            peak_bytes: 0,
            slots: BTreeMap::new(),
        }
    }

    fn total(&self) -> u64 {
        self.used_bytes.saturating_add(self.activation_bytes)
    }

    /// Sets the activation bytes currently live.
    pub fn set_activation_bytes(&mut self, bytes: u64) -> Result<(), ExecutionRefusal> {
        let total = self.used_bytes.saturating_add(bytes);
        if total > self.budget_bytes {
            return Err(ExecutionRefusal::OverWindow {
                tensor: usize::MAX,
                needed_bytes: total,
                budget_bytes: self.budget_bytes,
            });
        }
        self.activation_bytes = bytes;
        self.peak_bytes = self.peak_bytes.max(self.total());
        Ok(())
    }

    /// Reserves room and starts a load.
    pub fn begin_load(&mut self, tensor: usize, bytes: u64) -> Result<(), ExecutionRefusal> {
        if self.slots.contains_key(&tensor) {
            return Err(ExecutionRefusal::AlreadyResident { tensor });
        }
        let needed = self.total().saturating_add(bytes);
        if needed > self.budget_bytes {
            return Err(ExecutionRefusal::OverWindow {
                tensor,
                needed_bytes: needed,
                budget_bytes: self.budget_bytes,
            });
        }
        self.slots.insert(
            tensor,
            Slot {
                bytes,
                state: Residency::Loading,
                users: 0,
            },
        );
        self.used_bytes = self.used_bytes.saturating_add(bytes);
        self.peak_bytes = self.peak_bytes.max(self.total());
        Ok(())
    }

    /// The load's completion event was observed.
    pub fn complete_load(&mut self, tensor: usize) -> Result<(), ExecutionRefusal> {
        match self.slots.get_mut(&tensor) {
            Some(slot) if slot.state == Residency::Loading => {
                slot.state = Residency::Resident;
                Ok(())
            }
            Some(_) => Err(ExecutionRefusal::AlreadyResident { tensor }),
            None => Err(ExecutionRefusal::NotResident { tensor }),
        }
    }

    /// An operation starts using these tensors; refused unless every one is resident.
    pub fn begin_use(&mut self, tensors: &[usize]) -> Result<(), ExecutionRefusal> {
        if let Some(tensor) = tensors.iter().find(|tensor| {
            self.slots
                .get(tensor)
                .is_none_or(|slot| slot.state != Residency::Resident)
        }) {
            return Err(ExecutionRefusal::NotResident { tensor: *tensor });
        }
        for tensor in tensors {
            if let Some(slot) = self.slots.get_mut(tensor) {
                slot.users = slot.users.saturating_add(1);
            }
        }
        Ok(())
    }

    /// The operation's completion event was observed.
    pub fn end_use(&mut self, tensors: &[usize]) -> Result<(), ExecutionRefusal> {
        for tensor in tensors {
            match self.slots.get_mut(tensor) {
                Some(slot) if slot.users > 0 => slot.users -= 1,
                _ => return Err(ExecutionRefusal::NotResident { tensor: *tensor }),
            }
        }
        Ok(())
    }

    /// Frees a tensor; refused while a running operation uses it or a load is in flight.
    pub fn evict(&mut self, tensor: usize) -> Result<u64, ExecutionRefusal> {
        match self.slots.get(&tensor) {
            None => Err(ExecutionRefusal::NotResident { tensor }),
            Some(slot) if slot.users > 0 || slot.state == Residency::Loading => {
                Err(ExecutionRefusal::EvictWhileInUse { tensor })
            }
            Some(slot) => {
                let bytes = slot.bytes;
                self.slots.remove(&tensor);
                self.used_bytes = self.used_bytes.saturating_sub(bytes);
                Ok(bytes)
            }
        }
    }

    /// Weight bytes resident or loading now.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// The most bytes, weights and activations, ever held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }
}

/// Drives a plan through a [`DeviceWindow`] in its double-buffered order; returns the
/// peak device bytes. Refused wherever the runtime rules would refuse it.
pub fn replay_on_window(
    problem: &WindowProblem,
    plan: &ResidencyPlan,
) -> Result<u64, StreamingError> {
    problem.check_plan(plan)?;
    let mut window = DeviceWindow::new(problem.budget);
    let empty = BTreeSet::new();
    let first = plan.sets.first().ok_or(StreamingError::Invalid {
        field: "ResidencyPlan",
        reason: "one resident set per operation",
    })?;
    for tensor in first {
        window.begin_load(*tensor, problem.tensor_bytes[*tensor])?;
        window.complete_load(*tensor)?;
    }
    for (k, set) in plan.sets.iter().enumerate() {
        let next = plan.sets.get(k + 1).unwrap_or(&empty);
        window.set_activation_bytes(problem.activation_bytes_at(k))?;
        window.begin_use(&problem.ops[k].reads)?;
        for tensor in next.difference(set) {
            window.begin_load(*tensor, problem.tensor_bytes[*tensor])?;
        }
        for tensor in next.difference(set) {
            window.complete_load(*tensor)?;
        }
        window.end_use(&problem.ops[k].reads)?;
        for tensor in set.difference(next) {
            window.evict(*tensor)?;
        }
    }
    Ok(window.peak_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ExecutionCategory, GpuDeviceKey, MonotonicTime};
    use crate::model_memory::bench::rng::SeededRng;
    use crate::model_memory::math::bounds::BandwidthRating;
    use crate::model_memory::residency::host::{
        admit_host, HostError, HostPlan, HostScope, HostScopeKind, ScopeOccupancy,
    };
    use crate::model_memory::residency::vram::{admit_vram, VramError, VramPlan};
    use crate::model_memory::streaming::test_support::*;

    fn budget_of(bytes: u64) -> WindowBudget {
        WindowBudget::from_capacity(Capacity::Physical { bytes }, 0).unwrap()
    }

    fn op(reads: &[usize], compute_seconds: f64) -> ExactOp {
        ExactOp {
            reads: reads.to_vec(),
            compute_seconds,
            output_activation_bytes: 0,
        }
    }

    /// A tied embedding/head (tensor 0, 1 GB) and `layers` layers of 1 GB, one pass.
    fn tied_pass(layers: usize) -> Vec<ExactOp> {
        let mut ops = vec![op(&[0], 0.001)];
        for layer in 0..layers {
            ops.push(op(&[1 + layer], 0.01));
        }
        ops.push(op(&[0], 0.002));
        ops
    }

    #[test]
    fn live_ranges_are_intervals_and_ties_are_long() {
        let mut ops = tied_pass(3);
        ops[1].output_activation_bytes = 10;
        let problem =
            WindowProblem::new(vec![GB; 4], ops, budget_of(10 * GB), read_path(0.0, 25e9)).unwrap();
        let ranges = problem.live_ranges();
        let tied = ranges
            .iter()
            .find(|r| r.item == LiveItem::Weight { tensor: 0 })
            .unwrap();
        assert_eq!((tied.first_op, tied.last_op, tied.uses), (0, 4, 2));
        assert!(tied.is_long());
        let layer = ranges
            .iter()
            .find(|r| r.item == LiveItem::Weight { tensor: 2 })
            .unwrap();
        assert!(!layer.is_long());
        let activation = ranges
            .iter()
            .find(|r| r.item == LiveItem::Activation { op: 1 })
            .unwrap();
        assert_eq!((activation.first_op, activation.last_op), (1, 2));
        assert_eq!(problem.activation_bytes_at(2), 10);
    }

    #[test]
    fn the_window_keeps_only_the_next_working_set_and_double_buffers() {
        // Six layers of 1 GB, 3 GB of device memory: the current layer and the next.
        let ops: Vec<ExactOp> = (0..6).map(|layer| op(&[layer], 0.05)).collect();
        let problem =
            WindowProblem::new(vec![GB; 6], ops, budget_of(3 * GB), read_path(0.0, 25e9)).unwrap();
        let plan = layer_window(&problem, 1, false).unwrap();
        for (k, set) in plan.sets.iter().enumerate() {
            assert_eq!(set, &[k].into_iter().collect::<BTreeSet<_>>());
        }
        let window = problem.evaluate(&plan).unwrap();
        // 1 GB at 25 GB/s is 40 ms, under the 50 ms compute: only the first load shows.
        assert!((window.finish_seconds - (0.04 + 6.0 * 0.05)).abs() < 1e-12);
        assert_eq!(window.stall_seconds, 0.0);
        assert_eq!(window.peak_weight_bytes, 2 * GB);
        assert_eq!(replay_on_window(&problem, &plan).unwrap(), 2 * GB);
        // Serial offload pays every load in full.
        let serial = problem.serial_offload().unwrap();
        assert!((serial.finish_seconds - 6.0 * (0.04 + 0.05)).abs() < 1e-12);
        assert!(window.finish_seconds < serial.finish_seconds);
        // A window of three does not fit in 3 GB once the next set loads beside it.
        assert!(matches!(
            problem.evaluate(&layer_window(&problem, 3, false).unwrap()),
            Err(StreamingError::OverDeviceBudget { .. })
        ));
    }

    #[test]
    fn the_window_never_beats_the_oracle_on_seeded_interval_sets() {
        let mut rng = SeededRng::new(2026);
        let mut strictly_better = 0;
        for _ in 0..60 {
            let tensors = 3 + rng.below(4) as usize;
            let ops_count = 3 + rng.below(5) as usize;
            let bytes: Vec<u64> = (0..tensors).map(|_| (1 + rng.below(4)) * GB).collect();
            let ops: Vec<ExactOp> = (0..ops_count)
                .map(|_| {
                    let mut reads: Vec<usize> = (0..1 + rng.below(2))
                        .map(|_| rng.below(tensors as u64) as usize)
                        .collect();
                    reads.sort_unstable();
                    reads.dedup();
                    ExactOp {
                        reads,
                        compute_seconds: (1 + rng.below(20)) as f64 * 0.01,
                        output_activation_bytes: rng.below(2) * GB / 4,
                    }
                })
                .collect();
            let device = (6 + rng.below(8)) * GB;
            let Ok(problem) =
                WindowProblem::new(bytes, ops, budget_of(device), read_path(0.001, 25e9))
            else {
                continue;
            };
            let (Ok((_, plan, window)), Ok((_, best))) =
                (best_window(&problem, 3), oracle(&problem))
            else {
                continue;
            };
            assert!(
                best.finish_seconds <= window.finish_seconds + 1e-9,
                "the oracle lost: {} > {}",
                best.finish_seconds,
                window.finish_seconds
            );
            replay_on_window(&problem, &plan).unwrap();
            if best.finish_seconds + 1e-9 < window.finish_seconds {
                strictly_better += 1;
            }
        }
        // The oracle finds something the simple window misses on some sets.
        assert!(strictly_better > 0);
    }

    #[test]
    fn tied_weights_are_pinned_or_reloaded_by_cost() {
        // Embedding/head tied (1 GB), three 1 GB layers, 3 GB device.
        let problem = WindowProblem::new(
            vec![GB; 4],
            tied_pass(3),
            budget_of(3 * GB),
            read_path(0.0, 25e9),
        )
        .unwrap();
        let reload = problem
            .evaluate(&layer_window(&problem, 1, false).unwrap())
            .unwrap();
        let pinned = problem
            .evaluate(&layer_window(&problem, 1, true).unwrap())
            .unwrap();
        // Without pinning, the tied tensor crosses the path twice.
        assert_eq!(reload.transferred_bytes, 5 * GB);
        assert_eq!(pinned.transferred_bytes, 4 * GB);
        let (choice, _, _) = best_window(&problem, 2).unwrap();
        let (_, best) = oracle(&problem).unwrap();
        assert!(best.transferred_bytes <= pinned.transferred_bytes);
        assert!(choice.window_ops >= 1);
        // At 2 GB the tied tensor cannot stay beside two layers: the window reloads it.
        let tight = WindowProblem::new(
            vec![GB; 4],
            tied_pass(3),
            budget_of(2 * GB),
            read_path(0.0, 25e9),
        )
        .unwrap();
        assert!(tight
            .evaluate(&layer_window(&tight, 1, true).unwrap())
            .is_err());
        assert_eq!(
            tight
                .evaluate(&layer_window(&tight, 1, false).unwrap())
                .unwrap()
                .transferred_bytes,
            5 * GB
        );
    }

    #[test]
    fn per_token_reload_bandwidth_on_worked_numbers() {
        // 14 GB of weights, 5 GB kept resident: 9 GB cross a measured 24 GB/s path every
        // token, so a token takes at least 0.375 s (2.67 tokens/s). A 0.1 s objective needs
        // 90 GB/s.
        let mut table = ResourceTable::new();
        let link = ResourceId::new("pcie0-h2d").unwrap();
        table
            .add(
                link.clone(),
                BandwidthRating::measured_directional(24e9).unwrap(),
            )
            .unwrap();
        let cost = decode_reload_cost(14 * GB, 5 * GB, 0.02, &table, &link).unwrap();
        assert_eq!(cost.streamed_bytes_per_token, 9 * GB);
        assert!((cost.seconds_per_token_lower_bound - 0.375).abs() < 1e-12);
        assert!((cost.tokens_per_second_upper_bound - 1.0 / 0.375).abs() < 1e-9);
        assert!(cost.link_bound);
        assert!(!cost.can_meet(0.1));
        assert!((cost.bandwidth_needed_bytes_per_second(0.1) - 90e9).abs() < 1.0);
        // Compute-bound when nearly everything is resident.
        let resident = decode_reload_cost(14 * GB, 14 * GB - GB / 10, 0.02, &table, &link).unwrap();
        assert!(!resident.link_bound);
        assert!(resident.can_meet(0.1));
        assert!(decode_reload_cost(GB, 2 * GB, 0.02, &table, &link).is_err());
    }

    #[test]
    fn simulated_decoding_moves_at_least_the_non_resident_bytes_every_token() {
        // Tied embedding/head and four 1 GB layers; 4 GB of device memory.
        let tokens = 3;
        let ops: Vec<ExactOp> = (0..tokens).flat_map(|_| tied_pass(4)).collect();
        let problem =
            WindowProblem::new(vec![GB; 5], ops, budget_of(4 * GB), read_path(0.0, 24e9)).unwrap();
        let (_, _, window) = best_window(&problem, 2).unwrap();
        let per_token = window.transferred_bytes / tokens as u64;
        // At most the 4 GB budget minus room to double-buffer one layer stays resident.
        let resident_max = 4 * GB - GB;
        assert!(per_token >= 5 * GB - resident_max - GB);
        // And the time is at least the bytes over the path.
        assert!(window.finish_seconds >= window.transferred_bytes as f64 / 24e9);
    }

    #[test]
    fn unified_memory_is_not_a_substitute_for_bounded_accounting() {
        assert_eq!(
            WindowBudget::from_capacity(Capacity::VirtualReservation { bytes: 64 * GB }, 0),
            Err(StreamingError::UnifiedMemoryIsNotCapacity)
        );
        // The window's demand goes through the §2.7 device and host admission.
        let ops: Vec<ExactOp> = (0..4).map(|layer| op(&[layer], 0.05)).collect();
        let problem =
            WindowProblem::new(vec![GB; 4], ops, budget_of(3 * GB), read_path(0.0, 25e9)).unwrap();
        let evaluation = problem
            .evaluate(&layer_window(&problem, 1, false).unwrap())
            .unwrap();
        let lifetime = Interval::new(
            MonotonicTime::ZERO,
            MonotonicTime::from_nanos(10_000_000_000),
        )
        .unwrap();
        let scope = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-a");
        let device = GpuDeviceKey {
            machine: digest("yougori/test/streaming/machine/v1", &[b"m"]),
            device: digest("yougori/test/streaming/device/v1", &[b"d"]),
        };
        let vram = |usable_vram| VramPlan {
            device,
            usable_vram,
            safety_reserve_bytes: GB / 2,
            allocations: vec![],
            processes: vec![process_vram(
                "streamer".into(),
                scope,
                lifetime,
                GB / 2,
                KvBound::Reserved { bytes: GB },
                &evaluation,
            )],
        };
        assert!(admit_vram(&vram(Capacity::Physical { bytes: 8 * GB })).is_ok());
        assert!(matches!(
            admit_vram(&vram(Capacity::Physical { bytes: 3 * GB })),
            Err(VramError::DoesNotFit(_))
        ));
        assert!(matches!(
            admit_vram(&vram(Capacity::VirtualReservation { bytes: 64 * GB })),
            Err(VramError::VirtualReservationIsNotCapacity { .. })
        ));
        let host = |pinned_cap| HostPlan {
            scopes: vec![
                HostScope {
                    name: "host".into(),
                    kind: HostScopeKind::HostRam,
                    parent: None,
                    capacity: Capacity::Physical { bytes: 64 * GB },
                    safety_reserve_bytes: GB,
                    occupancy: ScopeOccupancy::default(),
                },
                HostScope {
                    name: "pinned".into(),
                    kind: HostScopeKind::PinnedRam,
                    parent: None,
                    capacity: Capacity::Physical { bytes: pinned_cap },
                    safety_reserve_bytes: GB / 4,
                    occupancy: ScopeOccupancy::default(),
                },
            ],
            demands: vec![host_source_demand(
                4 * GB,
                lifetime,
                "host".into(),
                "pinned".into(),
            )],
        };
        assert!(admit_host(&host(16 * GB)).is_ok());
        assert!(matches!(
            admit_host(&host(2 * GB)),
            Err(HostError::DoesNotFit(_))
        ));
    }

    #[test]
    fn the_device_window_refuses_unmapped_use_and_busy_eviction() {
        let mut window = DeviceWindow::new(budget_of(2 * GB));
        window.begin_load(0, GB).unwrap();
        // In flight is not resident.
        assert_eq!(
            window.begin_use(&[0]),
            Err(ExecutionRefusal::NotResident { tensor: 0 })
        );
        assert_eq!(
            window.evict(0),
            Err(ExecutionRefusal::EvictWhileInUse { tensor: 0 })
        );
        window.complete_load(0).unwrap();
        window.begin_use(&[0]).unwrap();
        assert_eq!(
            window.evict(0),
            Err(ExecutionRefusal::EvictWhileInUse { tensor: 0 })
        );
        window.begin_load(1, GB).unwrap();
        assert!(matches!(
            window.begin_load(2, GB),
            Err(ExecutionRefusal::OverWindow { tensor: 2, .. })
        ));
        window.end_use(&[0]).unwrap();
        assert_eq!(window.evict(0), Ok(GB));
        assert_eq!(
            window.begin_use(&[0]),
            Err(ExecutionRefusal::NotResident { tensor: 0 })
        );
        assert_eq!(window.used_bytes(), GB);
        assert_eq!(window.peak_bytes(), 2 * GB);
    }

    #[test]
    fn the_oracle_is_only_for_tiny_problems() {
        let ops: Vec<ExactOp> = (0..ORACLE_MAX_OPS + 1).map(|_| op(&[0], 0.01)).collect();
        let problem =
            WindowProblem::new(vec![GB], ops, budget_of(4 * GB), read_path(0.0, 25e9)).unwrap();
        assert!(matches!(
            oracle(&problem),
            Err(StreamingError::OracleTooLarge { .. })
        ));
        assert!(WindowProblem::new(
            vec![0],
            vec![op(&[0], 0.01)],
            budget_of(GB),
            read_path(0.0, 1e9)
        )
        .is_err());
    }
}
