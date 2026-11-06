//! Deadline-aware layer streaming and memory-limited exact execution: GPU §4.4, §4.11 and
//! GPU-W07 of docs/combined-gpu-memory-and-vm-sandbox-plan.md (lines 689–698, 760–769 and
//! 1079–1092), on the §2.3–§2.6 model (lines 379–434) and the §3.6–§3.7 activation and
//! allocation rules (lines 576–614).
//!
//! - [`architecture`]: one explicit architecture: execution groups and their tensor and
//!   buffer read sets, embedding/output-head ties, nonpersistent buffers, dynamic request
//!   shapes, the comparison with the ordinary loader's read set, and the gate that sends
//!   every unsupported architecture to the normal loader (GPU-W07 items 1, 2, 5, 6, 8).
//! - [`deadline`]: the latest useful arrival and slack of every group, and the transfer
//!   order: file order, execution order, or deadline order with a small lookahead between
//!   a contiguous bulk read and an urgent scattered range (§4.4; GPU-W07 item 4), checked
//!   against an exhaustive order oracle on tiny requests (§2.3 line 395).
//! - [`dag`]: the same schedule as a request DAG (§2.3), cross-checked against the
//!   §2.6 recurrence.
//! - [`execution`]: the per-request state machine that records availability and compute
//!   events, never computes a group before its own weights are usable, refuses mixed
//!   generations and shapes, handles cancellation, OOM and late groups, and refuses a
//!   dense first-token claim before every required layer and the output head (§2.6 line
//!   432, §3.6 lines 599–601; GPU-W07 items 3 and 7).
//! - [`simulate`]: the fake substrate: an event-driven run with seeded variation and
//!   injected faults, the declared stall error band, and steady-generation interference
//!   (GPU-W07 acceptance).
//! - [`window`]: live ranges as intervals, the double-buffered layer window, the exhaustive
//!   offline oracle, tied weights, per-token reload bandwidth, and bounded device and host
//!   accounting instead of unified-memory oversubscription (§4.11).
//! - [`moe`]: exact expert dependencies and expert locality and miss rate measured from a
//!   routing trace (§2.6 line 434, §4.4, §4.11).
//! - [`evidence`]: simulated attempts recorded as CORE-08 run records on the fake
//!   substrate, comparisons against both required baselines, and the claim records of
//!   GPU §4.17 (lines 908–915) with their typed decisions.
//!
//! The recurrence `f_i = max(a_i, f_(i-1)) + t_i` (whole, or one step at a time through
//! [`finish_after`](crate::model_memory::math::overlap::finish_after)), the no-stall
//! condition, first-token dependencies and exact experts, with eviction, come from
//! [`crate::model_memory::math::overlap`]; the
//! read cost `t(c) = alpha + c/B` from [`crate::model_memory::math::chunking`]; physical
//! bounds from [`crate::model_memory::math::bounds`]; the request DAG and transport batch
//! size g_t from [`crate::model_memory::graph`]; executor dependencies from
//! [`crate::model_memory::executor`]; device and host admission from
//! [`crate::model_memory::residency`]; records, provenance and comparisons from
//! [`crate::foundation::report`]. Nothing here starts a process, touches a GPU or reads a
//! file. Execute-while-load itself is enabled only on fresh CORE-01 evidence for the
//! actual runtime ([`crate::foundation::evidence::Capability::ExecuteWhileLoad`]). The
//! executor still orders a job's extents by stored offset, so a deadline order is
//! submitted as one job per read until it gains a per-dependency priority. Durations are
//! `f64` seconds, bytes are `u64`, runtime events carry
//! [`MonotonicTime`](crate::foundation::ids::MonotonicTime) from an injected
//! [`Clock`](crate::foundation::ids::Clock).
//!
//! # Claim record
//!
//! Four experiments, each kept as GPU §4.17 asks. Every result below comes from the fake,
//! time-controlled substrate: [`evidence::decide`] caps it at "inconclusive", because
//! originality needs a literature comparison and a performance claim needs hardware
//! measurements this module cannot make. The decisions are computed by
//! [`evidence::decide`] and asserted by tests.
//!
//! ## E1: deadline-ordered streaming of a dense decoder (§4.4)
//!
//! 1. Contribution: order the transfers of one dense decoder by the latest useful arrival
//!    of each execution group, and let a lookahead of at most three steps choose between
//!    a coalesced contiguous read and the urgent tensor alone, judged by the §2.6
//!    first-token recurrence.
//! 2. Closest prior work: PipeSwitch (OSDI 2020, line 697): pipelined model transmission
//!    in execution order, grouped layers, overlap of transfer and compute.
//! 3. Difference tested: priority by slack plus the bulk-versus-scattered choice, when
//!    the stored order differs from the execution order (lexicographic tensor names).
//! 4. Assumptions: a group is usable only when every byte of its read set arrived and
//!    verified; one read path serves requests one at a time; compute runs groups in the
//!    exact model order. Smallest counterexample to the plan's literal "least slack"
//!    rule: tensors x (deadline 10, transfer 8) and y (deadline 5, transfer 1): least
//!    slack sends x first and y is 4 late; earliest deadline sends y first and nothing is
//!    late. The lookahead therefore weighs both rules.
//! 5. Baselines: the ordinary loader (load everything, then compute) and, as the strongest
//!    compatible baseline, execution-order streaming (the PipeSwitch formulation), both
//!    simulated on the same fake read path.
//! 6. Result: on the constructed lexicographic case deadline order beats file order and
//!    matches or beats execution order; on seeded tiny requests it never beats the
//!    exhaustive order oracle and never loses to its own least-slack base rule. On fakes
//!    the decision is **inconclusive**.
//!
//! ## E2: an MoE adapter with explicit expert dependencies (§4.4, §2.6 line 434)
//!
//! 1. Contribution: load the exact experts a request's prefill routing names first, by
//!    deadline, and every other expert afterwards.
//! 2. Closest prior work: PipeSwitch's execution-order transmission, which has no expert
//!    routing and therefore moves every expert of a layer before the next layer.
//! 3. Difference tested: explicit expert dependencies in the deadline order.
//! 4. Assumptions: the prefill routing is known when the plan is made, which holds only in
//!    replay of a recorded trace; a live router reveals it at run time. Smallest
//!    counterexample: a routed expert that the plan did not name; the group then stalls
//!    until that exact expert loads, and no other expert stands in.
//! 5. Baselines: the ordinary loader and execution-order streaming.
//! 6. Result: first token earlier than both baselines on the fake; **inconclusive**.
//!
//! ## E3: memory-limited exact execution with a double-buffered layer window (§4.11)
//!
//! 1. Contribution: keep only the read sets of the next few operations resident, load the
//!    next operation's new tensors into a second buffer while the current one computes,
//!    and pin a tensor across its whole live range when the ties make that cheaper.
//! 2. Closest prior work: the existing offload backends the plan says to build on (line
//!    768), and PipeSwitch's pipelined transfer for the double buffer.
//! 3. Difference tested: the simple window against an exhaustive offline oracle over every
//!    residency set, and against serial offload (load, then compute).
//! 4. Assumptions: the operation order is fixed and exact; loads for operation k+1 run
//!    while operation k computes; a buffer is freed only after its last consumer
//!    finished. Smallest counterexample: an embedding and output head tied to one tensor
//!    under a budget that cannot hold it beside two layers; the window then reloads it.
//! 5. Baselines: serial offload (strongest compatible on a device that cannot hold the
//!    model); the ordinary loader cannot run at all.
//! 6. Result: the window never beats the oracle and beats serial offload on the fake;
//!    **inconclusive**.
//!
//! ## E4: dense decoding by per-token weight streaming at interactive latency (§4.11)
//!
//! 1. Contribution: none beyond capacity: a dense model larger than the device runs by
//!    streaming its non-resident weights for every token.
//! 2. Closest prior work: the existing offload backends (line 768).
//! 3. Difference tested: whether the streamed bytes per token fit an interactive per-token
//!    latency objective.
//! 4. Assumptions: every non-resident weight byte crosses the read path once per token.
//!    Smallest counterexample to "runs on a small GPU means usable": 9 GB streamed per
//!    token over a measured 24 GB/s path is at least 0.375 s per token, against a 0.1 s
//!    objective.
//! 5. Baselines: none can run; the ordinary loader refuses a model larger than the device.
//! 6. Result: capacity gained, latency objective missed: **narrowed** to a clearly labeled
//!    capacity-only mode.

use std::fmt;

use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::bench::BenchError;
use crate::model_memory::graph::{GranularityError, GraphError, ScheduleError};
use crate::model_memory::math::bounds::BoundsError;
use crate::model_memory::math::overlap::OverlapError;
use crate::model_memory::math::InputError;
use crate::model_memory::residency::host::HostError;
use crate::model_memory::residency::vram::VramError;

pub mod architecture;
pub mod dag;
pub mod deadline;
pub mod evidence;
pub mod execution;
pub mod moe;
pub mod simulate;
pub mod window;

#[cfg(test)]
mod test_support;

/// Why a streaming plan, run or record was refused. Every refusal is typed; nothing is
/// clamped into range or silently replaced by a weaker plan (plan S1).
#[derive(Clone, Debug, PartialEq)]
pub enum StreamingError {
    /// A value is out of its range.
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    Name(IdError),
    Math(InputError),
    Overlap(OverlapError),
    Bounds(BoundsError),
    Granularity(GranularityError),
    Graph(GraphError),
    Schedule(ScheduleError),
    Report(ReportError),
    Vram(VramError),
    Host(HostError),
    Bench(BenchError),
    /// A name appears twice where each must be unique.
    Duplicate {
        field: &'static str,
        name: String,
    },
    /// An index refers to nothing that was declared.
    Unknown {
        field: &'static str,
        index: usize,
    },
    /// Two tensors claim overlapping stored bytes.
    OverlappingTensors {
        first: String,
        second: String,
    },
    /// A tensor or buffer no execution group reads: the streamed read set would differ
    /// from the ordinary loader's (GPU-W07 item 6).
    Unread {
        name: String,
    },
    /// The groups are not embedding, layers, output head in that order.
    GroupOrder {
        reason: &'static str,
    },
    /// The streamed read set differs from the ordinary loader's (GPU-W07 item 6).
    ReadSetMismatch {
        tensor: String,
        problem: ReadSetProblem,
    },
    /// The request is longer than the architecture was planned for.
    ShapeTooLarge {
        prompt_tokens: u64,
        max_prompt_tokens: u64,
    },
    /// MoE routing is missing, not exact, or given for a dense model (§2.6 line 434).
    Routing {
        group: usize,
        reason: &'static str,
    },
    /// The plan would load more than the destination reservation holds.
    OverDestinationBudget {
        needed_bytes: u64,
        budget_bytes: u64,
    },
    /// Execution-time refusals.
    Execution(ExecutionRefusal),
    /// The device window would exceed its physical budget (§4.11).
    OverDeviceBudget {
        op: usize,
        needed_bytes: u64,
        budget_bytes: u64,
    },
    /// Unified-memory oversubscription offered as device capacity (§4.11 line 768).
    UnifiedMemoryIsNotCapacity,
    /// The offline oracle is exhaustive and only for tiny problems (§2.3 line 395).
    OracleTooLarge {
        ops: usize,
        tensors: usize,
        max_ops: usize,
        max_tensors: usize,
    },
    /// A simulated result offered under a substrate other than the fake one (S12 G0).
    SimulationOnRealSubstrate,
    /// MoE locality needs a recorded routing trace; sparse routing is never assumed to
    /// mean sparse residency (§4.11 line 766).
    EmptyTrace,
}

/// How the streamed read set differs from the ordinary loader's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadSetProblem {
    /// The ordinary loader loads it; streaming does not.
    MissingFromStream,
    /// Streaming loads it; the ordinary loader does not.
    NotInOrdinaryLoader,
    /// Same name, different content identity.
    ContentDiffers,
    /// The ordinary loader names it twice.
    Repeated,
}

/// A runtime action the per-request state machine refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRefusal {
    /// GPU §2.6 and §4.4: a group never computes before every tensor and buffer it reads
    /// is usable.
    ComputeBeforeUsable {
        group: usize,
        missing_tensors: Vec<usize>,
        missing_buffers: Vec<usize>,
    },
    /// Groups compute in the exact model order.
    OutOfOrder { expected: usize, requested: usize },
    /// One group computes at a time on the stream.
    ComputeBusy { running: usize },
    /// No group is computing, or another one is.
    NotRunningGroup { group: usize },
    /// The request already ended (cancelled, failed or completed).
    Ended,
    /// §3.6 line 599: a request never mixes layers from different generations.
    MixedGenerations { expected: u64, found: u64 },
    /// §3.6 line 601: execute-while-load serves only its explicitly assigned request.
    UnrelatedRequest,
    /// A compute was reported for another request shape than the plan's.
    ShapeMismatch,
    /// A tensor or buffer was reported usable twice.
    AlreadyUsable,
    /// §3.7 line 605: a tensor is used only while it is resident.
    NotResident { tensor: usize },
    /// §3.7 line 605: unmapping (eviction) requires quiescence.
    EvictWhileInUse { tensor: usize },
    /// A load would exceed the physical device window.
    OverWindow {
        tensor: usize,
        needed_bytes: u64,
        budget_bytes: u64,
    },
    /// A tensor is already resident or loading.
    AlreadyResident { tensor: usize },
}

impl fmt::Display for StreamingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, reason } => write!(f, "{field}: {reason}"),
            Self::Name(error) => error.fmt(f),
            Self::Math(error) => error.fmt(f),
            Self::Overlap(error) => error.fmt(f),
            Self::Bounds(error) => error.fmt(f),
            Self::Granularity(error) => error.fmt(f),
            Self::Graph(error) => error.fmt(f),
            Self::Schedule(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Vram(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
            Self::Bench(error) => write!(f, "{error:?}"),
            Self::Duplicate { field, name } => write!(f, "{field} lists {name:?} twice"),
            Self::Unknown { field, index } => write!(f, "{field} names unknown index {index}"),
            Self::OverlappingTensors { first, second } => {
                write!(f, "tensors {first} and {second} overlap in storage")
            }
            Self::Unread { name } => write!(
                f,
                "{name} is read by no execution group, so streaming would load a different \
                 set than the ordinary loader"
            ),
            Self::GroupOrder { reason } => write!(f, "execution groups: {reason}"),
            Self::ReadSetMismatch { tensor, problem } => {
                write!(f, "{tensor}: {problem:?} against the ordinary loader")
            }
            Self::ShapeTooLarge {
                prompt_tokens,
                max_prompt_tokens,
            } => write!(
                f,
                "a prompt of {prompt_tokens} tokens exceeds the planned {max_prompt_tokens}"
            ),
            Self::Routing { group, reason } => write!(f, "group {group}: {reason}"),
            Self::OverDestinationBudget {
                needed_bytes,
                budget_bytes,
            } => write!(
                f,
                "the plan loads {needed_bytes} bytes but the destination holds {budget_bytes}"
            ),
            Self::Execution(refusal) => write!(f, "refused: {refusal:?}"),
            Self::OverDeviceBudget {
                op,
                needed_bytes,
                budget_bytes,
            } => write!(
                f,
                "operation {op} needs {needed_bytes} device bytes but {budget_bytes} are \
                 budgeted"
            ),
            Self::UnifiedMemoryIsNotCapacity => f.write_str(
                "unified-memory oversubscription supplies no physical capacity; account \
                 host and device memory explicitly",
            ),
            Self::OracleTooLarge {
                ops,
                tensors,
                max_ops,
                max_tensors,
            } => write!(
                f,
                "the exhaustive oracle takes at most {max_ops} operations and {max_tensors} \
                 tensors, not {ops} and {tensors}"
            ),
            Self::SimulationOnRealSubstrate => f.write_str(
                "a simulated result is recorded only on the fake time-controlled substrate",
            ),
            Self::EmptyTrace => f.write_str("expert locality needs a recorded routing trace"),
        }
    }
}

impl std::error::Error for StreamingError {}

crate::model_memory::from_error!(
    StreamingError:
    IdError => Name,
    InputError => Math,
    OverlapError => Overlap,
    BoundsError => Bounds,
    GranularityError => Granularity,
    GraphError => Graph,
    ScheduleError => Schedule,
    ReportError => Report,
    VramError => Vram,
    HostError => Host,
    BenchError => Bench,
    ExecutionRefusal => Execution,
);

/// A finite value of zero or more.
pub(crate) fn non_negative(field: &'static str, value: f64) -> Result<f64, StreamingError> {
    if !value.is_finite() {
        return Err(StreamingError::Invalid {
            field,
            reason: "not a finite number",
        });
    }
    if value < 0.0 {
        return Err(StreamingError::Invalid {
            field,
            reason: "negative",
        });
    }
    Ok(value)
}

/// Checked byte sum.
pub(crate) fn add_bytes(field: &'static str, left: u64, right: u64) -> Result<u64, StreamingError> {
    left.checked_add(right).ok_or(StreamingError::Invalid {
        field,
        reason: "does not fit in 64 bits",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_refuse_instead_of_clamping() {
        assert!(non_negative("x", f64::NAN).is_err());
        assert!(non_negative("x", -0.5).is_err());
        assert_eq!(non_negative("x", 0.0), Ok(0.0));
        assert!(add_bytes("b", u64::MAX, 1).is_err());
        assert_eq!(add_bytes("b", 2, 3), Ok(5));
    }

    #[test]
    fn errors_render_a_reason() {
        let text = StreamingError::UnifiedMemoryIsNotCapacity.to_string();
        assert!(text.contains("no physical capacity"));
        let refusal: StreamingError = ExecutionRefusal::UnrelatedRequest.into();
        assert!(refusal.to_string().contains("UnrelatedRequest"));
    }
}
