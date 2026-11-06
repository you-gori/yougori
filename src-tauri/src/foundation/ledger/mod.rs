//! CORE-03: the host admission and reservation ledger
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 line 40).
//!
//! One [`Ledger`] per host counts physical capacity once per host resource and GPU
//! device: host RAM, pinned host RAM, VRAM, storage quota and I/O, network and CPU
//! initialization slots, burst VM roots and memory/snapshot pages (S10 line 179). VRAM
//! is keyed by the shared [`GpuDeviceKey`](crate::foundation::ids::GpuDeviceKey). Only
//! host observations set capacity, and a supervisor reserve is never granted. Declared
//! capacity does not lapse, but the host's observation of unmanaged usage does: once it
//! is older than the configured age, no more of that resource is granted until the host
//! observes it again, while existing reservations stay.
//!
//! A host-level reservation is charged against physical capacity and, separately,
//! against its tenant's budget. A child (a model load inside a VM or a runtime
//! allocation) is carved from its parent and never exceeds it; the host enforces the
//! parent (S3.2, GPU part §3.1 line 491). Reservations are made before their workload is
//! created; a request is granted whole, waits in a bounded queue, or is refused with a
//! [`CapacityError`] naming the limiting resource and whether a retry can make progress
//! (S10 line 179).
//!
//! Cancellation is idempotent and wakes the queue. A created workload's amounts count
//! until the host observes their release, so stopping work never yields false free
//! capacity (INT-01, INT-02, S10 line 185); after a partial start, reconciliation keeps
//! what is in use and releases the rest. Guest reports are kept as observations
//! ([`SourceClass`](crate::foundation::evidence::SourceClass)) and never raise available
//! capacity. Every reservation records its requester, execution, operation, tenant,
//! parent, clock timestamps and cost attribution for BENCH-08 (S7 line 128). An owner
//! resource-return hold denies new background reservations of the held resources while
//! existing ones drain (S10 line 185, S7 line 131).
//!
//! The queue is served in arrival order unless [`QueueFairness`] enables aging, tenant
//! turns and foreground first; every queued request keeps its wait and bypass record, and
//! each tenant its queue statistics (GPU-W06). A request that does not fit can first run a
//! [`ReclaimLadder`] its caller lends: cancel speculation, reclaim unused scratch, drop
//! low-value caches, park eligible idle models, then queue or reject, counting only what
//! the ledger's own accounting returns (GPU-W05).
//!
//! When several clients share one host ledger, one [`LedgerHistory`] per ledger takes
//! its closed records, its records of closed shared extents and ended transition peaks,
//! and its events, keeps a bounded window of them, exports them to a sink such as a
//! durable journal, and holds each queued request's outcome for the client holding its
//! ticket. Accumulated history then never stops admission. Nothing is exported until an
//! owner configures a [`HistoryDestination`]: a [`HistoryJournal`] on a CORE-06 durable
//! log, bounded and rotated, with every loss recorded.
//!
//! A reservation can be owned beyond its request (S03). A [`Lifecycle`] (one execution,
//! one VM boot or one model activation generation, under its tenant) owns parents: when
//! it drains nothing more is carved from them, and when it ends or is revoked they are
//! released with everything carved from them. A bounded, time-limited
//! [`TransitionPeak`] covers the overlap while a new generation loads before the old one
//! releases, admitted against the same capacity and falling back to the steady amounts.
//! One physical extent several holders share is one reservation under its [`ExtentKey`],
//! released when its last holder leaves and attributed to each holder for cost without
//! double counting. An [`AllocationObservation`] from a source with authority counts and
//! flags use beyond a reservation, which then grows no further, and records unused
//! amounts without returning them.

mod admission;
mod error;
mod fairness;
mod history;
mod history_journal;
mod reclaim;
mod record;
mod request;
mod resource;

#[cfg(test)]
mod tests;

pub use admission::lifecycle::{
    Lifecycle, LifecycleEnd, LifecycleReport, LifecycleScope, LifecycleStatus, MAX_ENDED_LIFECYCLES,
};
pub use admission::observed::{
    AllocationObservation, AllocationReport, OverUse, OwnerFinding, UnderUse,
};
pub use admission::ownership::{GrowthRefusal, OwnershipError};
pub use admission::sharing::{
    Departure, ExtentKey, HolderCost, HolderExit, HolderSpan, ShareAdmission, ShareRefusal,
    ShareRelease, SharedExtent, SharedExtentRecord, MAX_EXTENT_RECORDS,
};
pub use admission::transition::{
    PeakEnd, PeakOutcome, PeakRecord, TransitionPeak, MAX_PEAK_RECORDS, MAX_TRANSITION_WINDOW,
};
pub use admission::{
    Admission, CapacityDeclaration, ExecutionCancelReport, HoldReport, Ledger, LedgerConfig,
    LedgerEvent, PhysicalCapacity, QueueLimits, ReconcileOutcome, ReleaseOutcome,
    MAX_NESTING_DEPTH,
};
pub use error::{
    CapacityError, LedgerError, Limit, ParentField, QueueRefusal, RetryProspect, Shortfall,
    Transition,
};
pub use fairness::{
    ClaimReason, QueueClaim, QueueEntry, QueueExit, QueueFairness, QueueRecord, TenantQueueStats,
    MAX_QUEUE_RECORDS,
};
pub use history::{
    HistoryEntry, HistoryError, HistoryItem, HistoryLimits, HistorySink, HistoryTotals,
    JsonLinesSink, LedgerHistory, SinkError, TicketOutcome,
};
pub use history_journal::{
    ExportOutcome, HistoryDestination, HistoryExport, HistoryJournal, JournalRecord, JournalTotals,
    MissingReason,
};
pub use reclaim::{
    DeclineReason, LadderReport, LadderSkip, NominationRefusal, ReclaimAdmission, ReclaimLadder,
    ReclaimNeed, ReclaimResponse, ReclaimStep, Reclaimer, RefusedNomination, ReturnedReservation,
    StepOutcome, StepReport,
};
pub use record::{
    AmountChange, ChangeCause, CloseReason, PhaseDurations, RecordedObservation, ReservationRecord,
    ReservationState, UsageObservation,
};
pub use request::{
    CostPurpose, HoldId, Priority, Provenance, QueuePolicy, QueueTicket, Requester, ReservationId,
    ReservationRequest,
};
pub use resource::{
    AmountEntry, Amounts, AmountsError, DeviceId, HostResource, ResourceKey, ResourceUnit,
};
