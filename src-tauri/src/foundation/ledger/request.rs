//! What a reservation request carries: who asks, for which execution, operation and
//! tenant, at what priority, inside which parent, and whether it may wait (CORE-03).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::resource::Amounts;
use crate::foundation::ids::{ExecutionId, OperationId, TenantId};

macro_rules! sequence_id {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// The number, unique within one ledger.
            pub const fn get(self) -> u64 {
                self.0
            }

            pub(super) const fn new(value: u64) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, " {}"), self.0)
            }
        }
    };
}

sequence_id!(
    /// One reservation, numbered by the ledger that granted it.
    ReservationId,
    "reservation"
);
sequence_id!(
    /// One queued request, numbered by the ledger that queued it.
    QueueTicket,
    "queue ticket"
);
sequence_id!(
    /// One owner resource-return hold (S10 line 185).
    HoldId,
    "hold"
);

/// The component asking for a reservation (CORE-03 accounting provenance).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requester {
    /// VM lifecycle: roots, memory and snapshot pages, network and CPU initialization
    /// slots (VM-W16, VM-W24, VM-W26).
    VmLifecycle,
    /// The model placement governor, a policy client of this ledger and never a second
    /// host capacity authority (GPU part §3.1, line 491).
    ModelPlacement,
    /// Byte reservations of transfers (CORE-05).
    Transfer,
    /// Launch transactions of the coordination protocol (CORE-04).
    Coordination,
}

/// Background work is denied by an owner resource-return hold; foreground work is not
/// (S10 line 185, S7 line 131).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Background,
    Foreground,
}

/// What a reservation's cost is charged to in BENCH-08 (S7 line 128: idle time, VM
/// resources, storage, transfer and retry costs). Idle time comes from the record's
/// phases and retries from [`Provenance::retry_number`], so neither is a purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostPurpose {
    /// Model serving or other compute.
    Compute,
    /// An additional replica of something already served.
    Replica,
    /// Resources of a VM.
    VmResources,
    /// Stored data.
    Storage,
    /// Data in transfer.
    Transfer,
}

/// Who asked, for what, and how the cost is attributed (CORE-03 "accounting
/// provenance"). The parent and the timestamps are added by the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub requester: Requester,
    /// The parent execution the reservation belongs to; a child reservation belongs to
    /// its parent's execution.
    pub execution: ExecutionId,
    pub operation: OperationId,
    /// The tenant whose budget is charged.
    pub tenant: TenantId,
    pub purpose: CostPurpose,
    /// Zero for an original attempt, n for the nth retry; BENCH-08 charges retries
    /// separately.
    pub retry_number: u32,
}

impl Provenance {
    /// Whether this serves a retry, which BENCH-08 charges as retry cost.
    pub const fn is_retry(&self) -> bool {
        self.retry_number > 0
    }
}

/// Whether a request that does not fit yet may wait in the bounded queue (S10 line 179).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuePolicy {
    /// Refuse at once with an actionable capacity error.
    NoWait,
    /// Wait at most this long; the ledger's own limit applies when it is shorter.
    WaitUpTo(Duration),
}

/// A request to reserve before creating (S10 line 179).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationRequest {
    pub provenance: Provenance,
    pub priority: Priority,
    /// The reservation this one is carved from (S3.2): a model load inside a VM or a
    /// runtime allocation. `None` charges host capacity and the tenant budget.
    pub parent: Option<ReservationId>,
    pub demand: Amounts,
    pub queue: QueuePolicy,
}

impl ReservationRequest {
    /// A host-level request that does not wait.
    pub fn new(provenance: Provenance, priority: Priority, demand: Amounts) -> Self {
        Self {
            provenance,
            priority,
            parent: None,
            demand,
            queue: QueuePolicy::NoWait,
        }
    }

    /// Carves the request from `parent` instead of host capacity.
    pub fn within(mut self, parent: ReservationId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Lets the request wait in the queue for at most `max_wait`.
    pub fn wait_up_to(mut self, max_wait: Duration) -> Self {
        self.queue = QueuePolicy::WaitUpTo(max_wait);
        self
    }
}
