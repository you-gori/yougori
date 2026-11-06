//! Boundary 3 of GPU §3.1: the transfer executor.
//!
//! Responsibility: bounded reads, verification, copies, decoding and events. Must not
//! own: choosing a different model. A [`TransferOrder`] pins the exact model, the exact
//! extents with their expected digests and lengths, the destination device and the byte
//! budget; its fields are private and it has no setter. The executor has no catalog,
//! no model name and no request, so it has nothing to choose another model from. What
//! it reports is checked against the order by the flow: an extent outside the order or
//! with another digest is refused, never published (§3.5: a hash mismatch is never a
//! warning followed by use).
//!
//! The portable path behind this boundary is P03's state machine
//! ([`crate::model_memory::executor`]), adapted by
//! [`PortableExecutor`](super::PortableExecutor); its source kinds are used here
//! unchanged, so an import-only bind is never accepted as a read source (Appendix A.3).
//! An order names each extent's stored location in the catalog's names
//! ([`StoredExtent`]) and the destination the governor reserved for it
//! ([`TransferDestination`]): weights in their own holding, other state in the
//! activation's own memory. That is all P03 needs to resolve, read and place it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::catalog::{ExtentRef, StoredExtent};
use super::governor::{TransferBudget, TransferDestination};
use super::preparation::PreparationToken;
use crate::foundation::ids::{
    ContentKey, ExecutionId, GpuDeviceKey, MonotonicTime, OperationId, TenantId,
};
use crate::model_memory::executor::SourceKind;
use crate::model_memory::identity::ExecutionIdentity;

/// One extent to transfer with the identity it must have when it arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OrderedExtent {
    pub extent: ExtentRef,
    pub digest: ContentKey,
    pub length_bytes: u64,
    /// Where the catalog stores it, when a catalog object holds it.
    pub stored: Option<StoredExtent>,
}

/// Why an order could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum OrderRefusal {
    NoExtents,
    DuplicateExtent {
        extent: ExtentRef,
    },
    /// The budget does not name this object.
    OutsideBudget {
        extent: ExtentRef,
    },
    ExceedsBudget {
        total_bytes: u64,
        budget_bytes: u64,
    },
    Overflow,
}

impl fmt::Display for OrderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExtents => f.write_str("the order has no extents"),
            Self::DuplicateExtent { .. } => f.write_str("the order names an extent twice"),
            Self::OutsideBudget { .. } => {
                f.write_str("the order names an object outside its transfer budget")
            }
            Self::ExceedsBudget {
                total_bytes,
                budget_bytes,
            } => write!(
                f,
                "the order needs {total_bytes} bytes; the budget allows {budget_bytes}"
            ),
            Self::Overflow => f.write_str("the order's size does not fit in 64 bits"),
        }
    }
}

/// Exactly what one preparation may transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TransferOrder {
    model: ExecutionIdentity,
    execution: ExecutionId,
    operation: OperationId,
    tenant: TenantId,
    recipient: GpuDeviceKey,
    destination: Option<TransferDestination>,
    destinations: BTreeMap<ExtentRef, TransferDestination>,
    budget_bytes: u64,
    total_bytes: u64,
    extents: Vec<OrderedExtent>,
}

impl TransferOrder {
    /// Every extent must be named by the budget, once, and their total must fit it.
    pub fn new(
        preparation: &PreparationToken,
        budget: &TransferBudget,
        extents: Vec<OrderedExtent>,
    ) -> Result<Self, OrderRefusal> {
        if extents.is_empty() {
            return Err(OrderRefusal::NoExtents);
        }
        let mut seen = BTreeSet::new();
        let mut total_bytes = 0u64;
        for ordered in &extents {
            if !seen.insert(ordered.extent) {
                return Err(OrderRefusal::DuplicateExtent {
                    extent: ordered.extent,
                });
            }
            if !budget.permits(&ordered.extent) {
                return Err(OrderRefusal::OutsideBudget {
                    extent: ordered.extent,
                });
            }
            total_bytes = total_bytes
                .checked_add(ordered.length_bytes)
                .ok_or(OrderRefusal::Overflow)?;
        }
        if total_bytes > budget.max_bytes() {
            return Err(OrderRefusal::ExceedsBudget {
                total_bytes,
                budget_bytes: budget.max_bytes(),
            });
        }
        Ok(Self {
            model: preparation.model(),
            execution: preparation.execution().clone(),
            operation: preparation.operation().clone(),
            tenant: preparation.tenant().clone(),
            recipient: budget.recipient(),
            destination: budget.destination(),
            destinations: extents
                .iter()
                .filter_map(|ordered| {
                    budget
                        .destinations()
                        .get(&ordered.extent)
                        .map(|destination| (ordered.extent, *destination))
                })
                .collect(),
            budget_bytes: budget.max_bytes(),
            total_bytes,
            extents,
        })
    }

    /// The one model the order serves.
    pub fn model(&self) -> ExecutionIdentity {
        self.model
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// The tenant the transfer is charged to and authorized as.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn recipient(&self) -> GpuDeviceKey {
        self.recipient
    }

    /// The GPU allocation the activation reserved for extents without their own
    /// destination, and its reservation: the activation's own memory.
    pub fn destination(&self) -> Option<TransferDestination> {
        self.destination
    }

    /// Where `extent` lands: its own destination, as weights in their holding, otherwise
    /// the order's.
    pub fn destination_of(&self, extent: &ExtentRef) -> Option<TransferDestination> {
        self.destinations.get(extent).copied().or(self.destination)
    }

    /// The most the executor may read for this order.
    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn extents(&self) -> &[OrderedExtent] {
        &self.extents
    }

    pub fn expected(&self, extent: &ExtentRef) -> Option<&OrderedExtent> {
        self.extents
            .iter()
            .find(|ordered| ordered.extent == *extent)
    }
}

/// The executor's handle on a submitted order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TransferTicket(u64);

impl TransferTicket {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One extent whose whole chain (read, verify, decode, copy, completion event) finished
/// (§3.5 step 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ExtentCompletion {
    /// The extent delivered.
    pub extent: ExtentRef,
    /// The decoded content key the executor verified.
    pub verified_digest: ContentKey,
    /// Bytes read for it, retries included.
    pub bytes_read: u64,
    /// Where the bytes were read from (P03's source kinds).
    pub source: SourceKind,
    pub completed_at: MonotonicTime,
}

/// Why an order was not accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum TransferRefusal {
    /// No authorized source has this extent.
    SourceUnavailable {
        extent: ExtentRef,
    },
    ExceedsBudget {
        total_bytes: u64,
        budget_bytes: u64,
    },
    /// The order names no destination the activation reserved.
    NoDestination,
    /// No catalog object holds the extent in a form a transfer can read.
    NotStored {
        extent: ExtentRef,
    },
    /// The executor refused the order, in its own words; nothing started.
    Rejected {
        reason: String,
    },
}

impl fmt::Display for TransferRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnavailable { .. } => f.write_str("no authorized source has the extent"),
            Self::ExceedsBudget { .. } => f.write_str("the order exceeds its transfer budget"),
            Self::NoDestination => f.write_str("the order has no reserved destination"),
            Self::NotStored { .. } => {
                f.write_str("no catalog object holds the extent in a readable form")
            }
            Self::Rejected { reason } => write!(f, "the executor refused the order: {reason}"),
        }
    }
}

/// Why an extent did not complete. Its bytes are never used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum TransferFailure {
    UnknownTicket {
        ticket: TransferTicket,
    },
    NotOrdered {
        extent: ExtentRef,
    },
    HashMismatch {
        extent: ExtentRef,
        expected: ContentKey,
        actual: ContentKey,
    },
    SourceFailed {
        extent: ExtentRef,
    },
    /// The executor stopped making progress on the extent.
    Stalled {
        extent: ExtentRef,
    },
    /// The executor gave the extent up, in its own words.
    Failed {
        extent: ExtentRef,
        reason: String,
    },
    Cancelled,
}

impl fmt::Display for TransferFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownTicket { .. } => "unknown transfer",
            Self::NotOrdered { .. } => "the extent is not part of the order",
            Self::HashMismatch { .. } => "the extent did not match its identity",
            Self::SourceFailed { .. } => "the source failed",
            Self::Stalled { .. } => "the transfer stopped making progress",
            Self::Failed { .. } => "the executor gave the extent up",
            Self::Cancelled => "the transfer was cancelled",
        })
    }
}

/// The transfer executor boundary. Transfers run in the background from `submit`;
/// `await_extent` returns when one extent's whole chain has completed, which is what
/// lets loading overlap reconstruction and computation (GPU §1 path 3).
pub trait TransferExecutor {
    /// Starts reading, verifying, decoding and copying exactly the ordered extents, within
    /// the order's budget.
    fn submit(&mut self, order: &TransferOrder) -> Result<TransferTicket, TransferRefusal>;

    /// Waits until one ordered extent is verified and copied.
    fn await_extent(
        &mut self,
        ticket: TransferTicket,
        extent: &ExtentRef,
    ) -> Result<ExtentCompletion, TransferFailure>;

    /// Stops the remaining work of an order at a safe boundary: reads and copies in
    /// flight drain first, so once it returns no staging buffer of the order is in use.
    fn cancel(&mut self, ticket: TransferTicket);
}
