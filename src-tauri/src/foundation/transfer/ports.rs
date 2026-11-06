//! Ports to the modules a transfer needs that are still being written: authority
//! (CORE-04 coordination, T09), the byte budget (CORE-03 ledger, T04), verified extents
//! (CORE-02 catalog, T05) and progress (CORE-06 events, T10).
//!
//! Each port is the least this module needs. Tests drive them through fakes; adapters
//! over the real modules replace the fakes once those modules are committed.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::endpoint::{Direction, Endpoint};
use super::range::{ByteRange, RangeSet};
use super::status::StopReason;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, ExecutionId, MonotonicTime, OperationId, TenantId,
};

/// The authority a parent execution holds now (S3.1): its authorization epoch and when
/// that authority expires. `expires_at` is a point on `clock`, so it is compared only
/// with readings of that clock session (CORE-01 clock sessions), never across a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentAuthority {
    pub epoch: AuthorizationEpoch,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
}

/// Where a parent execution stands, as the authority port reports it (S3.1, INT-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ParentStatus {
    /// The parent holds authority now.
    Authorized { authority: ParentAuthority },
    /// The parent is at authorization epoch `current` but holds no authority under it:
    /// revoked, being recovered, or not yet granted. After a revocation `current` is the
    /// advanced epoch, so a transfer bound to an older one sees the revocation at once.
    NoAuthority { current: AuthorizationEpoch },
    /// The parent is not running, or is unknown.
    NotRunning,
}

crate::foundation::strict_serde::strict_tag!(ParentStatus, "status");

/// Authority port (CORE-04 coordination, T09): whether the authorization a transfer is
/// bound to is still current (S3.1, INT-02).
pub trait AuthorityPort: Send + Sync {
    /// Where `parent` stands now.
    fn parent_status(&self, parent: &ExecutionId) -> ParentStatus;
}

/// A byte reservation request (S3.7 byte budget; CORE-03 reserve before create).
///
/// It is charged to the parent's transfer budget for this direction, never to the
/// general release budget (S3.7, VM-D12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteReservationRequest {
    pub tenant: TenantId,
    pub parent: ExecutionId,
    pub operation: OperationId,
    pub direction: Direction,
    pub requested_bytes: u64,
    /// Zero when the transfer opens; n when a grant re-issued for its attempt n + 1
    /// reserves again, so retry costs are attributed separately (CORE-03, BENCH-08).
    pub retry_number: u32,
}

/// A reservation the byte budget granted, held until released, with the transfer's
/// network slot when the port holds one (S10 line 179).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteReservation {
    /// The ledger's identity for the reservation.
    pub token: u64,
    /// The bytes the request asked for. For a direction the port counts no bytes for
    /// (uploads and peer sends under the T14 follow-up decision) they are bounded by the
    /// envelope's own budget alone, and the reservation holds the slot.
    pub reserved_bytes: u64,
}

/// The byte budget could not reserve the bytes (CORE-03: say what limits the request and
/// whether a retry can progress).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteBudgetRefusal {
    pub requested_bytes: u64,
    pub available_bytes: u64,
    /// Whether waiting for other reservations to end could let a retry succeed.
    pub retry_can_progress: bool,
}

impl fmt::Display for ByteBudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the transfer budget has {} of the {} bytes requested",
            self.available_bytes, self.requested_bytes
        )?;
        if self.retry_can_progress {
            f.write_str("; retry once other transfers finish")
        } else {
            f.write_str("; retrying will not help")
        }
    }
}

/// What limits the transfer's network slot (S10 line 179: the output names the limiting
/// resource), in the terms of the CORE-03 ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotLimit {
    /// Every slot the host may grant is held; one frees when another transfer ends.
    HostCapacity,
    /// The host has not observed its slots, or its observation lapsed; none is granted
    /// until it observes them again.
    HostObservation,
    /// The tenant's slot budget, charged separately from the host's capacity.
    TenantBudget,
    /// The parent reservation the slot would be carved from.
    ParentReservation,
    /// An owner resource-return hold denies background transfers a slot (S10 line 185).
    OwnerReturnHold,
}

/// No network slot is free for the transfer (S10 line 179): network slots are the
/// limiting resource, `limit` says under which rule, and `retry_can_progress` whether a
/// retry can succeed at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSlotRefusal {
    pub limit: SlotLimit,
    /// Whether a retry can succeed once another transfer ends, the hold ends or the host
    /// observes its slots; false when the limit is exceeded outright, as for a tenant
    /// with no slot budget.
    pub retry_can_progress: bool,
}

impl fmt::Display for NetworkSlotRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let limit = match self.limit {
            SlotLimit::HostCapacity => "every network slot of this host is held",
            SlotLimit::HostObservation => "the host has not observed its network slots",
            SlotLimit::TenantBudget => "the tenant's network slot budget is used up",
            SlotLimit::ParentReservation => "the parent reservation has no network slot left",
            SlotLimit::OwnerReturnHold => {
                "an owner resource-return hold denies network slots to background transfers"
            }
        };
        write!(f, "no network slot is free for the transfer: {limit}")?;
        let retry = match (self.retry_can_progress, self.limit) {
            (false, _) => "; retrying will not help",
            (true, SlotLimit::HostObservation) => "; retry after a host probe",
            (true, SlotLimit::OwnerReturnHold) => "; retry after the hold ends",
            (true, _) => "; retry once another transfer ends",
        };
        f.write_str(retry)
    }
}

/// Why the budget port could not reserve for a transfer: its bytes, or the network slot
/// every active transfer holds through a port that holds one (S10 line 179).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resource", content = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservationRefusal {
    Bytes(ByteBudgetRefusal),
    NetworkSlot(NetworkSlotRefusal),
}

crate::foundation::strict_serde::strict_tag!(ReservationRefusal, "resource");

impl fmt::Display for ReservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(refusal) => write!(f, "{refusal}"),
            Self::NetworkSlot(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// The reservation behind a transfer is no longer held: the ledger withdrew it, as when
/// the parent's reservations are cancelled on revocation (INT-02). No more bytes move
/// under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationWithdrawn;

impl fmt::Display for ReservationWithdrawn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the transfer's byte reservation was withdrawn")
    }
}

impl std::error::Error for ReservationWithdrawn {}

/// Byte budget port (CORE-03 ledger, T04): reserve bytes before any moves, charge each
/// admitted chunk against them, and release them when the transfer ends. A port may hold
/// the transfer's network slot in the same reservation (S10 line 179); the session then
/// reserves on every attempt and releases at every terminal phase, slot included.
pub trait ByteBudgetPort: Send + Sync {
    /// Reserves exactly `request.requested_bytes`, or refuses; a partial grant is not a
    /// reservation.
    fn reserve(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ByteBudgetRefusal>;

    /// Reserves the transfer's bytes and, through a port that holds one, its network
    /// slot, as one all-or-nothing request (S10 line 179: reserve before creating, and
    /// name the limiting resource). A port holding no slot keeps this default, which
    /// reserves the bytes alone.
    fn reserve_transfer(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ReservationRefusal> {
        self.reserve(request).map_err(ReservationRefusal::Bytes)
    }

    /// Whether every transfer holds a network slot through this port, from its open to
    /// its terminal phase (S10 line 179). The session then reserves on every attempt,
    /// even one with no budget left, so an active transfer always holds its slot.
    fn holds_network_slot(&self) -> bool {
        false
    }

    /// Charges a chunk before its bytes move: `used_bytes` of `reservation` are now used.
    /// Refused when the reservation is no longer held; the transfer then stops.
    fn charge(
        &self,
        reservation: ByteReservation,
        used_bytes: u64,
    ) -> Result<(), ReservationWithdrawn>;

    /// Ends `reservation`, of which `used_bytes` were charged. Chunks admitted under it may
    /// still be moving until `settled_by` (the stop's declared bound, or the release time
    /// when nothing was in flight), so its bytes count until then: stopping never yields
    /// false free capacity (CORE-03, INT-02). Releasing cannot fail: the ledger reconciles
    /// a reservation it does not recognise.
    fn release(&self, reservation: ByteReservation, used_bytes: u64, settled_by: MonotonicTime);
}

/// Verified extents port (CORE-02 catalog, T05): which byte ranges of an object are
/// already verified, so a retry reuses them instead of moving them again (INT-08).
pub trait VerifiedExtentsPort: Send + Sync {
    /// The ranges of `object` that `recipient` holds verified against the object's
    /// content identity and that `tenant` may read as `parent` (S3.3: equal bytes are
    /// not permission). Verification is the host's; a guest's claim is never an answer.
    /// The session clips the answer to the envelope's scope, so it can never widen a
    /// grant.
    fn verified(
        &self,
        tenant: &TenantId,
        parent: &ExecutionId,
        recipient: &Endpoint,
        object: &ContentKey,
    ) -> RangeSet;
}

/// What happened, in one progress event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ProgressPhase {
    Started,
    /// A retry began a new attempt.
    Resumed,
    ChunkDelivered {
        object: ContentKey,
        range: ByteRange,
    },
    /// The attempt failed; its in-flight chunks were dropped.
    Interrupted {
        dropped_in_flight_bytes: u64,
    },
    Stopped {
        reason: StopReason,
    },
    Completed,
}

crate::foundation::strict_serde::strict_tag!(ProgressPhase, "kind");

/// Where a transfer's bytes come from, by the kind of its source alone: a progress event
/// names no endpoint (CORE-06 redaction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrigin {
    /// This host: its catalog or the parent execution.
    Local,
    /// An enrolled Yougori peer host.
    Peer,
    /// A registered external route, such as a model repository.
    Remote,
}

impl ByteOrigin {
    /// The kind of `source`.
    pub const fn of(source: &Endpoint) -> Self {
        match source {
            Endpoint::HostCatalog | Endpoint::Execution { .. } => Self::Local,
            Endpoint::PeerHost { .. } => Self::Peer,
            Endpoint::NamedRoute { .. } => Self::Remote,
        }
    }
}

/// One object's bytes at the moment of a progress event (CORE-06; GPU part §3.10:
/// completed, total and committed usable bytes per resource).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectProgress {
    pub object: ContentKey,
    /// Bytes of the object the transfer grants.
    pub granted_bytes: u64,
    /// Granted bytes at the recipient: verified, or delivered in this attempt.
    pub completed_bytes: u64,
    /// Granted bytes the catalog had verified, and so usable, when the attempt started
    /// or the transfer finished.
    pub verified_bytes: u64,
}

/// One progress event (CORE-06: operation identity, typed generation, monotonic
/// sequence, phase). It carries no credential and no endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferProgress {
    /// The operation the progress belongs to: the envelope's, or for a continuation
    /// after a stop a new one (see `continuation_operation`).
    pub operation: OperationId,
    /// The stopped operation a continuation follows, for every event of the
    /// continuation; `None` otherwise.
    pub continues: Option<OperationId>,
    pub parent: ExecutionId,
    /// The authorization epoch the transfer moved under.
    pub epoch: AuthorizationEpoch,
    /// One more than the previous event of this transfer, across attempts, so a reader
    /// can find gaps and duplicates (CORE-06).
    pub sequence: u64,
    pub attempt: u32,
    pub at: MonotonicTime,
    pub phase: ProgressPhase,
    /// Bytes the scope grants.
    pub scope_bytes: u64,
    /// Granted bytes found verified at the start of the attempt, and reused.
    pub verified_bytes: u64,
    /// Bytes delivered in this attempt.
    pub delivered_bytes: u64,
    /// Bytes charged to the budget over all attempts.
    pub used_bytes: u64,
    pub budget_bytes: u64,
    pub origin: ByteOrigin,
    /// The objects this event changes: the delivered chunk's object, or every object of
    /// the scope when the transfer as a whole moves on.
    pub objects: Vec<ObjectProgress>,
}

/// Progress port (CORE-06 events, T10).
pub trait ProgressPort: Send + Sync {
    /// Takes one event. It must not block: progress is its own bounded stream that may
    /// drop events under pressure, and no transfer decision waits for it (CORE-06,
    /// INT-10). The session checks authority before it emits.
    fn emit(&self, event: TransferProgress);
}

/// The clock and the four ports a transfer gate uses.
#[derive(Clone)]
pub struct TransferPorts {
    pub clock: Arc<dyn Clock>,
    /// The session of `clock`. Envelopes and parent authority stamped on another session,
    /// such as before a restart, are refused rather than compared.
    pub clock_session: ClockSession,
    pub authority: Arc<dyn AuthorityPort>,
    pub budget: Arc<dyn ByteBudgetPort>,
    pub extents: Arc<dyn VerifiedExtentsPort>,
    pub progress: Arc<dyn ProgressPort>,
}

impl fmt::Debug for TransferPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferPorts")
            .field("now", &self.clock.now())
            .finish_non_exhaustive()
    }
}
