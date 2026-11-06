//! CORE-05: the authenticated transfer/session envelope
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2, S3.1, S3.7, INT-02, INT-08).
//!
//! A [`TransferEnvelope`] binds one transfer to its object and range scope, direction,
//! typed source and recipient, credential handle, parent execution and authorization
//! epoch, byte budget, stop bounds and expiry, with the clock session the expiry is read
//! on (CORE-01), so an envelope from before a restart is refused rather than compared.
//! The issuer seals it with HMAC-SHA256 ([`TransferKey::seal`]). A [`TransferGate`]
//! verifies the seal and opens a
//! [`TransferSession`], which admits chunk by chunk only what the envelope allows and
//! keeps every bound across retries, reusing verified extents instead of widening the
//! grant. Revoked or expired transfers stop within the envelope's [`StopBounds`].
//!
//! Endpoints are typed objects: there is no URL authority and no generic proxy. Model
//! downloads and private-weight uploads carry their own byte budgets, and nothing here
//! touches the VM-D12 [`GeneralReleaseBudget`].
//!
//! Every active transfer, in every direction, may also hold one network slot in the
//! CORE-03 ledger (S10 line 179) through [`LedgerByteBudget::holding_network_slot`]:
//! reserved with its bytes as one all-or-nothing request when the session opens, held
//! until its terminal phase or until a continuation takes over, and refused with an
//! actionable [`NetworkSlotRefusal`] when none is free.
//!
//! The modules this one needs that are still being written are reached through ports:
//! [`AuthorityPort`] (CORE-04, T09), [`ByteBudgetPort`] (CORE-03, T04),
//! [`VerifiedExtentsPort`] (CORE-02, T05) and [`ProgressPort`] (CORE-06, T10).

mod catalog_extents;
mod coordinator_authority;
mod endpoint;
mod envelope;
mod event_progress;
mod hmac;
mod ledger_budget;
mod ports;
mod range;
mod refusal;
mod release;
mod scope;
mod session;
mod status;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod tests;

pub use catalog_extents::CatalogExtents;
pub use coordinator_authority::{parent_status_in, CoordinatorAuthority};
pub use endpoint::{Connection, CredentialRef, Direction, Endpoint, EndpointError};
pub use envelope::{
    EnvelopeError, EnvelopeFields, KeyError, SealedEnvelope, StopBounds, Tampered,
    TransferEnvelope, TransferKey, TransferSchemaVersion, UnsupportedTransferSchema,
    ENVELOPE_DIGEST_DOMAIN, TRANSFER_SCHEMA_VERSION,
};
pub use event_progress::EventProgress;
pub use hmac::{hmac_sha256, tags_equal, HMAC_SHA256_TAG_BYTES};
pub use ledger_budget::{LedgerByteBudget, NotCountedInBytes, NETWORK_SLOT_RESOURCE};
pub use ports::{
    AuthorityPort, ByteBudgetPort, ByteBudgetRefusal, ByteOrigin, ByteReservation,
    ByteReservationRequest, NetworkSlotRefusal, ObjectProgress, ParentAuthority, ParentStatus,
    ProgressPhase, ProgressPort, ReservationRefusal, ReservationWithdrawn, SlotLimit,
    TransferPorts, TransferProgress, VerifiedExtentsPort,
};
pub use range::{ByteRange, RangeError, RangeSet};
pub use refusal::{RetryViolation, TransferRefusal};
pub use release::{
    GeneralReleaseBudget, ReleaseBudgetExceeded, VM_D12_GENERAL_RELEASE_BUDGET_BYTES,
};
pub use scope::{ObjectGrant, ScopeError, TransferScope};
pub use session::{
    continuation_operation, ChunkPermit, TransferGate, TransferSession, CONTINUATION_DOMAIN,
};
pub use status::{StopReason, StopRecord, TransferStatus};
