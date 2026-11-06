//! Why [`super::ActiveAdapters`] refused an operation, with the identities and amounts a
//! caller needs to act on it.

use std::fmt;

use crate::foundation::coordination::LeaseRefusal;
use crate::foundation::ids::{AuthorizationEpoch, GrantId, LeaseId, MonotonicTime};
use crate::foundation::ledger::LedgerError;
use crate::model_memory::boundaries::CapacityRefusal;
use crate::model_memory::identity::{
    AdapterIdentity, ExecutionIdentity, GrantRefusal, IdentityError, LogicalModelIdentity,
    LoraRefusal,
};

use super::{DetachCause, Input, Route};
use crate::model_memory::adapters::adapter::AdapterRefusal;
use crate::model_memory::adapters::kv::KvReuseRefusal;

/// Why an adapter was not attached.
#[derive(Clone, Debug, PartialEq)]
pub enum AttachRefusal {
    /// The coordination authority revoked the adapter's grant under the activation's
    /// authority; it is never attached there again.
    Revoked { grant: GrantId },
    /// The caller holds no grant to serve the adapter's artifact.
    Unauthorized(GrantRefusal),
    /// P07's compatibility check refused it against the base.
    Incompatible(AdapterRefusal),
    /// Its previous attachment is still detaching; attach it again once it is released.
    StillDetaching { adapter: AdapterIdentity },
    /// The runner declared no bytes for it.
    NoBytes,
    /// It alone needs more than the backend's limits allow: refused.
    ExceedsLimits {
        requested_bytes: u64,
        max_bytes: u64,
        max_resident: u32,
    },
    /// It fits the limits once other adapters are released: it keeps its place among the
    /// waiting attachments; detach one and retry then.
    AwaitingRelease {
        requested_bytes: u64,
        free_bytes: u64,
        free_slots: u32,
    },
    /// It fits what is free, but attachments waiting ahead of it claim that: it keeps its
    /// place behind them (first in, first out); retry once they are attached.
    QueuedBehind {
        requested_bytes: u64,
        free_bytes: u64,
        free_slots: u32,
        ahead: u32,
    },
    /// It would wait, but `waiting` attachments already wait, the most the queue holds.
    WaitQueueFull { waiting: u32 },
    /// The CORE-01 evidence of the backend's limits is no longer fresh: renew it
    /// ([`super::ActiveAdapters::renew_limits`]) before attaching anything more.
    LimitsNotCurrent { fresh_until: MonotonicTime },
    /// The activation's whole authority was revoked at `epoch`; nothing is attached here
    /// again.
    AuthorityRevoked { epoch: AuthorizationEpoch },
    /// The ledger refused its reservation; this names the limiting resource, such as the
    /// activation's own reservation.
    Ledger { refusal: CapacityRefusal },
    /// The activation's reservation is not open and in use, so nothing can be carved
    /// from it.
    NoReservation,
}

impl fmt::Display for AttachRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked { grant } => write!(f, "the adapter's grant {grant} was revoked"),
            Self::Unauthorized(refusal) => write!(f, "the adapter is not authorized: {refusal}"),
            Self::Incompatible(refusal) => write!(f, "the adapter is incompatible: {refusal}"),
            Self::StillDetaching { adapter } => {
                write!(f, "adapter {adapter} is still being detached")
            }
            Self::NoBytes => f.write_str("the adapter declares no device bytes"),
            Self::ExceedsLimits {
                requested_bytes,
                max_bytes,
                max_resident,
            } => write!(
                f,
                "the adapter needs {requested_bytes} bytes; the backend holds at most \
                 {max_resident} adapters in {max_bytes} bytes"
            ),
            Self::AwaitingRelease {
                requested_bytes,
                free_bytes,
                free_slots,
            } => write!(
                f,
                "the adapter needs {requested_bytes} bytes and a slot; {free_bytes} bytes and \
                 {free_slots} slots are free, so it waits until another adapter is released"
            ),
            Self::QueuedBehind {
                requested_bytes,
                free_bytes,
                free_slots,
                ahead,
            } => write!(
                f,
                "the adapter needs {requested_bytes} bytes and a slot; {free_bytes} bytes and \
                 {free_slots} slots are free, but {ahead} attachments waiting ahead of it \
                 claim them, so it waits its turn"
            ),
            Self::WaitQueueFull { waiting } => write!(
                f,
                "the adapter would wait, but {waiting} attachments already wait, the most the \
                 queue holds"
            ),
            Self::LimitsNotCurrent { fresh_until } => write!(
                f,
                "the evidence of the backend's adapter limits was fresh until {} ns; observe \
                 it again",
                fresh_until.as_nanos()
            ),
            Self::AuthorityRevoked { epoch } => {
                write!(f, "the activation's authority was revoked at epoch {epoch}")
            }
            Self::Ledger { refusal } => write!(f, "the adapter cannot be reserved: {refusal}"),
            Self::NoReservation => {
                f.write_str("the activation's reservation cannot be carved from")
            }
        }
    }
}

impl std::error::Error for AttachRefusal {}

/// Why an adapter was not detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachRefusal {
    NotAttached {
        adapter: AdapterIdentity,
    },
    AlreadyDetached {
        adapter: AdapterIdentity,
        cause: DetachCause,
    },
}

impl fmt::Display for DetachRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAttached { adapter } => write!(f, "adapter {adapter} is not attached"),
            Self::AlreadyDetached { adapter, cause } => {
                write!(f, "adapter {adapter} is already detached: {cause}")
            }
        }
    }
}

impl std::error::Error for DetachRefusal {}

/// Why a request may not be served on a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteRefusal {
    /// A request already holds this lease.
    LeaseInUse {
        lease: LeaseId,
    },
    /// The adapter's grant was revoked under the activation's authority.
    Revoked {
        grant: GrantId,
    },
    NotAttached {
        adapter: AdapterIdentity,
    },
    /// The adapter was detached; it serves no new request.
    Detaching {
        adapter: AdapterIdentity,
    },
    UnknownVariant {
        variant: ExecutionIdentity,
    },
    /// An input's grant was revoked, so the variant serves no one.
    VariantInvalidated {
        variant: ExecutionIdentity,
        grant: GrantId,
    },
    /// The caller holds no grant to serve this input.
    Unauthorized {
        input: Input,
        refusal: GrantRefusal,
    },
    /// The activation's whole authority was revoked at `epoch`; nothing is served here
    /// again.
    AuthorityRevoked {
        epoch: AuthorizationEpoch,
    },
    /// The runner retired the variant; it serves no new request.
    VariantRetired {
        variant: ExecutionIdentity,
    },
    /// The coordinator did not bind the request's lease to the grants of what it is served
    /// with, so the request is not admitted.
    LeaseNotBound {
        refusal: LeaseRefusal,
    },
}

impl fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseInUse { lease } => write!(f, "lease {lease} already holds a request"),
            Self::Revoked { grant } => write!(f, "the adapter's grant {grant} was revoked"),
            Self::NotAttached { adapter } => write!(f, "adapter {adapter} is not attached"),
            Self::Detaching { adapter } => {
                write!(
                    f,
                    "adapter {adapter} was detached and serves no new request"
                )
            }
            Self::UnknownVariant { variant } => {
                write!(f, "merged variant {variant} is not recorded")
            }
            Self::VariantInvalidated { variant, grant } => write!(
                f,
                "merged variant {variant} serves no one: the grant {grant} of an input was revoked"
            ),
            Self::Unauthorized { input, refusal } => {
                write!(f, "the caller may not be served {input}: {refusal}")
            }
            Self::AuthorityRevoked { epoch } => {
                write!(f, "the activation's authority was revoked at epoch {epoch}")
            }
            Self::VariantRetired { variant } => {
                write!(
                    f,
                    "merged variant {variant} was retired and serves no new request"
                )
            }
            Self::LeaseNotBound { refusal } => write!(
                f,
                "the request's lease was not bound to the grants it is served with: {refusal}"
            ),
        }
    }
}

impl std::error::Error for RouteRefusal {}

/// Why a request in flight may not go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestRefusal {
    /// No request holds this lease on this route; it ended, or was never admitted.
    UnknownRequest { lease: LeaseId },
    /// Its route was detached or revoked and its drain bound passed: it must have stopped.
    DrainBoundPassed {
        lease: LeaseId,
        bound_at: MonotonicTime,
    },
}

impl fmt::Display for RequestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRequest { lease } => {
                write!(f, "no request holds lease {lease} on this route")
            }
            Self::DrainBoundPassed { lease, bound_at } => write!(
                f,
                "the request under lease {lease} had to stop by {} ns",
                bound_at.as_nanos()
            ),
        }
    }
}

impl std::error::Error for RequestRefusal {}

/// Why an adapter's reservation was not released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    NotAttached {
        adapter: AdapterIdentity,
    },
    /// It still serves new requests; detach it first.
    StillAttached {
        adapter: AdapterIdentity,
    },
    /// Requests may still use it; they end by their drain bounds.
    StillInUse {
        adapter: AdapterIdentity,
        leases: Vec<LeaseId>,
    },
    /// The ledger refused the release, as for a source without authority over it; the
    /// reservation still counts.
    Ledger(LedgerError),
}

impl fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAttached { adapter } => write!(f, "adapter {adapter} is not attached"),
            Self::StillAttached { adapter } => {
                write!(f, "adapter {adapter} still serves; detach it first")
            }
            Self::StillInUse { adapter, leases } => write!(
                f,
                "adapter {adapter} is still used by {} requests",
                leases.len()
            ),
            Self::Ledger(error) => write!(f, "the ledger kept the adapter's memory: {error}"),
        }
    }
}

impl std::error::Error for ReleaseRefusal {}

/// Why a session's adapter was not switched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwitchRefusal {
    /// The session runs another model than this activation's base, such as a merged
    /// variant.
    OtherBase,
    /// The target adapter does not serve new requests.
    Route(RouteRefusal),
    /// T07 refused the change.
    Lora(LoraRefusal),
}

impl fmt::Display for SwitchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherBase => f.write_str("the session does not run this activation's base"),
            Self::Route(refusal) => refusal.fmt(f),
            Self::Lora(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for SwitchRefusal {}

/// Why a merged variant was not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantRefusal {
    /// The spec merges no adapter.
    NotMerged,
    /// It was merged into another base than this activation's.
    OtherBase { base: LogicalModelIdentity },
    /// Its execution spec has no identity.
    Execution(IdentityError),
    /// Its execution spec executes another logical model.
    ExecutesAnotherModel,
    /// A merged adapter has no input listed, so its owner's grant could not be required.
    MissingInput { adapter: AdapterIdentity },
    /// An input is listed for an adapter the variant does not merge.
    UnknownInput { adapter: AdapterIdentity },
    /// An input's grant was revoked under the activation's authority.
    InputRevoked {
        adapter: AdapterIdentity,
        grant: GrantId,
    },
    /// The activation's whole authority was revoked at `epoch`.
    AuthorityRevoked { epoch: AuthorizationEpoch },
    /// No variant of this identity is recorded here.
    NotRecorded { variant: ExecutionIdentity },
    /// The variant was retired or invalidated: it holds no new memory and serves no new
    /// request.
    Ended { variant: ExecutionIdentity },
    /// The runner declared no device bytes for a variant it materialized.
    NoBytes,
    /// The ledger refused the variant's reservation; this names the limiting resource,
    /// such as the activation's own reservation.
    Ledger { refusal: CapacityRefusal },
    /// The activation's reservation is not open and in use, so nothing can be carved from
    /// it.
    NoReservation,
}

impl fmt::Display for VariantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMerged => f.write_str("the spec merges no adapter"),
            Self::OtherBase { base } => {
                write!(
                    f,
                    "the variant was merged into base {base}, not this activation's"
                )
            }
            Self::Execution(error) => write!(f, "the variant's execution spec: {error}"),
            Self::ExecutesAnotherModel => {
                f.write_str("the variant's execution spec executes another logical model")
            }
            Self::MissingInput { adapter } => {
                write!(f, "merged adapter {adapter} has no input listed")
            }
            Self::UnknownInput { adapter } => {
                write!(f, "adapter {adapter} is listed but not merged")
            }
            Self::InputRevoked { adapter, grant } => {
                write!(
                    f,
                    "the grant {grant} of merged adapter {adapter} was revoked"
                )
            }
            Self::AuthorityRevoked { epoch } => {
                write!(f, "the activation's authority was revoked at epoch {epoch}")
            }
            Self::NotRecorded { variant } => {
                write!(f, "merged variant {variant} is not recorded")
            }
            Self::Ended { variant } => {
                write!(f, "merged variant {variant} was retired or invalidated")
            }
            Self::NoBytes => f.write_str("the variant declares no device bytes"),
            Self::Ledger { refusal } => write!(f, "the variant cannot be reserved: {refusal}"),
            Self::NoReservation => {
                f.write_str("the activation's reservation cannot be carved from")
            }
        }
    }
}

impl std::error::Error for VariantRefusal {}

/// Why a KV state was not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvRecordRefusal {
    Request(RequestRefusal),
    Route(RouteRefusal),
    /// The state names another model or adapter than the request's route.
    NotProducedOnRoute,
}

impl fmt::Display for KvRecordRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(refusal) => refusal.fmt(f),
            Self::Route(refusal) => refusal.fmt(f),
            Self::NotProducedOnRoute => {
                f.write_str("the KV names another model or adapter than the request's route")
            }
        }
    }
}

impl std::error::Error for KvRecordRefusal {}

/// Why stored KV may not serve a request on its route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterKvRefusal {
    Request(RequestRefusal),
    Route(RouteRefusal),
    /// The KV request names another model or adapter than the route it was admitted on.
    RequestNotOnItsRoute,
    /// The state was never recorded, or a revocation invalidated it.
    NotRecorded,
    /// The state was produced under another adapter or variant (GPU §3.9 line 797).
    ProducedUnderAnother {
        produced: Route,
        serving: Route,
    },
    /// P07's reuse check refused.
    Reuse(KvReuseRefusal),
}

impl fmt::Display for AdapterKvRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(refusal) => refusal.fmt(f),
            Self::Route(refusal) => refusal.fmt(f),
            Self::RequestNotOnItsRoute => f.write_str(
                "the KV request names another model or adapter than the request's route",
            ),
            Self::NotRecorded => f.write_str("the KV is not recorded, or was invalidated"),
            Self::ProducedUnderAnother { produced, serving } => write!(
                f,
                "the KV was produced under {produced} and is never served under {serving}"
            ),
            Self::Reuse(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for AdapterKvRefusal {}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base => f.write_str("the base"),
            Self::Adapter(adapter) => write!(f, "adapter {adapter}"),
            Self::Merged(variant) => write!(f, "merged variant {variant}"),
        }
    }
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base => f.write_str("the base"),
            Self::Adapter(adapter) => write!(f, "adapter {adapter}"),
        }
    }
}

impl fmt::Display for DetachCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detached => f.write_str("detached by the runner"),
            Self::Revoked { grant } => write!(f, "its grant {grant} was revoked"),
            Self::AuthorityRevoked { epoch } => {
                write!(f, "the activation's authority was revoked at epoch {epoch}")
            }
        }
    }
}
