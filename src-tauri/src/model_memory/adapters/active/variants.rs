//! Device memory of merged variants materialized on the activation (G06 of
//! docs/combined-plan-leftover-tasks.md: "variant memory accounting"; GPU-W10 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1307: "independently materialized
//! merged variants"; GPU §3.9: a merged variant is a separate copy, never the shared base
//! changed in place; GPU §2.7: every byte counted).
//!
//! A merged variant is its own weights. One the runner materializes beside the base on
//! this activation ([`ActiveAdapters::materialize_variant`]) is recorded as
//! [`ActiveAdapters::record_variant`] records it, and its bytes are carved as a CORE-03
//! child of the activation's reservation, in use at once, as an adapter's are; the ledger
//! refuses one past that reservation and names the limit. A variant that runs as its own
//! activation is recorded without memory here, its memory being that activation's.
//!
//! The variant's memory is released through the ledger
//! ([`ActiveAdapters::release_variant`]) only once it serves no new request, because the
//! runner retired it ([`ActiveAdapters::retire_variant`]), a revocation invalidated it or
//! the activation's authority was revoked, and no request in flight may still use it, and
//! only on the runner's own report that it unloaded it, or a stronger source.

use std::fmt;

use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{GrantId, LeaseId, MonotonicTime, OperationId};
use crate::foundation::ledger::{LedgerError, ReleaseOutcome, ReservationId};
use crate::model_memory::identity::ExecutionIdentity;

use super::{
    carve, ActiveAdapters, AdapterHost, AttachRefusal, Drain, MergedVariant, Route, VariantRefusal,
};

/// What materializing a variant produced: its reservation. Load the variant when
/// `newly_materialized`; otherwise it holds memory here already.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariantReceipt {
    pub variant: ExecutionIdentity,
    pub reservation: ReservationId,
    pub bytes: u64,
    pub newly_materialized: bool,
}

/// One recorded merged variant as the registry holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariantView {
    /// Its CORE-03 child of the activation's reservation, when materialized here.
    pub reservation: Option<ReservationId>,
    /// The device bytes it holds here; zero when its memory is held elsewhere.
    pub bytes: u64,
    /// The revoked grant that invalidated it.
    pub invalidated: Option<GrantId>,
    /// Retired by the runner.
    pub retired: bool,
    /// Requests still in flight on it.
    pub in_flight: usize,
}

/// Why a variant's memory was not released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantReleaseRefusal {
    NotRecorded {
        variant: ExecutionIdentity,
    },
    /// It holds no memory here.
    NoMemory {
        variant: ExecutionIdentity,
    },
    /// It still serves new requests; retire it first.
    StillServing {
        variant: ExecutionIdentity,
    },
    /// Requests may still use it; they end by their drain bounds.
    StillInUse {
        variant: ExecutionIdentity,
        leases: Vec<LeaseId>,
    },
    /// The ledger refused the release, as for a source without authority over it; the
    /// reservation still counts.
    Ledger(LedgerError),
}

impl fmt::Display for VariantReleaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRecorded { variant } => write!(f, "merged variant {variant} is not recorded"),
            Self::NoMemory { variant } => {
                write!(f, "merged variant {variant} holds no memory here")
            }
            Self::StillServing { variant } => {
                write!(f, "merged variant {variant} still serves; retire it first")
            }
            Self::StillInUse { variant, leases } => write!(
                f,
                "merged variant {variant} is still used by {} requests",
                leases.len()
            ),
            Self::Ledger(error) => write!(f, "the ledger kept the variant's memory: {error}"),
        }
    }
}

impl std::error::Error for VariantReleaseRefusal {}

impl ActiveAdapters {
    /// Records a merged variant the runner materialized on this activation and carves its
    /// `bytes` of device memory as a CORE-03 child of the activation's reservation, in use
    /// at once (GPU §3.9). The variant is checked as [`ActiveAdapters::record_variant`]
    /// checks it, with the authority asked through `host`. A variant that already holds
    /// memory here is returned as it is; one retired or invalidated is refused. A refusal
    /// reserves nothing and leaves a variant this call recorded unrecorded again.
    pub fn materialize_variant<H: AdapterHost>(
        &mut self,
        host: &mut H,
        variant: MergedVariant,
        bytes: u64,
        operation: &OperationId,
    ) -> Result<VariantReceipt, VariantRefusal> {
        let known = variant
            .execution
            .identity()
            .is_ok_and(|identity| self.variants.contains_key(&identity));
        let identity = self.record_variant(variant, &*host)?;
        let forget = |adapters: &mut Self| {
            if !known {
                adapters.variants.remove(&identity);
            }
        };
        let Some(entry) = self.variants.get(&identity) else {
            return Err(VariantRefusal::NotRecorded { variant: identity });
        };
        if entry.invalidated.is_some() || entry.retired {
            return Err(VariantRefusal::Ended { variant: identity });
        }
        if let Some((reservation, held)) = entry.memory {
            return Ok(VariantReceipt {
                variant: identity,
                reservation,
                bytes: held,
                newly_materialized: false,
            });
        }
        if bytes == 0 {
            forget(self);
            return Err(VariantRefusal::NoBytes);
        }
        let (parent, device) = (self.base.reservation, self.base.device);
        let carved = host
            .write_ledger(|ledger| carve(ledger, parent, device, operation, bytes))
            .map_err(|refusal| match refusal {
                AttachRefusal::Ledger { refusal } => VariantRefusal::Ledger { refusal },
                _ => VariantRefusal::NoReservation,
            });
        let reservation = match carved {
            Ok(reservation) => reservation,
            Err(refusal) => {
                forget(self);
                return Err(refusal);
            }
        };
        if let Some(entry) = self.variants.get_mut(&identity) {
            entry.memory = Some((reservation, bytes));
        }
        Ok(VariantReceipt {
            variant: identity,
            reservation,
            bytes,
            newly_materialized: true,
        })
    }

    /// Retires a recorded variant for new requests, as to free its memory. Requests in
    /// flight on it may run until `now` plus the drain bound; once none remains, a variant
    /// holding memory here is listed to unload.
    pub fn retire_variant(
        &mut self,
        variant: ExecutionIdentity,
        now: MonotonicTime,
    ) -> Result<Drain, VariantRefusal> {
        let entry = self
            .variants
            .get_mut(&variant)
            .ok_or(VariantRefusal::NotRecorded { variant })?;
        if entry.retired || entry.invalidated.is_some() {
            return Err(VariantRefusal::Ended { variant });
        }
        entry.retired = true;
        let bound = now.saturating_add(self.drain_bound);
        let draining = self.bound_requests(Route::Merged(variant), None, |_| bound);
        let unload_variants = if self.variant_unloadable(&variant) {
            vec![variant]
        } else {
            Vec::new()
        };
        Ok(Drain {
            draining,
            unload: Vec::new(),
            unload_variants,
        })
    }

    /// Releases a variant's memory through the ledger once the runner unloaded it, as
    /// `source` observed: its own report suffices for a child reservation (CORE-03).
    /// Refused while the variant serves new requests or a request may still use it, so
    /// memory is never released under a request (GPU §3.6 step 7). The variant's record
    /// ends with its memory. A ledger refusal keeps it counted; call again with an
    /// authoritative source.
    pub fn release_variant<H: AdapterHost>(
        &mut self,
        host: &mut H,
        variant: ExecutionIdentity,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, VariantReleaseRefusal> {
        let entry = self
            .variants
            .get(&variant)
            .ok_or(VariantReleaseRefusal::NotRecorded { variant })?;
        let (reservation, _) = entry
            .memory
            .ok_or(VariantReleaseRefusal::NoMemory { variant })?;
        if !self.variant_ended(&variant) {
            return Err(VariantReleaseRefusal::StillServing { variant });
        }
        let leases = self.leases_on(Route::Merged(variant));
        if !leases.is_empty() {
            return Err(VariantReleaseRefusal::StillInUse { variant, leases });
        }
        let outcome = host
            .write_ledger(|ledger| match ledger.cancel(reservation) {
                Ok(ReleaseOutcome::Pending) => ledger.confirm_release(reservation, source),
                other => other,
            })
            .map_err(VariantReleaseRefusal::Ledger)?;
        self.variants.remove(&variant);
        Ok(outcome)
    }

    /// One recorded variant, if it is recorded.
    pub fn variant(&self, variant: &ExecutionIdentity) -> Option<VariantView> {
        let entry = self.variants.get(variant)?;
        Some(VariantView {
            reservation: entry.memory.map(|(reservation, _)| reservation),
            bytes: entry.memory.map_or(0, |(_, bytes)| bytes),
            invalidated: entry.invalidated,
            retired: entry.retired,
            in_flight: self.leases_on(Route::Merged(*variant)).len(),
        })
    }

    /// The device bytes the variants materialized here hold.
    pub fn variant_bytes(&self) -> u64 {
        self.variants
            .values()
            .filter_map(|entry| entry.memory.map(|(_, bytes)| bytes))
            .fold(0u64, u64::saturating_add)
    }

    /// The variants holding memory here that serve no new request and that nothing uses
    /// any more: unload each, then call [`ActiveAdapters::release_variant`].
    pub fn unloadable_variants(&self) -> Vec<ExecutionIdentity> {
        self.variants
            .keys()
            .filter(|variant| self.variant_unloadable(variant))
            .copied()
            .collect()
    }

    /// Whether `variant` serves no new request: retired, invalidated, or the activation's
    /// authority was revoked.
    fn variant_ended(&self, variant: &ExecutionIdentity) -> bool {
        self.authority_revoked.is_some()
            || self
                .variants
                .get(variant)
                .is_some_and(|entry| entry.retired || entry.invalidated.is_some())
    }

    /// Whether `variant` holds memory here, has ended and no request is in flight on it.
    pub(super) fn variant_unloadable(&self, variant: &ExecutionIdentity) -> bool {
        self.variants
            .get(variant)
            .is_some_and(|entry| entry.memory.is_some())
            && self.variant_ended(variant)
            && self.leases_on(Route::Merged(*variant)).is_empty()
    }
}
