//! The backend's adapter limits from CORE-01 evidence, and the attachments waiting under
//! them (G06 of docs/combined-plan-leftover-tasks.md: "a CORE-01 capability for adapter
//! limits" and "a FIFO for waiting attaches"; GPU-W10 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, lines 1305 and 1307; GPU §3.9).
//!
//! What the pinned backend accepts for unmerged adapters, the largest rank, the most
//! adapters resident at once and their bytes together, is CORE-01 `AdapterLimits` evidence
//! about the exact runtime: fresh, at least a live report from it, observed under the
//! configuration in force and naming the runtime's own backend release, by CORE-01's own
//! rules. Without it no unmerged adapter is attached ([`evidenced_adapter_limits`] refuses
//! with CORE-01's refusal and its remedy). Limits taken from evidence serve new
//! attachments only while the evidence is fresh ([`super::AttachRefusal::LimitsNotCurrent`]);
//! adapters already attached keep serving.
//!
//! An attachment that must wait for a slot or bytes keeps its place first in, first out
//! ([`crate::model_memory::boundaries::WaitQueue`], by adapter identity): a later one is
//! attached only from what every attachment waiting ahead of it leaves.

use std::fmt;
use std::time::Duration;

use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, ProbeRegistry, Remedy,
    Requirement, RuntimeSubject, SourceClass, Subject, SupportDetail, UnknownReason,
};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::model_memory::adapters::adapter::AdapterLimits;
use crate::model_memory::boundaries::{WaitLimits, Waiter};
use crate::model_memory::identity::AdapterIdentity;

use super::{ActiveAdapters, ActiveBase, AttachRefusal, BackendAdapterLimits};

/// The backend's adapter limits as fresh CORE-01 evidence shows them. Made only by
/// [`evidenced_adapter_limits`], so limits are never assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidencedAdapterLimits {
    limits: BackendAdapterLimits,
    fresh_until: MonotonicTime,
    source: SourceClass,
}

impl EvidencedAdapterLimits {
    pub fn limits(&self) -> BackendAdapterLimits {
        self.limits
    }

    /// The last moment, on the registry's clock, at which the evidence may be relied on.
    pub fn fresh_until(&self) -> MonotonicTime {
        self.fresh_until
    }

    /// Where the evidence came from.
    pub fn source(&self) -> SourceClass {
        self.source
    }
}

/// Why no adapter limits could be taken from evidence: no unmerged adapter is attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterLimitsRefusal {
    /// CORE-01 refused: the evidence is missing, too weak, from another configuration,
    /// stale, inconclusive, or says the backend serves no unmerged adapters.
    Evidence(EvidenceRefusal),
}

impl AdapterLimitsRefusal {
    /// What the user can do, as CORE-01 names it.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::Evidence(refusal) => refusal.remedy(),
        }
    }
}

impl fmt::Display for AdapterLimitsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(refusal) => {
                write!(
                    f,
                    "the backend's adapter limits are not evidenced: {refusal}"
                )
            }
        }
    }
}

impl std::error::Error for AdapterLimitsRefusal {}

/// The adapter limits CORE-01 shows for `runtime` under `configuration`, judged by
/// `policy`, or why there are none.
pub fn evidenced_adapter_limits<C: Clock>(
    registry: &ProbeRegistry<C>,
    runtime: &RuntimeSubject,
    configuration: ConfigurationFingerprint,
    policy: EvidencePolicy,
) -> Result<EvidencedAdapterLimits, AdapterLimitsRefusal> {
    let satisfied = registry
        .evaluate(&Requirement::new(
            Capability::AdapterLimits,
            Subject::Runtime(runtime.clone()),
            policy.minimum_source,
            policy.max_age,
            configuration,
        ))
        .map_err(AdapterLimitsRefusal::Evidence)?;
    match satisfied.detail() {
        SupportDetail::AdapterLimits {
            max_rank,
            max_resident,
            max_bytes,
            ..
        } => Ok(EvidencedAdapterLimits {
            limits: BackendAdapterLimits {
                rank: AdapterLimits {
                    max_rank: max_rank.get(),
                },
                max_resident: max_resident.get(),
                max_bytes: max_bytes.get(),
            },
            fresh_until: satisfied.fresh_until(),
            source: satisfied.source(),
        }),
        // CORE-01 records a detail that does not fit its capability as unknown.
        _ => Err(AdapterLimitsRefusal::Evidence(EvidenceRefusal::Unknown {
            capability: Capability::AdapterLimits,
            reason: UnknownReason::InconsistentReport,
        })),
    }
}

impl ActiveAdapters {
    /// No adapter attached to `base` yet, with the backend's limits from CORE-01 evidence;
    /// new attachments need them fresh. `drain_bound` is as for [`ActiveAdapters::new`].
    pub fn with_evidenced_limits(
        base: ActiveBase,
        limits: EvidencedAdapterLimits,
        drain_bound: Duration,
    ) -> Self {
        let mut adapters = Self::new(base, limits.limits, drain_bound);
        adapters.limits_until = Some(limits.fresh_until);
        adapters
    }

    /// Fresh evidence of the backend's limits: they apply to attachments from now on.
    /// Adapters already resident stay; while they exceed new, smaller limits, attachments
    /// wait.
    pub fn renew_limits(&mut self, limits: EvidencedAdapterLimits) {
        self.limits = limits.limits;
        self.limits_until = Some(limits.fresh_until);
    }

    /// Until when the evidence of the limits may be relied on; `None` for declared limits.
    pub fn limits_fresh_until(&self) -> Option<MonotonicTime> {
        self.limits_until
    }

    /// Refuses new attachments once the evidence of the limits is no longer fresh.
    pub(super) fn limits_current(&self, now: MonotonicTime) -> Result<(), AttachRefusal> {
        match self.limits_until {
            Some(fresh_until) if now > fresh_until => {
                Err(AttachRefusal::LimitsNotCurrent { fresh_until })
            }
            _ => Ok(()),
        }
    }

    /// The attachments waiting for a slot or bytes, first in line first: the order in
    /// which to retry them once an adapter is released. Places that expired by `now` are
    /// dropped.
    pub fn attach_waiters(&mut self, now: MonotonicTime) -> Vec<Waiter<AdapterIdentity>> {
        self.attach_waits.expire(now);
        self.attach_waits.waiters().cloned().collect()
    }

    /// An attachment waiting for `adapter` gives up its place. Returns whether it waited.
    pub fn withdraw_attach(&mut self, adapter: &AdapterIdentity) -> bool {
        self.attach_waits.leave(adapter).is_some()
    }

    /// How many attachments may wait and for how long each keeps its place.
    pub fn set_attach_wait_limits(&mut self, limits: WaitLimits) {
        self.attach_waits.set_limits(limits);
    }
}
