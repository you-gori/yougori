//! Rate-bounded emission (VM part §8.2 line 2270: "Bound attacker-controlled log fields and
//! emission rate"; VM-W43 line 2491).
//!
//! A flood of signals must not become a flood of notifications, responses or audit
//! records. [`EmissionGate`] counts emissions in fixed windows of a CORE-06
//! [`EmissionLimit`] on the host clock, the rule CORE-06 applies to guest observations, and
//! counts what it holds back so the next emission can summarize it. Revocations never pass
//! through a gate: the revocation channel is never blocked.

use std::time::Duration;

use super::signal::MonitoringSignal;
use crate::foundation::events::{
    AuditAppendAuthority, AuditJournal, AuditReceipt, AuditRefusal, AuditSpool, AuditStore,
    EmissionLimit, EventContext, Phase, RateLimiter,
};
use crate::foundation::ids::{Clock, MonotonicTime, OperationId};

/// At most `limit.max_events()` emissions per `limit.window()`, in fixed windows that start
/// at the first emission after the previous window ended: CORE-06's [`RateLimiter`] rule,
/// plus a count of what it held back.
#[derive(Clone, Copy, Debug)]
pub struct EmissionGate {
    limit: EmissionLimit,
    limiter: RateLimiter,
    held_back: u64,
}

impl EmissionGate {
    /// A gate that has admitted nothing yet.
    pub fn new(limit: EmissionLimit) -> Self {
        Self {
            limit,
            limiter: RateLimiter::new(limit),
            held_back: 0,
        }
    }

    /// The CORE-06 limit the gate applies.
    pub const fn limit(&self) -> EmissionLimit {
        self.limit
    }

    /// Admits one emission at `now`, or holds it back, counts it and says how long until
    /// the window ends.
    pub fn admit(&mut self, now: MonotonicTime) -> Result<(), Duration> {
        self.limiter.admit(now).inspect_err(|_| {
            self.held_back = self.held_back.saturating_add(1);
        })
    }

    /// Emissions held back since the count was last taken.
    pub const fn held_back(&self) -> u64 {
        self.held_back
    }

    /// Takes the held-back count, for the summary in the next emission.
    pub fn take_held_back(&mut self) -> u64 {
        std::mem::take(&mut self.held_back)
    }
}

/// What happened to one signal's audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalAudit {
    Recorded(AuditReceipt),
    /// The gate held the record back; `held_back` counts every record it held back so far.
    HeldBack {
        retry_after: Duration,
        held_back: u64,
    },
    /// The journal refused it (CORE-06 fails closed when storage and spool refuse).
    Refused(AuditRefusal),
}

/// Records one monitoring signal in the CORE-06 journal through `gate`: a host-observed
/// signal as a [`HostFact::DetectionSignal`](crate::foundation::events::HostFact), a
/// guest-reported one as a guest observation, which the journal also bounds by its own
/// limit.
pub fn record_signal<S: AuditStore, Q: AuditSpool, J: Clock>(
    journal: &mut AuditJournal<S, Q, J>,
    authority: &mut AuditAppendAuthority,
    gate: &mut EmissionGate,
    signal: &MonitoringSignal,
    operation: OperationId,
    clock: &dyn Clock,
) -> SignalAudit {
    if let Err(retry_after) = gate.admit(clock.now()) {
        return SignalAudit::HeldBack {
            retry_after,
            held_back: gate.held_back(),
        };
    }
    match journal.append(
        authority,
        EventContext::new(operation, Phase::Running),
        signal.audit_draft(),
    ) {
        Ok(receipt) => SignalAudit::Recorded(receipt),
        Err(refusal) => SignalAudit::Refused(refusal),
    }
}
