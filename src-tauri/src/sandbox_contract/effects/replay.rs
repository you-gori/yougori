//! Replay protection for capability nonces (VM part §6.3 line 2143; VM-W29; VM-P13).
//!
//! Nonces are scoped by issuer and sandbox ([`SandboxRef`]), issued in increasing order
//! and never reused: compaction removes records, never the counter. A consumed nonce is
//! recorded with its capability's expiry, clock session and authorization epoch, and the
//! guard is serializable so the record persists across restarts. Only a live capability
//! can be consumed: unexpired on this clock session and bound to the current epoch. That
//! is what makes compaction safe, because a record is removed only once every capability
//! that could carry it is expired (beyond the allowed clock uncertainty) or bound to an
//! epoch that is no longer current.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::canonical::entries;
use super::capability::Nonce;
use super::description::SandboxRef;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{AuthorizationEpoch, MonotonicTime};

/// What a consumed nonce was bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceRecord {
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
    pub epoch: AuthorizationEpoch,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeState {
    /// The next nonce to issue; it never decreases.
    next_nonce: u64,
    used: BTreeMap<Nonce, NonceRecord>,
}

/// What a compaction removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactionReport {
    pub removed: usize,
    pub kept: usize,
}

/// The persisted replay state of one issuer or enforcement point.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayGuard {
    #[serde(with = "entries")]
    scopes: BTreeMap<SandboxRef, ScopeState>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues the next nonce of `sandbox`'s scope.
    pub fn issue(&mut self, sandbox: &SandboxRef) -> Result<Nonce, ReplayRefusal> {
        let scope = self.scopes.entry(sandbox.clone()).or_default();
        let nonce = scope.next_nonce.max(1);
        scope.next_nonce = nonce.checked_add(1).ok_or(ReplayRefusal::NoncesExhausted)?;
        Ok(Nonce::new(nonce))
    }

    /// Consumes a nonce this guard issued.
    pub fn consume_issued(
        &mut self,
        sandbox: &SandboxRef,
        nonce: Nonce,
        record: NonceRecord,
        now: MonotonicTime,
        session: ClockSession,
        current_epoch: AuthorizationEpoch,
    ) -> Result<(), ReplayRefusal> {
        let issued = self
            .scopes
            .get(sandbox)
            .is_some_and(|scope| nonce.get() >= 1 && nonce.get() < scope.next_nonce);
        if !issued {
            return Err(ReplayRefusal::NeverIssued);
        }
        self.consume_presented(sandbox, nonce, record, now, session, current_epoch)
    }

    /// Consumes a nonce an issuer elsewhere issued, at an enforcement point.
    pub fn consume_presented(
        &mut self,
        sandbox: &SandboxRef,
        nonce: Nonce,
        record: NonceRecord,
        now: MonotonicTime,
        session: ClockSession,
        current_epoch: AuthorizationEpoch,
    ) -> Result<(), ReplayRefusal> {
        if record.clock != session {
            return Err(ReplayRefusal::OtherClock);
        }
        if now >= record.expires_at {
            return Err(ReplayRefusal::Expired);
        }
        if record.epoch != current_epoch {
            return Err(ReplayRefusal::StaleEpoch {
                bound: record.epoch,
                current: current_epoch,
            });
        }
        let scope = self.scopes.entry(sandbox.clone()).or_default();
        if scope.used.contains_key(&nonce) {
            return Err(ReplayRefusal::Replayed);
        }
        scope.used.insert(nonce, record);
        scope.next_nonce = scope.next_nonce.max(nonce.get().saturating_add(1));
        Ok(())
    }

    /// Whether `nonce` of `sandbox` was consumed and is still recorded.
    pub fn is_consumed(&self, sandbox: &SandboxRef, nonce: Nonce) -> bool {
        self.scopes
            .get(sandbox)
            .is_some_and(|scope| scope.used.contains_key(&nonce))
    }

    /// Recorded nonces over every scope.
    pub fn recorded(&self) -> usize {
        self.scopes.values().map(|scope| scope.used.len()).sum()
    }

    /// Removes records no live capability can carry: on `session` and expired by at least
    /// `allowed_clock_uncertainty`, or bound to an epoch older than the sandbox's current
    /// one. A record on another session with a current epoch is kept, since its expiry
    /// cannot be read.
    pub fn compact(
        &mut self,
        now: MonotonicTime,
        session: ClockSession,
        allowed_clock_uncertainty: Duration,
        current_epoch: impl Fn(&SandboxRef) -> Option<AuthorizationEpoch>,
    ) -> CompactionReport {
        let mut report = CompactionReport::default();
        for (sandbox, scope) in &mut self.scopes {
            let current = current_epoch(sandbox);
            scope.used.retain(|_, record| {
                let expired = record.clock == session
                    && record.expires_at.saturating_add(allowed_clock_uncertainty) <= now;
                let superseded = current.is_some_and(|epoch| record.epoch < epoch);
                let remove = expired || superseded;
                if remove {
                    report.removed += 1;
                } else {
                    report.kept += 1;
                }
                !remove
            });
        }
        report
    }
}

strict_tagged_enum! {
    /// Why a nonce was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ReplayRefusal (tag = "refusal", wire = ReplayRefusalWire, wire_name = "ReplayRefusalWire") {
        /// This issuer never issued the nonce for this sandbox.
        NeverIssued,
        Replayed,
        Expired,
        OtherClock,
        StaleEpoch { bound: AuthorizationEpoch, current: AuthorizationEpoch },
        NoncesExhausted,
    }
}

impl fmt::Display for ReplayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeverIssued => f.write_str("the nonce was never issued for this sandbox"),
            Self::Replayed => f.write_str("the nonce was already used"),
            Self::Expired => f.write_str("the capability carrying the nonce expired"),
            Self::OtherClock => f.write_str("the nonce's expiry is on another clock session"),
            Self::StaleEpoch { bound, current } => write!(
                f,
                "the nonce is bound to authorization epoch {bound}, and the sandbox is at \
                 {current}"
            ),
            Self::NoncesExhausted => f.write_str("no nonces are left for this sandbox"),
        }
    }
}

impl std::error::Error for ReplayRefusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ExecutionId};
    use crate::sandbox_contract::effects::description::IssuerId;

    fn sandbox(issuer: &str, execution: &str) -> SandboxRef {
        SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[issuer.as_bytes()])),
            execution: ExecutionId::new(execution).unwrap(),
        }
    }

    fn session(n: u128) -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(n))
    }

    fn record(expires: u64, epoch: u64) -> NonceRecord {
        NonceRecord {
            clock: session(1),
            expires_at: MonotonicTime::from_nanos(expires),
            epoch: AuthorizationEpoch::new(epoch),
        }
    }

    const NOW: MonotonicTime = MonotonicTime::from_nanos(10);

    #[test]
    fn nonces_are_scoped_by_issuer_and_sandbox_and_used_once() {
        let mut guard = ReplayGuard::new();
        let a = sandbox("host-1", "exe-a");
        let first = guard.issue(&a).unwrap();
        assert_eq!(first, Nonce::new(1));
        let epoch = AuthorizationEpoch::new(1);
        guard
            .consume_issued(&a, first, record(100, 1), NOW, session(1), epoch)
            .unwrap();
        assert_eq!(
            guard.consume_issued(&a, first, record(100, 1), NOW, session(1), epoch),
            Err(ReplayRefusal::Replayed)
        );
        // The same number in another sandbox or under another issuer is another nonce,
        // and one this issuer never issued there is refused.
        for other in [sandbox("host-1", "exe-b"), sandbox("host-2", "exe-a")] {
            assert_eq!(
                guard.consume_issued(&other, first, record(100, 1), NOW, session(1), epoch),
                Err(ReplayRefusal::NeverIssued)
            );
        }
        assert_eq!(
            guard.consume_issued(&a, Nonce::new(7), record(100, 1), NOW, session(1), epoch),
            Err(ReplayRefusal::NeverIssued)
        );
    }

    #[test]
    fn only_live_capabilities_consume_a_nonce() {
        let mut guard = ReplayGuard::new();
        let a = sandbox("host-1", "exe-a");
        let nonce = guard.issue(&a).unwrap();
        let epoch = AuthorizationEpoch::new(2);
        assert_eq!(
            guard.consume_issued(&a, nonce, record(10, 2), NOW, session(1), epoch),
            Err(ReplayRefusal::Expired)
        );
        assert_eq!(
            guard.consume_issued(&a, nonce, record(100, 1), NOW, session(1), epoch),
            Err(ReplayRefusal::StaleEpoch {
                bound: AuthorizationEpoch::new(1),
                current: epoch
            })
        );
        assert_eq!(
            guard.consume_issued(&a, nonce, record(100, 2), NOW, session(2), epoch),
            Err(ReplayRefusal::OtherClock)
        );
        assert!(!guard.is_consumed(&a, nonce));
    }

    #[test]
    fn replay_state_survives_a_restart_and_nonces_are_never_reissued() {
        let mut guard = ReplayGuard::new();
        let a = sandbox("host-1", "exe-a");
        let nonce = guard.issue(&a).unwrap();
        guard
            .consume_issued(
                &a,
                nonce,
                record(100, 1),
                NOW,
                session(1),
                AuthorizationEpoch::FIRST,
            )
            .unwrap();
        let persisted = serde_json::to_string(&guard).unwrap();
        let mut restored: ReplayGuard = serde_json::from_str(&persisted).unwrap();
        assert_eq!(
            restored.consume_issued(
                &a,
                nonce,
                record(100, 1),
                NOW,
                session(1),
                AuthorizationEpoch::FIRST
            ),
            Err(ReplayRefusal::Replayed)
        );
        assert_eq!(restored.issue(&a).unwrap(), Nonce::new(2));
        assert!(serde_json::from_str::<ReplayGuard>(r#"{"scopes": [], "forget": true}"#).is_err());
    }

    #[test]
    fn compaction_removes_only_records_no_live_capability_can_carry() {
        let mut guard = ReplayGuard::new();
        let a = sandbox("host-1", "exe-a");
        let epoch = AuthorizationEpoch::new(3);
        let consume = |guard: &mut ReplayGuard, expires: u64, clock: ClockSession| {
            let nonce = guard.issue(&a).unwrap();
            guard
                .consume_presented(
                    &a,
                    nonce,
                    NonceRecord {
                        clock,
                        expires_at: MonotonicTime::from_nanos(expires),
                        epoch,
                    },
                    MonotonicTime::from_nanos(1),
                    clock,
                    epoch,
                )
                .unwrap();
            nonce
        };
        let expired = consume(&mut guard, 50, session(1));
        let in_uncertainty = consume(&mut guard, 95, session(1));
        let live = consume(&mut guard, 500, session(1));
        let old_session = consume(&mut guard, 5, session(9));
        // At 100 ns with 5 ns uncertainty: 50 + 5 <= 100 is removed, 95 + 5 <= 100 too,
        // 500 is live, and the other session's record cannot be judged by time.
        let report = guard.compact(
            MonotonicTime::from_nanos(99),
            session(1),
            Duration::from_nanos(5),
            |_| Some(epoch),
        );
        assert_eq!(
            report,
            CompactionReport {
                removed: 1,
                kept: 3
            }
        );
        assert!(!guard.is_consumed(&a, expired));
        assert!(guard.is_consumed(&a, in_uncertainty));
        let report = guard.compact(
            MonotonicTime::from_nanos(100),
            session(1),
            Duration::from_nanos(5),
            |_| Some(epoch),
        );
        assert_eq!(
            report,
            CompactionReport {
                removed: 1,
                kept: 2
            }
        );
        assert!(guard.is_consumed(&a, live));
        assert!(guard.is_consumed(&a, old_session));
        // Once the epoch moves on, nothing bound to the old one can be live.
        let report = guard.compact(
            MonotonicTime::from_nanos(100),
            session(1),
            Duration::from_nanos(5),
            |_| Some(AuthorizationEpoch::new(4)),
        );
        assert_eq!(
            report,
            CompactionReport {
                removed: 2,
                kept: 0
            }
        );
        // The counter never goes back: compaction frees storage, not identities.
        assert_eq!(guard.issue(&a).unwrap(), Nonce::new(5));
    }
}
