//! Remote-side deadline accounting for V12. This does not mint authority: an
//! authenticated host grant bounds an existing remote VM's CORE-04 child lease.
//! The remote engine anchors each request BEFORE it is handed to the SSH agent.
//! Network, IPC, scheduling and process-pause delay therefore consume its TTL.
//! A grant received after the old bound ended cannot revive the execution.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::{GrantRef, LeaseGrant};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::MonotonicTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteGrantRefusal {
    InvalidLimits,
    Closed,
    ClockRegressed,
    Expired,
    NoPendingRequest,
    ForeignAuthority,
    InvalidTtl,
    NotGranted,
}

impl fmt::Display for RemoteGrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "remote delegation limits are invalid",
            Self::Closed => "the remote delegation ended",
            Self::ClockRegressed => "the remote delegation clock regressed",
            Self::Expired => "the remote delegation expired",
            Self::NoPendingRequest => "the host sent an unsolicited delegation",
            Self::ForeignAuthority => "the host changed the delegation's authority or clock",
            Self::InvalidTtl => "the delegation TTL exceeds the accepted bound or is zero",
            Self::NotGranted => "the host has not delegated work authority",
        })
    }
}

impl std::error::Error for RemoteGrantRefusal {}

/// A received bound, measured on the remote engine clock. The caller still has to
/// obtain/check the CORE-04 lease under the exact real VM and boot; this is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteGrantBound {
    pub authority: GrantRef,
    pub clock: ClockSession,
    pub requested_at: MonotonicTime,
    pub expires_at: MonotonicTime,
}

/// Not persisted or restored: engine recovery ends the control session and its
/// bootstrap/child lease. Starting another connection does not reuse this object.
#[derive(Clone, Debug)]
pub struct RemoteGrantWindow {
    high_water: MonotonicTime,
    expires_at: MonotonicTime,
    max_ttl: Duration,
    pending: Option<MonotonicTime>,
    bound: Option<RemoteGrantBound>,
    renew_at: MonotonicTime,
    ended: bool,
}

impl RemoteGrantWindow {
    /// The bootstrap permits only management of an empty VM, never workload input.
    /// Its first request is anchored here, before the peer sends its first heartbeat.
    pub fn new(
        now: MonotonicTime,
        bootstrap: Duration,
        max_ttl: Duration,
    ) -> Result<Self, RemoteGrantRefusal> {
        if bootstrap.is_zero() || max_ttl.is_zero() || bootstrap > max_ttl {
            return Err(RemoteGrantRefusal::InvalidLimits);
        }
        let expires_at = now
            .checked_add(bootstrap)
            .ok_or(RemoteGrantRefusal::InvalidLimits)?;
        Ok(Self {
            high_water: now,
            expires_at,
            max_ttl,
            pending: Some(now),
            bound: None,
            renew_at: now,
            ended: false,
        })
    }

    fn refuse<T>(&mut self, error: RemoteGrantRefusal) -> Result<T, RemoteGrantRefusal> {
        self.ended = true;
        self.pending = None;
        Err(error)
    }

    /// Check before reading queued frames, as well as in the independent VM driver.
    pub fn check(&mut self, now: MonotonicTime) -> Result<(), RemoteGrantRefusal> {
        if self.ended {
            return Err(RemoteGrantRefusal::Closed);
        }
        if now < self.high_water {
            return self.refuse(RemoteGrantRefusal::ClockRegressed);
        }
        self.high_water = now;
        if now >= self.expires_at {
            return self.refuse(RemoteGrantRefusal::Expired);
        }
        Ok(())
    }

    /// No work before the first delegation; failed checks can never be revived.
    pub fn authorize(
        &mut self,
        now: MonotonicTime,
    ) -> Result<RemoteGrantBound, RemoteGrantRefusal> {
        self.check(now)?;
        self.bound.ok_or(RemoteGrantRefusal::NotGranted)
    }

    /// At most one request is in flight. Its anchor belongs to the remote ENGINE,
    /// not to the possibly paused stdio bridge. Heartbeats alone never renew it.
    pub fn request_if_due(
        &mut self,
        now: MonotonicTime,
    ) -> Result<Option<(GrantRef, ClockSession)>, RemoteGrantRefusal> {
        self.check(now)?;
        if self.pending.is_some() || now < self.renew_at {
            return Ok(None);
        }
        let Some(bound) = self.bound else {
            return Ok(None);
        };
        self.pending = Some(now);
        Ok(Some((bound.authority, bound.clock)))
    }

    /// Call only after the frame's MAC/session/sequence and direction are accepted.
    /// A late host grant loses all transit time. It never starts a fresh full TTL
    /// at receipt, even when the agent or engine was paused while it was queued.
    pub fn accept(
        &mut self,
        grant: LeaseGrant,
        now: MonotonicTime,
    ) -> Result<RemoteGrantBound, RemoteGrantRefusal> {
        self.check(now)?;
        let Some(requested_at) = self.pending.take() else {
            return self.refuse(RemoteGrantRefusal::NoPendingRequest);
        };
        if self
            .bound
            .is_some_and(|old| old.authority != grant.authority || old.clock != grant.clock)
        {
            return self.refuse(RemoteGrantRefusal::ForeignAuthority);
        }
        let ttl = Duration::from_nanos(grant.ttl_nanos);
        if ttl.is_zero() || ttl > self.max_ttl {
            return self.refuse(RemoteGrantRefusal::InvalidTtl);
        }
        let Some(expires_at) = requested_at.checked_add(ttl) else {
            return self.refuse(RemoteGrantRefusal::InvalidTtl);
        };
        if expires_at <= now {
            return self.refuse(RemoteGrantRefusal::Expired);
        }
        let bound = RemoteGrantBound {
            authority: grant.authority,
            clock: grant.clock,
            requested_at,
            expires_at,
        };
        self.expires_at = expires_at;
        self.renew_at = now.saturating_add(expires_at.saturating_duration_since(now) / 2);
        self.bound = Some(bound);
        Ok(bound)
    }

    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
    /// Conservative supervisor view; reading it cannot renew or revive anything.
    pub fn remaining(&self, now: MonotonicTime) -> Duration {
        if self.ended || now < self.high_water {
            Duration::ZERO
        } else {
            self.expires_at.saturating_duration_since(now)
        }
    }
    pub fn close(&mut self) {
        self.ended = true;
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::LeaseId;

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }
    fn grant(clock: ClockSession, seconds: u64) -> LeaseGrant {
        LeaseGrant {
            authority: GrantRef::Lease {
                lease: LeaseId::new(1),
            },
            clock,
            ttl_nanos: seconds * 1_000_000_000,
        }
    }
    fn window() -> RemoteGrantWindow {
        RemoteGrantWindow::new(at(0), Duration::from_secs(30), Duration::from_secs(60)).unwrap()
    }

    #[test]
    fn transit_and_scheduling_delay_consume_the_grant_and_renewal_ttl() {
        let clock = ClockSession::generate();
        let mut w = window();
        assert_eq!(w.authorize(at(1)), Err(RemoteGrantRefusal::NotGranted));
        assert_eq!(
            w.accept(grant(clock, 20), at(7)).unwrap().expires_at,
            at(20)
        );
        assert_eq!(w.request_if_due(at(12)).unwrap(), None);
        assert!(w.request_if_due(at(14)).unwrap().is_some());
        assert_eq!(w.request_if_due(at(15)).unwrap(), None);
        let renewed = w.accept(grant(clock, 20), at(18)).unwrap();
        assert_eq!(renewed.requested_at, at(14));
        assert_eq!(renewed.expires_at, at(34));
        assert_eq!(w.authorize(at(34)), Err(RemoteGrantRefusal::Expired));
    }

    #[test]
    fn a_queued_renewal_cannot_revive_an_expired_execution() {
        let clock = ClockSession::generate();
        let mut w = window();
        w.accept(grant(clock, 20), at(1)).unwrap();
        w.request_if_due(at(12)).unwrap().unwrap();
        // Host answered while alive, but the engine/agent did not run until expiry.
        assert_eq!(
            w.accept(grant(clock, 60), at(21)),
            Err(RemoteGrantRefusal::Expired)
        );
        assert_eq!(
            w.accept(grant(clock, 60), at(22)),
            Err(RemoteGrantRefusal::Closed)
        );
    }

    #[test]
    fn bootstrap_and_a_grant_whose_transit_consumed_all_time_end_without_work() {
        let clock = ClockSession::generate();
        assert_eq!(
            window().accept(grant(clock, 60), at(30)),
            Err(RemoteGrantRefusal::Expired)
        );
        assert_eq!(
            window().accept(grant(clock, 5), at(6)),
            Err(RemoteGrantRefusal::Expired)
        );
    }

    #[test]
    fn heartbeat_polling_never_extends_authority_and_closed_sessions_stay_closed() {
        let clock = ClockSession::generate();
        let mut w = window();
        w.accept(grant(clock, 20), at(1)).unwrap();
        for second in 2..20 {
            w.request_if_due(at(second)).unwrap();
        }
        assert_eq!(w.check(at(20)), Err(RemoteGrantRefusal::Expired));
        assert_eq!(w.check(at(10)), Err(RemoteGrantRefusal::Closed));
        let mut fresh = window();
        fresh.close();
        assert_eq!(
            fresh.accept(grant(clock, 20), at(1)),
            Err(RemoteGrantRefusal::Closed)
        );
    }

    #[test]
    fn rollback_unsolicited_and_replaced_authority_are_terminal_refusals() {
        let clock = ClockSession::generate();
        let mut w = window();
        w.check(at(3)).unwrap();
        assert_eq!(
            w.accept(grant(clock, 20), at(2)),
            Err(RemoteGrantRefusal::ClockRegressed)
        );
        assert_eq!(w.check(at(4)), Err(RemoteGrantRefusal::Closed));
        let mut w = window();
        w.accept(grant(clock, 20), at(1)).unwrap();
        assert_eq!(
            w.accept(grant(clock, 20), at(2)),
            Err(RemoteGrantRefusal::NoPendingRequest)
        );
        let mut w = window();
        w.accept(grant(clock, 20), at(1)).unwrap();
        w.request_if_due(at(12)).unwrap();
        assert_eq!(
            w.accept(grant(ClockSession::generate(), 20), at(13)),
            Err(RemoteGrantRefusal::ForeignAuthority)
        );
    }

    #[test]
    fn zero_oversized_and_overflowed_bounds_are_refused() {
        let clock = ClockSession::generate();
        assert_eq!(
            window().accept(grant(clock, 0), at(1)),
            Err(RemoteGrantRefusal::InvalidTtl)
        );
        assert_eq!(
            window().accept(grant(clock, 61), at(1)),
            Err(RemoteGrantRefusal::InvalidTtl)
        );
        assert!(RemoteGrantWindow::new(
            MonotonicTime::from_nanos(u64::MAX),
            Duration::from_secs(1),
            Duration::from_secs(60)
        )
        .is_err());
    }
}
