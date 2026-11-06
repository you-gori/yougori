//! The revocation priority lane (CORE-06 "metrics floods cannot suppress revocation";
//! INT-10 "metrics pressure cannot block revocation"; VM part §8.2 "never block the
//! revocation channel").
//!
//! The lane has its own bound and is drained before progress and metrics, so no backlog
//! there delays it, and it never waits on audit storage. It never refuses or drops a
//! revocation: a second revocation of one execution keeps the higher epoch, and when more
//! executions are pending than the lane holds, the overflow widens to revoking everything
//! until the receiver reconciles, which is stricter, never weaker.
//!
//! The revocation of one grant under an execution's authority ([`GrantRevocation`],
//! CORE-04) travels on the same lane, under the same bound and the same widening. It
//! leaves the execution's epoch in force, so it is kept apart from the execution's
//! revocations; a second revocation of the same grant keeps the higher epoch.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::envelope::{ConfigError, EventEnvelope, HighWater, ResolvedThrough, StreamKind};
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, GrantId, MonotonicTime};

/// One revocation: from `epoch` on, nothing bound to an earlier authorization epoch of
/// `execution` is honoured (S3.1; CORE-04 "revocation blocks new child work").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub execution: ExecutionId,
    /// The authorization epoch now in force.
    pub epoch: AuthorizationEpoch,
    pub reason: RevocationReason,
}

/// One grant revoked under `execution`'s authority (CORE-04 per-grant revocation; VM
/// part §6.3 step 1: a tombstone rather than an epoch advance): from now on nothing bound
/// to `grant` under `execution` is honoured, while `epoch`, the authorization epoch in
/// force, and every other grant of `execution` stay in force.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevocation {
    pub execution: ExecutionId,
    pub grant: GrantId,
    /// The authorization epoch in force when the grant was revoked; revoking the grant
    /// leaves it unchanged.
    pub epoch: AuthorizationEpoch,
    pub reason: RevocationReason,
}

/// Why authority was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    PolicyChanged,
    AuthorizationExpired,
    SecurityEvent,
    OwnerReclaimed,
}

/// Bound of the revocation lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationConfig {
    /// Executions with a pending revocation at most; more widen to revoking everything. A
    /// pending grant revocation takes one place too.
    pub max_pending_executions: usize,
}

impl RevocationConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_pending_executions == 0 {
            return Err(ConfigError::Zero {
                setting: "max_pending_executions",
            });
        }
        Ok(())
    }
}

/// What the lane did with a revocation. Every outcome keeps it in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationAdmission {
    Queued,
    /// Raised the epoch of the pending revocation of the same execution, or of the same
    /// grant, in place.
    Raised,
    /// An equal or higher epoch of the same execution, or of the same grant, is already
    /// pending. A grant is also covered by a pending revocation of its execution at a
    /// later epoch, which ends everything bound to the grant's epoch.
    AlreadyCovered,
    /// The lane was full: every execution is treated as revoked until reconciled.
    Widened,
}

/// The lane overflowed: the receiver treats every execution as revoked and denies new
/// work for all of them until it reconciles authorization with its authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAll {
    /// When the first revocation that did not fit arrived.
    pub since: MonotonicTime,
    /// How many revocations it covers.
    pub covered: u64,
}

/// One delivery from the lane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationBatch {
    /// Applied first when present.
    pub revoke_all: Option<RevokeAll>,
    pub notices: Vec<EventEnvelope<Revocation>>,
    /// Grants revoked under executions whose epochs stay in force, in the order they were
    /// first revoked.
    pub grants: Vec<EventEnvelope<GrantRevocation>>,
    /// Per issuer, every sequence up to `through` was delivered or covered.
    pub resolved: Vec<ResolvedThrough>,
}

impl RevocationBatch {
    pub fn is_empty(&self) -> bool {
        self.revoke_all.is_none() && self.notices.is_empty() && self.grants.is_empty()
    }
}

/// Counts of what the lane did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTotals {
    pub issued: u64,
    pub raised: u64,
    pub covered: u64,
    pub widened: u64,
    pub delivered: u64,
}

/// The revocation priority lane (CORE-06; INT-10).
#[derive(Clone, Debug)]
pub struct RevocationLane {
    config: RevocationConfig,
    pending: VecDeque<EventEnvelope<Revocation>>,
    pending_grants: VecDeque<EventEnvelope<GrantRevocation>>,
    revoke_all: Option<RevokeAll>,
    marks: HighWater,
    totals: RevocationTotals,
}

impl RevocationLane {
    pub fn new(config: RevocationConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            pending: VecDeque::new(),
            pending_grants: VecDeque::new(),
            revoke_all: None,
            marks: HighWater::new(StreamKind::Revocation),
            totals: RevocationTotals::default(),
        })
    }

    /// Takes one revocation. It never refuses and never waits.
    pub fn push(
        &mut self,
        event: EventEnvelope<Revocation>,
        now: MonotonicTime,
    ) -> RevocationAdmission {
        self.marks.note(&event.key(), event.sequence());
        self.totals.issued = self.totals.issued.saturating_add(1);
        let execution = event.payload().execution.clone();
        if let Some(pending) = self
            .pending
            .iter_mut()
            .find(|pending| pending.payload().execution == execution)
        {
            if event.payload().epoch > pending.payload().epoch {
                *pending = event;
                self.totals.raised = self.totals.raised.saturating_add(1);
                return RevocationAdmission::Raised;
            }
            self.totals.covered = self.totals.covered.saturating_add(1);
            return RevocationAdmission::AlreadyCovered;
        }
        if self.pending() < self.config.max_pending_executions {
            self.pending.push_back(event);
            return RevocationAdmission::Queued;
        }
        self.widen(now)
    }

    /// Takes one grant revocation as [`RevocationLane::push`] takes a revocation: it never
    /// refuses and never waits. A pending revocation of the grant's execution at a later
    /// epoch already covers it, and a second revocation of the same grant keeps the
    /// higher epoch.
    pub fn push_grant(
        &mut self,
        event: EventEnvelope<GrantRevocation>,
        now: MonotonicTime,
    ) -> RevocationAdmission {
        self.marks.note(&event.key(), event.sequence());
        self.totals.issued = self.totals.issued.saturating_add(1);
        let revoked = event.payload();
        if self.pending.iter().any(|pending| {
            pending.payload().execution == revoked.execution
                && pending.payload().epoch > revoked.epoch
        }) {
            self.totals.covered = self.totals.covered.saturating_add(1);
            return RevocationAdmission::AlreadyCovered;
        }
        if let Some(pending) = self.pending_grants.iter_mut().find(|pending| {
            pending.payload().execution == revoked.execution
                && pending.payload().grant == revoked.grant
        }) {
            if revoked.epoch > pending.payload().epoch {
                *pending = event;
                self.totals.raised = self.totals.raised.saturating_add(1);
                return RevocationAdmission::Raised;
            }
            self.totals.covered = self.totals.covered.saturating_add(1);
            return RevocationAdmission::AlreadyCovered;
        }
        if self.pending() < self.config.max_pending_executions {
            self.pending_grants.push_back(event);
            return RevocationAdmission::Queued;
        }
        self.widen(now)
    }

    /// The lane is full: every execution is treated as revoked until reconciled.
    fn widen(&mut self, now: MonotonicTime) -> RevocationAdmission {
        let widened = self.revoke_all.get_or_insert(RevokeAll {
            since: now,
            covered: 0,
        });
        widened.covered = widened.covered.saturating_add(1);
        self.totals.widened = self.totals.widened.saturating_add(1);
        RevocationAdmission::Widened
    }

    /// Everything pending: the executions' revocations in the order the executions were
    /// first revoked, and the grants' in the order the grants were.
    pub fn drain(&mut self) -> RevocationBatch {
        let notices: Vec<_> = self.pending.drain(..).collect();
        let grants: Vec<_> = self.pending_grants.drain(..).collect();
        let delivered = notices.len().saturating_add(grants.len());
        self.totals.delivered = self
            .totals
            .delivered
            .saturating_add(u64::try_from(delivered).unwrap_or(u64::MAX));
        RevocationBatch {
            revoke_all: self.revoke_all.take(),
            notices,
            grants,
            resolved: self.marks.take_unreported(),
        }
    }

    /// Revocations pending, of executions and of grants.
    pub fn pending(&self) -> usize {
        self.pending.len().saturating_add(self.pending_grants.len())
    }

    pub fn totals(&self) -> RevocationTotals {
        self.totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::envelope::{Phase, ProducerCore, ProducerIncarnation};
    use crate::foundation::events::fakes::{context, execution, producer};
    use crate::foundation::evidence::SourceClass;

    const NOW: MonotonicTime = MonotonicTime::from_nanos(7);

    fn issuer() -> ProducerCore {
        ProducerCore::new(
            producer("coordinator"),
            ProducerIncarnation::FIRST,
            StreamKind::Revocation,
            SourceClass::HostProbe,
        )
    }

    fn revoke(core: &mut ProducerCore, name: &str, epoch: u64) -> EventEnvelope<Revocation> {
        core.seal(
            context("op-1", Phase::Revoked),
            NOW,
            Revocation {
                execution: execution(name),
                epoch: AuthorizationEpoch::new(epoch),
                reason: RevocationReason::UserRequested,
            },
        )
        .unwrap()
    }

    fn revoke_grant(
        core: &mut ProducerCore,
        name: &str,
        grant: &str,
        epoch: u64,
    ) -> EventEnvelope<GrantRevocation> {
        core.seal(
            context("op-1", Phase::Revoked),
            NOW,
            GrantRevocation {
                execution: execution(name),
                grant: GrantId::from_digest(crate::foundation::ids::digest(
                    "yougori/test/grant/v1",
                    &[grant.as_bytes()],
                )),
                epoch: AuthorizationEpoch::new(epoch),
                reason: RevocationReason::SecurityEvent,
            },
        )
        .unwrap()
    }

    fn lane(max_pending_executions: usize) -> RevocationLane {
        RevocationLane::new(RevocationConfig {
            max_pending_executions,
        })
        .unwrap()
    }

    #[test]
    fn a_second_revocation_keeps_the_higher_epoch() {
        let mut lane = lane(4);
        let mut core = issuer();
        assert_eq!(
            lane.push(revoke(&mut core, "exe-1", 5), NOW),
            RevocationAdmission::Queued
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-2", 2), NOW),
            RevocationAdmission::Queued
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-1", 7), NOW),
            RevocationAdmission::Raised
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-1", 6), NOW),
            RevocationAdmission::AlreadyCovered
        );
        let batch = lane.drain();
        let epochs: Vec<(String, u64)> = batch
            .notices
            .iter()
            .map(|notice| {
                (
                    notice.payload().execution.to_string(),
                    notice.payload().epoch.get(),
                )
            })
            .collect();
        assert_eq!(epochs, [("exe-1".to_owned(), 7), ("exe-2".to_owned(), 2)]);
        assert_eq!(batch.revoke_all, None);
        assert_eq!(batch.resolved[0].through.get(), 4);
        assert!(lane.drain().is_empty());
    }

    #[test]
    fn overflow_widens_to_revoking_everything_instead_of_dropping() {
        let mut lane = lane(2);
        let mut core = issuer();
        lane.push(revoke(&mut core, "exe-1", 2), NOW);
        lane.push(revoke(&mut core, "exe-2", 2), NOW);
        assert_eq!(
            lane.push(revoke(&mut core, "exe-3", 2), NOW),
            RevocationAdmission::Widened
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-4", 2), NOW),
            RevocationAdmission::Widened
        );
        let batch = lane.drain();
        assert_eq!(
            batch.revoke_all,
            Some(RevokeAll {
                since: NOW,
                covered: 2
            })
        );
        assert_eq!(batch.notices.len(), 2);
        assert_eq!(batch.resolved[0].through.get(), 4);
        assert_eq!(lane.totals().widened, 2);
        // The widening is delivered once; the lane then works normally again.
        assert_eq!(
            lane.push(revoke(&mut core, "exe-5", 3), NOW),
            RevocationAdmission::Queued
        );
        assert_eq!(lane.drain().revoke_all, None);
    }

    #[test]
    fn a_grant_revocation_is_kept_apart_from_its_executions_epoch() {
        let mut lane = lane(4);
        let mut core = issuer();
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-1", "route", 3), NOW),
            RevocationAdmission::Queued
        );
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-1", "delegation", 3), NOW),
            RevocationAdmission::Queued,
            "another grant of the same execution is its own revocation"
        );
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-1", "route", 3), NOW),
            RevocationAdmission::AlreadyCovered
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-1", 3), NOW),
            RevocationAdmission::Queued,
            "a grant revocation never covers its execution's revocation"
        );
        assert_eq!(lane.pending(), 3);
        let batch = lane.drain();
        assert_eq!(batch.notices.len(), 1);
        let grants: Vec<u64> = batch
            .grants
            .iter()
            .map(|notice| notice.sequence().get())
            .collect();
        assert_eq!(grants, [1, 2]);
        assert_eq!(batch.resolved[0].through.get(), 4);
        assert_eq!(lane.totals().delivered, 3);
        assert!(lane.drain().is_empty());

        // A pending revocation of the execution at a later epoch ends everything bound to
        // the grant's epoch, so it covers the grant.
        lane.push(revoke(&mut core, "exe-2", 5), NOW);
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-2", "route", 4), NOW),
            RevocationAdmission::AlreadyCovered
        );
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-3", "route", 1), NOW),
            RevocationAdmission::Queued
        );
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-3", "route", 2), NOW),
            RevocationAdmission::Raised
        );
        let batch = lane.drain();
        assert_eq!(batch.grants.len(), 1);
        assert_eq!(batch.grants[0].payload().epoch, AuthorizationEpoch::new(2));
    }

    #[test]
    fn grant_revocations_share_the_bound_and_widen_instead_of_dropping() {
        let mut lane = lane(2);
        let mut core = issuer();
        lane.push(revoke(&mut core, "exe-1", 2), NOW);
        lane.push_grant(revoke_grant(&mut core, "exe-2", "route", 1), NOW);
        assert_eq!(
            lane.push_grant(revoke_grant(&mut core, "exe-3", "route", 1), NOW),
            RevocationAdmission::Widened
        );
        assert_eq!(
            lane.push(revoke(&mut core, "exe-4", 2), NOW),
            RevocationAdmission::Widened
        );
        let batch = lane.drain();
        assert_eq!(
            batch.revoke_all,
            Some(RevokeAll {
                since: NOW,
                covered: 2
            })
        );
        assert_eq!((batch.notices.len(), batch.grants.len()), (1, 1));
        assert_eq!(lane.totals().widened, 2);
    }

    #[test]
    fn configuration_is_checked() {
        assert_eq!(
            RevocationLane::new(RevocationConfig {
                max_pending_executions: 0
            })
            .err(),
            Some(ConfigError::Zero {
                setting: "max_pending_executions"
            })
        );
    }
}
