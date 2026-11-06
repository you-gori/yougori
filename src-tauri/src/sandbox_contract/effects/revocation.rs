//! Post-revocation bounds and revocation acknowledgments (VM part §2.5 lines 1819–1824;
//! §6.3 lines 2129–2143; VM-P14, VM-P40).
//!
//! For disconnected remote execution a short-lived lease limits what can still happen
//! after a revocation:
//!
//! ```text
//! remaining_authorized_time <= lease_TTL + allowed_clock_uncertainty
//! remaining_effects <= outstanding_reserved_effects + valid_lease_budget
//! ```
//!
//! [`PostRevocationBounds::compute`] gives these only for an enforcement point that
//! checks leases and cannot mint renewals, and refuses otherwise. Committed external
//! actions are never revoked retroactively: the bounds limit what follows, not what
//! already happened.
//!
//! A revocation linearizes when the [`RevocationRegistry`] records its tombstone: from
//! then on no authorization bound to the revoked epoch or an older one succeeds, even
//! before the coordinator's epoch advance reaches this enforcement point. Each
//! acknowledgment is its own typed milestone with the evidence source that backs it:
//! "new authorizations denied" is not "sockets closed", "VM stopped", "provider stopped
//! billing" or "disk cleanup finished". Tombstones are compacted only once the authority
//! itself denies the revoked epoch and no capability bound to it can still be live.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::canonical::entries;
use super::description::{EffectId, SandboxRef};
use crate::foundation::coordination::RevocationMilestone;
use crate::foundation::events::RevocationReason;
use crate::foundation::evidence::{ClockSession, SourceClass};
use crate::foundation::ids::{AuthorizationEpoch, MonotonicTime};

/// What an enforcement point can do with leases (§2.5 line 1824).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementPoint {
    pub checks_leases: bool,
    pub can_mint_renewals: bool,
}

/// The bounds do not apply to this enforcement point (§2.5 line 1824).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundNotApplicable {
    pub point: EnforcementPoint,
}

impl fmt::Display for BoundNotApplicable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.point.checks_leases {
            f.write_str("the enforcement point does not check leases, so no bound applies")
        } else {
            f.write_str("the enforcement point can mint renewals, so no bound applies")
        }
    }
}

impl std::error::Error for BoundNotApplicable {}

/// What can still happen after a revocation (§2.5 lines 1821–1822).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostRevocationBounds {
    pub remaining_authorized_time: Duration,
    pub remaining_effects: u64,
}

impl PostRevocationBounds {
    /// The bounds, or why they do not apply. Saturates rather than wraps.
    pub fn compute(
        point: EnforcementPoint,
        lease_ttl: Duration,
        allowed_clock_uncertainty: Duration,
        outstanding_reserved_effects: u64,
        valid_lease_budget: u64,
    ) -> Result<Self, BoundNotApplicable> {
        if !point.checks_leases || point.can_mint_renewals {
            return Err(BoundNotApplicable { point });
        }
        Ok(Self {
            remaining_authorized_time: lease_ttl.saturating_add(allowed_clock_uncertainty),
            remaining_effects: outstanding_reserved_effects.saturating_add(valid_lease_budget),
        })
    }
}

/// A short-lived lease held by a disconnected remote enforcement point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteLease {
    pub ttl: Duration,
    /// Effects the lease allows without contacting the authority.
    pub effect_budget: u64,
}

/// A remote enforcement point that checks its lease on its own clock and has no way to
/// renew it (§2.5 line 1824). Once the lease ends it allows nothing until a new lease
/// arrives from the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteEnforcementPoint {
    lease: RemoteLease,
    issued_at_remote: MonotonicTime,
    effects_used: u64,
}

impl RemoteEnforcementPoint {
    /// Holds `lease` from `issued_at_remote` on the remote clock.
    pub const fn new(lease: RemoteLease, issued_at_remote: MonotonicTime) -> Self {
        Self {
            lease,
            issued_at_remote,
            effects_used: 0,
        }
    }

    pub const fn enforcement(&self) -> EnforcementPoint {
        EnforcementPoint {
            checks_leases: true,
            can_mint_renewals: false,
        }
    }

    /// Allows one effect at `remote_now` if the lease is unexpired and has budget left.
    pub fn try_effect(&mut self, remote_now: MonotonicTime) -> Result<u64, RemoteRefusal> {
        let expires = self.issued_at_remote.saturating_add(self.lease.ttl);
        if remote_now >= expires {
            return Err(RemoteRefusal::LeaseExpired);
        }
        if self.effects_used >= self.lease.effect_budget {
            return Err(RemoteRefusal::BudgetSpent);
        }
        self.effects_used = self.effects_used.saturating_add(1);
        Ok(self.lease.effect_budget.saturating_sub(self.effects_used))
    }

    /// Effects the lease still allows, ignoring expiry.
    pub const fn valid_lease_budget(&self) -> u64 {
        self.lease.effect_budget.saturating_sub(self.effects_used)
    }
}

/// Why a remote enforcement point refused an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteRefusal {
    LeaseExpired,
    BudgetSpent,
}

/// One revocation acknowledgment (§6.3 line 2139). Each is distinct; none implies another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationAck {
    /// The tombstone is recorded; no new authorization succeeds (§6.3 steps 1–2).
    NewAuthorizationsDenied,
    /// Every eligible channel, long streams included, is closed (§6.3 step 2).
    SocketsClosed,
    /// The VM stopped (§6.3 step 4).
    VmStopped,
    /// The remote provider confirmed it stopped billing.
    ProviderStoppedBilling,
    /// Bounded cleanup finished (§6.3 step 5).
    DiskCleanupFinished,
}

impl RevocationAck {
    pub const ALL: [Self; 5] = [
        Self::NewAuthorizationsDenied,
        Self::SocketsClosed,
        Self::VmStopped,
        Self::ProviderStoppedBilling,
        Self::DiskCleanupFinished,
    ];

    /// The least trusted evidence that may record the acknowledgment: a host observation,
    /// or for billing the provider's own API. A guest report never acknowledges anything.
    pub const fn minimum_source(self) -> SourceClass {
        match self {
            Self::ProviderStoppedBilling => SourceClass::ProviderApi,
            Self::NewAuthorizationsDenied
            | Self::SocketsClosed
            | Self::VmStopped
            | Self::DiskCleanupFinished => SourceClass::HostProbe,
        }
    }

    /// The acknowledgment a CORE-04 revocation milestone stands for, where one does.
    /// Closed leases are not closed sockets, and GPU reclamation is no acknowledgment of
    /// this list. The first denied authorization measures the decision's effect rather
    /// than acknowledging it; all channels closed implies sockets closed, which CORE-04
    /// records with it, so it maps to nothing of its own.
    pub const fn from_milestone(milestone: RevocationMilestone) -> Option<Self> {
        match milestone {
            RevocationMilestone::NewAuthorizationsDenied => Some(Self::NewAuthorizationsDenied),
            RevocationMilestone::SocketsClosed => Some(Self::SocketsClosed),
            RevocationMilestone::VmStopped => Some(Self::VmStopped),
            RevocationMilestone::ProviderStoppedBilling => Some(Self::ProviderStoppedBilling),
            RevocationMilestone::CleanupFinished => Some(Self::DiskCleanupFinished),
            RevocationMilestone::FirstDeniedAuthorization
            | RevocationMilestone::AllChannelsClosed
            | RevocationMilestone::LeasesClosed
            | RevocationMilestone::GpuReclaimed => None,
        }
    }
}

/// When an acknowledgment was recorded and what backs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckEntry {
    pub at: MonotonicTime,
    pub source: SourceClass,
}

/// One sandbox's revocation tombstone (§6.3 step 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecord {
    pub sandbox: SandboxRef,
    /// Every authorization bound to this epoch or an older one is denied.
    pub revoked_through: AuthorizationEpoch,
    pub reason: RevocationReason,
    /// The linearization point: from here on no new authorization succeeds.
    pub linearized_at: MonotonicTime,
    pub acks: BTreeMap<RevocationAck, AckEntry>,
    /// Effects dispatched before the linearization point whose outcomes are not yet known
    /// (§6.3 step 5).
    pub uncertain: BTreeSet<EffectId>,
}

impl RevocationRecord {
    pub fn denies(&self, epoch: AuthorizationEpoch) -> bool {
        epoch <= self.revoked_through
    }

    pub fn acknowledged(&self, ack: RevocationAck) -> Option<AckEntry> {
        self.acks.get(&ack).copied()
    }
}

/// Why an acknowledgment was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckRefusal {
    NotRevoked,
    InsufficientSource {
        ack: RevocationAck,
        minimum: SourceClass,
        source: SourceClass,
    },
    /// Earlier than the revocation's linearization point.
    BeforeLinearization,
}

impl fmt::Display for AckRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRevoked => f.write_str("the sandbox has no revocation to acknowledge"),
            Self::InsufficientSource {
                ack,
                minimum,
                source,
            } => write!(f, "{ack:?} needs at least a {minimum}, not a {source}"),
            Self::BeforeLinearization => {
                f.write_str("an acknowledgment cannot precede the revocation it acknowledges")
            }
        }
    }
}

impl std::error::Error for AckRefusal {}

/// Every revocation tombstone this enforcement point holds, persisted with its state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRegistry {
    #[serde(with = "entries")]
    records: BTreeMap<SandboxRef, RevocationRecord>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the tombstone: the linearization point. Revoking again only raises the
    /// revoked epoch; it never lowers it or moves the linearization point.
    pub fn revoke(
        &mut self,
        sandbox: &SandboxRef,
        revoked_through: AuthorizationEpoch,
        reason: RevocationReason,
        now: MonotonicTime,
    ) -> &RevocationRecord {
        let record = self
            .records
            .entry(sandbox.clone())
            .or_insert_with(|| RevocationRecord {
                sandbox: sandbox.clone(),
                revoked_through,
                reason,
                linearized_at: now,
                acks: BTreeMap::from([(
                    RevocationAck::NewAuthorizationsDenied,
                    AckEntry {
                        at: now,
                        source: SourceClass::HostProbe,
                    },
                )]),
                uncertain: BTreeSet::new(),
            });
        record.revoked_through = record.revoked_through.max(revoked_through);
        record
    }

    pub fn record(&self, sandbox: &SandboxRef) -> Option<&RevocationRecord> {
        self.records.get(sandbox)
    }

    /// Whether an authorization of `sandbox` bound to `epoch` is denied.
    pub fn denies(&self, sandbox: &SandboxRef, epoch: AuthorizationEpoch) -> bool {
        self.records
            .get(sandbox)
            .is_some_and(|record| record.denies(epoch))
    }

    /// Records one acknowledgment, backed by evidence from `source`.
    pub fn acknowledge(
        &mut self,
        sandbox: &SandboxRef,
        ack: RevocationAck,
        source: SourceClass,
        now: MonotonicTime,
    ) -> Result<(), AckRefusal> {
        let record = self
            .records
            .get_mut(sandbox)
            .ok_or(AckRefusal::NotRevoked)?;
        if !source.satisfies(ack.minimum_source()) {
            return Err(AckRefusal::InsufficientSource {
                ack,
                minimum: ack.minimum_source(),
                source,
            });
        }
        if now < record.linearized_at {
            return Err(AckRefusal::BeforeLinearization);
        }
        record
            .acks
            .entry(ack)
            .or_insert(AckEntry { at: now, source });
        Ok(())
    }

    pub(super) fn note_uncertain(&mut self, sandbox: &SandboxRef, effect: EffectId) {
        if let Some(record) = self.records.get_mut(sandbox) {
            record.uncertain.insert(effect);
        }
    }

    pub(super) fn resolve_uncertain(&mut self, sandbox: &SandboxRef, effect: &EffectId) {
        if let Some(record) = self.records.get_mut(sandbox) {
            record.uncertain.remove(effect);
        }
    }

    /// Removes tombstones that are no longer needed: the authority's own epoch is past
    /// the revoked one, so it denies those authorizations itself, and no capability bound
    /// to them can be live. `latest_expiry` gives the latest expiry of any capability the
    /// sandbox was issued; one on another clock session is refused everywhere already.
    /// A tombstone with unresolved uncertain outcomes is kept.
    pub fn compact(
        &mut self,
        now: MonotonicTime,
        session: ClockSession,
        allowed_clock_uncertainty: Duration,
        current_epoch: impl Fn(&SandboxRef) -> Option<AuthorizationEpoch>,
        latest_expiry: impl Fn(&SandboxRef) -> Option<(ClockSession, MonotonicTime)>,
    ) -> usize {
        let before = self.records.len();
        self.records.retain(|sandbox, record| {
            let superseded =
                current_epoch(sandbox).is_some_and(|epoch| epoch > record.revoked_through);
            let expired = match latest_expiry(sandbox) {
                None => true,
                Some((clock, expires_at)) => {
                    clock != session || expires_at.saturating_add(allowed_clock_uncertainty) <= now
                }
            };
            !(superseded && expired && record.uncertain.is_empty())
        });
        before - self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ExecutionId};
    use crate::sandbox_contract::effects::description::IssuerId;

    const SECOND: Duration = Duration::from_secs(1);

    fn sandbox() -> SandboxRef {
        SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"host"])),
            execution: ExecutionId::new("exe-a").unwrap(),
        }
    }

    fn at_seconds(seconds: u64) -> MonotonicTime {
        MonotonicTime::ZERO.saturating_add(Duration::from_secs(seconds))
    }

    #[test]
    fn the_bounds_hold_on_worked_numbers() {
        // A 30 s lease with 2 s of clock uncertainty: 32 s. Three reserved effects in
        // flight plus a lease budget of 5: 8 effects.
        let bounds = PostRevocationBounds::compute(
            EnforcementPoint {
                checks_leases: true,
                can_mint_renewals: false,
            },
            30 * SECOND,
            2 * SECOND,
            3,
            5,
        )
        .unwrap();
        assert_eq!(bounds.remaining_authorized_time, 32 * SECOND);
        assert_eq!(bounds.remaining_effects, 8);
    }

    #[test]
    fn the_bounds_refuse_points_that_skip_leases_or_mint_renewals() {
        for point in [
            EnforcementPoint {
                checks_leases: false,
                can_mint_renewals: false,
            },
            EnforcementPoint {
                checks_leases: true,
                can_mint_renewals: true,
            },
        ] {
            assert_eq!(
                PostRevocationBounds::compute(point, SECOND, SECOND, 0, 0),
                Err(BoundNotApplicable { point })
            );
        }
    }

    /// Every issue time inside the lease, every revocation time and every remote clock
    /// lag up to the uncertainty: the remote point never acts later than
    /// `lease_TTL + allowed_clock_uncertainty` after the revocation, nor more often than
    /// `outstanding_reserved_effects + valid_lease_budget` times.
    #[test]
    fn a_disconnected_remote_point_stays_within_both_bounds() {
        let ttl_seconds = 30;
        let uncertainty_seconds = 2;
        let lease = RemoteLease {
            ttl: Duration::from_secs(ttl_seconds),
            effect_budget: 5,
        };
        let outstanding_reserved_effects = 3;
        let bounds = PostRevocationBounds::compute(
            RemoteEnforcementPoint::new(lease, MonotonicTime::ZERO).enforcement(),
            lease.ttl,
            Duration::from_secs(uncertainty_seconds),
            outstanding_reserved_effects,
            lease.effect_budget,
        )
        .unwrap();
        // A second point with a budget that never runs out shows the time bound alone.
        let unlimited = RemoteLease {
            ttl: lease.ttl,
            effect_budget: u64::MAX,
        };
        let mut worst_seconds = 0;
        for revoked_after_issue in 0..=ttl_seconds {
            for lag in 0..=uncertainty_seconds {
                let mut counted = RemoteEnforcementPoint::new(lease, at_seconds(0));
                let mut timed = RemoteEnforcementPoint::new(unlimited, at_seconds(0));
                let mut effects_after_revocation = outstanding_reserved_effects;
                let mut last_after_revocation = 0;
                // Host second h reads h - lag on the remote clock once the lag accrues.
                for host_second in revoked_after_issue..=ttl_seconds + 10 {
                    let remote = at_seconds(host_second.saturating_sub(lag));
                    if counted.try_effect(remote).is_ok() {
                        effects_after_revocation += 1;
                    }
                    if timed.try_effect(remote).is_ok() {
                        last_after_revocation = host_second - revoked_after_issue;
                    }
                }
                assert!(effects_after_revocation <= bounds.remaining_effects);
                assert!(
                    Duration::from_secs(last_after_revocation) < bounds.remaining_authorized_time
                );
                worst_seconds = worst_seconds.max(last_after_revocation);
            }
        }
        // Revoked at issue with the full lag: the last effect lands at 31 s, inside 32 s.
        assert_eq!(worst_seconds, ttl_seconds + uncertainty_seconds - 1);
    }

    #[test]
    fn acknowledgments_are_distinct_and_need_their_evidence() {
        let mut registry = RevocationRegistry::new();
        let sandbox = sandbox();
        assert_eq!(
            registry.acknowledge(
                &sandbox,
                RevocationAck::VmStopped,
                SourceClass::HostProbe,
                at_seconds(1)
            ),
            Err(AckRefusal::NotRevoked)
        );
        let record = registry.revoke(
            &sandbox,
            AuthorizationEpoch::new(4),
            RevocationReason::SecurityEvent,
            at_seconds(10),
        );
        assert_eq!(
            record.acks.keys().copied().collect::<Vec<_>>(),
            vec![RevocationAck::NewAuthorizationsDenied]
        );
        registry
            .acknowledge(
                &sandbox,
                RevocationAck::SocketsClosed,
                SourceClass::HostProbe,
                at_seconds(11),
            )
            .unwrap();
        let record = registry.record(&sandbox).unwrap();
        for ack in [
            RevocationAck::VmStopped,
            RevocationAck::ProviderStoppedBilling,
            RevocationAck::DiskCleanupFinished,
        ] {
            assert_eq!(record.acknowledged(ack), None, "{ack:?}");
        }
        assert_eq!(
            registry.acknowledge(
                &sandbox,
                RevocationAck::VmStopped,
                SourceClass::GuestReport,
                at_seconds(12)
            ),
            Err(AckRefusal::InsufficientSource {
                ack: RevocationAck::VmStopped,
                minimum: SourceClass::HostProbe,
                source: SourceClass::GuestReport
            })
        );
        assert!(registry
            .acknowledge(
                &sandbox,
                RevocationAck::ProviderStoppedBilling,
                SourceClass::GuestReport,
                at_seconds(12)
            )
            .is_err());
        registry
            .acknowledge(
                &sandbox,
                RevocationAck::ProviderStoppedBilling,
                SourceClass::ProviderApi,
                at_seconds(13),
            )
            .unwrap();
        assert_eq!(
            registry.acknowledge(
                &sandbox,
                RevocationAck::DiskCleanupFinished,
                SourceClass::HostProbe,
                at_seconds(9)
            ),
            Err(AckRefusal::BeforeLinearization)
        );
        let record = registry.record(&sandbox).unwrap();
        assert_eq!(record.acks.len(), 3);
        assert_eq!(record.acknowledged(RevocationAck::VmStopped), None);
        assert_eq!(
            RevocationAck::ALL.len(),
            RevocationAck::ALL.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    fn coordination_milestones_map_only_where_they_mean_the_same() {
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::NewAuthorizationsDenied),
            Some(RevocationAck::NewAuthorizationsDenied)
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::VmStopped),
            Some(RevocationAck::VmStopped)
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::CleanupFinished),
            Some(RevocationAck::DiskCleanupFinished)
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::LeasesClosed),
            None
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::GpuReclaimed),
            None
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::FirstDeniedAuthorization),
            None
        );
        assert_eq!(
            RevocationAck::from_milestone(RevocationMilestone::AllChannelsClosed),
            None
        );
    }

    #[test]
    fn tombstones_deny_older_epochs_never_lower_and_compact_only_when_safe() {
        let mut registry = RevocationRegistry::new();
        let sandbox = sandbox();
        let session = ClockSession::from_uuid(uuid::Uuid::from_u128(1));
        registry.revoke(
            &sandbox,
            AuthorizationEpoch::new(4),
            RevocationReason::UserRequested,
            at_seconds(10),
        );
        assert!(registry.denies(&sandbox, AuthorizationEpoch::new(3)));
        assert!(registry.denies(&sandbox, AuthorizationEpoch::new(4)));
        assert!(!registry.denies(&sandbox, AuthorizationEpoch::new(5)));
        registry.revoke(
            &sandbox,
            AuthorizationEpoch::new(2),
            RevocationReason::UserRequested,
            at_seconds(20),
        );
        let record = registry.record(&sandbox).unwrap();
        assert_eq!(record.revoked_through, AuthorizationEpoch::new(4));
        assert_eq!(record.linearized_at, at_seconds(10));

        let latest = Some((session, at_seconds(100)));
        // The authority still at the revoked epoch: kept.
        assert_eq!(
            registry.compact(
                at_seconds(200),
                session,
                SECOND,
                |_| Some(AuthorizationEpoch::new(4)),
                |_| latest
            ),
            0
        );
        // Past the epoch, but a capability could still be live within the uncertainty.
        assert_eq!(
            registry.compact(
                at_seconds(100),
                session,
                SECOND,
                |_| Some(AuthorizationEpoch::new(5)),
                |_| latest
            ),
            0
        );
        registry.note_uncertain(
            &sandbox,
            EffectId::new(digest("yougori/test/e/v1", &[b"x"])),
        );
        assert_eq!(
            registry.compact(
                at_seconds(101),
                session,
                SECOND,
                |_| Some(AuthorizationEpoch::new(5)),
                |_| latest
            ),
            0
        );
        registry.resolve_uncertain(
            &sandbox,
            &EffectId::new(digest("yougori/test/e/v1", &[b"x"])),
        );
        assert_eq!(
            registry.compact(
                at_seconds(101),
                session,
                SECOND,
                |_| Some(AuthorizationEpoch::new(5)),
                |_| latest
            ),
            1
        );
        assert!(registry.record(&sandbox).is_none());
        let json = serde_json::to_string(&registry).unwrap();
        assert_eq!(
            serde_json::from_str::<RevocationRegistry>(&json).unwrap(),
            registry
        );
    }
}
