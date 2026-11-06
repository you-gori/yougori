//! Nonces, generations and tombstones (VM part §6.3 lines 2321–2323; VM-W29 line 2635).
//!
//! Nonces and generation numbers are scoped by issuer and sandbox identity, so a nonce
//! accepted under one issuer or sandbox says nothing about another. Replay protection is
//! persisted across restarts. A revoked generation leaves a tombstone, and a tombstone is
//! compacted only once no valid capability bound to it can exist: the latest expiry of
//! such a capability plus the allowed clock uncertainty has passed. An identity below a
//! tombstone is never accepted again.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::leases::SkewPolicy;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Digest, ExecutionId, MonotonicTime, SandboxBootGeneration,
};

/// The host or issuer a nonce or generation is scoped by (§6.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerId(Digest);

impl IssuerId {
    pub const DOMAIN: &'static str = "yougori/lifecycle/issuer/v1";

    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// An issuer named by text.
    pub fn named(name: &str) -> Self {
        Self(digest(Self::DOMAIN, &[name.as_bytes()]))
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuerId({})", self.0)
    }
}

impl fmt::Display for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A nonce as the issuer numbered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(u64);

impl Nonce {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What a nonce is scoped by: the issuer, the sandbox and the generations it was issued
/// under (§6.3 "scoped by host/issuer and sandbox identity").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceScope {
    pub issuer: IssuerId,
    pub sandbox: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub authorization: AuthorizationEpoch,
}

/// A revoked generation (§6.3 "records a generation tombstone").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub issuer: IssuerId,
    pub sandbox: ExecutionId,
    /// The epoch no longer honoured; nothing at or below it is accepted again.
    pub epoch: AuthorizationEpoch,
    pub recorded_at: MonotonicTime,
    /// The latest a capability bound to the epoch could be honoured anywhere, before
    /// clock uncertainty.
    pub latest_capability_expiry: MonotonicTime,
}

impl Tombstone {
    /// When no valid capability bound to this generation can exist any more.
    pub fn safe_to_compact_at(&self, skew: &SkewPolicy) -> MonotonicTime {
        self.latest_capability_expiry
            .saturating_add(skew.allowed_clock_uncertainty)
    }
}

/// Why a nonce was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReplayRefusal {
    /// The nonce was already accepted under this scope.
    Replayed { scope: NonceScope, nonce: Nonce },
    /// The scope's generation is at or below a tombstone.
    TombstonedGeneration {
        scope: NonceScope,
        tombstoned: AuthorizationEpoch,
    },
}

crate::foundation::strict_serde::strict_tag!(ReplayRefusal, "refusal");

impl fmt::Display for ReplayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replayed { scope, nonce } => write!(
                f,
                "nonce {} was already used for sandbox {} under issuer {} at authorization \
                 epoch {}",
                nonce.get(),
                scope.sandbox,
                scope.issuer,
                scope.authorization
            ),
            Self::TombstonedGeneration { scope, tombstoned } => write!(
                f,
                "authorization epoch {} of sandbox {} is at or below tombstoned epoch {}",
                scope.authorization, scope.sandbox, tombstoned
            ),
        }
    }
}

impl std::error::Error for ReplayRefusal {}

/// Why a tombstone was kept at compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum KeptReason {
    /// A capability bound to the generation may still be honoured until `until`.
    CapabilityMayExist { until: MonotonicTime },
}

crate::foundation::strict_serde::strict_tag!(KeptReason, "reason");

/// What a compaction did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompactionReport {
    pub removed: Vec<Tombstone>,
    pub kept: Vec<(Tombstone, KeptReason)>,
}

/// Persisted replay protection and tombstones (§6.3; VM-W29).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayGuard {
    /// Every nonce accepted, with its scope.
    seen: BTreeSet<(NonceScope, Nonce)>,
    tombstones: Vec<Tombstone>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest tombstoned epoch of `sandbox` under `issuer`, if any.
    pub fn tombstoned_epoch(
        &self,
        issuer: IssuerId,
        sandbox: &ExecutionId,
    ) -> Option<AuthorizationEpoch> {
        self.tombstones
            .iter()
            .filter(|tombstone| tombstone.issuer == issuer && &tombstone.sandbox == sandbox)
            .map(|tombstone| tombstone.epoch)
            .max()
    }

    /// Accepts `nonce` under `scope` once. A replay, or a scope at or below a tombstone,
    /// is refused.
    pub fn accept(&mut self, scope: NonceScope, nonce: Nonce) -> Result<(), ReplayRefusal> {
        if let Some(tombstoned) = self.tombstoned_epoch(scope.issuer, &scope.sandbox) {
            if scope.authorization <= tombstoned {
                return Err(ReplayRefusal::TombstonedGeneration { scope, tombstoned });
            }
        }
        if !self.seen.insert((scope.clone(), nonce)) {
            return Err(ReplayRefusal::Replayed { scope, nonce });
        }
        Ok(())
    }

    /// Records a tombstone. Recording the same generation again keeps the later expiry.
    pub fn record_tombstone(&mut self, tombstone: Tombstone) {
        if let Some(existing) = self.tombstones.iter_mut().find(|existing| {
            existing.issuer == tombstone.issuer
                && existing.sandbox == tombstone.sandbox
                && existing.epoch == tombstone.epoch
        }) {
            existing.latest_capability_expiry = existing
                .latest_capability_expiry
                .max(tombstone.latest_capability_expiry);
            return;
        }
        self.tombstones.push(tombstone);
    }

    pub fn tombstones(&self) -> &[Tombstone] {
        &self.tombstones
    }

    /// How many nonces are remembered.
    pub fn remembered_nonces(&self) -> usize {
        self.seen.len()
    }

    /// Removes the tombstones, and the nonces of their scopes, whose generation no valid
    /// capability can be bound to any more at `now` under `skew`. A tombstone that a
    /// capability may still be bound to is kept, so an identity is never reused while old
    /// valid capabilities can exist (§6.3).
    pub fn compact(&mut self, now: MonotonicTime, skew: &SkewPolicy) -> CompactionReport {
        let mut report = CompactionReport::default();
        let mut remaining = Vec::with_capacity(self.tombstones.len());
        for tombstone in self.tombstones.drain(..) {
            let until = tombstone.safe_to_compact_at(skew);
            if now > until {
                report.removed.push(tombstone);
            } else {
                report
                    .kept
                    .push((tombstone.clone(), KeptReason::CapabilityMayExist { until }));
                remaining.push(tombstone);
            }
        }
        self.tombstones = remaining;
        for removed in &report.removed {
            self.seen.retain(|(scope, _)| {
                !(scope.issuer == removed.issuer
                    && scope.sandbox == removed.sandbox
                    && scope.authorization <= removed.epoch)
            });
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn scope(issuer: &str, sandbox: &str, epoch: u64) -> NonceScope {
        NonceScope {
            issuer: IssuerId::named(issuer),
            sandbox: ExecutionId::new(sandbox).unwrap(),
            boot: SandboxBootGeneration::FIRST,
            authorization: AuthorizationEpoch::new(epoch),
        }
    }

    fn skew() -> SkewPolicy {
        SkewPolicy {
            allowed_clock_uncertainty: Duration::from_secs(30),
        }
    }

    #[test]
    fn nonces_are_scoped_by_issuer_and_sandbox_and_replay_persists() {
        let mut guard = ReplayGuard::new();
        guard
            .accept(scope("host-a", "exe-1", 1), Nonce::new(7))
            .unwrap();
        assert_eq!(
            guard.accept(scope("host-a", "exe-1", 1), Nonce::new(7)),
            Err(ReplayRefusal::Replayed {
                scope: scope("host-a", "exe-1", 1),
                nonce: Nonce::new(7)
            })
        );
        guard
            .accept(scope("host-b", "exe-1", 1), Nonce::new(7))
            .unwrap();
        guard
            .accept(scope("host-a", "exe-2", 1), Nonce::new(7))
            .unwrap();
        let persisted: ReplayGuard =
            serde_json::from_str(&serde_json::to_string(&guard).unwrap()).unwrap();
        let mut restarted = persisted;
        assert!(matches!(
            restarted.accept(scope("host-a", "exe-1", 1), Nonce::new(7)),
            Err(ReplayRefusal::Replayed { .. })
        ));
        assert_eq!(restarted.remembered_nonces(), 3);
    }

    #[test]
    fn a_tombstoned_generation_is_never_accepted_again() {
        let mut guard = ReplayGuard::new();
        guard.record_tombstone(Tombstone {
            issuer: IssuerId::named("host-a"),
            sandbox: ExecutionId::new("exe-1").unwrap(),
            epoch: AuthorizationEpoch::new(2),
            recorded_at: at(10),
            latest_capability_expiry: at(100),
        });
        for epoch in [1, 2] {
            assert_eq!(
                guard.accept(scope("host-a", "exe-1", epoch), Nonce::new(1)),
                Err(ReplayRefusal::TombstonedGeneration {
                    scope: scope("host-a", "exe-1", epoch),
                    tombstoned: AuthorizationEpoch::new(2)
                })
            );
        }
        guard
            .accept(scope("host-a", "exe-1", 3), Nonce::new(1))
            .unwrap();
        guard
            .accept(scope("host-b", "exe-1", 1), Nonce::new(1))
            .unwrap();
    }

    #[test]
    fn tombstones_compact_only_when_no_valid_capability_can_exist() {
        let mut guard = ReplayGuard::new();
        guard
            .accept(scope("host-a", "exe-1", 1), Nonce::new(1))
            .unwrap();
        let tombstone = Tombstone {
            issuer: IssuerId::named("host-a"),
            sandbox: ExecutionId::new("exe-1").unwrap(),
            epoch: AuthorizationEpoch::new(1),
            recorded_at: at(10),
            latest_capability_expiry: at(100),
        };
        guard.record_tombstone(tombstone.clone());
        let early = guard.compact(at(130), &skew());
        assert!(early.removed.is_empty());
        assert_eq!(
            early.kept,
            vec![(
                tombstone.clone(),
                KeptReason::CapabilityMayExist { until: at(130) }
            )],
            "at exactly expiry plus uncertainty a capability may still be honoured"
        );
        assert_eq!(guard.tombstones().len(), 1);
        assert_eq!(guard.remembered_nonces(), 1);
        guard.record_tombstone(Tombstone {
            latest_capability_expiry: at(150),
            ..tombstone.clone()
        });
        assert_eq!(
            guard.tombstones().len(),
            1,
            "the later expiry replaces the earlier"
        );
        assert!(guard.compact(at(180), &skew()).removed.is_empty());
        let late = guard.compact(at(181), &skew());
        assert_eq!(late.removed.len(), 1);
        assert!(guard.tombstones().is_empty());
        assert_eq!(guard.remembered_nonces(), 0);
    }
}
