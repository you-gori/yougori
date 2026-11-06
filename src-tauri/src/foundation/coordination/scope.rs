//! Issuer- and host-scoped authority identities (S2 CORE-04; VM part §6.3: "Nonces and
//! generation numbers are scoped by host/issuer and sandbox identity ... never reuse an
//! identity while old valid capabilities can exist"; VM-W29: security-specific
//! generation/issuer identities bound to CORE-04's typed identities;
//! docs/combined-plan-remaining-only.md §8, S04 / M13 / M17).
//!
//! A bare authorization epoch is a counter: two hosts, two issuers on one host, two runs of
//! one coordinator and two sandboxes all count 1, 2, 3, … A [`ScopedEpoch`] binds the
//! epoch to the host and the issuer that issued it, the run of the coordination authority
//! ([`Incarnation`]) and the execution it belongs to. So an epoch from another host, issuer,
//! run or sandbox is never taken for the one in force, and a counter that a restart or a
//! restored snapshot set back hands out no identity that was already used: every recovery
//! raises the incarnation, which is handed out only once persisted
//! ([`Coordinator::current_incarnation`]), and the durable floor keeps it from going back
//! ([`AuthorityFloor`](super::AuthorityFloor)). A scoped epoch carries an authorization
//! epoch, never a model activation generation (S3.1): a model eviction, reactivation or
//! restored activation counter cannot make an old scoped epoch current.
//!
//! A [`ScopedGrant`] is a grant whose [`GrantId`] is derived from the scoped epoch it was
//! issued under, so it dies with that epoch: once the epoch advances or the coordinator
//! restarts, [`Coordinator::check_scoped_grant`] refuses it whether or not a tombstone
//! names it. Network grants of the authority's settings keep their unscoped identities
//! ([`network_grant_id`](super::network_grant_id)) and their tombstones.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::capacity::CapacityPort;
use super::coordinator::Coordinator;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, Digest, DigestBuilder, ExecutionId, GrantId, Incarnation,
};

/// The digest domain of [`ScopedEpoch::digest`].
const SCOPED_EPOCH_DOMAIN: &str = "yougori/coordination/scoped-epoch/v1";
/// The digest domain of [`ScopedGrant::id`].
const SCOPED_GRANT_DOMAIN: &str = "yougori/coordination/scoped-grant/v1";

macro_rules! scope_handle {
    ($(#[$doc:meta])* $name:ident, $domain:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            /// The digest domain of [`Self::named`].
            pub const DOMAIN: &'static str = $domain;

            /// The identity a digest names.
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            /// The identity named by text, such as a configured name.
            pub fn named(name: &str) -> Self {
                Self(digest(Self::DOMAIN, &[name.as_bytes()]))
            }

            /// The digest of the identity.
            pub const fn digest(self) -> Digest {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

scope_handle!(
    /// A host, by the digest of its enrolled identity, such as its host key (VM part
    /// §7.6).
    HostId,
    "yougori/coordination/host/v1"
);
scope_handle!(
    /// An authority that issues epochs, grants and nonces on a host, such as the
    /// coordination authority or a broker. Its digest domain is the one
    /// `sandbox/lifecycle/replay.rs` uses for its issuers, so that module can take this type
    /// without changing what it stores.
    IssuerId,
    "yougori/lifecycle/issuer/v1"
);

/// Who issued an identity: the host and the issuing authority on it (VM part §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityIssuer {
    pub host: HostId,
    pub issuer: IssuerId,
}

impl fmt::Display for AuthorityIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "issuer {} on host {}", self.issuer, self.host)
    }
}

/// An authorization epoch in its scope: the host and issuer that issued it, the run of the
/// coordination authority and the execution it belongs to (VM part §6.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEpoch {
    pub issuer: AuthorityIssuer,
    pub incarnation: Incarnation,
    pub execution: ExecutionId,
    pub authorization: AuthorizationEpoch,
}

impl ScopedEpoch {
    /// Where the epoch stands among the epochs of its issuer and execution: an earlier run
    /// comes first, then an earlier epoch of the same run.
    pub fn position(&self) -> (Incarnation, AuthorizationEpoch) {
        (self.incarnation, self.authorization)
    }

    /// Whether `other` is of the same issuer and execution, so the two can be ordered.
    pub fn same_line(&self, other: &Self) -> bool {
        self.issuer == other.issuer && self.execution == other.execution
    }

    /// The scoped epoch as one digest, bound to every part of the scope.
    pub fn digest(&self) -> Digest {
        DigestBuilder::new(SCOPED_EPOCH_DOMAIN)
            .digest(&self.issuer.host.digest())
            .digest(&self.issuer.issuer.digest())
            .u64(self.incarnation.get())
            .str(self.execution.as_str())
            .u64(self.authorization.get())
            .finish()
    }

    /// A grant issued under this epoch, named `local` by its issuer.
    pub fn grant(&self, local: Digest) -> ScopedGrant {
        ScopedGrant {
            epoch: self.clone(),
            local,
        }
    }
}

impl fmt::Display for ScopedEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authorization epoch {} of {} in run {} of {}",
            self.authorization, self.execution, self.incarnation, self.issuer
        )
    }
}

/// A grant issued under one scoped epoch, such as a scoped delegation (VM part §4.6). Its
/// identity binds the whole scope, so it is honoured only while that epoch is in force in
/// that run ([`Coordinator::check_scoped_grant`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedGrant {
    pub epoch: ScopedEpoch,
    /// What the issuer names the grant within the epoch.
    pub local: Digest,
}

impl ScopedGrant {
    /// The grant's identity: a digest of its scoped epoch and its local name. Leases are
    /// issued under it ([`Coordinator::start_granted_work`]) and its revocation tombstones
    /// it ([`Coordinator::revoke_grant`]).
    pub fn id(&self) -> GrantId {
        GrantId::from_digest(
            DigestBuilder::new(SCOPED_GRANT_DOMAIN)
                .digest(&self.epoch.digest())
                .digest(&self.local)
                .finish(),
        )
    }
}

/// Why a scoped identity is not honoured (VM part §6.3; VM-P13: wrongly scoped, cross-VM
/// and stale-generation capabilities fail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ScopeRefusal {
    /// Another host issued it.
    ForeignHost {
        presented: HostId,
        expected: HostId,
    },
    /// Another authority on the host issued it.
    ForeignIssuer {
        presented: IssuerId,
        expected: IssuerId,
    },
    /// The coordination authority's run is not persisted yet, so nothing is scoped by it:
    /// a crash now would recover the same run again.
    IncarnationNotPersisted,
    /// An earlier run issued it; recovery revives nothing.
    EarlierIncarnation {
        presented: Incarnation,
        current: Incarnation,
    },
    /// A run this authority has not reached: it did not issue it.
    UnknownIncarnation {
        presented: Incarnation,
        current: Incarnation,
    },
    UnknownExecution {
        execution: ExecutionId,
    },
    /// The execution's authorization epoch has advanced past it.
    StaleEpoch {
        presented: AuthorizationEpoch,
        current: AuthorizationEpoch,
    },
    /// An epoch the execution has not reached: this authority did not issue it.
    FutureEpoch {
        presented: AuthorizationEpoch,
        current: AuthorizationEpoch,
    },
    /// The execution was retired: nothing under it is honoured again
    /// ([`Coordinator::retire`]).
    Retired {
        execution: ExecutionId,
    },
    /// The grant was revoked under its execution (a tombstone).
    GrantRevoked {
        grant: GrantId,
    },
}

crate::foundation::strict_serde::strict_tag!(ScopeRefusal, "refusal");

impl fmt::Display for ScopeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignHost {
                presented,
                expected,
            } => write!(
                f,
                "issued on host {presented}, but this authority runs on host {expected}"
            ),
            Self::ForeignIssuer {
                presented,
                expected,
            } => write!(
                f,
                "issued by issuer {presented}, but this authority is issuer {expected}"
            ),
            Self::IncarnationNotPersisted => f.write_str(
                "the coordination authority's run is not persisted yet; nothing is scoped by it",
            ),
            Self::EarlierIncarnation { presented, current } => write!(
                f,
                "issued in run {presented} of the coordination authority, which is in run \
                 {current}; recovery revives nothing"
            ),
            Self::UnknownIncarnation { presented, current } => write!(
                f,
                "run {presented} was never reached; the coordination authority is in run \
                 {current}"
            ),
            Self::UnknownExecution { execution } => write!(f, "execution {execution} is unknown"),
            Self::StaleEpoch { presented, current } => write!(
                f,
                "authorization epoch {presented} is no longer in force; the execution is at \
                 {current}"
            ),
            Self::FutureEpoch { presented, current } => write!(
                f,
                "authorization epoch {presented} was never issued; the execution is at {current}"
            ),
            Self::Retired { execution } => write!(
                f,
                "execution {execution} was retired; nothing under it is honoured again"
            ),
            Self::GrantRevoked { grant } => write!(f, "grant {grant} was revoked"),
        }
    }
}

impl std::error::Error for ScopeRefusal {}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// The epoch in force for `execution`, a VM sandbox's or a labelled runtime's, scoped by
    /// `issuer` and this run (VM part §6.3). Refused until this run is persisted
    /// ([`Coordinator::confirm_persisted`]), for an unknown execution and for a retired one.
    pub fn scoped_epoch(
        &self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
    ) -> Result<ScopedEpoch, ScopeRefusal> {
        let incarnation = self
            .current_incarnation()
            .map_err(|_| ScopeRefusal::IncarnationNotPersisted)?;
        let authorization = self.epoch_in_force(execution)?;
        Ok(ScopedEpoch {
            issuer,
            incarnation,
            execution: execution.clone(),
            authorization,
        })
    }

    /// Whether `presented` names the epoch in force now, issued by `issuer` in this run:
    /// another host or issuer, an earlier or unknown run, an epoch the execution has left or
    /// not reached, and a retired execution are refused. Enforcement points that receive a
    /// scoped epoch check it here.
    pub fn check_scoped_epoch(
        &self,
        issuer: AuthorityIssuer,
        presented: &ScopedEpoch,
    ) -> Result<(), ScopeRefusal> {
        if presented.issuer.host != issuer.host {
            return Err(ScopeRefusal::ForeignHost {
                presented: presented.issuer.host,
                expected: issuer.host,
            });
        }
        if presented.issuer.issuer != issuer.issuer {
            return Err(ScopeRefusal::ForeignIssuer {
                presented: presented.issuer.issuer,
                expected: issuer.issuer,
            });
        }
        let current = self.scoped_epoch(issuer, &presented.execution)?;
        if presented.incarnation < current.incarnation {
            return Err(ScopeRefusal::EarlierIncarnation {
                presented: presented.incarnation,
                current: current.incarnation,
            });
        }
        if presented.incarnation > current.incarnation {
            return Err(ScopeRefusal::UnknownIncarnation {
                presented: presented.incarnation,
                current: current.incarnation,
            });
        }
        if presented.authorization < current.authorization {
            return Err(ScopeRefusal::StaleEpoch {
                presented: presented.authorization,
                current: current.authorization,
            });
        }
        if presented.authorization > current.authorization {
            return Err(ScopeRefusal::FutureEpoch {
                presented: presented.authorization,
                current: current.authorization,
            });
        }
        Ok(())
    }

    /// A grant issued now under the epoch in force for `execution`, named `local` by
    /// `issuer` ([`ScopedEpoch::grant`]).
    pub fn scoped_grant(
        &self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
        local: Digest,
    ) -> Result<ScopedGrant, ScopeRefusal> {
        Ok(self.scoped_epoch(issuer, execution)?.grant(local))
    }

    /// Whether `presented` is honoured now: its epoch is the one in force in this run
    /// ([`Coordinator::check_scoped_epoch`]) and its identity was not revoked. Returns that
    /// identity, under which leases are issued and bound
    /// ([`Coordinator::start_granted_work`], [`Coordinator::bind_grants`]).
    pub fn check_scoped_grant(
        &self,
        issuer: AuthorityIssuer,
        presented: &ScopedGrant,
    ) -> Result<GrantId, ScopeRefusal> {
        self.check_scoped_epoch(issuer, &presented.epoch)?;
        let grant = presented.id();
        if self.grant_revoked(&presented.epoch.execution, grant) {
            return Err(ScopeRefusal::GrantRevoked { grant });
        }
        Ok(grant)
    }

    /// The authorization epoch in force for `execution`: its sandbox's or its labelled
    /// runtime's. A retired sandbox has none.
    pub(super) fn epoch_in_force(
        &self,
        execution: &ExecutionId,
    ) -> Result<AuthorizationEpoch, ScopeRefusal> {
        if let Some(sandbox) = self.sandboxes.get(execution) {
            let generations = sandbox.generations();
            if generations.is_retired() {
                return Err(ScopeRefusal::Retired {
                    execution: execution.clone(),
                });
            }
            return Ok(generations.authorization);
        }
        self.labelled
            .get(execution)
            .map(|record| record.epoch())
            .ok_or_else(|| ScopeRefusal::UnknownExecution {
                execution: execution.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(host: &str, name: &str) -> AuthorityIssuer {
        AuthorityIssuer {
            host: HostId::named(host),
            issuer: IssuerId::named(name),
        }
    }

    fn epoch(issuer: AuthorityIssuer, run: u64, of: &str, value: u64) -> ScopedEpoch {
        ScopedEpoch {
            issuer,
            incarnation: Incarnation::new(run),
            execution: ExecutionId::new(of).unwrap(),
            authorization: AuthorizationEpoch::new(value),
        }
    }

    #[test]
    fn every_part_of_the_scope_changes_the_identity() {
        let base = epoch(issuer("host-a", "coordinator"), 1, "exe-1", 2);
        let local = digest("yougori/test/grant/v1", &[b"route"]);
        let variants = [
            epoch(issuer("host-b", "coordinator"), 1, "exe-1", 2),
            epoch(issuer("host-a", "broker"), 1, "exe-1", 2),
            epoch(issuer("host-a", "coordinator"), 2, "exe-1", 2),
            epoch(issuer("host-a", "coordinator"), 1, "exe-2", 2),
            epoch(issuer("host-a", "coordinator"), 1, "exe-1", 3),
        ];
        for variant in &variants {
            assert_ne!(variant.digest(), base.digest());
            assert_ne!(variant.grant(local).id(), base.grant(local).id());
        }
        assert_eq!(base.grant(local).id(), base.clone().grant(local).id());
        assert_ne!(
            base.grant(local).id(),
            base.grant(digest("yougori/test/grant/v1", &[b"other"]))
                .id()
        );
        assert!(base.same_line(&epoch(issuer("host-a", "coordinator"), 9, "exe-1", 1)));
        assert!(!base.same_line(&variants[0]));
        assert!(
            epoch(issuer("host-a", "coordinator"), 1, "exe-1", 9).position()
                < epoch(issuer("host-a", "coordinator"), 2, "exe-1", 1).position()
        );
    }

    #[test]
    fn the_issuer_domain_is_the_lifecycle_replay_guards() {
        assert_eq!(IssuerId::DOMAIN, "yougori/lifecycle/issuer/v1");
        assert_eq!(
            IssuerId::named("host-a").digest(),
            digest("yougori/lifecycle/issuer/v1", &[b"host-a"])
        );
        assert_ne!(
            HostId::named("host-a").digest(),
            IssuerId::named("host-a").digest()
        );
    }

    #[test]
    fn scoped_identities_read_back_strictly() {
        let scoped = epoch(issuer("host-a", "coordinator"), 3, "exe-1", 4);
        let json = serde_json::to_value(&scoped).unwrap();
        assert_eq!(
            serde_json::from_value::<ScopedEpoch>(json.clone()).unwrap(),
            scoped
        );
        let mut extra = json;
        extra["boot"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ScopedEpoch>(extra).is_err());
        let grant = scoped.grant(digest("yougori/test/grant/v1", &[b"route"]));
        let json = serde_json::to_value(&grant).unwrap();
        assert_eq!(serde_json::from_value::<ScopedGrant>(json).unwrap(), grant);
    }
}
