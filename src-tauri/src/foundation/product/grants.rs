//! CORE-04 grant records as shown to the user (S2 CORE-04: "VM revocation blocks new child
//! work"; S2 CORE-07 "permissions"; VM part §6.3 step 1: "advances the durable epoch or
//! records a generation tombstone"; VM-W43; VM-W53: "what it can read/release"; VM-W54:
//! "revoke/stop operations").
//!
//! An execution's authority, a VM sandbox's or a labelled runtime's, grants its work more
//! than the authority itself: the network grants of its settings, and grants their issuer
//! named, such as a route or a scoped delegation, that leases are issued under or bound
//! to. Revoking the authority advances its authorization epoch and ends every grant under
//! it; revoking one grant records a tombstone under the execution instead and leaves the
//! epoch and every other grant in force. [`ExecutionGrants`] shows them as the coordinator
//! records them: the authorization epoch in force, the authority last granted and where it
//! stands when shown ([`AuthorityStanding`]), and each grant once, by its [`GrantId`], with
//! its [`GrantScope`], the leases in force that depend on it and its [`GrantStatus`]:
//!
//! - held: granted under the authority in force, honoured only while that authority is
//!   current and checked again at every use; it states what is granted, not that anything
//!   enforces it;
//! - lapsed: granted under an authority that is not in force when shown (revoked, expired,
//!   never granted or on another clock); a new authority grants it afresh;
//! - revoked: revoked in this run, with when and what its revocation cancelled, and never
//!   honoured under the execution again;
//! - tombstoned: revoked before the coordinator last recovered; only the persisted
//!   tombstone remains, and it is never granted again.
//!
//! These are the coordinator's own records of what it grants, not evidence about the
//! world, so none carries an evidence state and none can stand in for one. Whether a grant
//! is held is never stored on its own: it follows from the authority's standing when the
//! document is shown, recomputed when it is read and when it is shown again
//! ([`ExecutionGrants::as_of`]), so a stored document never shows a grant as held after
//! its authority expired or on another clock. CORE-04 is part of the foundation, so the
//! conversion from the coordinator is here ([`ExecutionGrants::of`]); it reads the
//! coordinator's records and decides nothing again.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::text::ShownText;
use super::view::ShownAt;
use crate::foundation::coordination::{
    network_grant_id, CapacityPort, Coordinator, LeaseState, RevokedGrant,
};
use crate::foundation::evidence::{AuthorityGrant, ClockReading, ClockSession, NetworkGrant};
use crate::foundation::ids::{AuthorizationEpoch, Clock, ExecutionId, GrantId, MonotonicTime};

/// Where an execution's authority stands when a document is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStanding {
    /// Granted under the epoch in force, on the clock the document is shown on, and not
    /// expired.
    InForce,
    /// The authorization epoch advanced past the authority granted.
    Revoked,
    /// It expired.
    Expired,
    /// No authority is granted now, such as before a sandbox's authority is active or
    /// after it stopped.
    NotGranted,
    /// Granted on another clock, such as before a restart, so it cannot be shown as in
    /// force.
    OtherClock,
}

impl AuthorityStanding {
    /// Where `authority`, under the authorization epoch in force `epoch`, stands at `at`
    /// on the clock `clock`.
    pub fn of(
        authority: Option<&AuthorityGrant>,
        epoch: AuthorizationEpoch,
        clock: ClockSession,
        at: MonotonicTime,
    ) -> Self {
        match authority {
            None => Self::NotGranted,
            Some(granted) if granted.epoch != epoch => Self::Revoked,
            Some(granted) if granted.clock != clock => Self::OtherClock,
            Some(granted) if at >= granted.expires_at => Self::Expired,
            Some(_) => Self::InForce,
        }
    }

    pub const fn is_in_force(self) -> bool {
        matches!(self, Self::InForce)
    }

    /// Why a grant under the authority is not held, in a person's words.
    const fn lapse(self) -> &'static str {
        match self {
            Self::InForce => "the authority is in force",
            Self::Revoked => "the authority it was granted under was revoked",
            Self::Expired => "the authority it was granted under expired",
            Self::NotGranted => "no authority is granted now",
            Self::OtherClock => {
                "the authority was granted on another clock, such as before a restart"
            }
        }
    }
}

strict_product_enum! {
    /// What one grant covers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GrantScope tag "scope" {
        /// A network grant of the authority's settings (VM part §1.3): a named route, a
        /// typed credentialed operation or a published service. Its identity is the
        /// coordinator's `network_grant_id` of it.
        Network { network: NetworkGrant },
        /// A grant its issuer named, such as a route or a scoped delegation, that work
        /// under the execution was issued under or bound to; it covers that work.
        Issued,
        /// A revoked grant whose scope this run did not record: only its identity is known.
        Unrecorded,
    }
}

strict_product_enum! {
    /// Where one grant stands.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GrantStatus tag "status" {
        /// Granted under the authority in force.
        Held,
        /// Granted under an authority that is not in force when shown.
        Lapsed,
        /// Revoked in this run at `at`: `cancelled_leases` leases bound to it were
        /// cancelled, the last to stop by `stop_by`, and `activations` model activations
        /// whose settings use it admit no request again. The authorization epoch and every
        /// other grant stayed in force.
        Revoked {
            at: MonotonicTime,
            cancelled_leases: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            stop_by: Option<MonotonicTime>,
            activations: u64,
        },
        /// Revoked before the coordinator last recovered: only its tombstone remains.
        Tombstoned,
    }
}

impl GrantStatus {
    /// Whether the grant was revoked under the execution, in this run or before.
    pub const fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. } | Self::Tombstoned)
    }
}

impl From<&RevokedGrant> for GrantStatus {
    fn from(revoked: &RevokedGrant) -> Self {
        Self::Revoked {
            at: revoked.at,
            cancelled_leases: count(revoked.cancellations.len()),
            stop_by: revoked
                .cancellations
                .iter()
                .map(|cancellation| cancellation.bound_at)
                .max(),
            activations: count(revoked.activations.len()),
        }
    }
}

fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// One grant as shown: its identity, what it covers, the leases in force that depend on
/// it, its status and the words a person reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantShown {
    grant: GrantId,
    scope: GrantScope,
    /// Leases issued under or bound to it that are neither released nor cancelled; an
    /// expired one is refused at its next check.
    leases: u64,
    status: GrantStatus,
    text: ShownText,
}

impl GrantShown {
    fn new(
        grant: GrantId,
        scope: GrantScope,
        leases: u64,
        status: GrantStatus,
        standing: AuthorityStanding,
    ) -> Self {
        Self {
            grant,
            scope,
            leases,
            status,
            text: ShownText::new(&words(grant, scope, leases, status, standing)),
        }
    }

    pub fn grant(&self) -> GrantId {
        self.grant
    }

    pub fn scope(&self) -> GrantScope {
        self.scope
    }

    pub fn leases(&self) -> u64 {
        self.leases
    }

    pub fn status(&self) -> GrantStatus {
        self.status
    }

    /// The words a person reads.
    pub fn text(&self) -> &ShownText {
        &self.text
    }

    /// A network grant's identity is its own; only a revoked grant's scope may be
    /// unrecorded; no lease in force depends on a revoked grant; a revocation's record is
    /// consistent; a grant is held exactly when the authority stands in force; and the
    /// words are the status's own.
    fn check(&self, standing: AuthorityStanding) -> Result<(), GrantError> {
        let grant = self.grant;
        if let GrantScope::Network { network } = &self.scope {
            if network_grant_id(network) != grant {
                return Err(GrantError::NotItsIdentity { grant });
            }
        }
        match self.status {
            GrantStatus::Held | GrantStatus::Lapsed if self.scope == GrantScope::Unrecorded => {
                return Err(GrantError::UnrecordedScope { grant });
            }
            GrantStatus::Held if !standing.is_in_force() => {
                return Err(GrantError::HeldWithoutAuthority { grant });
            }
            GrantStatus::Lapsed if standing.is_in_force() => {
                return Err(GrantError::LapsedUnderAuthority { grant });
            }
            GrantStatus::Revoked { .. } | GrantStatus::Tombstoned if self.leases != 0 => {
                return Err(GrantError::LeasesAfterRevocation { grant });
            }
            GrantStatus::Revoked {
                at,
                cancelled_leases,
                stop_by,
                ..
            } if stop_by.is_some() != (cancelled_leases > 0)
                || stop_by.is_some_and(|bound| bound < at) =>
            {
                return Err(GrantError::RevocationRecord { grant });
            }
            _ => {}
        }
        let expected = ShownText::new(&words(
            grant,
            self.scope,
            self.leases,
            self.status,
            standing,
        ));
        if self.text != expected {
            return Err(GrantError::Words { grant });
        }
        Ok(())
    }

    /// The grant under an authority now standing `standing`: a held or lapsed grant
    /// follows it, a revoked one stays revoked.
    fn under(&self, standing: AuthorityStanding) -> Self {
        let status = match self.status {
            GrantStatus::Held | GrantStatus::Lapsed if standing.is_in_force() => GrantStatus::Held,
            GrantStatus::Held | GrantStatus::Lapsed => GrantStatus::Lapsed,
            revoked => revoked,
        };
        Self::new(self.grant, self.scope, self.leases, status, standing)
    }
}

impl fmt::Display for GrantShown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text.as_str())
    }
}

impl<'de> Deserialize<'de> for GrantShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            grant: GrantId,
            scope: GrantScope,
            leases: u64,
            status: GrantStatus,
            text: ShownText,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            grant: wire.grant,
            scope: wire.scope,
            leases: wire.leases,
            status: wire.status,
            text: wire.text,
        })
    }
}

/// The first twelve hexadecimal digits of a digest, for a person to tell grants apart.
fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

/// The words of one grant.
fn words(
    grant: GrantId,
    scope: GrantScope,
    leases: u64,
    status: GrantStatus,
    standing: AuthorityStanding,
) -> String {
    let what = match scope {
        GrantScope::Network {
            network: NetworkGrant::NamedRoute { route },
        } => format!("network route {}", short(&route.to_hex())),
        GrantScope::Network {
            network: NetworkGrant::CredentialedOperation { operation },
        } => format!("credentialed operation {}", short(&operation.to_hex())),
        GrantScope::Network {
            network: NetworkGrant::PublishedService { service },
        } => format!("published service {}", short(&service.to_hex())),
        GrantScope::Issued => format!(
            "grant {} for work under this execution",
            short(&grant.to_string())
        ),
        GrantScope::Unrecorded => format!(
            "grant {}, whose scope this run did not record",
            short(&grant.to_string())
        ),
    };
    let depending = match leases {
        0 => String::new(),
        1 => " (1 lease in force depends on it)".to_owned(),
        many => format!(" ({many} leases in force depend on it)"),
    };
    let status = match status {
        GrantStatus::Held => "held under the authority in force; it is checked again at every \
                              use, and a grant states what is allowed, not that anything \
                              enforces it"
            .to_owned(),
        GrantStatus::Lapsed => format!("not held: {}", standing.lapse()),
        GrantStatus::Revoked {
            at,
            cancelled_leases,
            stop_by,
            activations,
        } => {
            let stop = stop_by.map_or_else(String::new, |bound| {
                format!(", to stop by {} ns", bound.as_nanos())
            });
            format!(
                "revoked at {} ns and never honoured under this execution again; \
                 {cancelled_leases} lease(s) cancelled{stop}; {activations} model \
                 activation(s) admit no request again; the authorization epoch and every \
                 other grant stay in force",
                at.as_nanos()
            )
        }
        GrantStatus::Tombstoned => "revoked before Yougori last recovered; only its \
                                    tombstone remains, and it is never granted again"
            .to_owned(),
    };
    format!("{what}{depending}: {status}")
}

/// The grants of one execution's authority as shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionGrants {
    execution: ExecutionId,
    /// The authorization epoch in force: revoking the authority advances it, revoking one
    /// grant leaves it.
    epoch: AuthorizationEpoch,
    /// The authority last granted, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<AuthorityGrant>,
    /// Where the authority stands when shown.
    standing: AuthorityStanding,
    /// Every grant once, by identity.
    grants: Vec<GrantShown>,
}

impl ExecutionGrants {
    /// The grants of `execution`'s authority as `coordinator` records them, shown at
    /// `now`, a reading of the evidence clock: the network grants of its settings, every
    /// grant a lease under it was issued under or bound to, and every grant revoked under
    /// it. A grant revoked in this run shows what its revocation cancelled; one revoked
    /// before the coordinator last recovered shows its tombstone. `None` when the
    /// coordinator knows no such execution. The tombstones are read from the state the
    /// coordinator would persist, which copies its records.
    pub fn of<C: Clock, P: CapacityPort>(
        coordinator: &Coordinator<C, P>,
        execution: &ExecutionId,
        now: ClockReading,
    ) -> Option<Self> {
        let (epoch, authority, settings) = match coordinator.sandbox(execution) {
            Some(sandbox) => (
                sandbox.generations().authorization,
                sandbox.authority(),
                sandbox.settings_grant(),
            ),
            None => {
                let record = coordinator.labelled_runtime(execution)?;
                (
                    record.epoch(),
                    Some(record.authority()),
                    record.settings_grant(),
                )
            }
        };
        let standing = AuthorityStanding::of(authority.as_ref(), epoch, now.session(), now.at());
        // What each grant covers: a network grant of the settings, or one a revocation in
        // this run withdrew from them; else one leases were issued under or bound to; else
        // a tombstone only.
        let mut scopes: BTreeMap<GrantId, GrantScope> = settings
            .network
            .iter()
            .map(|network| {
                (
                    network_grant_id(network),
                    GrantScope::Network { network: *network },
                )
            })
            .collect();
        let tombstones = coordinator
            .persist()
            .revoked_grants
            .remove(execution)
            .unwrap_or_default();
        for grant in &tombstones {
            if let Some(network) = coordinator
                .revoked_grant(execution, *grant)
                .and_then(|revoked| revoked.network)
            {
                scopes.insert(*grant, GrantScope::Network { network });
            }
        }
        let mut leases: BTreeMap<GrantId, u64> = BTreeMap::new();
        for record in coordinator
            .leases()
            .filter(|record| record.lease().parent() == execution)
        {
            for grant in record.lease().grants() {
                scopes.entry(*grant).or_insert(GrantScope::Issued);
                if matches!(record.state(), LeaseState::Active) {
                    *leases.entry(*grant).or_default() += 1;
                }
            }
        }
        for grant in tombstones {
            scopes.entry(grant).or_insert(GrantScope::Unrecorded);
        }
        let grants = scopes
            .into_iter()
            .map(|(grant, scope)| {
                let status = match coordinator.revoked_grant(execution, grant) {
                    Some(revoked) => GrantStatus::from(revoked),
                    None if coordinator.grant_revoked(execution, grant) => GrantStatus::Tombstoned,
                    None if standing.is_in_force() => GrantStatus::Held,
                    None => GrantStatus::Lapsed,
                };
                let depending = leases.get(&grant).copied().unwrap_or(0);
                GrantShown::new(grant, scope, depending, status, standing)
            })
            .collect();
        Some(Self {
            execution: execution.clone(),
            epoch,
            authority,
            standing,
            grants,
        })
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    pub fn authority(&self) -> Option<&AuthorityGrant> {
        self.authority.as_ref()
    }

    pub fn standing(&self) -> AuthorityStanding {
        self.standing
    }

    /// Every grant, in identity order.
    pub fn grants(&self) -> &[GrantShown] {
        &self.grants
    }

    /// The grant `grant`.
    pub fn grant(&self, grant: GrantId) -> Option<&GrantShown> {
        self.grants.iter().find(|shown| shown.grant == grant)
    }

    /// The records are consistent on their own: the authority is not from a later epoch
    /// than the one in force, the standing is one the records allow (not granted exactly
    /// without an authority, revoked exactly under an older epoch), every grant is listed
    /// once in identity order, and each is consistent with the standing shown
    /// ([`GrantShown`]).
    pub fn check_records(&self) -> Result<(), GrantError> {
        if self
            .authority
            .is_some_and(|authority| authority.epoch > self.epoch)
        {
            return Err(GrantError::AuthorityAfterEpoch);
        }
        let recorded = match self.authority {
            None => matches!(self.standing, AuthorityStanding::NotGranted),
            Some(authority) if authority.epoch != self.epoch => {
                matches!(self.standing, AuthorityStanding::Revoked)
            }
            Some(_) => !matches!(
                self.standing,
                AuthorityStanding::NotGranted | AuthorityStanding::Revoked
            ),
        };
        if !recorded {
            return Err(GrantError::StandingNotRecorded {
                shown: self.standing,
            });
        }
        if self
            .grants
            .windows(2)
            .any(|pair| pair[0].grant >= pair[1].grant)
        {
            return Err(GrantError::Order);
        }
        self.grants
            .iter()
            .try_for_each(|grant| grant.check(self.standing))
    }

    /// The records are consistent ([`ExecutionGrants::check_records`]) and the standing is
    /// where the authority stood when the document was shown.
    pub fn check(&self, shown: &ShownAt) -> Result<(), GrantError> {
        self.check_records()?;
        let standing =
            AuthorityStanding::of(self.authority.as_ref(), self.epoch, shown.clock, shown.at);
        if standing != self.standing {
            return Err(GrantError::Standing {
                shown: self.standing,
                actual: standing,
            });
        }
        Ok(())
    }

    /// The grants shown again at `now`: the authority's standing then, a held grant
    /// lapsing when the authority is no longer in force. Revocations are unchanged.
    pub fn as_of(&self, now: ClockReading) -> Self {
        let standing =
            AuthorityStanding::of(self.authority.as_ref(), self.epoch, now.session(), now.at());
        Self {
            execution: self.execution.clone(),
            epoch: self.epoch,
            authority: self.authority,
            standing,
            grants: self
                .grants
                .iter()
                .map(|grant| grant.under(standing))
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for ExecutionGrants {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            execution: ExecutionId,
            epoch: AuthorizationEpoch,
            #[serde(default)]
            authority: Option<AuthorityGrant>,
            standing: AuthorityStanding,
            grants: Vec<GrantShown>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let grants = Self {
            execution: wire.execution,
            epoch: wire.epoch,
            authority: wire.authority,
            standing: wire.standing,
            grants: wire.grants,
        };
        grants.check_records().map_err(serde::de::Error::custom)?;
        Ok(grants)
    }
}

/// Why grant records are inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// The authority shown is from a later epoch than the one in force.
    AuthorityAfterEpoch,
    /// The grants are not each listed once, in identity order.
    Order,
    /// A network grant is shown under another identity than its own.
    NotItsIdentity { grant: GrantId },
    /// A held or lapsed grant without its scope.
    UnrecordedScope { grant: GrantId },
    /// A grant shown as held while the authority is not in force.
    HeldWithoutAuthority { grant: GrantId },
    /// A grant shown as lapsed while the authority is in force.
    LapsedUnderAuthority { grant: GrantId },
    /// A lease in force depends on a revoked grant.
    LeasesAfterRevocation { grant: GrantId },
    /// A revocation names a stop bound without a cancelled lease, or the reverse, or one
    /// before the revocation.
    RevocationRecord { grant: GrantId },
    /// The words are not the grant's own.
    Words { grant: GrantId },
    /// The standing contradicts the records: not granted with an authority, revoked under
    /// the epoch in force, or the reverse.
    StandingNotRecorded { shown: AuthorityStanding },
    /// The standing is not where the authority stood when shown.
    Standing {
        shown: AuthorityStanding,
        actual: AuthorityStanding,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityAfterEpoch => {
                f.write_str("the authority shown is from a later epoch than the one in force")
            }
            Self::Order => f.write_str("every grant is listed once, in identity order"),
            Self::NotItsIdentity { grant } => {
                write!(f, "grant {grant} is not the identity of its network grant")
            }
            Self::UnrecordedScope { grant } => write!(
                f,
                "grant {grant} is not revoked, so what it covers is recorded"
            ),
            Self::HeldWithoutAuthority { grant } => write!(
                f,
                "grant {grant} is shown as held while the authority is not in force"
            ),
            Self::LapsedUnderAuthority { grant } => write!(
                f,
                "grant {grant} is shown as lapsed while the authority is in force"
            ),
            Self::LeasesAfterRevocation { grant } => {
                write!(f, "no lease in force depends on the revoked grant {grant}")
            }
            Self::RevocationRecord { grant } => write!(
                f,
                "the revocation of grant {grant} names a stop bound exactly when it cancelled \
                 a lease, never before the revocation"
            ),
            Self::Words { grant } => write!(f, "the words of grant {grant} are not its own"),
            Self::StandingNotRecorded { shown } => write!(
                f,
                "the authority is shown as {shown:?}, which its records contradict"
            ),
            Self::Standing { shown, actual } => write!(
                f,
                "the authority is shown as {shown:?} but stood {actual:?} when the document \
                 was shown"
            ),
        }
    }
}

impl std::error::Error for GrantError {}
