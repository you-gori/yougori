//! Authorized peers (table line 543): eligible immutable weights or explicitly
//! transferable state, served under an expiring authorization and a donor budget, and
//! planned with the peer's topology (§1.1 line 312: a congested donor may lose to NVMe).
//!
//! The authorization names the catalog scopes whose objects the peer may hold and serve,
//! when it ends, and how many bytes the donor agreed to serve. From its expiry on nothing
//! is offered or charged. Weights are model weights or their sidecars; state moves only
//! with its owning tenant's explicit consent. An offer must carry every shared link of
//! the peer's topology, so the planner counts them (T03). Whether the requester may read
//! the object at all is the catalog's scope rule, checked when sources are chosen.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::{checked_sum, Tier};
use crate::foundation::catalog::{ArtifactClass, Scope};
use crate::foundation::ids::{Clock, MonotonicTime, OperationId, TenantId};
use crate::model_memory::math::{CutId, SourceId};
use crate::model_memory::residency::eviction::{CopyTier, ReconstructibleCopy, Verification};

/// The authorization under which a peer donates (table line 543).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAuthorization {
    /// Scopes whose objects the peer may hold and serve.
    pub scopes: BTreeSet<Scope>,
    /// The authorization ends here: from this instant on nothing is served.
    pub expires_at: MonotonicTime,
    /// Bytes the donor agreed to serve under this authorization, in total.
    pub donor_budget_bytes: u64,
}

/// A tenant's explicit consent to move its state to a peer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferConsent {
    pub tenant: TenantId,
    pub operation: OperationId,
}

/// What a peer may hold (table line 543).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerContent {
    /// Immutable model weights or their sidecar.
    ImmutableWeights,
    /// State its owning tenant made transferable.
    TransferableState { consent: TransferConsent },
}

/// Why a peer refused (table line 543).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRefusal {
    ZeroBytes,
    /// The authorization has expired.
    Expired {
        expired_at: MonotonicTime,
    },
    /// The authorization does not name the object's scope.
    ScopeNotAuthorized {
        scope: Scope,
    },
    /// Only model weights and sidecars are eligible as weights.
    NotWeights {
        object: ObjectRef,
    },
    /// State without an owning tenant cannot be consented to.
    StateWithoutTenant {
        object: ObjectRef,
    },
    /// Consent comes from the state's own tenant only.
    ConsentFromAnotherTenant {
        consenting: TenantId,
        owner: TenantId,
    },
    AlreadyHeld {
        object: ObjectRef,
    },
    NotHeld {
        object: ObjectRef,
    },
    DonorBudgetExhausted {
        donor_budget_bytes: u64,
        served_bytes: u64,
        requested_bytes: u64,
    },
    /// The offer's path leaves out a shared link of the peer's topology.
    TopologyMissing {
        cut: CutId,
    },
    Overflow,
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBytes => f.write_str("a holding or charge has at least one byte"),
            Self::Expired { expired_at } => write!(
                f,
                "the peer's authorization expired at {} ns",
                expired_at.as_nanos()
            ),
            Self::ScopeNotAuthorized { scope } => {
                write!(f, "the peer is not authorized for objects of {scope}")
            }
            Self::NotWeights { object } => {
                write!(
                    f,
                    "{object} is not model weights, so it is not eligible as weights"
                )
            }
            Self::StateWithoutTenant { object } => {
                write!(f, "{object} has no tenant to consent to moving it")
            }
            Self::ConsentFromAnotherTenant { consenting, owner } => {
                write!(f, "{consenting} cannot consent for {owner}'s state")
            }
            Self::AlreadyHeld { object } => write!(f, "the peer already holds {object}"),
            Self::NotHeld { object } => write!(f, "the peer does not hold {object}"),
            Self::DonorBudgetExhausted {
                donor_budget_bytes,
                served_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} more bytes exceed the donor budget: {served_bytes} of \
                 {donor_budget_bytes} are served"
            ),
            Self::TopologyMissing { cut } => {
                write!(f, "the path leaves out the peer's shared link {cut}")
            }
            Self::Overflow => f.write_str("a byte total does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for PeerRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Holding {
    content: PeerContent,
    bytes: u64,
}

/// One authorized peer (table line 543).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSource {
    authorization: PeerAuthorization,
    topology: Vec<CutId>,
    served_bytes: u64,
    holdings: BTreeMap<ObjectRef, Holding>,
}

impl PeerSource {
    /// `topology` names the shared links between the peer and this host, such as a
    /// switch uplink or the host's network receive path.
    pub fn new(authorization: PeerAuthorization, topology: Vec<CutId>) -> Self {
        Self {
            authorization,
            topology,
            served_bytes: 0,
            holdings: BTreeMap::new(),
        }
    }

    pub fn authorization(&self) -> &PeerAuthorization {
        &self.authorization
    }

    pub fn served_bytes(&self) -> u64 {
        self.served_bytes
    }

    pub fn donor_remaining_bytes(&self) -> u64 {
        self.authorization
            .donor_budget_bytes
            .saturating_sub(self.served_bytes)
    }

    /// Whether the authorization is live now: strictly before its expiry.
    pub fn authorized(&self, clock: &dyn Clock) -> Result<(), PeerRefusal> {
        if clock.now() < self.authorization.expires_at {
            Ok(())
        } else {
            Err(PeerRefusal::Expired {
                expired_at: self.authorization.expires_at,
            })
        }
    }

    /// Records what the peer holds: weights of an authorized scope, or state with its
    /// owning tenant's consent.
    pub fn hold(
        &mut self,
        object: ObjectRef,
        content: PeerContent,
        bytes: u64,
    ) -> Result<(), PeerRefusal> {
        if bytes == 0 {
            return Err(PeerRefusal::ZeroBytes);
        }
        if !self.authorization.scopes.contains(&object.scope) {
            return Err(PeerRefusal::ScopeNotAuthorized {
                scope: object.scope,
            });
        }
        match &content {
            PeerContent::ImmutableWeights => {
                if !matches!(
                    object.class,
                    ArtifactClass::ModelWeights | ArtifactClass::ModelSidecar
                ) {
                    return Err(PeerRefusal::NotWeights { object });
                }
            }
            PeerContent::TransferableState { consent } => match object.tenant() {
                None => return Err(PeerRefusal::StateWithoutTenant { object }),
                Some(owner) if *owner != consent.tenant => {
                    return Err(PeerRefusal::ConsentFromAnotherTenant {
                        consenting: consent.tenant.clone(),
                        owner: owner.clone(),
                    })
                }
                Some(_) => {}
            },
        }
        if self.holdings.contains_key(&object) {
            return Err(PeerRefusal::AlreadyHeld { object });
        }
        self.holdings.insert(object, Holding { content, bytes });
        Ok(())
    }

    /// Charges bytes the donor served; refused after expiry or beyond the donor budget.
    pub fn charge(&mut self, bytes: u64, clock: &dyn Clock) -> Result<(), PeerRefusal> {
        self.authorized(clock)?;
        if bytes == 0 {
            return Err(PeerRefusal::ZeroBytes);
        }
        let total = checked_sum([self.served_bytes, bytes]).ok_or(PeerRefusal::Overflow)?;
        if total > self.authorization.donor_budget_bytes {
            return Err(PeerRefusal::DonorBudgetExhausted {
                donor_budget_bytes: self.authorization.donor_budget_bytes,
                served_bytes: self.served_bytes,
                requested_bytes: bytes,
            });
        }
        self.served_bytes = total;
        Ok(())
    }

    /// The peer's copy of the object. This host has not verified its bytes, and the
    /// authorization can expire, so it never reconstructs a dropped GPU copy (T08).
    pub fn copy_of(&self, object: &ObjectRef) -> Option<ObjectCopy> {
        self.holdings.get(object).map(|_| ObjectCopy {
            object: object.clone(),
            holder: None,
            copy: ReconstructibleCopy {
                tier: CopyTier::AuthorizedPeer,
                verification: Verification::Unverified,
            },
        })
    }

    /// Offers a held object to `requester` while the authorization is live and donor
    /// budget remains. The offer covers no more than the remaining donor budget, and its
    /// path must include the peer's topology. Whether the requester may read the object is
    /// the catalog's scope rule, checked when sources are chosen.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
        clock: &dyn Clock,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse =
            |refusal| OfferRefusal::new(&source, Tier::AuthorizedPeer, TierRefusal::Peer(refusal));
        self.authorized(clock).map_err(refuse)?;
        if !self.authorization.scopes.contains(&object.scope) {
            return Err(refuse(PeerRefusal::ScopeNotAuthorized {
                scope: object.scope.clone(),
            }));
        }
        let holding = self.holdings.get(object).ok_or_else(|| {
            refuse(PeerRefusal::NotHeld {
                object: object.clone(),
            })
        })?;
        if let Some(cut) = self.topology.iter().find(|cut| !path.cuts.contains(cut)) {
            return Err(refuse(PeerRefusal::TopologyMissing { cut: cut.clone() }));
        }
        let remaining_bytes = self.donor_remaining_bytes();
        if remaining_bytes == 0 {
            return Err(refuse(PeerRefusal::DonorBudgetExhausted {
                donor_budget_bytes: self.authorization.donor_budget_bytes,
                served_bytes: self.served_bytes,
                requested_bytes: holding.bytes,
            }));
        }
        let covers_bytes = holding.bytes.min(remaining_bytes);
        Ok(SourceOffer::new(
            Tier::AuthorizedPeer,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }
}

#[cfg(test)]
mod tests;
