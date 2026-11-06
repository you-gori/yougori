//! Resident advertisements (§3.2, line 506: "A resident advertisement is a hint with an
//! expiry and generation, not authority to read the data. Recheck compatibility and
//! authorization before serving or transferring").
//!
//! An advertisement only says where to look. Using one checks it against the
//! authoritative record: it must be unexpired, made under the current authority binding
//! (S3.1), of the current activation generation and in agreement with the record; the
//! resident execution identity must be the one required; and a scoped grant the catalog
//! still backs must authorize the use. Only a passing recheck makes a
//! [`RecheckedResidency`], so holding one proves the recheck happened.

use std::fmt;
use std::ops::Deref;

use crate::foundation::ids::{
    AuthorizationEpoch, Clock, GpuDeviceKey, ModelActivationGeneration, MonotonicTime, TenantId,
    TrustScope,
};

use super::fields::AuthorityBinding;
use super::layers::{ArtifactIdentity, ExecutionIdentity};
use super::sharing::{check_grant, GrantNeed, GrantRefusal, GrantedUse, ScopedGrant};

/// What is resident where (§3.2 item 5), and the authority it is bound to (S3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Residency {
    pub execution: ExecutionIdentity,
    pub artifact: ArtifactIdentity,
    pub owner: TenantId,
    pub scope: TrustScope,
    pub device: GpuDeviceKey,
    pub authority: AuthorityBinding,
}

/// A hint that a residency exists, with its activation generation and an expiry on the
/// shared monotonic clock (line 506). Never authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentAdvertisement {
    pub residency: Residency,
    pub generation: ModelActivationGeneration,
    pub expires_at: MonotonicTime,
}

/// The authoritative record of a residency and its current activation generation, from
/// the coordinator rather than from the advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentResidency {
    pub residency: Residency,
    pub generation: ModelActivationGeneration,
}

/// What the advertisement would be used for (line 506 "serving or transferring").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvertisementPurpose {
    /// Serve requests from the resident copy, inside its trust scope.
    Serve,
    /// Copy the artifact's bytes to `recipient`.
    Transfer { recipient: TrustScope },
}

/// Who wants to use an advertisement, and for what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisementRequest {
    pub requester: TenantId,
    /// The execution identity the request needs; only an equal identity is compatible.
    pub required: ExecutionIdentity,
    pub purpose: AdvertisementPurpose,
}

/// What a passing recheck established (line 506): the authoritative residency, its
/// activation generation and how long the recheck holds. Read through a
/// [`RecheckedResidency`]; on its own it proves nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecheckedFacts {
    pub residency: Residency,
    pub generation: ModelActivationGeneration,
    /// The earlier of the advertisement's and the grant's expiries.
    pub valid_until: MonotonicTime,
}

/// A residency rechecked against the authority, usable until `valid_until`: the earlier
/// of the advertisement's and the grant's expiries (line 506).
///
/// Only [`ResidentAdvertisement::recheck`] makes one, so a function that takes it knows
/// the recheck passed. Its [`RecheckedFacts`] are read through `Deref` and cannot be
/// changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecheckedResidency {
    facts: RecheckedFacts,
}

impl RecheckedResidency {
    /// What the recheck established.
    pub fn facts(&self) -> &RecheckedFacts {
        &self.facts
    }

    /// The facts, giving up the proof.
    pub fn into_facts(self) -> RecheckedFacts {
        self.facts
    }
}

impl Deref for RecheckedResidency {
    type Target = RecheckedFacts;

    fn deref(&self) -> &RecheckedFacts {
        &self.facts
    }
}

/// Why an advertisement may not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvertisementRefusal {
    Expired {
        expires_at: MonotonicTime,
        now: MonotonicTime,
    },
    /// Made under another authority binding than the current record's, as before a
    /// revocation raised the VM authorization epoch (S3.1). Both epochs are named; a
    /// binding that differs only in parent execution or runtime category is refused the
    /// same way.
    AuthorityChanged {
        advertised_epoch: Option<AuthorizationEpoch>,
        current_epoch: Option<AuthorizationEpoch>,
    },
    OlderGeneration {
        advertised: ModelActivationGeneration,
        current: ModelActivationGeneration,
    },
    /// Newer than the authority knows, so it cannot be checked.
    AheadOfAuthority {
        advertised: ModelActivationGeneration,
        current: ModelActivationGeneration,
    },
    /// The advertisement's residency differs from the authoritative record.
    DisagreesWithAuthority,
    /// The resident execution identity is not the one required.
    Incompatible,
    Unauthorized(GrantRefusal),
}

impl fmt::Display for AdvertisementRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { expires_at, now } => write!(
                f,
                "the advertisement expired at {} ns; it is now {} ns",
                expires_at.as_nanos(),
                now.as_nanos()
            ),
            Self::AuthorityChanged {
                advertised_epoch,
                current_epoch,
            } => write!(
                f,
                "the advertisement was made under authorization epoch {}; the current record is under {}",
                epoch_text(*advertised_epoch),
                epoch_text(*current_epoch)
            ),
            Self::OlderGeneration {
                advertised,
                current,
            } => write!(
                f,
                "the advertisement is for activation {advertised}; the current one is {current}"
            ),
            Self::AheadOfAuthority {
                advertised,
                current,
            } => write!(
                f,
                "the advertisement claims activation {advertised}, newer than the recorded {current}"
            ),
            Self::DisagreesWithAuthority => {
                f.write_str("the advertisement disagrees with the authoritative record")
            }
            Self::Incompatible => {
                f.write_str("the resident execution identity is not the one required")
            }
            Self::Unauthorized(refusal) => write!(f, "the use is not authorized: {refusal}"),
        }
    }
}

impl std::error::Error for AdvertisementRefusal {}

fn epoch_text(epoch: Option<AuthorizationEpoch>) -> String {
    epoch.map_or_else(|| "none".to_owned(), |epoch| epoch.to_string())
}

impl ResidentAdvertisement {
    /// Line 506 and S3.1: checks expiry, authority binding, generation, agreement with
    /// `current`, compatibility and authorization, in that order, before anything is
    /// served or transferred. Authorization asks the catalog again whether it still backs
    /// `grant` (INT-05).
    pub fn recheck(
        &self,
        current: &CurrentResidency,
        request: &AdvertisementRequest,
        grant: Option<&ScopedGrant>,
        clock: &dyn Clock,
    ) -> Result<RecheckedResidency, AdvertisementRefusal> {
        let now = clock.now();
        if now >= self.expires_at {
            return Err(AdvertisementRefusal::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        if self.residency.authority != current.residency.authority {
            return Err(AdvertisementRefusal::AuthorityChanged {
                advertised_epoch: self.residency.authority.epoch(),
                current_epoch: current.residency.authority.epoch(),
            });
        }
        if self.generation < current.generation {
            return Err(AdvertisementRefusal::OlderGeneration {
                advertised: self.generation,
                current: current.generation,
            });
        }
        if self.generation > current.generation {
            return Err(AdvertisementRefusal::AheadOfAuthority {
                advertised: self.generation,
                current: current.generation,
            });
        }
        if self.residency != current.residency {
            return Err(AdvertisementRefusal::DisagreesWithAuthority);
        }
        if current.residency.execution != request.required {
            return Err(AdvertisementRefusal::Incompatible);
        }
        let (scope, granted_use) = match &request.purpose {
            AdvertisementPurpose::Serve => (&current.residency.scope, GrantedUse::Serve),
            AdvertisementPurpose::Transfer { recipient } => (recipient, GrantedUse::Transfer),
        };
        let need = GrantNeed {
            owner: &current.residency.owner,
            grantee: &request.requester,
            artifact: &current.residency.artifact,
            scope,
            granted_use,
        };
        let grant_expires_at =
            check_grant(grant, &need, now).map_err(AdvertisementRefusal::Unauthorized)?;
        Ok(RecheckedResidency {
            facts: RecheckedFacts {
                residency: current.residency.clone(),
                generation: current.generation,
                valid_until: grant_expires_at.min(self.expires_at),
            },
        })
    }
}
