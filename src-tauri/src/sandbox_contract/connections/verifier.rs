//! The authentication port of a private publication (VM §4.7: "private previews use
//! authentication and expiring access").
//!
//! The gate never interprets proof material. A [`ProofVerifier`] turns a proof into the
//! principal it proves and the end of its validity, for exactly one [`ProofBinding`]: one
//! publication of one sandbox under one authorization epoch. The gate hands the principal
//! to V02's [`IngressTable::admit`], which checks the publication's authentication mode
//! and audience, and closes a session admitted on a proof once that proof expires. Tests
//! fake the verifier.
//!
//! [`IngressTable::admit`]: crate::sandbox_contract::destinations::IngressTable::admit

use std::fmt;

use super::gate::GatePublicationId;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, MonotonicTime};
use crate::sandbox_contract::destinations::{AuthenticationMode, PrincipalId};

/// What an inbound caller presented: the mode it claims and the material that proves it
/// (a platform session, a bearer token, a client certificate's binding). The material is
/// never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationProof {
    mode: AuthenticationMode,
    material: Vec<u8>,
}

impl AuthenticationProof {
    pub fn new(mode: AuthenticationMode, material: impl Into<Vec<u8>>) -> Self {
        Self {
            mode,
            material: material.into(),
        }
    }

    /// The authentication mode the caller claims.
    pub const fn mode(&self) -> AuthenticationMode {
        self.mode
    }

    /// The proof material, for the verifier only.
    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

impl fmt::Debug for AuthenticationProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationProof")
            .field("mode", &self.mode)
            .field("material", &format_args!("<{} bytes>", self.material.len()))
            .finish()
    }
}

/// What a proof must have been issued for. The publication id is unique for the gate's
/// whole life ([`GatePublicationId`]), and the sandbox and authorization epoch are bound
/// besides, so a proof never carries over to another publication, another sandbox or a
/// later epoch. [`super::ConnectionGate::proof_binding`] gives it for a publication.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofBinding {
    pub sandbox: ExecutionId,
    pub epoch: AuthorizationEpoch,
    pub publication: GatePublicationId,
}

/// What a verifier proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    pub principal: PrincipalId,
    /// When the proof stops holding, on the shared clock. A session admitted on it closes
    /// then, whatever the publication's own expiry.
    pub valid_until: MonotonicTime,
}

/// Why a verifier refused a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofRefusal {
    /// The material does not prove anything.
    Invalid,
    /// The proof expired.
    Expired,
    /// The proof was issued for another binding: another publication, sandbox or epoch.
    /// Proofs never carry across.
    WrongPublication,
    /// The verifier does not handle this mode.
    UnsupportedMode { mode: AuthenticationMode },
}

impl fmt::Display for ProofRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("the authentication proof is invalid"),
            Self::Expired => f.write_str("the authentication proof expired"),
            Self::WrongPublication => {
                f.write_str("the authentication proof was issued for another publication")
            }
            Self::UnsupportedMode { mode } => {
                write!(f, "{mode:?} authentication is not verified here")
            }
        }
    }
}

impl std::error::Error for ProofRefusal {}

/// Verifies authentication proofs for publications that authenticate.
pub trait ProofVerifier {
    /// The principal `proof` proves for `binding` at `now`, in the proof's own mode, and
    /// until when. A proof must be bound to exactly the binding it was issued for.
    fn verify(
        &self,
        binding: &ProofBinding,
        proof: &AuthenticationProof,
        now: MonotonicTime,
    ) -> Result<VerifiedProof, ProofRefusal>;
}
