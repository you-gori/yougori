//! The OCI importer's publisher-signature port over the configured trust roots (VM-W48,
//! plan line 2671: "publisher policies ... wrong signatures"; §8.3, line 2455: "revoked
//! releases and key rotation"; V10's `sandbox_contract::oci::PublisherSignatures`).
//!
//! [`TrustRootSignatures`] answers the port with the foundation's
//! [`TrustRoots::verify_statement`](crate::foundation::signing::TrustRoots::verify_statement)
//! for [`ArtifactClass::OciLayer`], under the roots in force ([`SharedTrustRoots`], so a
//! reloaded file applies to the next check) at the calendar time a [`TrustCalendar`]
//! gives. The statement is the OCI importer's own (`oci::manifest_statement`, domain
//! `yougori/oci/manifest-statement/v1`); this module adds no domain.
//!
//! The port has two refusals. A key that may not vouch for OCI layers now (revoked, not
//! allowed the class, or outside its validity window) is reported as
//! [`SignatureRefusal::UnknownPublisher`], since no usable key is known for the publisher,
//! and only a signature that does not verify under a usable key is
//! [`SignatureRefusal::BadSignature`]. [`TrustRootSignatures::check`] keeps the typed
//! [`KeyRefusal`]. Accepting a signature is authenticity only; whether the publisher is
//! trusted stays the catalog policy's call.

use std::fmt;
use std::sync::Arc;

use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::Digest;
use crate::foundation::signing::{KeyRefusal, RootKeyId, SharedTrustRoots, TrustCalendar};
use crate::sandbox_contract::oci::{PublisherSignatures, SignatureRefusal};

/// OCI publisher signatures checked against the configured trust roots.
#[derive(Clone)]
pub struct TrustRootSignatures {
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
}

impl fmt::Debug for TrustRootSignatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRootSignatures")
            .field("keys", &self.roots.current().keys().count())
            .finish_non_exhaustive()
    }
}

impl TrustRootSignatures {
    /// Checks signatures under the roots in force in `roots`, at `calendar`'s time.
    pub fn new(roots: SharedTrustRoots, calendar: Arc<dyn TrustCalendar>) -> Self {
        Self { roots, calendar }
    }

    /// The trust-root key that vouches for `statement` as `publisher`'s for OCI layers
    /// now, or the typed reason none does.
    pub fn check(
        &self,
        publisher: &PublisherId,
        statement: &Digest,
        signature: &[u8],
    ) -> Result<RootKeyId, KeyRefusal> {
        self.roots
            .current()
            .verify_statement(
                publisher,
                ArtifactClass::OciLayer,
                statement,
                signature,
                self.calendar.now(),
            )
            .map(|key| key.id().clone())
    }
}

impl PublisherSignatures for TrustRootSignatures {
    fn verify(
        &self,
        publisher: &PublisherId,
        statement: &Digest,
        signature: &[u8],
    ) -> Result<(), SignatureRefusal> {
        self.check(publisher, statement, signature)
            .map(|_| ())
            .map_err(|refusal| signature_refusal(&refusal))
    }
}

/// The port's refusal for a trust-root refusal.
fn signature_refusal(refusal: &KeyRefusal) -> SignatureRefusal {
    match refusal {
        KeyRefusal::UnknownPublisher { .. }
        | KeyRefusal::Revoked { .. }
        | KeyRefusal::ClassNotAllowed { .. }
        | KeyRefusal::NotYetValid { .. }
        | KeyRefusal::Expired { .. } => SignatureRefusal::UnknownPublisher,
        KeyRefusal::Signature { .. } => SignatureRefusal::BadSignature,
    }
}
