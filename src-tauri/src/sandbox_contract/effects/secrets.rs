//! Secret classes and opaque credential handles (VM part §4.5 lines 1991–2008; VM-W28).
//!
//! Six classes with distinct treatment (§4.5 table, lines 1995–2002). Only the three
//! external credential classes can back an executor, and an executor never receives
//! one: it gets a typed operation and a [`CredentialHandle`], an opaque reference into
//! the host vault with no method that yields secret bytes (§4.5 line 2004). A signed
//! download URL is a bearer capability and so a credential, never "non-secret". A
//! sandbox-local secret cannot authorize host or external privileges, user private
//! content is confidential without being a key, and a canary is a detection artifact
//! that can never become a genuine credential.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::description::{CostCeiling, RouteRef};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::foundation::transfer::CredentialRef;

/// The §4.5 secret classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    /// Remains in the vault or executor; never intentionally delivered to the workload.
    LongLivedProviderCredential,
    /// Scope, audience, expiry and delegated budget explicit; still a credential.
    ShortLivedCapability,
    /// A bearer capability, not "non-secret"; kept out of the guest in the strict profile.
    SignedDownloadUrl,
    /// May exist in the guest; cannot authorize host or external privileges.
    SandboxLocalSecret,
    /// Confidential data requiring a release policy.
    UserPrivateContent,
    /// A detection artifact; never a genuine production credential.
    FakeCanary,
}

/// The sandbox profile a decision about guest exposure is made for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureProfile {
    /// The external-credentials-out-of-guest profile.
    Strict,
    Standard,
}

/// Whether a secret of a class may be placed in the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestExposure {
    Never,
    /// Only with explicit scope, audience, expiry and delegated budget.
    WithExplicitTerms,
    /// Only under a data-access grant; release out of the sandbox needs release policy.
    WithDataGrant,
    Allowed,
}

impl SecretClass {
    pub const ALL: [Self; 6] = [
        Self::LongLivedProviderCredential,
        Self::ShortLivedCapability,
        Self::SignedDownloadUrl,
        Self::SandboxLocalSecret,
        Self::UserPrivateContent,
        Self::FakeCanary,
    ];

    /// Whether possession grants access outside the sandbox: the three external
    /// credential classes, the signed URL included.
    pub const fn is_external_credential(self) -> bool {
        matches!(
            self,
            Self::LongLivedProviderCredential
                | Self::ShortLivedCapability
                | Self::SignedDownloadUrl
        )
    }

    /// Every class is confidential: none is "non-secret" (§4.5 lines 1999 and 2001).
    pub const fn is_confidential(self) -> bool {
        true
    }

    /// Whether release out of the sandbox needs release policy. True for every class; a
    /// canary's release is what detection looks for.
    pub const fn needs_release_policy(self) -> bool {
        true
    }

    /// Whether the class can stand for a genuine credential; a canary never can.
    pub const fn is_genuine(self) -> bool {
        !matches!(self, Self::FakeCanary)
    }

    /// The §4.5 guest treatment in `profile`.
    pub const fn guest_exposure(self, profile: ExposureProfile) -> GuestExposure {
        match (self, profile) {
            (Self::LongLivedProviderCredential, _) => GuestExposure::Never,
            (Self::ShortLivedCapability, ExposureProfile::Strict) => GuestExposure::Never,
            (Self::ShortLivedCapability, ExposureProfile::Standard) => {
                GuestExposure::WithExplicitTerms
            }
            (Self::SignedDownloadUrl, ExposureProfile::Strict) => GuestExposure::Never,
            (Self::SignedDownloadUrl, ExposureProfile::Standard) => {
                GuestExposure::WithExplicitTerms
            }
            (Self::SandboxLocalSecret, _) => GuestExposure::Allowed,
            (Self::UserPrivateContent, _) => GuestExposure::WithDataGrant,
            (Self::FakeCanary, _) => GuestExposure::Allowed,
        }
    }
}

/// The explicit terms of a short-lived external capability (§4.5 line 1998).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShortLivedTerms {
    /// The digest of the provider-side scope.
    pub scope: Digest,
    /// The one route it is good for.
    pub audience: RouteRef,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
    pub delegated_budget: CostCeiling,
}

strict_tagged_enum! {
    /// An external credential class with what its class requires.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ExternalCredential (tag = "class", wire = ExternalCredentialWire, wire_name = "ExternalCredentialWire") {
        LongLivedProvider,
        ShortLived { terms: ShortLivedTerms },
        /// A bearer capability for one route until its expiry.
        SignedDownloadUrl { audience: RouteRef, clock: ClockSession, expires_at: MonotonicTime },
    }
}

impl ExternalCredential {
    pub const fn class(&self) -> SecretClass {
        match self {
            Self::LongLivedProvider => SecretClass::LongLivedProviderCredential,
            Self::ShortLived { .. } => SecretClass::ShortLivedCapability,
            Self::SignedDownloadUrl { .. } => SecretClass::SignedDownloadUrl,
        }
    }
}

/// An opaque reference to an external credential in the host vault (§4.5 line 2004).
/// It holds no secret bytes and has no method that returns any; the provider adapter
/// resolves it inside the vault boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialHandle {
    reference: CredentialRef,
    credential: ExternalCredential,
}

impl CredentialHandle {
    pub const fn new(reference: CredentialRef, credential: ExternalCredential) -> Self {
        Self {
            reference,
            credential,
        }
    }

    /// A handle for a secret of `class`; refused for every class that is not an external
    /// credential, so a sandbox-local secret, private content or a canary can never back
    /// an executor.
    pub fn for_class(
        reference: CredentialRef,
        class: SecretClass,
        credential: ExternalCredential,
    ) -> Result<Self, CredentialRefusal> {
        if !class.is_external_credential() {
            return Err(CredentialRefusal::NotAnExternalCredential { class });
        }
        if credential.class() != class {
            return Err(CredentialRefusal::ClassMismatch {
                declared: class,
                terms: credential.class(),
            });
        }
        Ok(Self::new(reference, credential))
    }

    pub const fn reference(&self) -> CredentialRef {
        self.reference
    }

    pub const fn class(&self) -> SecretClass {
        self.credential.class()
    }

    pub const fn credential(&self) -> &ExternalCredential {
        &self.credential
    }

    /// Whether the credential may be used for `route` at `now` on `session`.
    pub fn usable_for(
        &self,
        route: RouteRef,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), CredentialRefusal> {
        let (audience, clock, expires_at) = match self.credential {
            ExternalCredential::LongLivedProvider => return Ok(()),
            ExternalCredential::ShortLived { terms } => {
                (terms.audience, terms.clock, terms.expires_at)
            }
            ExternalCredential::SignedDownloadUrl {
                audience,
                clock,
                expires_at,
            } => (audience, clock, expires_at),
        };
        if audience != route {
            return Err(CredentialRefusal::WrongAudience);
        }
        if clock != session {
            return Err(CredentialRefusal::OtherClock);
        }
        if now >= expires_at {
            return Err(CredentialRefusal::Expired { expires_at });
        }
        Ok(())
    }
}

/// A canary planted to detect leaks (§4.5 line 2002). It has no conversion into a
/// [`CredentialHandle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryToken {
    pub marker: Digest,
}

impl CanaryToken {
    pub const fn class(&self) -> SecretClass {
        SecretClass::FakeCanary
    }

    /// Whether the marker's text form appears in `bytes`.
    pub fn appears_in(&self, bytes: &[u8]) -> bool {
        let marker = self.marker.to_hex();
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }
}

strict_tagged_enum! {
    /// Why a credential handle was refused or cannot be used.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CredentialRefusal (tag = "refusal", wire = CredentialRefusalWire, wire_name = "CredentialRefusalWire") {
        NotAnExternalCredential { class: SecretClass },
        ClassMismatch { declared: SecretClass, terms: SecretClass },
        WrongAudience,
        OtherClock,
        Expired { expires_at: MonotonicTime },
    }
}

impl fmt::Display for CredentialRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnExternalCredential { class } => write!(
                f,
                "a {class:?} cannot authorize an external operation; only an external \
                 credential in the host vault can"
            ),
            Self::ClassMismatch { declared, terms } => {
                write!(
                    f,
                    "declared {declared:?} but its terms are those of {terms:?}"
                )
            }
            Self::WrongAudience => f.write_str("the credential is for another route"),
            Self::OtherClock => f.write_str("the credential's expiry is on another clock session"),
            Self::Expired { expires_at } => {
                write!(f, "the credential expired at {} ns", expires_at.as_nanos())
            }
        }
    }
}

impl std::error::Error for CredentialRefusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn reference() -> CredentialRef {
        CredentialRef::from_digest(digest("yougori/test/vault/v1", &[b"key"]))
    }

    fn route(name: &str) -> RouteRef {
        RouteRef::new(digest("yougori/test/route/v1", &[name.as_bytes()]))
    }

    #[test]
    fn the_section_4_5_table_is_encoded_class_by_class() {
        use ExposureProfile::{Standard, Strict};
        use GuestExposure::*;
        let table = [
            (SecretClass::LongLivedProviderCredential, Never, Never, true),
            (
                SecretClass::ShortLivedCapability,
                Never,
                WithExplicitTerms,
                true,
            ),
            (
                SecretClass::SignedDownloadUrl,
                Never,
                WithExplicitTerms,
                true,
            ),
            (SecretClass::SandboxLocalSecret, Allowed, Allowed, false),
            (
                SecretClass::UserPrivateContent,
                WithDataGrant,
                WithDataGrant,
                false,
            ),
            (SecretClass::FakeCanary, Allowed, Allowed, false),
        ];
        for (class, strict, standard, external) in table {
            assert_eq!(class.guest_exposure(Strict), strict, "{class:?}");
            assert_eq!(class.guest_exposure(Standard), standard, "{class:?}");
            assert_eq!(class.is_external_credential(), external, "{class:?}");
            assert!(class.is_confidential());
            assert!(class.needs_release_policy());
        }
        assert_eq!(table.len(), SecretClass::ALL.len());
    }

    #[test]
    fn a_signed_download_url_is_a_credential_never_non_secret() {
        let class = SecretClass::SignedDownloadUrl;
        assert!(class.is_confidential());
        assert!(class.is_external_credential());
        assert_eq!(
            class.guest_exposure(ExposureProfile::Strict),
            GuestExposure::Never
        );
    }

    #[test]
    fn local_secrets_private_content_and_canaries_cannot_back_an_executor() {
        for class in [
            SecretClass::SandboxLocalSecret,
            SecretClass::UserPrivateContent,
            SecretClass::FakeCanary,
        ] {
            assert_eq!(
                CredentialHandle::for_class(
                    reference(),
                    class,
                    ExternalCredential::LongLivedProvider
                ),
                Err(CredentialRefusal::NotAnExternalCredential { class })
            );
        }
        assert!(!SecretClass::FakeCanary.is_genuine());
        assert!(SecretClass::ALL
            .iter()
            .filter(|class| **class != SecretClass::FakeCanary)
            .all(|class| class.is_genuine()));
        assert_eq!(
            CredentialHandle::for_class(
                reference(),
                SecretClass::ShortLivedCapability,
                ExternalCredential::LongLivedProvider
            ),
            Err(CredentialRefusal::ClassMismatch {
                declared: SecretClass::ShortLivedCapability,
                terms: SecretClass::LongLivedProviderCredential
            })
        );
        let canary = CanaryToken {
            marker: digest("yougori/test/canary/v1", &[b"c"]),
        };
        assert_eq!(canary.class(), SecretClass::FakeCanary);
        assert!(canary.appears_in(format!("x{}y", canary.marker).as_bytes()));
        assert!(!canary.appears_in(b"nothing here"));
    }

    #[test]
    fn short_lived_terms_are_explicit_and_enforced() {
        let session = ClockSession::from_uuid(uuid::Uuid::from_u128(1));
        let terms = ShortLivedTerms {
            scope: digest("yougori/test/scope/v1", &[b"repo:write"]),
            audience: route("github"),
            clock: session,
            expires_at: MonotonicTime::from_nanos(100),
            delegated_budget: CostCeiling {
                max_spend_microunits: 0,
                max_volume_units: 10,
            },
        };
        let handle = CredentialHandle::for_class(
            reference(),
            SecretClass::ShortLivedCapability,
            ExternalCredential::ShortLived { terms },
        )
        .unwrap();
        assert_eq!(
            handle.usable_for(route("github"), MonotonicTime::from_nanos(99), session),
            Ok(())
        );
        assert_eq!(
            handle.usable_for(route("other"), MonotonicTime::from_nanos(1), session),
            Err(CredentialRefusal::WrongAudience)
        );
        assert_eq!(
            handle.usable_for(route("github"), MonotonicTime::from_nanos(100), session),
            Err(CredentialRefusal::Expired {
                expires_at: MonotonicTime::from_nanos(100)
            })
        );
        assert_eq!(
            handle.usable_for(
                route("github"),
                MonotonicTime::from_nanos(1),
                ClockSession::from_uuid(uuid::Uuid::from_u128(2))
            ),
            Err(CredentialRefusal::OtherClock)
        );
        // The handle's serialized form is the reference and the terms, never a secret.
        let json = serde_json::to_value(handle).unwrap();
        assert_eq!(
            serde_json::from_value::<CredentialHandle>(json).unwrap(),
            handle
        );
    }
}
