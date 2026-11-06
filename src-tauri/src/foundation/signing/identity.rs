//! CORE-08 signed component identity (S2 CORE-08, line 217: "Signed component identity
//! ... are reported consistently"; GPU-W11, line 1321: "authenticated pinned artifact
//! identity"; VM-W45, line 2668; S08 in docs/combined-plan-leftover-tasks.md: "a
//! signed-component field in the report's BuildIdentity").
//!
//! A [`SignedComponent`] records one verification of a publisher's signature over a
//! domain-separated statement: the artifact class, the publisher key's identity, the
//! statement digest, the calendar time of the check and the outcome, a refusal included
//! with its typed reason. Its only constructor runs the verification
//! ([`SignedComponent::check`], or the service's `identify`), so a component never
//! claims a verification nobody ran; the statement is kept, so a reader holding the
//! signature can verify it again ([`SignedComponent::reverify`]).
//!
//! [`SignedBuildIdentity`] is the record a run's build carries them in: the report's
//! [`BuildIdentity`] and the components of that build. It is a record of its own beside
//! the [`RunRecord`] rather than a field of `BuildIdentity`, because the report schema
//! refuses every other schema version when read: a new field would make the stored
//! version-3 records unreadable (the measurement sink reads its records back) and change
//! every place a `BuildIdentity` is built. This way the version-3 form is unchanged and
//! old records stay readable; a run's components are joined to its record by the build
//! ([`SignedBuildIdentity::describes`]). The record uses the report's schema version and
//! refuses any other version when read, typed, like the report's own records.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::roots::{KeyRefusal, RootKeyId, TrustRoots};
use super::service::has_keys;
use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::Digest;
use crate::foundation::report::{
    BuildIdentity, Label, ReportError, RunRecord, SchemaVersion, SCHEMA_VERSION,
};

/// Most components one [`SignedBuildIdentity`] lists.
pub const MAX_SIGNED_COMPONENTS: usize = 256;

fn key_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RootKeyId, D::Error> {
    RootKeyId::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// The outcome of one verification. Every variant other than [`Self::Verified`] is a
/// refusal: no key of the trust roots vouched for the statement then.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ComponentVerification {
    /// The trust-root key `key` vouched for the statement.
    Verified {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
    },
    /// No trust-root file was in force.
    NoTrustRoots {},
    /// The trust roots list no key that may sign the class.
    NoKeysForClass {},
    /// No key of the trust roots is the publisher's.
    UnknownPublisher {},
    /// The publisher's key is revoked.
    Revoked {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
        reason: Label,
    },
    /// The publisher's key may not sign the class.
    ClassNotAllowed {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
    },
    /// The publisher's key was not valid yet.
    NotYetValid {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
        valid_from: DateTime<Utc>,
    },
    /// The publisher's key had expired.
    Expired {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
        valid_until: DateTime<Utc>,
    },
    /// The signature does not verify under the publisher's key.
    BadSignature {
        #[serde(deserialize_with = "key_id")]
        key: RootKeyId,
    },
}

crate::foundation::strict_serde::strict_tag!(ComponentVerification, "outcome");

impl ComponentVerification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The trust-root key the outcome names, if a key of the roots was the publisher's.
    pub fn key(&self) -> Option<&RootKeyId> {
        match self {
            Self::Verified { key }
            | Self::Revoked { key, .. }
            | Self::ClassNotAllowed { key }
            | Self::NotYetValid { key, .. }
            | Self::Expired { key, .. }
            | Self::BadSignature { key } => Some(key),
            Self::NoTrustRoots {} | Self::NoKeysForClass {} | Self::UnknownPublisher {} => None,
        }
    }

    fn refused(refusal: KeyRefusal) -> Self {
        match refusal {
            KeyRefusal::UnknownPublisher { .. } => Self::UnknownPublisher {},
            KeyRefusal::Revoked { key, reason } => Self::Revoked { key, reason },
            KeyRefusal::ClassNotAllowed { key, .. } => Self::ClassNotAllowed { key },
            KeyRefusal::NotYetValid { key, valid_from } => Self::NotYetValid { key, valid_from },
            KeyRefusal::Expired { key, valid_until } => Self::Expired { key, valid_until },
            KeyRefusal::Signature { key, .. } => Self::BadSignature { key },
        }
    }
}

/// One signed component of a build: what was verified, by whom, over which statement,
/// when, and with which outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedComponent {
    class: ArtifactClass,
    /// The publisher key's identity: its fingerprint, the same in the catalog and in the
    /// sandbox update client.
    publisher: PublisherId,
    /// The domain-separated statement the signature covers.
    statement: Digest,
    /// The calendar time key windows were judged at.
    checked_at: DateTime<Utc>,
    verification: ComponentVerification,
}

impl SignedComponent {
    /// Verifies `signature` as `publisher`'s over `statement` about an artifact of
    /// `class` under `roots` at `at`, and records the outcome.
    pub fn check(
        roots: &TrustRoots,
        class: ArtifactClass,
        publisher: &PublisherId,
        statement: Digest,
        signature: &[u8],
        at: DateTime<Utc>,
    ) -> Self {
        let verification = if has_keys(roots, class) {
            match roots.verify_statement(publisher, class, &statement, signature, at) {
                Ok(key) => ComponentVerification::Verified {
                    key: key.id().clone(),
                },
                Err(refusal) => ComponentVerification::refused(refusal),
            }
        } else {
            ComponentVerification::NoKeysForClass {}
        };
        Self::unchecked(class, *publisher, statement, at, verification)
    }

    /// A refusal decided without trust roots to check against.
    pub(super) fn unchecked(
        class: ArtifactClass,
        publisher: PublisherId,
        statement: Digest,
        checked_at: DateTime<Utc>,
        verification: ComponentVerification,
    ) -> Self {
        Self {
            class,
            publisher,
            statement,
            checked_at,
            verification,
        }
    }

    /// Verifies the same statement again with `signature` under `roots` at `at`.
    pub fn reverify(&self, roots: &TrustRoots, signature: &[u8], at: DateTime<Utc>) -> Self {
        Self::check(
            roots,
            self.class,
            &self.publisher,
            self.statement,
            signature,
            at,
        )
    }

    pub fn class(&self) -> ArtifactClass {
        self.class
    }

    pub fn publisher(&self) -> &PublisherId {
        &self.publisher
    }

    pub fn statement(&self) -> &Digest {
        &self.statement
    }

    pub fn checked_at(&self) -> DateTime<Utc> {
        self.checked_at
    }

    pub fn verification(&self) -> &ComponentVerification {
        &self.verification
    }

    pub fn is_verified(&self) -> bool {
        self.verification.is_verified()
    }
}

/// Why a [`SignedBuildIdentity`] was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum SignedBuildError {
    /// Another schema version, or text that is not such a record: the report's own
    /// typed refusals ([`ReportError::UnsupportedSchemaVersion`], [`ReportError::Malformed`]).
    Report(ReportError),
    /// More than [`MAX_SIGNED_COMPONENTS`] components.
    TooManyComponents { found: usize, max: usize },
    /// The same statement about the same class is listed twice.
    DuplicateComponent {
        class: ArtifactClass,
        statement: Digest,
    },
}

impl fmt::Display for SignedBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Report(error) => write!(f, "{error}"),
            Self::TooManyComponents { found, max } => write!(
                f,
                "the build lists {found} signed components; at most {max}"
            ),
            Self::DuplicateComponent { class, statement } => write!(
                f,
                "the {class} statement {} is listed twice",
                statement.to_hex()
            ),
        }
    }
}

impl std::error::Error for SignedBuildError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBuildWire {
    schema_version: SchemaVersion,
    build: BuildIdentity,
    components: Vec<SignedComponent>,
}

/// A build's signed components (S2 CORE-08): the report's [`BuildIdentity`] and every
/// verification of the components it ran, each with its outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SignedBuildWire")]
pub struct SignedBuildIdentity {
    schema_version: SchemaVersion,
    build: BuildIdentity,
    components: Vec<SignedComponent>,
}

impl TryFrom<SignedBuildWire> for SignedBuildIdentity {
    type Error = SignedBuildError;

    fn try_from(wire: SignedBuildWire) -> Result<Self, Self::Error> {
        let SchemaVersion = wire.schema_version;
        Self::new(wire.build, wire.components)
    }
}

impl SignedBuildIdentity {
    /// The record of `build` with `components`; at most [`MAX_SIGNED_COMPONENTS`], each
    /// class and statement once.
    pub fn new(
        build: BuildIdentity,
        components: Vec<SignedComponent>,
    ) -> Result<Self, SignedBuildError> {
        if components.len() > MAX_SIGNED_COMPONENTS {
            return Err(SignedBuildError::TooManyComponents {
                found: components.len(),
                max: MAX_SIGNED_COMPONENTS,
            });
        }
        let mut seen = BTreeSet::new();
        for component in &components {
            if !seen.insert((component.class, component.statement)) {
                return Err(SignedBuildError::DuplicateComponent {
                    class: component.class,
                    statement: component.statement,
                });
            }
        }
        Ok(Self {
            schema_version: SchemaVersion,
            build,
            components,
        })
    }

    /// Reads a record from JSON. Another schema version is refused for its version
    /// before anything else is read, never reinterpreted.
    pub fn from_json(json: &str) -> Result<Self, SignedBuildError> {
        #[derive(Deserialize)]
        struct Versioned {
            schema_version: u64,
        }
        let malformed = |error: serde_json::Error| {
            SignedBuildError::Report(ReportError::Malformed {
                line: error.line(),
                column: error.column(),
            })
        };
        let Versioned { schema_version } = serde_json::from_str(json).map_err(malformed)?;
        if schema_version != u64::from(SCHEMA_VERSION) {
            return Err(SignedBuildError::Report(
                ReportError::UnsupportedSchemaVersion {
                    found: schema_version,
                },
            ));
        }
        let wire: SignedBuildWire = serde_json::from_str(json).map_err(malformed)?;
        Self::try_from(wire)
    }

    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    pub fn components(&self) -> &[SignedComponent] {
        &self.components
    }

    /// The components whose signature a trust-root key vouched for.
    pub fn verified(&self) -> impl Iterator<Item = &SignedComponent> {
        self.components
            .iter()
            .filter(|component| component.is_verified())
    }

    /// Whether every listed component verified (true for a build listing none).
    pub fn all_verified(&self) -> bool {
        self.components.iter().all(SignedComponent::is_verified)
    }

    /// Whether `record` ran this build.
    pub fn describes(&self, record: &RunRecord) -> bool {
        record.build == self.build
    }
}
