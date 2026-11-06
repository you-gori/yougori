//! The publisher's signature over a feature manifest, verified under the owner's trust
//! roots (§8.3, line 2453: "verify signed artifact metadata before execution"; VM-W05,
//! line 2590: "signed artifacts from the first release"; VM-W45, line 2668; S2 CORE-08:
//! "An unauthenticated checksum is not a release trust root"; VM-CP-23, line 3173: "an
//! unsigned manifest ... refused").
//!
//! The publisher signs, with Ed25519, `foundation::signing`'s content statement about the
//! manifest's canonical bytes as an artifact of class `guest_image`: its publisher
//! identity, the class, the bytes' content key and their length ([`signing_statement`]).
//! It is the statement the catalog's `SignedArtifactVerifier` authenticates for
//! `guest_image` objects under `StatementBinding::Content`, so a manifest stored in the
//! catalog (S02) carries the same attestation. The manifest binds the build record by
//! its content key, and the record and manifest bind every artifact by content key, so
//! one signature covers the release.
//!
//! [`verify_release`] runs in this order, so only authenticated bytes are parsed: the
//! size bound; a missing signature; the signature, checked by
//! `foundation::signing::SignedComponent::check` under the trust roots at the calendar
//! time given (key, class, validity window and revocation all apply), kept as the
//! CORE-08 [`SignedComponent`] whatever the outcome; the manifest read strictly; the
//! record's bytes against the content key the manifest names, before they are read; the
//! record read strictly; then [`FeatureManifest::bind`].

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::canonical::DocumentError;
use super::manifest::{BindingError, FeatureManifest, ManifestError, MAX_MANIFEST_BYTES};
use super::record::{BuildRecord, RecordError, MAX_RECORD_BYTES};
use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::{ContentKey, Digest};
use crate::foundation::signing::{
    content_statement, ComponentVerification, RootKeyId, SignedComponent, TrustRoots,
};
use crate::sandbox::trust::{HexBytes, UnixSeconds};

/// The artifact class a guest image manifest is signed as.
pub const MANIFEST_CLASS: ArtifactClass = ArtifactClass::GuestImage;

/// A publisher's detached signature over one manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// The publisher key's fingerprint (`Ed25519PublicKey::publisher_id`).
    pub publisher: PublisherId,
    pub signature: HexBytes,
}

/// The statement `publisher` signs for the manifest whose canonical bytes are
/// `manifest_bytes`.
pub fn signing_statement(publisher: &PublisherId, manifest_bytes: &[u8]) -> Digest {
    content_statement(
        publisher,
        MANIFEST_CLASS,
        &ContentKey::of(manifest_bytes),
        manifest_bytes.len() as u64,
    )
}

/// The calendar time `now` for key validity windows.
pub(super) fn calendar(now: UnixSeconds) -> Option<DateTime<Utc>> {
    i64::try_from(now.get())
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
}

/// Why a release was not verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum VerifyRefusal {
    /// The time cannot be written as calendar time.
    TimeOutOfRange {
        now: UnixSeconds,
    },
    /// The manifest carries no signature.
    Unsigned,
    /// No trust-root key vouched for the manifest; the component says why.
    Signature {
        component: SignedComponent,
    },
    Manifest {
        error: ManifestError,
    },
    Record {
        error: RecordError,
    },
    Binding {
        error: BindingError,
    },
}

impl fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeOutOfRange { now } => {
                write!(f, "{now} cannot be written as calendar time")
            }
            Self::Unsigned => f.write_str("the manifest is not signed"),
            Self::Signature { component } => write!(
                f,
                "no trust-root key vouched for the manifest: {}",
                verification_text(component.verification())
            ),
            Self::Manifest { error } => write!(f, "the manifest is refused: {error}"),
            Self::Record { error } => write!(f, "the build record is refused: {error}"),
            Self::Binding { error } => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for VerifyRefusal {}

/// The outcome of a signature check as text.
fn verification_text(verification: &ComponentVerification) -> String {
    match verification {
        ComponentVerification::Verified { key } => format!("trust-root key {key} vouched"),
        ComponentVerification::NoTrustRoots {} => "no trust roots are in force".to_owned(),
        ComponentVerification::NoKeysForClass {} => {
            format!("the trust roots list no key that may sign {MANIFEST_CLASS}")
        }
        ComponentVerification::UnknownPublisher {} => {
            "no trust-root key is the publisher's".to_owned()
        }
        ComponentVerification::Revoked { key, reason } => {
            format!("trust-root key {key} is revoked ({})", reason.as_str())
        }
        ComponentVerification::ClassNotAllowed { key } => {
            format!("trust-root key {key} may not sign {MANIFEST_CLASS}")
        }
        ComponentVerification::NotYetValid { key, valid_from } => format!(
            "trust-root key {key} is valid only from {}",
            valid_from.to_rfc3339()
        ),
        ComponentVerification::Expired { key, valid_until } => format!(
            "trust-root key {key} expired at {}",
            valid_until.to_rfc3339()
        ),
        ComponentVerification::BadSignature { key } => {
            format!("the signature does not verify under trust-root key {key}")
        }
    }
}

/// A release whose manifest a trust-root key vouched for, with the build record it binds.
/// Built only by [`verify_release`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedImage {
    manifest: FeatureManifest,
    record: BuildRecord,
    component: SignedComponent,
    key: RootKeyId,
}

impl VerifiedImage {
    pub fn manifest(&self) -> &FeatureManifest {
        &self.manifest
    }

    pub fn record(&self) -> &BuildRecord {
        &self.record
    }

    /// The CORE-08 record of the verification.
    pub fn component(&self) -> &SignedComponent {
        &self.component
    }

    /// The trust-root key that vouched for the manifest.
    pub fn key(&self) -> &RootKeyId {
        &self.key
    }
}

/// Verifies the release whose manifest is `manifest_bytes` and whose build record is
/// `record_bytes`, signed as `signature` says, under `roots` at `now` (read from the
/// shared clock through `sandbox::trust::TrustClock`).
pub fn verify_release(
    manifest_bytes: &[u8],
    record_bytes: &[u8],
    signature: &ManifestSignature,
    roots: &TrustRoots,
    now: UnixSeconds,
) -> Result<VerifiedImage, VerifyRefusal> {
    let at = calendar(now).ok_or(VerifyRefusal::TimeOutOfRange { now })?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyRefusal::Manifest {
            error: DocumentError::TooLarge {
                max_bytes: MAX_MANIFEST_BYTES,
            }
            .into(),
        });
    }
    if signature.signature.as_bytes().is_empty() {
        return Err(VerifyRefusal::Unsigned);
    }
    let component = SignedComponent::check(
        roots,
        MANIFEST_CLASS,
        &signature.publisher,
        signing_statement(&signature.publisher, manifest_bytes),
        signature.signature.as_bytes(),
        at,
    );
    let key = match component.verification().key() {
        Some(key) if component.is_verified() => key.clone(),
        _ => return Err(VerifyRefusal::Signature { component }),
    };
    let manifest = FeatureManifest::from_canonical(manifest_bytes)
        .map_err(|error| VerifyRefusal::Manifest { error })?;
    if record_bytes.len() > MAX_RECORD_BYTES {
        return Err(VerifyRefusal::Record {
            error: DocumentError::TooLarge {
                max_bytes: MAX_RECORD_BYTES,
            }
            .into(),
        });
    }
    let named = manifest.document().build_record;
    let found = ContentKey::of(record_bytes);
    if named != found {
        return Err(VerifyRefusal::Binding {
            error: BindingError::RecordNotBound {
                manifest: named,
                record: found,
            },
        });
    }
    let record = BuildRecord::from_canonical(record_bytes)
        .map_err(|error| VerifyRefusal::Record { error })?;
    manifest
        .bind(&record)
        .map_err(|error| VerifyRefusal::Binding { error })?;
    Ok(VerifiedImage {
        manifest,
        record,
        component,
        key,
    })
}
