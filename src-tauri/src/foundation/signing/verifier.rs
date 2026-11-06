//! The catalog verifier over configured trust roots (INT-09; S2 CORE-08, line 206:
//! "signed component identity ... An unauthenticated checksum is not a release trust
//! root").
//!
//! A publisher's attestation is its Ed25519 signature over a domain-separated statement
//! about the artifact the catalog's interfaces already identify, never over the raw
//! bytes:
//!
//! - [`content_statement`] binds the publisher, the artifact class and the content key
//!   with its true length (a [`TrustClaim::Publisher`](crate::foundation::catalog::TrustClaim)
//!   is "an attestation over the class and content key");
//! - [`manifest_statement`] binds the publisher, the class and the digest of the whole
//!   declaration, extent table included, for classes whose publishers sign the manifest
//!   (the [`ContentDescriptor::manifest_digest`] field).
//!
//! The scope is not signed: a publisher's statement holds in every scope, the catalog
//! keeps scopes apart by object identity, and each class's own policy decides whom it
//! trusts. The catalog still checks every byte against the content key, so a valid
//! signature never stands in for integrity, and a checksum never stands in for trust.

use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::roots::{KeyRefusal, RootKeyId, SharedTrustRoots};
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, ContentDescriptor, ObjectBytes, PublisherId, VerifierRejection,
};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};

/// Domain of [`content_statement`].
pub const CONTENT_STATEMENT_DOMAIN: &str = "yougori/signing/content-statement/v1";

/// Domain of [`manifest_statement`].
pub const MANIFEST_STATEMENT_DOMAIN: &str = "yougori/signing/manifest-statement/v1";

/// What a publisher signs to vouch for content of `class`: its publisher identity, the
/// class tag, the content key and the true length, under [`CONTENT_STATEMENT_DOMAIN`].
pub fn content_statement(
    publisher: &PublisherId,
    class: ArtifactClass,
    content_key: &ContentKey,
    length_bytes: u64,
) -> Digest {
    DigestBuilder::new(CONTENT_STATEMENT_DOMAIN)
        .digest(&publisher.digest())
        .str(class.tag())
        .digest(content_key.digest())
        .u64(length_bytes)
        .finish()
}

/// What a publisher signs to vouch for one declaration of `class`: its publisher
/// identity, the class tag and the declaration's digest (which binds the content key, the
/// true length and every extent), under [`MANIFEST_STATEMENT_DOMAIN`].
pub fn manifest_statement(
    publisher: &PublisherId,
    class: ArtifactClass,
    manifest_digest: &Digest,
) -> Digest {
    DigestBuilder::new(MANIFEST_STATEMENT_DOMAIN)
        .digest(&publisher.digest())
        .str(class.tag())
        .digest(manifest_digest)
        .finish()
}

/// Which statement a class's publishers sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementBinding {
    /// [`content_statement`]: the content key and true length.
    Content,
    /// [`manifest_statement`]: the whole declaration.
    Manifest,
}

impl StatementBinding {
    /// The statement `publisher` signs for `content` as an artifact of `class`.
    pub fn statement(
        self,
        publisher: &PublisherId,
        class: ArtifactClass,
        content: &ContentDescriptor,
    ) -> Digest {
        match self {
            Self::Content => {
                content_statement(publisher, class, &content.content_key, content.length_bytes)
            }
            Self::Manifest => manifest_statement(publisher, class, &content.manifest_digest),
        }
    }
}

/// Calendar time for key validity windows. Signers write windows in calendar time,
/// which a monotonic clock cannot supply; the engine and tests choose the source.
pub trait TrustCalendar: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// The system's calendar. Setting the system clock back makes an expired key valid
/// again; revocation does not depend on the calendar.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCalendar;

impl TrustCalendar for SystemCalendar {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// The class-specific structure check a signed class still needs before commit (the
/// [`ArtifactVerifier::validate`] half), supplied by the class's specialized importer.
pub trait StructureValidator: Send + Sync {
    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection>;
}

/// The responsible verifier of one artifact class whose publishers sign with keys of
/// the configured trust roots (INT-09; S2 CORE-08). It authenticates attestations with
/// Ed25519 under the roots in force and delegates the structure check.
pub struct SignedArtifactVerifier {
    class: ArtifactClass,
    binding: StatementBinding,
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
    structure: Box<dyn StructureValidator>,
}

impl SignedArtifactVerifier {
    /// A verifier for `class`, whose publishers sign the `binding` statement with keys
    /// of `roots`, with windows judged by `calendar`.
    pub fn new(
        class: ArtifactClass,
        binding: StatementBinding,
        roots: SharedTrustRoots,
        calendar: Arc<dyn TrustCalendar>,
        structure: Box<dyn StructureValidator>,
    ) -> Self {
        Self {
            class,
            binding,
            roots,
            calendar,
            structure,
        }
    }

    /// The typed reason behind [`ArtifactVerifier::authenticate`]: the key that vouched
    /// for `content` as `publisher`'s artifact of this verifier's class, or why none did.
    /// The catalog's interface reports every refusal as
    /// [`VerifierRejection::AttestationInvalid`]; evidence records take this one.
    pub fn check(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<RootKeyId, KeyRefusal> {
        let statement = self.binding.statement(publisher, self.class, content);
        let roots = self.roots.current();
        let key = roots.verify_statement(
            publisher,
            self.class,
            &statement,
            attestation,
            self.calendar.now(),
        )?;
        Ok(key.id().clone())
    }
}

impl fmt::Debug for SignedArtifactVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedArtifactVerifier")
            .field("class", &self.class)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl ArtifactVerifier for SignedArtifactVerifier {
    fn class(&self) -> ArtifactClass {
        self.class
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        if content.class != self.class {
            return Err(VerifierRejection::AttestationInvalid);
        }
        self.check(content, publisher, attestation)
            .map(drop)
            .map_err(|_| VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        self.structure.validate(content, bytes)
    }
}
