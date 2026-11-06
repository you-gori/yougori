//! Typed verifiers and trust policy per artifact class (INT-09; S2 CORE-08: "artifact
//! classes retain distinct publisher/trust policies ... an unauthenticated checksum is not
//! a release trust root").
//!
//! Integrity and trust are separate checks. A matching checksum shows the bytes are the
//! declared bytes; it never shows that anyone trusted may publish them. Every import needs
//! both: the content key and extent digests for integrity, and an accepted
//! [`TrustBasis`] for the class from the class's own policy. The responsible verifier
//! also validates the structure of the complete object before it is committed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::identity::{ArtifactClass, PublisherId, Scope};
use crate::foundation::ids::{ContentKey, Digest, TenantId};

/// What an import offers as the reason to trust its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustClaim {
    /// Only a checksum. It establishes integrity, never trust, so the catalog refuses it
    /// for every class whatever a verifier says (S2 CORE-08; line 45).
    ChecksumOnly,
    /// A publisher's attestation over the class and content key, checked by the class's
    /// verifier and admitted only if the class policy trusts that publisher.
    Publisher {
        publisher: PublisherId,
        attestation: Vec<u8>,
    },
    /// The importing tenant chose this as its own original. Accepted only into that
    /// tenant's scope and only for classes whose policy accepts user selections.
    UserSelected,
}

/// Why an object was trusted; recorded with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TrustBasis {
    Publisher { publisher: PublisherId },
    UserSelected { tenant: TenantId },
}

crate::foundation::strict_serde::strict_tag!(TrustBasis, "basis");

/// One artifact class's publisher/trust policy (S2 CORE-08). It starts trusting nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustPolicy {
    publishers: BTreeSet<PublisherId>,
    accepts_user_selected: bool,
}

impl TrustPolicy {
    /// A policy that trusts nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `publisher` for this class only.
    pub fn trust_publisher(mut self, publisher: PublisherId) -> Self {
        self.publishers.insert(publisher);
        self
    }

    /// Accepts originals a tenant selects for its own scope.
    pub fn accept_user_selected(mut self) -> Self {
        self.accepts_user_selected = true;
        self
    }

    /// Whether this class trusts `publisher`.
    pub fn trusts(&self, publisher: &PublisherId) -> bool {
        self.publishers.contains(publisher)
    }

    /// Whether this class accepts user-selected originals.
    pub fn accepts_user_selected(&self) -> bool {
        self.accepts_user_selected
    }
}

/// What a verifier is told about the object it checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentDescriptor {
    pub scope: Scope,
    pub class: ArtifactClass,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    /// The digest of the whole declaration, extent table included, so a class whose
    /// attestations sign the manifest can authenticate it (line 531). The catalog itself
    /// checks every byte against the content key before publication either way.
    pub manifest_digest: Digest,
}

/// A verifier's typed refusal (INT-09).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rejection", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum VerifierRejection {
    /// The attestation does not authenticate this class and content for this publisher.
    AttestationInvalid,
    /// The object's structure is corrupt.
    CorruptStructure { detail: String },
    /// The object is not in this class's format.
    WrongFormat { detail: String },
    /// The object could not be read.
    Unreadable { detail: String },
}

crate::foundation::strict_serde::strict_tag!(VerifierRejection, "rejection");

impl fmt::Display for VerifierRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttestationInvalid => f.write_str("the attestation does not authenticate it"),
            Self::CorruptStructure { detail } => write!(f, "its structure is corrupt: {detail}"),
            Self::WrongFormat { detail } => write!(f, "it is not in this class's format: {detail}"),
            Self::Unreadable { detail } => write!(f, "it could not be read: {detail}"),
        }
    }
}

/// The responsible verifier of one artifact class (INT-09). Specialized importers supply
/// these; tests use fakes.
pub trait ArtifactVerifier: Send + Sync {
    /// The one class this verifier is responsible for.
    fn class(&self) -> ArtifactClass;

    /// Authenticates `attestation` as `publisher`'s statement about this class and
    /// content key. Integrity was or will be established separately and is not trust.
    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection>;

    /// Validates the complete object's structure (headers, internal manifests, bounds)
    /// from a read-only view, before it is committed.
    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection>;
}

/// At most one responsible verifier per artifact class.
#[derive(Default)]
pub struct VerifierRegistry {
    verifiers: BTreeMap<ArtifactClass, Box<dyn ArtifactVerifier>>,
}

/// A second verifier was offered for a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateVerifier {
    pub class: ArtifactClass,
}

impl fmt::Display for DuplicateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a verifier for {} is already registered", self.class)
    }
}

impl std::error::Error for DuplicateVerifier {}

impl VerifierRegistry {
    /// An empty registry: no class is accepted until its verifier is registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the responsible verifier of its class; a class has at most one.
    pub fn register(
        &mut self,
        verifier: Box<dyn ArtifactVerifier>,
    ) -> Result<(), DuplicateVerifier> {
        let class = verifier.class();
        if self.verifiers.contains_key(&class) {
            return Err(DuplicateVerifier { class });
        }
        self.verifiers.insert(class, verifier);
        Ok(())
    }

    /// Whether `class` has a responsible verifier.
    pub fn is_registered(&self, class: ArtifactClass) -> bool {
        self.verifiers.contains_key(&class)
    }

    pub(super) fn get(&self, class: ArtifactClass) -> Option<&dyn ArtifactVerifier> {
        self.verifiers
            .get(&class)
            .map(|verifier| verifier.as_ref())
            .filter(|verifier| verifier.class() == class)
    }
}

impl fmt::Debug for VerifierRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.verifiers.keys()).finish()
    }
}

/// Why the trust check refused an import (INT-09; S2 CORE-08).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TrustRefusal {
    /// Only a checksum was offered; a checksum is never trust.
    ChecksumIsNotTrust { class: ArtifactClass },
    /// No verifier is responsible for this class, so nothing of it is accepted.
    NoVerifier { class: ArtifactClass },
    /// No policy is configured for this class, so nothing of it is trusted.
    NoPolicy { class: ArtifactClass },
    /// The class policy does not trust this publisher.
    PublisherNotTrusted {
        class: ArtifactClass,
        publisher: PublisherId,
    },
    /// The class verifier rejected the publisher's attestation.
    AttestationRejected {
        class: ArtifactClass,
        publisher: PublisherId,
        rejection: VerifierRejection,
    },
    /// The class policy does not accept user-selected originals.
    UserSelectionNotAccepted { class: ArtifactClass },
    /// A user selection can only add to the selecting tenant's own scope.
    UserSelectionOutsideTenantScope { class: ArtifactClass },
}

crate::foundation::strict_serde::strict_tag!(TrustRefusal, "refusal");

impl fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChecksumIsNotTrust { class } => write!(
                f,
                "a checksum establishes integrity, not trust; a {class} needs a trusted \
                 publisher's attestation or an accepted user selection"
            ),
            Self::NoVerifier { class } => write!(f, "no verifier is responsible for {class}"),
            Self::NoPolicy { class } => write!(f, "no trust policy is configured for {class}"),
            Self::PublisherNotTrusted { class, publisher } => {
                write!(f, "publisher {publisher} is not trusted for {class}")
            }
            Self::AttestationRejected {
                class,
                publisher,
                rejection,
            } => write!(
                f,
                "the {class} verifier rejected publisher {publisher}'s attestation: {rejection}"
            ),
            Self::UserSelectionNotAccepted { class } => {
                write!(
                    f,
                    "the {class} policy does not accept user-selected originals"
                )
            }
            Self::UserSelectionOutsideTenantScope { class } => write!(
                f,
                "a user-selected {class} can only be imported into the tenant's own scope"
            ),
        }
    }
}

impl std::error::Error for TrustRefusal {}

/// Decides whether `claim` makes `content` trusted for its class.
///
/// The checksum-only refusal comes first and does not consult the verifier, so even a
/// verifier that wrongly accepts everything cannot turn a checksum into trust.
pub(super) fn evaluate_trust(
    verifiers: &VerifierRegistry,
    policies: &BTreeMap<ArtifactClass, TrustPolicy>,
    content: &ContentDescriptor,
    claim: &TrustClaim,
) -> Result<TrustBasis, TrustRefusal> {
    let class = content.class;
    if matches!(claim, TrustClaim::ChecksumOnly) {
        return Err(TrustRefusal::ChecksumIsNotTrust { class });
    }
    let verifier = verifiers
        .get(class)
        .ok_or(TrustRefusal::NoVerifier { class })?;
    let policy = policies
        .get(&class)
        .ok_or(TrustRefusal::NoPolicy { class })?;
    match claim {
        TrustClaim::ChecksumOnly => Err(TrustRefusal::ChecksumIsNotTrust { class }),
        TrustClaim::Publisher {
            publisher,
            attestation,
        } => {
            if !policy.trusts(publisher) {
                return Err(TrustRefusal::PublisherNotTrusted {
                    class,
                    publisher: *publisher,
                });
            }
            verifier
                .authenticate(content, publisher, attestation)
                .map_err(|rejection| TrustRefusal::AttestationRejected {
                    class,
                    publisher: *publisher,
                    rejection,
                })?;
            Ok(TrustBasis::Publisher {
                publisher: *publisher,
            })
        }
        TrustClaim::UserSelected => {
            let Scope::Tenant { tenant } = &content.scope else {
                return Err(TrustRefusal::UserSelectionOutsideTenantScope { class });
            };
            if !policy.accepts_user_selected() {
                return Err(TrustRefusal::UserSelectionNotAccepted { class });
            }
            Ok(TrustBasis::UserSelected {
                tenant: tenant.clone(),
            })
        }
    }
}

/// Whether the trust basis recorded at import still holds under the current verifiers
/// and policy (INT-09; S2 CORE-08). Withdrawing a publisher, or the acceptance of user
/// selections, withdraws the trust of everything it admitted: a record never outlives the
/// policy that admitted it.
pub(super) fn recheck_trust(
    verifiers: &VerifierRegistry,
    policies: &BTreeMap<ArtifactClass, TrustPolicy>,
    scope: &Scope,
    class: ArtifactClass,
    basis: &TrustBasis,
) -> Result<(), TrustRefusal> {
    verifiers
        .get(class)
        .ok_or(TrustRefusal::NoVerifier { class })?;
    let policy = policies
        .get(&class)
        .ok_or(TrustRefusal::NoPolicy { class })?;
    match basis {
        TrustBasis::Publisher { publisher } if policy.trusts(publisher) => Ok(()),
        TrustBasis::Publisher { publisher } => Err(TrustRefusal::PublisherNotTrusted {
            class,
            publisher: *publisher,
        }),
        TrustBasis::UserSelected { tenant } => {
            if scope.tenant_id() != Some(tenant) {
                return Err(TrustRefusal::UserSelectionOutsideTenantScope { class });
            }
            if !policy.accepts_user_selected() {
                return Err(TrustRefusal::UserSelectionNotAccepted { class });
            }
            Ok(())
        }
    }
}

/// Read-only access to one object's bytes, for verifiers and read handles. It has no
/// method that writes (GPU part §3.4, line 546: consumers get read-only artifacts).
pub struct ObjectBytes {
    file: File,
    length_bytes: u64,
}

impl ObjectBytes {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let length_bytes = file.metadata()?.len();
        Ok(Self { file, length_bytes })
    }

    /// The object's length on disk.
    pub fn length_bytes(&self) -> u64 {
        self.length_bytes
    }

    /// Fills `buffer` from `offset_bytes`; refuses a range past the end of the object.
    pub fn read_exact_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> io::Result<()> {
        let in_bounds = offset_bytes
            .checked_add(buffer.len() as u64)
            .is_some_and(|end| end <= self.length_bytes);
        if !in_bounds {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the range ends past the end of the object",
            ));
        }
        self.file.seek(SeekFrom::Start(offset_bytes))?;
        self.file.read_exact(buffer)
    }
}

impl fmt::Debug for ObjectBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectBytes")
            .field("length_bytes", &self.length_bytes)
            .finish()
    }
}
