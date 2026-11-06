//! Typed provenance and publisher policies per artifact class (VM-W48, line 2496:
//! "Typed OCI/kernel/tool/model provenance and publisher policies on CORE-02/CORE-08.
//! Pin digests where supported and scope cache access. Keep artifact-class trust
//! policies distinct; valid identity is not safe behavior ... Registry redirects,
//! mutable tags, wrong signatures, cross-user cache reuse and corrupted local files
//! tested; provenance failures cannot execute content"; S2 CORE-02, line 39; S3.3, line
//! 53: "storage equality is not permission"; VM-P37, line 2637).
//!
//! Each provenance class maps to its own catalog [`ArtifactClass`], so the publisher
//! policy that decides is the catalog's own [`TrustPolicy`] for that class: this module
//! reads it and never keeps a second one. An artifact is identified only when its pins
//! hold (a digest reference, the pinned registry, the owner's own cache), the catalog's
//! class policy trusts its publisher, and the catalog holds it published and healthy;
//! the catalog's own re-check at open, read and verify is what decides. A
//! [`VerifiedIdentity`] carries no permission: execution needs an
//! [`ExecutionPermission`] for that exact object as well, and the catalog's read
//! authorization for the executing scope.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::pinned::{BuildInputs, ComponentVersion};
use super::signature::HexBytes;
use crate::foundation::catalog::{
    ArtifactClass, Catalog, IntegrityFailure, ObjectId, ObjectStatus, PublisherId, ReadRefusal,
    Scope, TrustClaim, TrustPolicy,
};
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{validate_identifier, ContentKey, Digest, ExecutionId, IdError};
use crate::foundation::report::CommitHash;

/// Longest accepted registry host or repository path.
pub const MAX_LOCATOR_BYTES: usize = 255;

/// The four provenance classes, each on its own catalog class and policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceClass {
    Oci,
    Kernel,
    Tool,
    Model,
}

impl ProvenanceClass {
    pub const ALL: [Self; 4] = [Self::Oci, Self::Kernel, Self::Tool, Self::Model];

    /// The catalog class whose verifier and trust policy govern this provenance class.
    /// Four distinct classes, so the policies stay distinct (line 2496).
    pub const fn artifact_class(self) -> ArtifactClass {
        match self {
            Self::Oci => ArtifactClass::OciLayer,
            Self::Kernel => ArtifactClass::GuestImage,
            Self::Tool => ArtifactClass::RuntimeUpdate,
            Self::Model => ArtifactClass::ModelWeights,
        }
    }
}

impl fmt::Display for ProvenanceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Oci => "oci",
            Self::Kernel => "kernel",
            Self::Tool => "tool",
            Self::Model => "model",
        })
    }
}

/// Why a locator is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocatorError {
    Empty,
    TooLong {
        max: usize,
    },
    InvalidCharacter {
        character: char,
    },
    /// A path starts or ends with `/`, or contains `//` or `..`.
    BadPath,
}

impl fmt::Display for LocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the locator is empty"),
            Self::TooLong { max } => write!(f, "the locator is longer than {max} bytes"),
            Self::InvalidCharacter { character } => {
                write!(f, "the locator contains {character:?}")
            }
            Self::BadPath => {
                f.write_str("the path starts or ends with '/' or contains '//' or '..'")
            }
        }
    }
}

impl std::error::Error for LocatorError {}

/// A registry host: lowercase letters, digits, '-' and '.', with an optional `:port`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RegistryHost(String);

impl RegistryHost {
    pub fn new(value: impl Into<String>) -> Result<Self, LocatorError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LocatorError::Empty);
        }
        if value.len() > MAX_LOCATOR_BYTES {
            return Err(LocatorError::TooLong {
                max: MAX_LOCATOR_BYTES,
            });
        }
        let (host, port) = match value.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value.as_str(), None),
        };
        if host.is_empty() {
            return Err(LocatorError::Empty);
        }
        if let Some(character) = host
            .chars()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.')))
        {
            return Err(LocatorError::InvalidCharacter { character });
        }
        if let Some(port) = port {
            if port.is_empty() {
                return Err(LocatorError::Empty);
            }
            if let Some(character) = port.chars().find(|c| !c.is_ascii_digit()) {
                return Err(LocatorError::InvalidCharacter { character });
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistryHost({})", self.0)
    }
}

impl fmt::Display for RegistryHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RegistryHost {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A repository path such as `library/debian` or `org/model`: lowercase letters, digits,
/// '.', '_', '-' and '/' between non-empty segments.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RepositoryPath(String);

impl RepositoryPath {
    pub fn new(value: impl Into<String>) -> Result<Self, LocatorError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LocatorError::Empty);
        }
        if value.len() > MAX_LOCATOR_BYTES {
            return Err(LocatorError::TooLong {
                max: MAX_LOCATOR_BYTES,
            });
        }
        if let Some(character) = value.chars().find(|c| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/'))
        }) {
            return Err(LocatorError::InvalidCharacter { character });
        }
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || value.split('/').any(|segment| segment == "..")
        {
            return Err(LocatorError::BadPath);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RepositoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepositoryPath({})", self.0)
    }
}

impl fmt::Display for RepositoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepositoryPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A tool name: the shared identifier grammar.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ToolName(String);

impl ToolName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ToolName({})", self.0)
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ToolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// How an OCI image was referenced: by its manifest digest (pinned) or by a mutable tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OciReference {
    Digest { manifest: Digest },
    Tag { tag: String },
}

/// Where an OCI layer came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciProvenance {
    /// The registry the image is pinned to.
    pub registry: RegistryHost,
    pub repository: RepositoryPath,
    pub reference: OciReference,
    /// The host that finally served the layer bytes, as the fetch layer observed it.
    pub served_by: RegistryHost,
    pub layer: ContentKey,
}

/// Where a guest kernel came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelProvenance {
    pub version: ComponentVersion,
    pub build: BuildInputs,
    pub content: ContentKey,
}

/// Where a tool or runtime component came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProvenance {
    pub name: ToolName,
    pub version: ComponentVersion,
    pub build: BuildInputs,
    pub content: ContentKey,
}

/// Where model weights came from: a repository at an exact revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvenance {
    pub repository: RepositoryPath,
    pub revision: CommitHash,
    pub content: ContentKey,
}

/// Typed provenance, one shape per class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Oci(OciProvenance),
    Kernel(KernelProvenance),
    Tool(ToolProvenance),
    Model(ModelProvenance),
}

impl Provenance {
    pub fn class(&self) -> ProvenanceClass {
        match self {
            Self::Oci(_) => ProvenanceClass::Oci,
            Self::Kernel(_) => ProvenanceClass::Kernel,
            Self::Tool(_) => ProvenanceClass::Tool,
            Self::Model(_) => ProvenanceClass::Model,
        }
    }

    pub fn content_key(&self) -> ContentKey {
        match self {
            Self::Oci(oci) => oci.layer,
            Self::Kernel(kernel) => kernel.content,
            Self::Tool(tool) => tool.content,
            Self::Model(model) => model.content,
        }
    }

    /// The pin rules for execution: an OCI image must be referenced by digest, not a
    /// mutable tag, and must have been served by the registry it is pinned to, not a
    /// redirect target (line 2496). Kernels, tools and models are pinned by content key
    /// and exact revision by construction.
    pub fn check_pins(&self) -> Result<(), ProvenanceRefusal> {
        if let Self::Oci(oci) = self {
            if let OciReference::Tag { tag } = &oci.reference {
                return Err(ProvenanceRefusal::MutableTag { tag: tag.clone() });
            }
            if oci.served_by != oci.registry {
                return Err(ProvenanceRefusal::RegistryRedirect {
                    pinned: oci.registry.clone(),
                    served_by: oci.served_by.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A publisher's attestation over the artifact, in the form the class verifier checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub publisher: PublisherId,
    pub attestation: HexBytes,
}

/// Provenance with the attestation that backs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub provenance: Provenance,
    pub attestation: Attestation,
}

impl ProvenanceRecord {
    pub fn class(&self) -> ProvenanceClass {
        self.provenance.class()
    }

    /// The claim to import this artifact into the catalog with; the catalog's own class
    /// verifier and policy then judge it (INT-09). It is never a checksum-only claim.
    pub fn trust_claim(&self) -> TrustClaim {
        TrustClaim::Publisher {
            publisher: self.attestation.publisher,
            attestation: self.attestation.attestation.as_bytes().to_vec(),
        }
    }
}

/// Why provenance did not identify an artifact, or an identified one may not execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceRefusal {
    /// A mutable tag names no fixed bytes; execution needs a digest reference.
    MutableTag { tag: String },
    /// The bytes were served by another host than the pinned registry.
    RegistryRedirect {
        pinned: RegistryHost,
        served_by: RegistryHost,
    },
    /// A cache entry of another scope matched; equal bytes are not permission (S3.3).
    CrossUserCacheReuse { owner: Scope, requester: Scope },
    /// A local file's bytes are not the bytes its provenance names.
    CorruptedLocalFile {
        expected: ContentKey,
        found: ContentKey,
    },
    /// The catalog has no trust policy for the class, so nothing of it is trusted.
    NoPolicy { class: ArtifactClass },
    /// The catalog's class policy does not trust this publisher.
    PublisherNotTrusted {
        class: ArtifactClass,
        publisher: PublisherId,
    },
    /// The catalog does not hold the artifact in this scope.
    NotInCatalog { object: ObjectId },
    /// The catalog holds it but has quarantined it; its reason decides.
    Quarantined {
        object: ObjectId,
        reason: IntegrityFailure,
    },
    /// The permission is for another object than the identified one.
    PermissionForAnotherObject {
        permitted: ObjectId,
        identified: ObjectId,
    },
    /// The catalog refused the executing scope's read of the object.
    CatalogRefused { refusal: ReadRefusal },
}

impl fmt::Display for ProvenanceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutableTag { tag } => {
                write!(
                    f,
                    "tag {tag:?} is mutable; execution needs a digest reference"
                )
            }
            Self::RegistryRedirect { pinned, served_by } => write!(
                f,
                "the bytes were served by {served_by}, not the pinned registry {pinned}"
            ),
            Self::CrossUserCacheReuse { owner, requester } => write!(
                f,
                "the cache entry belongs to {owner}; {requester} may not reuse it"
            ),
            Self::CorruptedLocalFile { expected, found } => write!(
                f,
                "the local file's content key is {found}, not the declared {expected}"
            ),
            Self::NoPolicy { class } => {
                write!(f, "the catalog has no trust policy for {class}")
            }
            Self::PublisherNotTrusted { class, publisher } => write!(
                f,
                "the catalog's {class} policy does not trust publisher {publisher}"
            ),
            Self::NotInCatalog { object } => {
                write!(f, "object {object} is not published in this scope")
            }
            Self::Quarantined { object, reason } => {
                write!(f, "object {object} is quarantined: {reason:?}")
            }
            Self::PermissionForAnotherObject {
                permitted,
                identified,
            } => write!(
                f,
                "the permission is for object {permitted}, not the identified {identified}"
            ),
            Self::CatalogRefused { refusal } => {
                write!(f, "the catalog refused the read: {refusal:?}")
            }
        }
    }
}

impl std::error::Error for ProvenanceRefusal {}

/// Whether the catalog's class policy (the one policy there is) trusts the record's
/// publisher, before an import is attempted.
pub fn admit_publisher(
    policies: &BTreeMap<ArtifactClass, TrustPolicy>,
    record: &ProvenanceRecord,
) -> Result<(), ProvenanceRefusal> {
    let class = record.class().artifact_class();
    let policy = policies
        .get(&class)
        .ok_or(ProvenanceRefusal::NoPolicy { class })?;
    if !policy.trusts(&record.attestation.publisher) {
        return Err(ProvenanceRefusal::PublisherNotTrusted {
            class,
            publisher: record.attestation.publisher,
        });
    }
    Ok(())
}

/// Checks a local file's bytes against the content key its provenance names.
pub fn verify_local_file(expected: ContentKey, bytes: &[u8]) -> Result<(), ProvenanceRefusal> {
    let found = ContentKey::of(bytes);
    if found == expected {
        Ok(())
    } else {
        Err(ProvenanceRefusal::CorruptedLocalFile { expected, found })
    }
}

/// A hit in a shared cache: whose entry it is, and what it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheHit {
    pub owner: Scope,
    pub class: ArtifactClass,
    pub content: ContentKey,
}

/// Admits a cache hit only for the scope that owns the entry (line 2496 "scope cache
/// access"; VM-P37, line 2637 "unauthorized shared-cache hits fail safely"). Another
/// scope's equal bytes are refused; sharing goes through a catalog grant, never the
/// cache.
pub fn admit_cache_hit(requester: &Scope, hit: &CacheHit) -> Result<ObjectId, ProvenanceRefusal> {
    if hit.owner != *requester {
        return Err(ProvenanceRefusal::CrossUserCacheReuse {
            owner: hit.owner.clone(),
            requester: requester.clone(),
        });
    }
    Ok(ObjectId::new(requester, hit.class, hit.content))
}

/// An artifact whose provenance and catalog trust were checked. It grants nothing: there
/// is no method on it that executes, reads or shares (line 2496 "valid identity is not
/// safe behavior"). Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedIdentity {
    class: ProvenanceClass,
    scope: Scope,
    object: ObjectId,
    content_key: ContentKey,
    publisher: PublisherId,
}

impl VerifiedIdentity {
    pub fn class(&self) -> ProvenanceClass {
        self.class
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn object(&self) -> ObjectId {
        self.object
    }

    pub fn content_key(&self) -> ContentKey {
        self.content_key
    }

    pub fn publisher(&self) -> PublisherId {
        self.publisher
    }
}

/// Identifies the artifact `record` describes in `scope`: pins hold, the catalog's class
/// policy trusts the publisher, and the catalog holds the object published and healthy.
/// The catalog's status already re-checks the trust basis the object was published
/// under against the current verifiers and policy, so a withdrawn publisher or a class
/// whose verifier is gone is refused here as the catalog refuses it.
pub fn identify(
    catalog: &Catalog,
    scope: &Scope,
    record: &ProvenanceRecord,
) -> Result<VerifiedIdentity, ProvenanceRefusal> {
    record.provenance.check_pins()?;
    admit_publisher(&catalog.config().trust, record)?;
    let class = record.class().artifact_class();
    let content_key = record.provenance.content_key();
    let object = ObjectId::new(scope, class, content_key);
    match catalog.status(scope, object) {
        ObjectStatus::Published => Ok(VerifiedIdentity {
            class: record.class(),
            scope: scope.clone(),
            object,
            content_key,
            publisher: record.attestation.publisher,
        }),
        ObjectStatus::Quarantined { reason } => {
            Err(ProvenanceRefusal::Quarantined { object, reason })
        }
        ObjectStatus::Absent => Err(ProvenanceRefusal::NotInCatalog { object }),
    }
}

/// Permission for one execution in one scope to execute one exact object. The
/// authority that owns execution policy issues it; this module only checks that it
/// names the identified object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPermission {
    pub scope: Scope,
    pub execution: ExecutionId,
    pub object: ObjectId,
}

/// An execution the gate admitted: the identity, the permission's execution, and the
/// catalog's verified-artifact set for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionAdmission {
    pub identity: VerifiedIdentity,
    pub execution: ExecutionId,
    pub verification: ArtifactVerification,
}

/// Admits execution of an identified artifact: the permission must name that exact
/// object, and the catalog must authorize the permission's scope and execution to read
/// it now (published, healthy, owned or granted). Identity alone admits nothing.
pub fn admit_execution(
    catalog: &Catalog,
    identity: &VerifiedIdentity,
    permission: &ExecutionPermission,
) -> Result<ExecutionAdmission, ProvenanceRefusal> {
    if permission.object != identity.object {
        return Err(ProvenanceRefusal::PermissionForAnotherObject {
            permitted: permission.object,
            identified: identity.object,
        });
    }
    let verification = catalog
        .artifact_verification(&permission.scope, &permission.execution, [identity.object])
        .map_err(|refusal| ProvenanceRefusal::CatalogRefused { refusal })?;
    Ok(ExecutionAdmission {
        identity: identity.clone(),
        execution: permission.execution.clone(),
        verification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, TenantId};
    use crate::sandbox::trust::pinned::tests::inputs;

    fn host(name: &str) -> RegistryHost {
        RegistryHost::new(name).unwrap()
    }

    fn oci(reference: OciReference, served_by: &str) -> Provenance {
        Provenance::Oci(OciProvenance {
            registry: host("registry.example"),
            repository: RepositoryPath::new("library/debian").unwrap(),
            reference,
            served_by: host(served_by),
            layer: ContentKey::of(b"layer"),
        })
    }

    #[test]
    fn a_mutable_tag_cannot_execute() {
        let tagged = oci(
            OciReference::Tag {
                tag: "latest".to_owned(),
            },
            "registry.example",
        );
        assert_eq!(
            tagged.check_pins(),
            Err(ProvenanceRefusal::MutableTag {
                tag: "latest".to_owned()
            })
        );
        let pinned = oci(
            OciReference::Digest {
                manifest: digest("yougori/test/manifest/v1", &[b"m"]),
            },
            "registry.example",
        );
        assert_eq!(pinned.check_pins(), Ok(()));
        assert_eq!(pinned.class(), ProvenanceClass::Oci);
        assert_eq!(pinned.content_key(), ContentKey::of(b"layer"));
    }

    #[test]
    fn a_registry_redirect_is_refused() {
        let redirected = oci(
            OciReference::Digest {
                manifest: digest("yougori/test/manifest/v1", &[b"m"]),
            },
            "cdn.other.example",
        );
        assert_eq!(
            redirected.check_pins(),
            Err(ProvenanceRefusal::RegistryRedirect {
                pinned: host("registry.example"),
                served_by: host("cdn.other.example"),
            })
        );
    }

    #[test]
    fn locators_are_checked() {
        assert!(RegistryHost::new("registry.example:5000").is_ok());
        assert_eq!(RegistryHost::new(""), Err(LocatorError::Empty));
        assert_eq!(
            RegistryHost::new("Registry.example"),
            Err(LocatorError::InvalidCharacter { character: 'R' })
        );
        assert_eq!(
            RegistryHost::new("registry.example/v2"),
            Err(LocatorError::InvalidCharacter { character: '/' })
        );
        assert_eq!(
            RegistryHost::new("registry.example:5a"),
            Err(LocatorError::InvalidCharacter { character: 'a' })
        );
        assert_eq!(
            RegistryHost::new("registry.example:"),
            Err(LocatorError::Empty)
        );
        assert!(RepositoryPath::new("org/model-7b").is_ok());
        assert_eq!(RepositoryPath::new("/org"), Err(LocatorError::BadPath));
        assert_eq!(RepositoryPath::new("org//x"), Err(LocatorError::BadPath));
        assert_eq!(RepositoryPath::new("org/../x"), Err(LocatorError::BadPath));
        assert_eq!(
            RepositoryPath::new("Org/x"),
            Err(LocatorError::InvalidCharacter { character: 'O' })
        );
        assert_eq!(
            RepositoryPath::new("a".repeat(256)),
            Err(LocatorError::TooLong { max: 255 })
        );
        assert!(ToolName::new("qemu secure").is_err());
        assert!(serde_json::from_str::<RegistryHost>("\"BAD\"").is_err());
    }

    #[test]
    fn a_cross_user_cache_hit_is_refused() {
        let a = Scope::tenant(TenantId::new("a").unwrap());
        let b = Scope::tenant(TenantId::new("b").unwrap());
        let hit = CacheHit {
            owner: a.clone(),
            class: ArtifactClass::ModelWeights,
            content: ContentKey::of(b"weights"),
        };
        assert_eq!(
            admit_cache_hit(&b, &hit),
            Err(ProvenanceRefusal::CrossUserCacheReuse {
                owner: a.clone(),
                requester: b.clone(),
            })
        );
        assert_eq!(
            admit_cache_hit(&Scope::Host, &hit),
            Err(ProvenanceRefusal::CrossUserCacheReuse {
                owner: a.clone(),
                requester: Scope::Host,
            })
        );
        assert_eq!(
            admit_cache_hit(&a, &hit),
            Ok(ObjectId::new(
                &a,
                ArtifactClass::ModelWeights,
                ContentKey::of(b"weights")
            ))
        );
    }

    #[test]
    fn a_corrupted_local_file_is_detected() {
        let expected = ContentKey::of(b"kernel");
        assert_eq!(verify_local_file(expected, b"kernel"), Ok(()));
        assert_eq!(
            verify_local_file(expected, b"kernel\0"),
            Err(ProvenanceRefusal::CorruptedLocalFile {
                expected,
                found: ContentKey::of(b"kernel\0"),
            })
        );
    }

    #[test]
    fn each_class_has_its_own_catalog_class_and_policy() {
        let classes: std::collections::BTreeSet<ArtifactClass> = ProvenanceClass::ALL
            .into_iter()
            .map(ProvenanceClass::artifact_class)
            .collect();
        assert_eq!(classes.len(), ProvenanceClass::ALL.len());

        let publisher = PublisherId::from_key_fingerprint(digest("yougori/test/p/v1", &[b"k"]));
        let record = ProvenanceRecord {
            provenance: Provenance::Kernel(KernelProvenance {
                version: ComponentVersion::new("6.6.52").unwrap(),
                build: inputs("k"),
                content: ContentKey::of(b"kernel"),
            }),
            attestation: Attestation {
                publisher,
                attestation: HexBytes::new(vec![1, 2, 3]),
            },
        };
        let mut policies = BTreeMap::new();
        assert_eq!(
            admit_publisher(&policies, &record),
            Err(ProvenanceRefusal::NoPolicy {
                class: ArtifactClass::GuestImage
            })
        );
        // Trusting the publisher for OCI layers says nothing about kernels.
        policies.insert(
            ArtifactClass::OciLayer,
            TrustPolicy::new().trust_publisher(publisher),
        );
        policies.insert(ArtifactClass::GuestImage, TrustPolicy::new());
        assert_eq!(
            admit_publisher(&policies, &record),
            Err(ProvenanceRefusal::PublisherNotTrusted {
                class: ArtifactClass::GuestImage,
                publisher,
            })
        );
        policies.insert(
            ArtifactClass::GuestImage,
            TrustPolicy::new().trust_publisher(publisher),
        );
        assert_eq!(admit_publisher(&policies, &record), Ok(()));
        assert_eq!(
            record.trust_claim(),
            TrustClaim::Publisher {
                publisher,
                attestation: vec![1, 2, 3]
            }
        );
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            serde_json::from_value::<ProvenanceRecord>(json.clone()).unwrap(),
            record
        );
        let mut extra = json;
        extra["safe"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProvenanceRecord>(extra).is_err());
    }
}
