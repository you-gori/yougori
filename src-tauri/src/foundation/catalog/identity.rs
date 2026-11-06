//! Scoped identities (S2 CORE-02 "scoped content identity"; S3.3 "storage equality is not
//! permission"; GPU part §3.4 "keep private models, licensed weights and tenant-derived
//! state in their authorized scope").

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::ids::{ContentKey, Digest, DigestBuilder, IdError, TenantId, MAX_ID_LEN};

/// Domain of [`ObjectId`].
pub const OBJECT_DOMAIN: &str = "yougori/catalog/object/v1";
/// Domain of [`RootId`].
pub const ROOT_DOMAIN: &str = "yougori/catalog/root/v1";
/// Domain of [`SourceIdentity::describe`].
pub const SOURCE_DOMAIN: &str = "yougori/catalog/source/v1";

/// The authorized scope that owns an object (GPU part §3.4).
///
/// Reading an object outside its owning scope needs a grant for that exact object
/// (S3.3, INT-05). There is no public scope: every read is either by the owner or under a
/// grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Scope {
    /// Yougori's own artifacts, such as guest images and runtime updates.
    Host,
    /// One tenant's artifacts: private models, licensed weights, tenant-derived state.
    Tenant { tenant: TenantId },
}

crate::foundation::strict_serde::strict_tag!(Scope, "scope");

impl Scope {
    /// A tenant's private scope.
    pub fn tenant(tenant: TenantId) -> Self {
        Self::Tenant { tenant }
    }

    /// The owning tenant; `None` for the host scope.
    pub fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::Host => None,
            Self::Tenant { tenant } => Some(tenant),
        }
    }

    /// Writes the scope as two digest parts: a kind tag and the tenant (empty for host).
    pub(super) fn bind(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Host => builder.str("host").str(""),
            Self::Tenant { tenant } => builder.str("tenant").str(tenant.as_str()),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => f.write_str("host"),
            Self::Tenant { tenant } => write!(f, "tenant {tenant}"),
        }
    }
}

/// The artifact class an object belongs to; each class has its own responsible verifier
/// and its own publisher/trust policy (INT-09; S2 CORE-08).
///
/// The specialized importers named in S2 CORE-02 (model sidecars, OCI extraction, guest
/// images, document manifests) interpret their classes; the catalog only stores and
/// verifies through them. A class is admitted only once its verifier is registered and
/// its trust policy configured, so adding one widens nothing by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    /// Original model files such as safetensors or GGUF.
    ModelWeights,
    /// A sidecar index over model files (GPU part §3.3); MODELS interprets it.
    ModelSidecar,
    /// Content extracted from an OCI image.
    OciLayer,
    /// A guest disk, kernel or firmware image.
    GuestImage,
    /// A document manifest.
    DocumentManifest,
    /// A runtime or component update (INT-09).
    RuntimeUpdate,
    /// A package a sandbox's declared dependencies resolve to (VM part, dependency
    /// partition), with its own verifier and publisher policy, never an OCI layer's.
    DependencyPackage,
    /// A signed model helper bundle the model runner loads (GPU-W11), with its own
    /// publisher policy, never a runtime update's or a sidecar's.
    ModelHelper,
}

impl ArtifactClass {
    /// Every class, each with its own verifier and trust policy (INT-09).
    pub const ALL: [Self; 8] = [
        Self::ModelWeights,
        Self::ModelSidecar,
        Self::OciLayer,
        Self::GuestImage,
        Self::DocumentManifest,
        Self::RuntimeUpdate,
        Self::DependencyPackage,
        Self::ModelHelper,
    ];

    /// The stable tag written into identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ModelWeights => "model_weights",
            Self::ModelSidecar => "model_sidecar",
            Self::OciLayer => "oci_layer",
            Self::GuestImage => "guest_image",
            Self::DocumentManifest => "document_manifest",
            Self::RuntimeUpdate => "runtime_update",
            Self::DependencyPackage => "dependency_package",
            Self::ModelHelper => "model_helper",
        }
    }
}

impl fmt::Display for ArtifactClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

digest_type!(
    /// The scoped identity of one catalog object: its owning scope, its artifact class
    /// and its content key (S2 CORE-02 "scoped content identity").
    ///
    /// Equal bytes in two scopes get two identities, and the catalog has no lookup by
    /// content key across scopes, so equality never doubles as permission (S3.3).
    ObjectId
);

impl ObjectId {
    /// The identity of `content` of `class` owned by `scope`.
    pub fn new(scope: &Scope, class: ArtifactClass, content: ContentKey) -> Self {
        Self(
            scope
                .bind(DigestBuilder::new(OBJECT_DOMAIN))
                .str(class.tag())
                .digest(content.digest())
                .finish(),
        )
    }

    /// For names read back from the catalog's own directories; a record whose identity
    /// does not recompute from its scope, class and content key is never loaded.
    pub(super) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

/// What an object is to its owner (GPU part §3.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ObjectRole {
    /// Bytes as obtained from the user or the publisher: the user's original. The catalog
    /// never deletes one to meet a budget (line 552).
    Original,
    /// A representation prepared from other objects of the same scope. It is
    /// reconstructible, and so evictable, only while every object it was derived from is
    /// still published and healthy.
    Prepared { derived_from: BTreeSet<ObjectId> },
}

crate::foundation::strict_serde::strict_tag!(ObjectRole, "role");

impl ObjectRole {
    /// Whether this is a user's original, which eviction never removes (line 552).
    pub fn is_original(&self) -> bool {
        matches!(self, Self::Original)
    }
}

digest_type!(
    /// The identity of the source an import reads from: an immutable repository revision
    /// and file, a peer object, or a preparation's inputs and converter. With the tenant
    /// scope and the model execution identity it keys single flight (line 533).
    SourceIdentity
);

impl SourceIdentity {
    /// The identity of a source of `kind` (such as `hf-revision-file`) at `locator`.
    pub fn describe(kind: &str, locator: &str) -> Self {
        Self(
            DigestBuilder::new(SOURCE_DOMAIN)
                .str(kind)
                .str(locator)
                .finish(),
        )
    }

    /// Wraps an identity a specialized importer computed under its own domain.
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

digest_type!(
    /// The model execution identity an import is prepared for (GPU part §3.2, layer 3:
    /// runner, kernels, layout, processed-weight format), by the digest of
    /// `model_memory::identity::ExecutionIdentity`. With the tenant scope and the source it
    /// keys single flight (line 533). It is not the sandbox's parent execution, which only
    /// binds each subscriber.
    ModelExecutionKey
);

impl ModelExecutionKey {
    /// Wraps the digest of a model execution identity.
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

digest_type!(
    /// A publisher, identified by the fingerprint of its signing key (S2 CORE-08 "signed
    /// component identity").
    PublisherId
);

impl PublisherId {
    /// The publisher whose signing key has this fingerprint.
    pub const fn from_key_fingerprint(fingerprint: Digest) -> Self {
        Self(fingerprint)
    }
}

/// The name of a root within its scope and kind: 1–128 letters, digits, '.', '_', ':' or
/// '-', starting with a letter or digit (the rule of `ids` identifiers).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RootName(String);

impl RootName {
    /// Checks `value` against the identifier rule.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        let first = value.chars().next().ok_or(IdError::Empty)?;
        if value.len() > MAX_ID_LEN {
            return Err(IdError::TooLong { max: MAX_ID_LEN });
        }
        if let Some(character) = value.chars().find(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-'))
        }) {
            return Err(IdError::InvalidCharacter { character });
        }
        if !first.is_ascii_alphanumeric() {
            return Err(IdError::InvalidStart);
        }
        Ok(Self(value))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RootName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RootName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// What a root keeps reachable (GPU part §3.4, line 552: local model deletion and
/// source-file deletion are distinct actions, so they act on distinct roots).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A locally installed model; only local model deletion removes it.
    LocalModel,
    /// A user's original source file; only source-file deletion removes it.
    SourceFile,
}

impl RootKind {
    /// The stable tag written into root identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LocalModel => "local_model",
            Self::SourceFile => "source_file",
        }
    }
}

digest_type!(
    /// The identity of one root: its scope, kind and name.
    RootId
);

impl RootId {
    /// The identity of the root `name` of `kind` in `scope`.
    pub fn new(scope: &Scope, kind: RootKind, name: &RootName) -> Self {
        Self(
            scope
                .bind(DigestBuilder::new(ROOT_DOMAIN))
                .str(kind.tag())
                .str(name.as_str())
                .finish(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> Scope {
        Scope::tenant(TenantId::new(name).unwrap())
    }

    #[test]
    fn equal_content_gets_a_distinct_identity_per_scope_and_class() {
        let content = ContentKey::of(b"weights");
        let a = ObjectId::new(&tenant("a"), ArtifactClass::ModelWeights, content);
        let b = ObjectId::new(&tenant("b"), ArtifactClass::ModelWeights, content);
        let host = ObjectId::new(&Scope::Host, ArtifactClass::ModelWeights, content);
        let sidecar = ObjectId::new(&tenant("a"), ArtifactClass::ModelSidecar, content);
        let all = BTreeSet::from([a, b, host, sidecar]);
        assert_eq!(all.len(), 4);
        assert_eq!(
            a,
            ObjectId::new(&tenant("a"), ArtifactClass::ModelWeights, content)
        );
        assert_ne!(a.digest(), *content.digest());
    }

    #[test]
    fn a_host_scope_never_collides_with_a_tenant_named_host() {
        let content = ContentKey::of(b"x");
        assert_ne!(
            ObjectId::new(&Scope::Host, ArtifactClass::GuestImage, content),
            ObjectId::new(&tenant("host"), ArtifactClass::GuestImage, content)
        );
    }

    #[test]
    fn roots_are_distinct_by_scope_kind_and_name() {
        let name = RootName::new("llama-3.1:8b").unwrap();
        let model = RootId::new(&tenant("a"), RootKind::LocalModel, &name);
        let source = RootId::new(&tenant("a"), RootKind::SourceFile, &name);
        let other = RootId::new(&tenant("b"), RootKind::LocalModel, &name);
        assert_eq!(BTreeSet::from([model, source, other]).len(), 3);
    }

    #[test]
    fn root_names_follow_the_identifier_rule() {
        assert_eq!(RootName::new(""), Err(IdError::Empty));
        assert_eq!(RootName::new("-x"), Err(IdError::InvalidStart));
        assert_eq!(
            RootName::new("a/b"),
            Err(IdError::InvalidCharacter { character: '/' })
        );
        assert_eq!(
            RootName::new("a".repeat(MAX_ID_LEN + 1)),
            Err(IdError::TooLong { max: MAX_ID_LEN })
        );
        assert!(serde_json::from_str::<RootName>("\"bad name\"").is_err());
        assert_eq!(
            serde_json::from_str::<RootName>("\"model-1\"").unwrap(),
            RootName::new("model-1").unwrap()
        );
    }

    #[test]
    fn identities_round_trip_through_serde() {
        let scope = tenant("a");
        let json = serde_json::to_value(&scope).unwrap();
        assert_eq!(json, serde_json::json!({"scope": "tenant", "tenant": "a"}));
        assert_eq!(serde_json::from_value::<Scope>(json).unwrap(), scope);
        assert_eq!(
            serde_json::to_value(Scope::Host).unwrap(),
            serde_json::json!({"scope": "host"})
        );
        let object = ObjectId::new(&scope, ArtifactClass::OciLayer, ContentKey::of(b"x"));
        let text = serde_json::to_string(&object).unwrap();
        assert_eq!(text, format!("\"{object}\""));
        assert_eq!(serde_json::from_str::<ObjectId>(&text).unwrap(), object);
        let role = ObjectRole::Prepared {
            derived_from: BTreeSet::from([object]),
        };
        let json = serde_json::to_value(&role).unwrap();
        assert_eq!(json["role"], "prepared");
        assert_eq!(serde_json::from_value::<ObjectRole>(json).unwrap(), role);
        for class in ArtifactClass::ALL {
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(class.tag())
            );
        }
    }

    #[test]
    fn source_identities_separate_kind_and_locator() {
        assert_ne!(
            SourceIdentity::describe("ab", "c"),
            SourceIdentity::describe("a", "bc")
        );
        assert_eq!(
            SourceIdentity::describe("hf", "org/model@abc/model.safetensors"),
            SourceIdentity::describe("hf", "org/model@abc/model.safetensors")
        );
    }
}
