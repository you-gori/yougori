//! VM-N4 dependency manifests (VM part §9.4, lines 2385–2389 and 2395; §5.4; VM-W57).
//!
//! A manifest is compiled from a lockfile before private data enters the compute VM. Only
//! the compiler resolves package names, and only before private inputs enter; a manifest
//! derived from a private repository is a metadata release that needs an explicit,
//! digest-bound authorization charged to the release budget (§2.5: names count where they
//! leave the trust domain). Afterwards the compute VM can name only approved object IDs:
//! catalog [`ObjectId`]s in the fetch service's scope. A dynamic dependency needs an
//! approved manifest update; arbitrary registry access is never reopened.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::contract::Approval;
use super::names::LabelTag;
use super::plan::to_u64;
use crate::foundation::catalog::{ArtifactClass, ImportManifest, ObjectId, PublisherId, Scope};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder, ExecutionId};
use crate::foundation::transfer::{Endpoint, GeneralReleaseBudget, ReleaseBudgetExceeded};

/// Domain of manifest, draft and update digests.
pub const MANIFEST_DOMAIN: &str = "yougori/sandbox/partition/manifest/v1";
/// Most entries one manifest may hold.
pub const MAX_MANIFEST_ENTRIES: usize = 4096;
const MAX_NAME_BYTES: usize = 214;
const MAX_VERSION_BYTES: usize = 128;
/// Length framing counted per disclosed field (§2.5: framing counts).
const FRAMING_BYTES: u64 = 8;
/// A registry route is disclosed as its 32-byte registration digest.
const ROUTE_BYTES: u64 = 32;

fn check_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A package name as a lockfile states it. Only the manifest compiler resolves names; a
/// private VM never may (line 2387).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PackageName(String);

impl PackageName {
    /// 1–214 visible ASCII characters.
    pub fn new(text: impl Into<String>) -> Result<Self, ManifestRefusal> {
        let text = text.into();
        if !check_text(&text, MAX_NAME_BYTES) {
            return Err(ManifestRefusal::InvalidName);
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PackageName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One pinned lockfile entry: name, version, artifact class, expected content and the
/// registry route registered by the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockEntry {
    pub name: PackageName,
    pub version: String,
    pub class: ArtifactClass,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    /// The registration digest of the registry route (CORE-05 named route).
    pub route: Digest,
}

impl LockEntry {
    fn disclosed_bytes(&self) -> u64 {
        to_u64(self.name.0.len())
            .saturating_add(to_u64(self.version.len()))
            .saturating_add(ROUTE_BYTES)
            .saturating_add(3 * FRAMING_BYTES)
    }
}

/// Where the fetch service reads an approved object: a registered route and the
/// registry's opaque pin for one artifact. No variant holds a URL.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedSource {
    pub route: Endpoint,
    pub coordinates: Digest,
}

/// What resolving a name at a registry returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedArtifact {
    pub coordinates: Digest,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    pub publisher: PublisherId,
}

/// A pinned artifact's declaration: its extent table and its publisher's attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedArtifact {
    pub manifest: ImportManifest,
    pub publisher: PublisherId,
    pub attestation: Vec<u8>,
}

/// A registry's answer to a pinned request. A redirect is never followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryReply {
    Artifact(PinnedArtifact),
    Redirect { location: String },
}

/// A registry failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    NotFound,
    Unavailable { detail: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("the registry has no such artifact"),
            Self::Unavailable { detail } => write!(f, "the registry is unavailable: {detail}"),
        }
    }
}

/// The registry side, as the fetch service and manifest compiler see it. Tests use fakes;
/// nothing in this module opens a connection.
pub trait RegistryPort {
    /// Resolves `name` at `version` on `route`. Only the manifest compiler calls this.
    fn resolve(
        &mut self,
        route: &Endpoint,
        name: &PackageName,
        version: &str,
    ) -> Result<ResolvedArtifact, RegistryError>;

    /// The declaration of one pinned artifact.
    fn declaration(&mut self, pin: &PinnedSource) -> Result<RegistryReply, RegistryError>;

    /// The artifact's length.
    fn length_bytes(&mut self, pin: &PinnedSource) -> Result<u64, RegistryError>;

    /// Reads from `offset_bytes` into `buffer`; returns how many bytes were read.
    fn read_at(
        &mut self,
        pin: &PinnedSource,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, RegistryError>;
}

strict_tagged_enum! {
/// What a manifest was compiled from (line 2389).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManifestOrigin (tag = "origin", wire = ManifestOriginWire, wire_name = "ManifestOriginWire") {
    /// A public lockfile.
    PublicLockfile,
    /// Dependencies derived from a private repository in a restricted inspection
    /// environment: their names can disclose private information.
    DerivedFromPrivate { source: LabelTag },
}
}

/// Whether private inputs have entered the compute VM yet (§5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateExposure {
    BeforePrivateInputs,
    PrivateInputsEntered,
}

/// Why a manifest, draft or update was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestRefusal {
    InvalidName,
    InvalidVersion,
    TooManyEntries {
        entries: usize,
        max: usize,
    },
    /// The fetch service and the compute VM must be separate scopes (line 2385).
    SameScope,
    DuplicateEntry {
        name: PackageName,
        version: String,
    },
    DuplicateContent {
        content_key: ContentKey,
    },
    /// Resolving names after private data entered the compute VM can carry that data
    /// (§5.4, VM-P45).
    PotentialExfiltration,
    /// A private-derived manifest's names are a metadata release (line 2389).
    MetadataReleaseNotAuthorized {
        draft: Digest,
        metadata_bytes: u64,
    },
    AuthorizationForOtherManifest {
        authorized: Digest,
        draft: Digest,
    },
    ReleaseBudget {
        exceeded: ReleaseBudgetExceeded,
    },
    Registry {
        name: PackageName,
        error: RegistryError,
    },
    /// The registry resolved the name to other content than the lockfile pins.
    LockMismatch {
        name: PackageName,
        version: String,
    },
    /// A dynamic dependency needs a manifest-update decision (line 2395).
    UpdateNeedsDecision,
    ApprovalForOtherUpdate,
    UpdateForOtherManifest,
    Encoding,
}

impl fmt::Display for ManifestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("a package name is 1-214 visible ASCII characters"),
            Self::InvalidVersion => f.write_str("a version is 1-128 visible ASCII characters"),
            Self::TooManyEntries { entries, max } => {
                write!(f, "{entries} entries; a manifest holds at most {max}")
            }
            Self::SameScope => {
                f.write_str("the fetch service and the compute VM must own separate scopes")
            }
            Self::DuplicateEntry { name, version } => {
                write!(f, "{name} {version} is listed twice")
            }
            Self::DuplicateContent { content_key } => {
                write!(f, "content {content_key} is listed twice")
            }
            Self::PotentialExfiltration => f.write_str(
                "private inputs have entered the compute VM; resolving package names now could \
                 carry private data, so dependencies are fixed before private inputs enter",
            ),
            Self::MetadataReleaseNotAuthorized {
                draft,
                metadata_bytes,
            } => write!(
                f,
                "manifest {draft} is derived from private data; releasing its {metadata_bytes} \
                 bytes of names needs explicit authorization before fetching"
            ),
            Self::AuthorizationForOtherManifest { authorized, draft } => write!(
                f,
                "the authorization covers manifest {authorized}, not {draft}"
            ),
            Self::ReleaseBudget { exceeded } => exceeded.fmt(f),
            Self::Registry { name, error } => write!(f, "resolving {name}: {error}"),
            Self::LockMismatch { name, version } => write!(
                f,
                "{name} {version} resolved to other content than the lockfile pins"
            ),
            Self::UpdateNeedsDecision => f.write_str(
                "a dynamic dependency needs an approved manifest update; registry access is \
                 never reopened",
            ),
            Self::ApprovalForOtherUpdate => f.write_str("the approval covers another update"),
            Self::UpdateForOtherManifest => f.write_str("the update was made for another manifest"),
            Self::Encoding => f.write_str("the manifest could not be encoded"),
        }
    }
}

impl std::error::Error for ManifestRefusal {}

fn check_entries(entries: &[LockEntry], existing: &[&LockEntry]) -> Result<(), ManifestRefusal> {
    let mut names = BTreeSet::new();
    let mut contents = BTreeSet::new();
    for entry in existing.iter().copied().chain(entries.iter()) {
        if !check_text(&entry.version, MAX_VERSION_BYTES) {
            return Err(ManifestRefusal::InvalidVersion);
        }
        if !names.insert((entry.name.clone(), entry.version.clone())) {
            return Err(ManifestRefusal::DuplicateEntry {
                name: entry.name.clone(),
                version: entry.version.clone(),
            });
        }
        if !contents.insert((entry.class, entry.content_key)) {
            return Err(ManifestRefusal::DuplicateContent {
                content_key: entry.content_key,
            });
        }
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ManifestRefusal> {
    serde_json::to_vec(value).map_err(|_| ManifestRefusal::Encoding)
}

/// A lockfile ready to compile, with the bytes of names it would disclose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestDraft {
    fetch_scope: Scope,
    consumer: Scope,
    execution: ExecutionId,
    origin: ManifestOrigin,
    entries: Vec<LockEntry>,
    metadata_bytes: u64,
    digest: Digest,
}

impl ManifestDraft {
    /// A draft for the compute VM `execution` of scope `consumer`, fetched into
    /// `fetch_scope`. Entries are kept sorted by name and version.
    pub fn new(
        fetch_scope: Scope,
        consumer: Scope,
        execution: ExecutionId,
        origin: ManifestOrigin,
        mut entries: Vec<LockEntry>,
    ) -> Result<Self, ManifestRefusal> {
        if fetch_scope == consumer {
            return Err(ManifestRefusal::SameScope);
        }
        if entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(ManifestRefusal::TooManyEntries {
                entries: entries.len(),
                max: MAX_MANIFEST_ENTRIES,
            });
        }
        check_entries(&entries, &[])?;
        entries
            .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
        let metadata_bytes = entries.iter().fold(0u64, |sum, entry| {
            sum.saturating_add(entry.disclosed_bytes())
        });
        let digest = DigestBuilder::new(MANIFEST_DOMAIN)
            .str("draft")
            .bytes(&encode(&fetch_scope)?)
            .bytes(&encode(&consumer)?)
            .str(execution.as_str())
            .bytes(&encode(&origin)?)
            .bytes(&encode(&entries)?)
            .finish();
        Ok(Self {
            fetch_scope,
            consumer,
            execution,
            origin,
            entries,
            metadata_bytes,
            digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The bytes of names, versions, routes and framing the draft discloses to a
    /// registry when resolved (§2.5).
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }

    pub fn origin(&self) -> &ManifestOrigin {
        &self.origin
    }

    pub fn entries(&self) -> &[LockEntry] {
        &self.entries
    }
}

/// An explicit authorization of a metadata release, bound to one draft or update digest
/// and its byte count (line 2389).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataReleaseAuthorization {
    authorized: Digest,
    metadata_bytes: u64,
    approval: Approval,
}

impl MetadataReleaseAuthorization {
    /// Authorizes releasing `draft`'s names.
    pub fn new(draft: &ManifestDraft, approval: Approval) -> Self {
        Self {
            authorized: draft.digest,
            metadata_bytes: draft.metadata_bytes,
            approval,
        }
    }

    pub fn approval(&self) -> &Approval {
        &self.approval
    }
}

/// One approved entry: the catalog object the compute VM may request and where the
/// fetch service finds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    pub object: ObjectId,
    pub class: ArtifactClass,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    pub pin: PinnedSource,
    pub publisher: PublisherId,
}

/// An approved, pinned dependency manifest bound to one compute VM (line 2385).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DependencyManifest {
    fetch_scope: Scope,
    consumer: Scope,
    execution: ExecutionId,
    origin: ManifestOrigin,
    version: u32,
    entries: BTreeMap<ObjectId, ManifestEntry>,
    locks: Vec<LockEntry>,
    digest: Digest,
}

impl DependencyManifest {
    /// The scope the fetch service imports into and owns.
    pub fn fetch_scope(&self) -> &Scope {
        &self.fetch_scope
    }

    /// The compute VM's scope, the only grantee.
    pub fn consumer(&self) -> &Scope {
        &self.consumer
    }

    /// The compute VM's execution, the only reader.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn origin(&self) -> &ManifestOrigin {
        &self.origin
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn entries(&self) -> &BTreeMap<ObjectId, ManifestEntry> {
        &self.entries
    }

    pub fn entry(&self, object: &ObjectId) -> Option<&ManifestEntry> {
        self.entries.get(object)
    }

    /// Every entry as a CORE-05 transfer scope: the objects and whole ranges a prefetch
    /// may move.
    pub fn transfer_scope(
        &self,
    ) -> Result<crate::foundation::transfer::TransferScope, crate::foundation::transfer::ScopeError>
    {
        use crate::foundation::transfer::{ObjectGrant, TransferScope};
        let grants = self
            .entries
            .values()
            .map(|entry| {
                ObjectGrant::whole(entry.length_bytes).map(|grant| (entry.content_key, grant))
            })
            .collect::<Result<Vec<_>, _>>()?;
        TransferScope::new(grants)
    }

    fn seal(mut self) -> Result<Self, ManifestRefusal> {
        let entries: Vec<&ManifestEntry> = self.entries.values().collect();
        self.digest = DigestBuilder::new(MANIFEST_DOMAIN)
            .str("manifest")
            .bytes(&encode(&self.fetch_scope)?)
            .bytes(&encode(&self.consumer)?)
            .str(self.execution.as_str())
            .bytes(&encode(&self.origin)?)
            .u64(u64::from(self.version))
            .bytes(&encode(&entries)?)
            .finish();
        Ok(self)
    }
}

/// Resolves lockfile entries to pinned, approved catalog objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManifestCompiler;

fn resolve_entries(
    fetch_scope: &Scope,
    entries: &[LockEntry],
    registry: &mut dyn RegistryPort,
) -> Result<Vec<ManifestEntry>, ManifestRefusal> {
    let mut resolved = Vec::with_capacity(entries.len());
    for entry in entries {
        let route = Endpoint::NamedRoute { route: entry.route };
        let artifact = registry
            .resolve(&route, &entry.name, &entry.version)
            .map_err(|error| ManifestRefusal::Registry {
                name: entry.name.clone(),
                error,
            })?;
        if artifact.content_key != entry.content_key || artifact.length_bytes != entry.length_bytes
        {
            return Err(ManifestRefusal::LockMismatch {
                name: entry.name.clone(),
                version: entry.version.clone(),
            });
        }
        resolved.push(ManifestEntry {
            object: ObjectId::new(fetch_scope, entry.class, entry.content_key),
            class: entry.class,
            content_key: entry.content_key,
            length_bytes: entry.length_bytes,
            pin: PinnedSource {
                route,
                coordinates: artifact.coordinates,
            },
            publisher: artifact.publisher,
        });
    }
    Ok(resolved)
}

impl ManifestCompiler {
    /// Compiles `draft` before private inputs enter the compute VM (line 2385). A
    /// private-derived draft needs an authorization for exactly this draft, and its
    /// metadata bytes are charged to `budget` before any registry is contacted
    /// (line 2389, §2.5).
    pub fn compile(
        &self,
        draft: &ManifestDraft,
        registry: &mut dyn RegistryPort,
        exposure: PrivateExposure,
        authorization: Option<&MetadataReleaseAuthorization>,
        budget: &mut GeneralReleaseBudget,
    ) -> Result<DependencyManifest, ManifestRefusal> {
        if exposure == PrivateExposure::PrivateInputsEntered {
            return Err(ManifestRefusal::PotentialExfiltration);
        }
        if let ManifestOrigin::DerivedFromPrivate { .. } = draft.origin {
            let authorization =
                authorization.ok_or(ManifestRefusal::MetadataReleaseNotAuthorized {
                    draft: draft.digest,
                    metadata_bytes: draft.metadata_bytes,
                })?;
            if authorization.authorized != draft.digest
                || authorization.metadata_bytes != draft.metadata_bytes
            {
                return Err(ManifestRefusal::AuthorizationForOtherManifest {
                    authorized: authorization.authorized,
                    draft: draft.digest,
                });
            }
            budget
                .charge(draft.metadata_bytes)
                .map_err(|exceeded| ManifestRefusal::ReleaseBudget { exceeded })?;
        }
        let resolved = resolve_entries(&draft.fetch_scope, &draft.entries, registry)?;
        DependencyManifest {
            fetch_scope: draft.fetch_scope.clone(),
            consumer: draft.consumer.clone(),
            execution: draft.execution.clone(),
            origin: draft.origin.clone(),
            version: 1,
            entries: resolved
                .into_iter()
                .map(|entry| (entry.object, entry))
                .collect(),
            locks: draft.entries.clone(),
            digest: Digest::from_bytes([0; 32]),
        }
        .seal()
    }

    /// Applies an approved manifest update (line 2395). Without a decision for exactly
    /// this update of exactly this manifest it is refused. Names requested after private
    /// inputs entered, or added to a private-derived manifest, are a metadata release
    /// charged to `budget`.
    pub fn apply_update(
        &self,
        manifest: &DependencyManifest,
        update: &ManifestUpdate,
        approval: Option<&UpdateApproval>,
        registry: &mut dyn RegistryPort,
        budget: &mut GeneralReleaseBudget,
    ) -> Result<DependencyManifest, ManifestRefusal> {
        let approval = approval.ok_or(ManifestRefusal::UpdateNeedsDecision)?;
        if approval.update != update.digest {
            return Err(ManifestRefusal::ApprovalForOtherUpdate);
        }
        if update.base != manifest.digest {
            return Err(ManifestRefusal::UpdateForOtherManifest);
        }
        let existing: Vec<&LockEntry> = manifest.locks.iter().collect();
        check_entries(&update.additions, &existing)?;
        let entries = manifest.locks.len().saturating_add(update.additions.len());
        if entries > MAX_MANIFEST_ENTRIES {
            return Err(ManifestRefusal::TooManyEntries {
                entries,
                max: MAX_MANIFEST_ENTRIES,
            });
        }
        let private_names = update.exposure == PrivateExposure::PrivateInputsEntered
            || matches!(manifest.origin, ManifestOrigin::DerivedFromPrivate { .. });
        if private_names {
            budget
                .charge(update.metadata_bytes)
                .map_err(|exceeded| ManifestRefusal::ReleaseBudget { exceeded })?;
        }
        let resolved = resolve_entries(&manifest.fetch_scope, &update.additions, registry)?;
        let mut next = manifest.clone();
        next.version = manifest.version.saturating_add(1);
        for entry in resolved {
            next.entries.insert(entry.object, entry);
        }
        next.locks.extend(update.additions.iter().cloned());
        next.seal()
    }
}

/// A requested manifest change: dynamic dependencies (line 2395).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestUpdate {
    base: Digest,
    additions: Vec<LockEntry>,
    exposure: PrivateExposure,
    metadata_bytes: u64,
    digest: Digest,
}

impl ManifestUpdate {
    /// A request to add `additions` to `base`, made with the compute VM at `exposure`.
    pub fn new(
        base: &DependencyManifest,
        additions: Vec<LockEntry>,
        exposure: PrivateExposure,
    ) -> Result<Self, ManifestRefusal> {
        let existing: Vec<&LockEntry> = base.locks.iter().collect();
        check_entries(&additions, &existing)?;
        let metadata_bytes = additions.iter().fold(0u64, |sum, entry| {
            sum.saturating_add(entry.disclosed_bytes())
        });
        let digest = DigestBuilder::new(MANIFEST_DOMAIN)
            .str("update")
            .digest(&base.digest)
            .bytes(&encode(&additions)?)
            .bytes(&encode(&exposure)?)
            .finish();
        Ok(Self {
            base: base.digest,
            additions,
            exposure,
            metadata_bytes,
            digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The bytes of names the update would disclose (§2.5).
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }
}

/// The decision approving one manifest update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateApproval {
    update: Digest,
    approval: Approval,
}

impl UpdateApproval {
    pub fn new(update: &ManifestUpdate, approval: Approval) -> Self {
        Self {
            update: update.digest,
            approval,
        }
    }

    pub fn approval(&self) -> &Approval {
        &self.approval
    }
}
