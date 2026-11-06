//! Freezing proposed files into an immutable manifest and validating it (VM part §5.2
//! steps 1–2, lines 2063–2064; VM-P16, VM-P37).
//!
//! The host reads each proposed file beneath the opened quarantine root through handles that
//! never follow a link ([`super::GrantedRoot`]), refusing links, reparse points, hard-linked
//! and non-regular files and names that collide, and records its name, size, kind and
//! content key (`ids::ContentKey`) with the producing execution. The manifest digest binds
//! all of it, so the later review and authorization name exactly these bytes. Validation
//! then checks allowed paths, sizes, kinds, provenance and the digest against the host's
//! promotion policy. Nothing is executed or parsed.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::fsutil::{self, HandleKind};
use super::names::{CollisionRefusal, EntryRole, GuestName, NameSet};
use super::review::{DestinationState, PathBlock, ReviewFlag};
use super::root::{GrantedRoot, RootOpenError, Walk};
use crate::foundation::ids::{
    ContentKey, Digest, DigestBuilder, ExecutionCategory, ExecutionId, MonotonicTime, OperationId,
    SandboxBootGeneration, TrustScope,
};

const MANIFEST_DOMAIN: &str = "yougori/sandbox/files/promotion-manifest/v1";

/// Who produced the proposed files (§5.2 step 2: provenance).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub operation: OperationId,
    pub scope: TrustScope,
}

/// One file the guest proposes for promotion. Declared values are guest claims; the host
/// computes the real ones and refuses a mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedFile {
    pub name: GuestName,
    pub declared_size_bytes: Option<u64>,
    pub declared_content: Option<ContentKey>,
}

/// The type of a frozen file. Only regular files are promoted; directories are implied
/// by names and links are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Regular,
    /// A regular file with an execute bit set.
    Executable,
}

impl FileKind {
    const fn tag(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Executable => "executable",
        }
    }
}

/// One frozen file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub name: GuestName,
    pub size_bytes: u64,
    pub kind: FileKind,
    pub content: ContentKey,
}

/// The immutable manifest of a proposed promotion (§5.2 step 1). Entries are ordered by
/// name and the digest binds the provenance and every entry; reading one back recomputes
/// the digest and refuses a mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ManifestWire")]
pub struct FrozenManifest {
    provenance: Provenance,
    entries: Vec<ManifestEntry>,
    digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    provenance: Provenance,
    entries: Vec<ManifestEntry>,
    digest: Digest,
}

impl TryFrom<ManifestWire> for FrozenManifest {
    type Error = PromotionRefusal;

    fn try_from(wire: ManifestWire) -> Result<Self, Self::Error> {
        let manifest = Self::new(wire.provenance, wire.entries)?;
        if manifest.digest != wire.digest {
            return Err(PromotionRefusal::ManifestDigestMismatch);
        }
        Ok(manifest)
    }
}

impl FrozenManifest {
    fn new(
        provenance: Provenance,
        mut entries: Vec<ManifestEntry>,
    ) -> Result<Self, PromotionRefusal> {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let mut names = NameSet::new();
        for entry in &entries {
            names
                .insert(&entry.name, EntryRole::File)
                .map_err(|refusal| PromotionRefusal::Collision { refusal })?;
        }
        let digest = manifest_digest(&provenance, &entries);
        Ok(Self {
            provenance,
            entries,
            digest,
        })
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The sum of every entry's size.
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .iter()
            .fold(0u64, |total, entry| total.saturating_add(entry.size_bytes))
    }
}

pub(super) fn category_tag(category: ExecutionCategory) -> &'static str {
    match category {
        ExecutionCategory::VmSandbox => "vm_sandbox",
        ExecutionCategory::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
        ExecutionCategory::ProviderContainerRuntime => "provider_container_runtime",
        ExecutionCategory::HostProcessModelRuntime => "host_process_model_runtime",
    }
}

fn manifest_digest(provenance: &Provenance, entries: &[ManifestEntry]) -> Digest {
    let mut builder = DigestBuilder::new(MANIFEST_DOMAIN)
        .str(provenance.execution.as_str())
        .u64(provenance.boot.get())
        .str(provenance.operation.as_str())
        .str(category_tag(provenance.scope.category))
        .digest(&provenance.scope.domain)
        .u64(entries.len() as u64);
    for entry in entries {
        builder = builder
            .str(entry.name.as_str())
            .u64(entry.size_bytes)
            .str(entry.kind.tag())
            .digest(entry.content.digest());
    }
    builder.finish()
}

/// The provenance a promotion must come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedProvenance {
    pub execution: ExecutionId,
    pub scope: TrustScope,
}

/// The host's promotion policy (§5.2 step 2). An empty prefix list allows nothing.
/// Prefixes compare with exact case, so a differently cased spelling is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionPolicy {
    pub allowed_prefixes: Vec<GuestName>,
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub allow_executable: bool,
    pub expected: ExpectedProvenance,
}

/// One filesystem step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoStep {
    ReadSource,
    ObserveDestination,
    InspectRoot,
    WriteBackup,
    CreateDirectory,
    WriteFile,
    Replace,
    Rollback,
}

/// Why a promotion step refused (VM part §5.2). Names are guest names; host paths never
/// appear in a refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum PromotionRefusal {
    NoFiles,
    TooManyEntries {
        entries: usize,
        limit: usize,
    },
    Collision {
        refusal: CollisionRefusal,
    },
    SourceMissing {
        name: GuestName,
    },
    SourceBlocked {
        name: GuestName,
        component: usize,
        block: PathBlock,
    },
    SourceIsLink {
        name: GuestName,
    },
    SourceNotRegularFile {
        name: GuestName,
    },
    /// A hard-linked source: another name may lie outside the quarantine root.
    SourceHasOtherNames {
        name: GuestName,
    },
    FileTooLarge {
        name: GuestName,
        size_bytes: u64,
        limit: u64,
    },
    TotalTooLarge {
        total_bytes: u64,
        limit: u64,
    },
    DeclaredSizeMismatch {
        name: GuestName,
        declared_bytes: u64,
        actual_bytes: u64,
    },
    DeclaredContentMismatch {
        name: GuestName,
    },
    SourceChangedWhileReading {
        name: GuestName,
    },
    ManifestDigestMismatch,
    ProvenanceMismatch,
    PathNotAllowed {
        name: GuestName,
    },
    KindNotAllowed {
        name: GuestName,
        kind: FileKind,
    },
    DestinationRootInvalid,
    /// The destination entry is not a regular file that can be replaced.
    TargetNotAFile {
        name: GuestName,
        state: DestinationState,
    },
    SnapshotDoesNotMatchManifest,
    SnapshotDigestMismatch,
    ReviewDigestMismatch,
    /// Flags the authorization did not acknowledge (§5.2 step 3).
    UnacknowledgedFlags {
        name: GuestName,
        flags: Vec<ReviewFlag>,
    },
    /// An acknowledgment for a flag or entry the review does not have.
    UnexpectedAcknowledgment {
        name: GuestName,
    },
    /// The authorization is bound to another manifest, review or destination base.
    AuthorizationMismatch {
        bound: &'static str,
    },
    AuthorizationExpired {
        expired_at: MonotonicTime,
    },
    AuthorizationOtherClock,
    AuthorizationDigestMismatch,
    BackupRootInvalid,
    /// The backup root lies inside the source or destination tree.
    BackupRootInsideTree,
    /// The destination root is not the one reviewed.
    DestinationRootChanged,
    /// A target expected absent now exists.
    TargetAppeared {
        name: GuestName,
    },
    /// A destination precondition changed after review.
    DestinationChanged {
        name: GuestName,
    },
    /// Source bytes, size or kind changed after the manifest was frozen.
    SourceChanged {
        name: GuestName,
    },
    /// The audit journal refused the record; the promotion does not proceed.
    AuditRefused {
        detail: String,
    },
    /// A staging or backup name the promotion needs is already taken.
    StagingConflict {
        name: GuestName,
    },
    Io {
        step: IoStep,
        name: Option<GuestName>,
        detail: String,
    },
    /// Applying stopped part-way and was undone: `restored` were put back, `unrestored`
    /// changed again after the promotion wrote them and were left alone.
    RolledBack {
        cause: Box<PromotionRefusal>,
        restored: Vec<GuestName>,
        unrestored: Vec<GuestName>,
    },
}

impl PromotionRefusal {
    pub(super) fn io(step: IoStep, name: Option<&GuestName>, error: &std::io::Error) -> Self {
        Self::Io {
            step,
            name: name.cloned(),
            detail: format!("{:?}", error.kind()),
        }
    }
}

impl fmt::Display for PromotionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFiles => f.write_str("nothing was proposed"),
            Self::TooManyEntries { entries, limit } => {
                write!(f, "{entries} files proposed; at most {limit}")
            }
            Self::Collision { refusal } => write!(f, "{refusal}"),
            Self::SourceMissing { name } => write!(f, "{name} is not in the quarantine"),
            Self::SourceBlocked {
                name,
                component,
                block,
            } => write!(
                f,
                "component {component} of {name} is a {block:?}, not a directory"
            ),
            Self::SourceIsLink { name } => write!(f, "{name} is a link or reparse point"),
            Self::SourceNotRegularFile { name } => write!(f, "{name} is not a regular file"),
            Self::SourceHasOtherNames { name } => write!(f, "{name} is hard-linked"),
            Self::FileTooLarge {
                name,
                size_bytes,
                limit,
            } => write!(f, "{name} has {size_bytes} bytes; at most {limit}"),
            Self::TotalTooLarge { total_bytes, limit } => {
                write!(f, "{total_bytes} bytes in total; at most {limit}")
            }
            Self::DeclaredSizeMismatch {
                name,
                declared_bytes,
                actual_bytes,
            } => write!(
                f,
                "{name} was declared as {declared_bytes} bytes but has {actual_bytes}"
            ),
            Self::DeclaredContentMismatch { name } => {
                write!(f, "{name} does not have the declared content")
            }
            Self::SourceChangedWhileReading { name } => {
                write!(f, "{name} changed while it was read")
            }
            Self::ManifestDigestMismatch => f.write_str("the manifest digest does not match"),
            Self::ProvenanceMismatch => f.write_str("the files come from another execution"),
            Self::PathNotAllowed { name } => write!(f, "{name} is outside the allowed paths"),
            Self::KindNotAllowed { name, kind } => write!(f, "{name} is {kind:?}, not allowed"),
            Self::DestinationRootInvalid => {
                f.write_str("the destination root is not a real directory")
            }
            Self::TargetNotAFile { name, state } => {
                write!(f, "{name} cannot be replaced: {state:?}")
            }
            Self::SnapshotDoesNotMatchManifest => {
                f.write_str("the destination snapshot is for other files")
            }
            Self::SnapshotDigestMismatch => f.write_str("the destination digest does not match"),
            Self::ReviewDigestMismatch => f.write_str("the review digest does not match"),
            Self::UnacknowledgedFlags { name, flags } => {
                write!(f, "{name} has unacknowledged flags {flags:?}")
            }
            Self::UnexpectedAcknowledgment { name } => {
                write!(f, "{name} was acknowledged for flags it does not have")
            }
            Self::AuthorizationMismatch { bound } => {
                write!(f, "the authorization is for another {bound}")
            }
            Self::AuthorizationExpired { expired_at } => {
                write!(
                    f,
                    "the authorization expired at {} ns",
                    expired_at.as_nanos()
                )
            }
            Self::AuthorizationOtherClock => {
                f.write_str("the authorization was stamped on another clock session")
            }
            Self::AuthorizationDigestMismatch => {
                f.write_str("the authorization digest does not match")
            }
            Self::BackupRootInvalid => f.write_str("the backup root is not a real directory"),
            Self::BackupRootInsideTree => {
                f.write_str("the backup root lies inside the source or destination")
            }
            Self::DestinationRootChanged => f.write_str("the destination root changed"),
            Self::TargetAppeared { name } => write!(f, "{name} appeared after review"),
            Self::DestinationChanged { name } => write!(f, "{name} changed after review"),
            Self::SourceChanged { name } => write!(f, "{name} changed after it was frozen"),
            Self::AuditRefused { detail } => write!(f, "the audit record was refused: {detail}"),
            Self::StagingConflict { name } => write!(f, "a staging name for {name} is taken"),
            Self::Io { step, name, detail } => match name {
                Some(name) => write!(f, "{step:?} failed for {name}: {detail}"),
                None => write!(f, "{step:?} failed: {detail}"),
            },
            Self::RolledBack {
                cause,
                restored,
                unrestored,
            } => write!(
                f,
                "undone after: {cause} ({} restored, {} left alone)",
                restored.len(),
                unrestored.len()
            ),
        }
    }
}

impl std::error::Error for PromotionRefusal {}

/// Hashes `name` beneath the opened `root` as a regular single-name file of at most
/// `max_bytes`, in bounded chunks through handles that never follow a link: its size, kind
/// and content key. Nothing of its content is kept.
pub(super) fn hash_source(
    root: &GrantedRoot,
    name: &GuestName,
    max_bytes: u64,
) -> Result<(u64, FileKind, ContentKey), PromotionRefusal> {
    let (mut opened, kind) = open_source_file(root, name, max_bytes)?;
    let size_bytes = opened.info.size;
    let content = fsutil::hash_open(&mut opened.file, size_bytes)
        .map_err(|error| PromotionRefusal::io(IoStep::ReadSource, Some(name), &error))?
        .ok_or_else(|| PromotionRefusal::SourceChangedWhileReading { name: name.clone() })?;
    let after = fsutil::file_info(&opened.file)
        .map_err(|error| PromotionRefusal::io(IoStep::ReadSource, Some(name), &error))?;
    if after.kind != HandleKind::File || after.size != size_bytes {
        return Err(PromotionRefusal::SourceChangedWhileReading { name: name.clone() });
    }
    Ok((size_bytes, kind, content))
}

/// Opens `name` beneath the opened `root` as a regular single-name file of at most
/// `max_bytes`, through handles that never follow a link, with its kind.
pub(super) fn open_source_file(
    root: &GrantedRoot,
    name: &GuestName,
    max_bytes: u64,
) -> Result<(super::root::Opened, FileKind), PromotionRefusal> {
    let opened = match root
        .walk(name)
        .map_err(|error| PromotionRefusal::io(IoStep::ReadSource, Some(name), &error))?
    {
        Walk::Found(opened) => opened,
        Walk::Missing { .. } => return Err(PromotionRefusal::SourceMissing { name: name.clone() }),
        Walk::Blocked { component, stop } => {
            return Err(PromotionRefusal::SourceBlocked {
                name: name.clone(),
                component,
                block: stop.block(),
            })
        }
    };
    match opened.info.kind {
        HandleKind::Link(_) => return Err(PromotionRefusal::SourceIsLink { name: name.clone() }),
        HandleKind::File => {}
        HandleKind::Directory | HandleKind::Device => {
            return Err(PromotionRefusal::SourceNotRegularFile { name: name.clone() })
        }
    }
    if opened.info.links > 1 {
        return Err(PromotionRefusal::SourceHasOtherNames { name: name.clone() });
    }
    if opened.info.size > max_bytes {
        return Err(PromotionRefusal::FileTooLarge {
            name: name.clone(),
            size_bytes: opened.info.size,
            limit: max_bytes,
        });
    }
    let kind = if opened.info.executable {
        FileKind::Executable
    } else {
        FileKind::Regular
    };
    Ok((opened, kind))
}

/// Opens the host-selected quarantine root at `path`.
pub(super) fn open_source(path: &Path) -> Result<GrantedRoot, PromotionRefusal> {
    GrantedRoot::open(path).map_err(|error| {
        let error = match error {
            RootOpenError::NotARealDirectory | RootOpenError::Changed => {
                std::io::Error::from(std::io::ErrorKind::InvalidInput)
            }
            RootOpenError::Io(error) => error,
        };
        PromotionRefusal::io(IoStep::InspectRoot, None, &error)
    })
}

/// Freezes `proposal` from the quarantine `source_root` into a manifest (§5.2 step 1),
/// opening the host-selected root first and reading at most the policy's sizes.
pub fn freeze(
    source_root: &Path,
    proposal: &[ProposedFile],
    provenance: Provenance,
    policy: &PromotionPolicy,
) -> Result<FrozenManifest, PromotionRefusal> {
    if proposal.is_empty() {
        return Err(PromotionRefusal::NoFiles);
    }
    freeze_in(&open_source(source_root)?, proposal, provenance, policy)
}

/// Freezes `proposal` from the already opened quarantine root `source` into a manifest
/// (§5.2 step 1), reading at most the policy's sizes.
pub fn freeze_in(
    source: &GrantedRoot,
    proposal: &[ProposedFile],
    provenance: Provenance,
    policy: &PromotionPolicy,
) -> Result<FrozenManifest, PromotionRefusal> {
    if proposal.is_empty() {
        return Err(PromotionRefusal::NoFiles);
    }
    if proposal.len() > policy.max_entries {
        return Err(PromotionRefusal::TooManyEntries {
            entries: proposal.len(),
            limit: policy.max_entries,
        });
    }
    let mut names = NameSet::new();
    for file in proposal {
        names
            .insert(&file.name, EntryRole::File)
            .map_err(|refusal| PromotionRefusal::Collision { refusal })?;
    }
    let mut entries = Vec::with_capacity(proposal.len());
    let mut total_bytes = 0u64;
    for file in proposal {
        let (size_bytes, kind, content) = hash_source(source, &file.name, policy.max_file_bytes)?;
        if let Some(declared_bytes) = file.declared_size_bytes {
            if declared_bytes != size_bytes {
                return Err(PromotionRefusal::DeclaredSizeMismatch {
                    name: file.name.clone(),
                    declared_bytes,
                    actual_bytes: size_bytes,
                });
            }
        }
        if file
            .declared_content
            .is_some_and(|declared| declared != content)
        {
            return Err(PromotionRefusal::DeclaredContentMismatch {
                name: file.name.clone(),
            });
        }
        total_bytes = total_bytes.saturating_add(size_bytes);
        if total_bytes > policy.max_total_bytes {
            return Err(PromotionRefusal::TotalTooLarge {
                total_bytes,
                limit: policy.max_total_bytes,
            });
        }
        entries.push(ManifestEntry {
            name: file.name.clone(),
            size_bytes,
            kind,
            content,
        });
    }
    FrozenManifest::new(provenance, entries)
}

/// Validates allowed paths, sizes, kinds, provenance and the digest (§5.2 step 2).
pub fn validate_manifest(
    manifest: &FrozenManifest,
    policy: &PromotionPolicy,
) -> Result<(), PromotionRefusal> {
    if manifest_digest(&manifest.provenance, &manifest.entries) != manifest.digest {
        return Err(PromotionRefusal::ManifestDigestMismatch);
    }
    if manifest.provenance.execution != policy.expected.execution
        || manifest.provenance.scope != policy.expected.scope
    {
        return Err(PromotionRefusal::ProvenanceMismatch);
    }
    if manifest.entries.is_empty() {
        return Err(PromotionRefusal::NoFiles);
    }
    if manifest.entries.len() > policy.max_entries {
        return Err(PromotionRefusal::TooManyEntries {
            entries: manifest.entries.len(),
            limit: policy.max_entries,
        });
    }
    for entry in &manifest.entries {
        if !policy
            .allowed_prefixes
            .iter()
            .any(|prefix| entry.name.starts_with(prefix))
        {
            return Err(PromotionRefusal::PathNotAllowed {
                name: entry.name.clone(),
            });
        }
        if entry.size_bytes > policy.max_file_bytes {
            return Err(PromotionRefusal::FileTooLarge {
                name: entry.name.clone(),
                size_bytes: entry.size_bytes,
                limit: policy.max_file_bytes,
            });
        }
        if entry.kind == FileKind::Executable && !policy.allow_executable {
            return Err(PromotionRefusal::KindNotAllowed {
                name: entry.name.clone(),
                kind: entry.kind,
            });
        }
    }
    let total_bytes = manifest.total_bytes();
    if total_bytes > policy.max_total_bytes {
        return Err(PromotionRefusal::TotalTooLarge {
            total_bytes,
            limit: policy.max_total_bytes,
        });
    }
    Ok(())
}
