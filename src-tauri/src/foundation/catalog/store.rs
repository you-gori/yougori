//! The on-disk layout under the caller's root and the durable records (GPU part §3.3,
//! line 533: temporary representation, complete index, read-back validation, durable
//! commit, catalog publication).
//!
//! ```text
//! <root>/staging/<flight>/flight.json         the staging declaration
//! <root>/staging/<flight>/journal             extents verified and synced, append-only
//! <root>/staging/<flight>/object/data         the temporary representation
//! <root>/staging/<flight>/object/index.json   its complete index
//! <root>/objects/<object>/{data,index.json}   committed, read-only
//! <root>/records/<object>.json                publication: published iff this exists
//! <root>/roots/<root>.json                    durable roots
//! <root>/format.json                          the layout format (see `migrate`)
//! <root>/catalog.lock                         empty; the open catalog locks it (see `lock`)
//! ```
//!
//! Every record is written to a temporary file, synced and renamed into place, so a
//! reader sees the old record or the complete new one. Nothing here touches a path
//! outside the root.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::content::ImportManifest;
use super::identity::{
    ArtifactClass, ModelExecutionKey, ObjectId, ObjectRole, RootId, RootKind, RootName, Scope,
    SourceIdentity,
};
use super::provenance::{bounded_detail, StorageFailure, StorageOperation};
use super::state::ObjectMetadata;
use super::trust::TrustBasis;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, OperationId};

/// The format of publication records, object indexes and roots; each carries it.
pub(super) const FORMAT_VERSION: u32 = 1;
/// The format of staging declarations. Format 1 keyed staging by the parent execution;
/// format 2 by the model execution identity (see `migrate`).
pub(super) const STAGING_FORMAT: u32 = 2;
/// The format of staging journals: an unversioned `manifest` header. A later format
/// declares itself with a `journal <format>` header, which this build never overwrites.
pub(super) const JOURNAL_FORMAT: u32 = 1;
pub(super) const DATA_FILE: &str = "data";
pub(super) const INDEX_FILE: &str = "index.json";
/// Domain of [`ObjectIndex::digest`].
pub(super) const INDEX_DOMAIN: &str = "yougori/catalog/index/v1";
/// Bound for records without extent tables (roots, staging declarations).
pub(super) const MAX_SMALL_RECORD_BYTES: u64 = 16 << 20;
const TEMPORARY_EXTENSION: &str = "tmp";
const JOURNAL_HEADER: &str = "manifest ";
const JOURNAL_VERSIONED: &str = "journal ";
const JOURNAL_ENTRY: &str = "extent ";

/// The complete index of one object (line 533 "complete index"): its identity, owner,
/// class, role, dependencies and the full extent table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectIndex {
    pub(super) format: u32,
    pub(super) object: ObjectId,
    pub(super) scope: Scope,
    pub(super) class: ArtifactClass,
    pub(super) role: ObjectRole,
    pub(super) depends_on: BTreeSet<ObjectId>,
    pub(super) manifest: ImportManifest,
}

impl ObjectIndex {
    /// The canonical digest of every field; the publication record binds it.
    pub(super) fn digest(&self) -> Digest {
        let builder = DigestBuilder::new(INDEX_DOMAIN)
            .u64(u64::from(self.format))
            .digest(&self.object.digest());
        let builder = self.scope.bind(builder).str(self.class.tag());
        let builder = match &self.role {
            ObjectRole::Original => builder.str("original"),
            ObjectRole::Prepared { derived_from } => {
                bind_set(builder.str("prepared"), derived_from)
            }
        };
        bind_set(builder, &self.depends_on)
            .digest(&self.manifest.digest())
            .finish()
    }

    /// The identity is the one its scope, class and content key determine.
    pub(super) fn identity_holds(&self) -> bool {
        self.format == FORMAT_VERSION
            && self.object == ObjectId::new(&self.scope, self.class, self.manifest.content_key)
    }

    pub(super) fn length_bytes(&self) -> u64 {
        self.manifest.true_length_bytes
    }
}

fn bind_set(builder: DigestBuilder, objects: &BTreeSet<ObjectId>) -> DigestBuilder {
    objects
        .iter()
        .fold(builder.u64(objects.len() as u64), |builder, object| {
            builder.digest(&object.digest())
        })
}

/// The publication record (line 533 "catalog publication"): the complete index plus
/// provenance. An object is published exactly when its record exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectRecord {
    pub(super) format: u32,
    pub(super) index: ObjectIndex,
    pub(super) source: SourceIdentity,
    pub(super) trust: TrustBasis,
    pub(super) metadata: ObjectMetadata,
    pub(super) operation: OperationId,
    pub(super) execution: ExecutionId,
}

/// A durable root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootRecord {
    pub(super) format: u32,
    pub(super) scope: Scope,
    pub(super) kind: RootKind,
    pub(super) name: RootName,
    pub(super) objects: BTreeSet<ObjectId>,
}

impl RootRecord {
    pub(super) fn id(&self) -> RootId {
        RootId::new(&self.scope, self.kind, &self.name)
    }
}

/// What a staging directory was created for; a resumed import reuses it only when every
/// field matches. It names the single-flight key's parts, not the parent execution, so a
/// subscriber from another execution of the tenant resumes it too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StagingRecord {
    pub(super) format: u32,
    pub(super) flight: Digest,
    pub(super) scope: Scope,
    pub(super) class: ArtifactClass,
    pub(super) source: SourceIdentity,
    pub(super) model_execution: Option<ModelExecutionKey>,
    pub(super) manifest_digest: Digest,
    pub(super) true_length_bytes: u64,
}

/// One entry of a listed directory.
pub(super) struct Listed {
    pub(super) name: String,
    pub(super) path: PathBuf,
    pub(super) is_dir: bool,
}

/// Paths under the catalog root, and the only filesystem calls the catalog makes.
#[derive(Clone, Debug)]
pub(super) struct Layout {
    root: PathBuf,
}

impl Layout {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub(super) fn root_path(&self) -> &Path {
        &self.root
    }

    pub(super) fn staging(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub(super) fn objects(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub(super) fn records(&self) -> PathBuf {
        self.root.join("records")
    }

    pub(super) fn roots(&self) -> PathBuf {
        self.root.join("roots")
    }

    pub(super) fn flight_dir(&self, flight: &Digest) -> PathBuf {
        self.staging().join(flight.to_hex())
    }

    pub(super) fn flight_record(&self, flight: &Digest) -> PathBuf {
        self.flight_dir(flight).join(super::migrate::FLIGHT_FILE)
    }

    pub(super) fn journal(&self, flight: &Digest) -> PathBuf {
        self.flight_dir(flight).join("journal")
    }

    pub(super) fn staged_object(&self, flight: &Digest) -> PathBuf {
        self.flight_dir(flight).join("object")
    }

    pub(super) fn object_dir(&self, object: &ObjectId) -> PathBuf {
        self.objects().join(object.to_string())
    }

    pub(super) fn record(&self, object: &ObjectId) -> PathBuf {
        self.records().join(format!("{object}.json"))
    }

    pub(super) fn root_record(&self, root: &RootId) -> PathBuf {
        self.roots().join(format!("{root}.json"))
    }

    pub(super) fn ensure(&self) -> Result<(), StorageFailure> {
        for dir in [self.staging(), self.objects(), self.records(), self.roots()] {
            self.create_dir(&dir)?;
        }
        Ok(())
    }

    pub(super) fn failure(
        &self,
        operation: StorageOperation,
        path: &Path,
        detail: impl fmt::Display,
    ) -> StorageFailure {
        StorageFailure {
            operation,
            path: self.relative(path),
            detail: bounded_detail(detail),
        }
    }

    pub(super) fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    pub(super) fn create_dir(&self, path: &Path) -> Result<(), StorageFailure> {
        fs::create_dir_all(path)
            .map_err(|error| self.failure(StorageOperation::CreateDirectory, path, error))
    }

    pub(super) fn exists(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    pub(super) fn file_len(&self, path: &Path) -> Option<u64> {
        fs::metadata(path)
            .ok()
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
    }

    /// Reads a whole file of at most `max_bytes`; a larger file is refused unread.
    pub(super) fn read_bounded(
        &self,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StorageFailure> {
        let file =
            File::open(path).map_err(|error| self.failure(StorageOperation::Open, path, error))?;
        let length = file
            .metadata()
            .map_err(|error| self.failure(StorageOperation::Read, path, error))?
            .len();
        if length > max_bytes {
            return Err(self.failure(
                StorageOperation::TooLarge,
                path,
                format!("{length} bytes; the bound is {max_bytes}"),
            ));
        }
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| self.failure(StorageOperation::Read, path, error))?;
        if bytes.len() as u64 > max_bytes {
            return Err(self.failure(StorageOperation::TooLarge, path, "the file grew while read"));
        }
        Ok(bytes)
    }

    pub(super) fn write_json_atomic<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<(), StorageFailure> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| self.failure(StorageOperation::Serialize, path, error))?;
        self.write_atomic(path, &bytes)
    }

    /// Writes `bytes` to a temporary sibling, syncs it and renames it over `path`.
    pub(super) fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageFailure> {
        let temporary = path.with_extension(TEMPORARY_EXTENSION);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|error| self.failure(StorageOperation::Open, &temporary, error))?;
        file.write_all(bytes)
            .map_err(|error| self.failure(StorageOperation::Write, &temporary, error))?;
        file.sync_all()
            .map_err(|error| self.failure(StorageOperation::Sync, &temporary, error))?;
        drop(file);
        self.rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            self.sync_dir(parent)?;
        }
        Ok(())
    }

    /// Opens, creating if needed, a staging data file sized to the true length. Existing
    /// bytes are kept; only extents listed in the journal and re-verified are ever used.
    pub(super) fn open_staging_data(
        &self,
        path: &Path,
        length_bytes: u64,
    ) -> Result<File, StorageFailure> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| self.failure(StorageOperation::Open, path, error))?;
        let current_bytes = file
            .metadata()
            .map_err(|error| self.failure(StorageOperation::Read, path, error))?
            .len();
        if current_bytes != length_bytes {
            file.set_len(length_bytes)
                .map_err(|error| self.failure(StorageOperation::Write, path, error))?;
        }
        Ok(file)
    }

    /// Flushes a file's data and metadata; it must still be writable.
    pub(super) fn sync_file(&self, path: &Path) -> Result<(), StorageFailure> {
        OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| self.failure(StorageOperation::Sync, path, error))
    }

    /// Flushes a directory's entries where the platform allows it. Windows offers no
    /// directory flush through std; NTFS journals the rename itself.
    pub(super) fn sync_dir(&self, path: &Path) -> Result<(), StorageFailure> {
        #[cfg(unix)]
        {
            File::open(path)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| self.failure(StorageOperation::Sync, path, error))?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    pub(super) fn set_read_only(&self, path: &Path) -> Result<(), StorageFailure> {
        let mut permissions = fs::metadata(path)
            .map_err(|error| self.failure(StorageOperation::Permissions, path, error))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
            .map_err(|error| self.failure(StorageOperation::Permissions, path, error))
    }

    /// Makes an existing file writable again; only the importer and the collector call it.
    pub(super) fn make_writable(&self, path: &Path) -> Result<(), StorageFailure> {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Ok(());
        };
        if !metadata.permissions().readonly() {
            return Ok(());
        }
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(if metadata.is_dir() { 0o700 } else { 0o600 });
        }
        #[cfg(not(unix))]
        {
            permissions.set_readonly(false);
        }
        fs::set_permissions(path, permissions)
            .map_err(|error| self.failure(StorageOperation::Permissions, path, error))
    }

    pub(super) fn rename(&self, from: &Path, to: &Path) -> Result<(), StorageFailure> {
        fs::rename(from, to).map_err(|error| {
            self.failure(
                StorageOperation::Rename,
                from,
                format!("to {}: {error}", self.relative(to)),
            )
        })
    }

    pub(super) fn remove_file_if_exists(&self, path: &Path) -> Result<(), StorageFailure> {
        if !self.exists(path) {
            return Ok(());
        }
        self.make_writable(path)?;
        fs::remove_file(path).map_err(|error| self.failure(StorageOperation::Remove, path, error))
    }

    /// Removes a directory tree the catalog made (at most a few levels deep), clearing
    /// read-only flags first. A missing tree is already removed.
    pub(super) fn remove_tree(&self, path: &Path) -> Result<(), StorageFailure> {
        self.remove_tree_within(path, 4)
    }

    fn remove_tree_within(&self, path: &Path, depth: u32) -> Result<(), StorageFailure> {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Ok(());
        };
        if !metadata.is_dir() {
            return self.remove_file_if_exists(path);
        }
        if depth == 0 {
            return Err(self.failure(
                StorageOperation::Remove,
                path,
                "the tree is deeper than the catalog makes",
            ));
        }
        for entry in self.list(path)? {
            self.remove_tree_within(&entry.path, depth - 1)?;
        }
        self.make_writable(path)?;
        fs::remove_dir(path).map_err(|error| self.failure(StorageOperation::Remove, path, error))
    }

    pub(super) fn list(&self, dir: &Path) -> Result<Vec<Listed>, StorageFailure> {
        let entries =
            fs::read_dir(dir).map_err(|error| self.failure(StorageOperation::List, dir, error))?;
        let mut listed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| self.failure(StorageOperation::List, dir, error))?;
            let is_dir = entry
                .file_type()
                .map_err(|error| self.failure(StorageOperation::List, &entry.path(), error))?
                .is_dir();
            listed.push(Listed {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path(),
                is_dir,
            });
        }
        listed.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(listed)
    }

    /// Removes temporary files an interrupted atomic write left behind; they were never
    /// renamed into place, so they were never published. Only an open catalog, which holds
    /// the root's lock, calls it: no other catalog can be writing them.
    pub(super) fn remove_temporaries(&self) -> Result<usize, StorageFailure> {
        let mut removed = 0;
        for dir in [self.root.clone(), self.records(), self.roots()] {
            for entry in self.list(&dir)? {
                if !entry.is_dir && entry.name.ends_with(&format!(".{TEMPORARY_EXTENSION}")) {
                    self.remove_file_if_exists(&entry.path)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// The extents a staging journal lists for `manifest_digest`. Every listed extent is
    /// still re-verified against the manifest before reuse, so a missing, foreign or torn
    /// journal can only cause refetching, never trust. A torn tail is cut off. A journal
    /// in a later, versioned format is refused and left exactly as it is.
    pub(super) fn journal_load(
        &self,
        path: &Path,
        manifest_digest: &Digest,
        extent_count: u32,
    ) -> Result<BTreeSet<u32>, StorageFailure> {
        let header = format!("{JOURNAL_HEADER}{}\n", manifest_digest.to_hex());
        let bound =
            (header.len() as u64).saturating_add(u64::from(extent_count).saturating_mul(24));
        let text = match self.read_bounded(path, bound) {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
            Err(_) => String::new(),
        };
        if let Some(versioned) = text.strip_prefix(JOURNAL_VERSIONED) {
            let found = versioned
                .split(|character: char| !character.is_ascii_digit())
                .next()
                .and_then(|number| number.parse::<u32>().ok())
                .unwrap_or(0);
            if found > JOURNAL_FORMAT {
                return Err(super::migrate::FormatRefusal {
                    kind: super::migrate::RecordKind::Journal,
                    path: self.relative(path),
                    found,
                    supported: JOURNAL_FORMAT,
                }
                .to_failure());
            }
        }
        let Some(body) = text.strip_prefix(&header) else {
            self.write_atomic(path, header.as_bytes())?;
            return Ok(BTreeSet::new());
        };
        let mut listed = BTreeSet::new();
        let mut valid = header.clone();
        let mut torn = false;
        for line in body.split_inclusive('\n') {
            let extent = line
                .strip_suffix('\n')
                .and_then(|line| line.strip_prefix(JOURNAL_ENTRY))
                .and_then(|number| number.parse::<u32>().ok())
                .filter(|extent| *extent < extent_count);
            match extent {
                Some(extent) => {
                    listed.insert(extent);
                    valid.push_str(line);
                }
                None => {
                    torn = true;
                    break;
                }
            }
        }
        if torn {
            self.write_atomic(path, valid.as_bytes())?;
        }
        Ok(listed)
    }

    /// Records that `extent` was verified and synced.
    pub(super) fn journal_append(&self, path: &Path, extent: u32) -> Result<(), StorageFailure> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| self.failure(StorageOperation::Open, path, error))?;
        file.write_all(format!("{JOURNAL_ENTRY}{extent}\n").as_bytes())
            .map_err(|error| self.failure(StorageOperation::Write, path, error))?;
        file.sync_data()
            .map_err(|error| self.failure(StorageOperation::Sync, path, error))
    }
}
