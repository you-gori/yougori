//! The staged workspace of a VM sandbox (VM part §5.1, §5.2, §5.4; VM-W14, VM-P15, VM-P16,
//! VM-CP-16; the plan's "one real tool workflow": a staged workspace, a credentialed
//! operation and artifact promotion, with failure and recovery).
//!
//! - **Import** copies the user's folder into a staging root under the engine's data
//!   folder, leaving out known credential locations (§5.4: a convenience, never a promise
//!   to find every secret) and anything that is not a regular file or a directory, and
//!   records the folder's baseline (each file's content key and size). Files are copied
//!   and hashed in bounded chunks, so a file's size is bounded by the workspace's quota,
//!   not by memory. The record is written last: an import cut short leaves no record, and
//!   the next start removes it.
//! - **The guest** reaches only the staging root, through the sandbox's file channel (the
//!   workspace grant, `VmService::attach_workspace`); the user's folder is never granted.
//!   It reads large files in ranges and writes them through uploads assembled in the
//!   workspace's `uploads` folder beside the staging root, each committed by one rename
//!   (`FileService::with_uploads`); nothing of a file is held whole on either side.
//! - **Review** compares the staging root with the baseline, freezes every added or
//!   modified file into a promotion manifest (`files::freeze_in`), observes the user's
//!   folder for each of them (`files::observe_destination_in`) and reviews the two
//!   (`files::review`: add or modify, and the executable, git hook, git configuration, CI,
//!   shell init and build script flags). The manifest, the snapshot and the review are
//!   kept. Deletions in the workspace are listed and never promoted.
//! - **Promotion** applies only the approved files and only as reviewed: they are frozen
//!   again with the content keys the review showed (a changed byte refuses), the user's
//!   folder is observed again and must still be what the review saw, each approved file's
//!   flags are acknowledged, and `files::apply_in` writes them, copying every original to
//!   the workspace's backup root first and rolling back on failure, under an audit
//!   admission. The intent is journaled before the first write, so a promotion cut short
//!   by an engine stop is found at the next start and reported file by file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::foundation::events::write_atomic;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    Clock, ContentHasher, ContentKey, ExecutionCategory, ExecutionId, OperationId,
    SandboxBootGeneration, TrustScope,
};
use crate::sandbox_contract::files::{
    apply_in, authorize, backup_label, freeze_in, observe_destination_in, review,
    undo_interrupted, validate_manifest, AppliedChange, ChangeKind, DestinationSnapshot,
    DestinationState, ExpectedProvenance, FrozenManifest, GrantedRoot, GuestName,
    PromotionAudit, PromotionPolicy, PromotionRoots, ProposedFile, Provenance, Review,
};

/// The record file of a workspace.
const RECORD: &str = "workspace.json";
/// The kept review: the manifest, the snapshot and the review the user saw.
const REVIEW: &str = "review.json";
/// A promotion's intent: the manifest, snapshot and review it applies, written before its
/// first write so a promotion an engine stop cuts short can be undone at the next start.
const PROMOTING: &str = "promoting.json";
const STAGING: &str = "staging";
const BACKUP: &str = "backup";
/// Where the guest's uploads are assembled before each is committed into the staging root.
const UPLOADS: &str = "uploads";
const RECORD_VERSION: u32 = 1;
/// Bounds of a workspace: what it may hold in all, and in one file. Files move in ranges and
/// uploads of at most `files::MAX_RANGE_BYTES`, so one file may take the whole quota; a
/// larger file is listed as skipped, never imported.
pub const MAX_TOTAL_BYTES: u64 = 1 << 30;
pub const MAX_FILE_BYTES: u64 = MAX_TOTAL_BYTES;
pub const MAX_FILES: usize = 20_000;
/// The longest text shown as a diff, per side.
const MAX_DIFF_BYTES: u64 = 256 << 10;
/// How long an approval may wait before it is applied.
const APPROVAL_VALID_FOR: Duration = Duration::from_secs(10 * 60);

/// Directory names never imported (credential stores, §5.4).
const EXCLUDED_DIRECTORIES: &[&str] = &[".ssh", ".aws", ".azure", ".gnupg", ".docker", ".kube"];
/// File names never imported.
const EXCLUDED_FILES: &[&str] = &[
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];
/// File name endings never imported.
const EXCLUDED_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx"];

/// Whether `name` (one component) is a credential location the import leaves out.
pub fn excluded(name: &str, directory: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if directory {
        return EXCLUDED_DIRECTORIES.contains(&lower.as_str());
    }
    if EXCLUDED_FILES.contains(&lower.as_str()) {
        return true;
    }
    // `.env` and `.env.<anything>`, except the conventional examples.
    if lower == ".env"
        || (lower.starts_with(".env.")
            && !matches!(lower.as_str(), ".env.example" | ".env.sample" | ".env.template"))
    {
        return true;
    }
    EXCLUDED_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// One file of the baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineFile {
    pub content: String,
    pub size_bytes: u64,
}

/// Where a workspace stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceState {
    Imported,
    Reviewed {
        review: String,
    },
    /// A promotion's intent, written before its first write, with the backup folder its
    /// originals go to (absent in records written before it was kept).
    Promoting {
        review: String,
        approved: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Promoted {
        review: String,
        applied: Vec<Value>,
    },
    /// A promotion cut short (the engine stopped during it), as found at the next start
    /// when its intent could not be read: reported file by file, nothing undone.
    PromotionInterrupted {
        review: String,
        applied: Vec<String>,
        not_applied: Vec<String>,
        changed: Vec<String>,
    },
    /// A promotion cut short, undone at the next start (`files::undo_interrupted`): the
    /// folder holds what the review saw again, except the files left, which were neither
    /// what the promotion wrote nor what the review saw.
    PromotionUndone {
        review: String,
        restored: Vec<String>,
        removed: Vec<String>,
        not_applied: Vec<String>,
        left: Vec<String>,
    },
}

/// A promotion's journaled intent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    manifest: FrozenManifest,
    snapshot: DestinationSnapshot,
    review: Review,
}

/// The record of one workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRecord {
    pub version: u32,
    pub sandbox: ExecutionId,
    /// The sandbox's boot generation the guest works in: the provenance of what it writes.
    pub boot: u64,
    pub source: PathBuf,
    pub imported_at: String,
    pub baseline: BTreeMap<String, BaselineFile>,
    pub excluded: Vec<String>,
    pub skipped: Vec<String>,
    pub state: WorkspaceState,
}

/// The kept review.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptReview {
    manifest: FrozenManifest,
    snapshot: DestinationSnapshot,
    review: Review,
    policy: PromotionPolicy,
}

/// The engine's workspaces, one folder each under `root`.
#[derive(Clone, Debug)]
pub struct WorkspaceStore {
    root: PathBuf,
}

/// One workspace.
#[derive(Clone, Debug)]
pub struct Workspace {
    dir: PathBuf,
    pub record: WorkspaceRecord,
}

fn io(context: &str, error: std::io::Error) -> String {
    format!("{context}: {error}")
}

/// `path` without the verbatim prefix `canonicalize` gives a drive path on Windows
/// (`\\?\D:\...`), as the folder is recorded and shown; any other path is kept.
fn plain(path: PathBuf) -> PathBuf {
    let stripped = path
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
        .map(PathBuf::from);
    stripped.unwrap_or(path)
}

/// A host path below a root as a guest name (`/`-separated components).
fn guest_name(relative: &Path) -> Result<GuestName, String> {
    let text = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    GuestName::parse(&text).map_err(|refusal| format!("{text}: {refusal:?}"))
}

/// The most bytes a copy or a hash holds at once.
const CHUNK_BYTES: usize = 256 << 10;

/// Reads `source` to its end in bounded chunks, giving each to `each` and hashing it as a
/// file of `size_bytes`: its content key, or an error when it was not exactly that long.
fn hash_chunks(
    source: &mut dyn Read,
    size_bytes: u64,
    shown: &str,
    each: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<ContentKey, String> {
    let mut hasher = ContentHasher::new(size_bytes);
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut limited = source.take(size_bytes.saturating_add(1));
    loop {
        let read = limited.read(&mut buffer).map_err(|error| io(shown, error))?;
        if read == 0 {
            break;
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        hasher
            .update(chunk)
            .map_err(|_| format!("{shown} changed while it was read"))?;
        each(chunk).map_err(|error| io(shown, error))?;
    }
    hasher
        .finish()
        .map_err(|_| format!("{shown} changed while it was read"))
}

/// The content key and size of a file, hashed in bounded chunks.
fn read_key(path: &Path) -> Result<(ContentKey, u64), String> {
    let shown = path.display().to_string();
    let mut file = fs::File::open(path).map_err(|error| io(&shown, error))?;
    let size = file.metadata().map_err(|error| io(&shown, error))?.len();
    let key = hash_chunks(&mut file, size, &shown, &mut |_| Ok(()))?;
    Ok((key, size))
}

/// Copies the file `from` to the new file `to` in bounded chunks, hashing what it copies:
/// the copy's content key and size.
fn copy_hashed(from: &Path, to: &Path, shown: &str) -> Result<(ContentKey, u64), String> {
    let mut source = fs::File::open(from).map_err(|error| io(shown, error))?;
    let size = source.metadata().map_err(|error| io(shown, error))?.len();
    let mut target = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|error| io(shown, error))?;
    let key = hash_chunks(&mut source, size, shown, &mut |chunk| {
        std::io::Write::write_all(&mut target, chunk)
    })?;
    Ok((key, size))
}

/// Refuses `name` unless it is one plain path component on every host: not empty, no separator,
/// no `:` (a drive or an alternate data stream on Windows), not `.` or `..`, no trailing dot or
/// space, no device name (`NUL`, `COM1`, ...) and no short-name alias. The shared id grammar
/// allows `:`, so an id such as `D:.` joined under a folder would name a drive-relative path on
/// Windows, outside that folder; such an id is refused before any file-system use.
pub(crate) fn plain_component(name: &str) -> Result<(), String> {
    match GuestName::parse(name) {
        Ok(parsed) if parsed.component_count() == 1 => Ok(()),
        _ => Err(format!("{name:?} can't name a folder of its own here; nothing was read or changed.")),
    }
}

/// `root` joined with `name`, refused unless `name` is a plain component (`plain_component`) and
/// the result stays directly under `root`.
pub(crate) fn child_of(root: &Path, name: &str) -> Result<PathBuf, String> {
    plain_component(name)?;
    let child = root.join(name);
    if child.parent() != Some(root) || !child.starts_with(root) {
        return Err(format!("{name:?} would leave its folder; nothing was read or changed."));
    }
    Ok(child)
}

impl WorkspaceStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The folder of `sandbox`'s workspace. A sandbox id that is not one plain path component
    /// is refused before any file-system use (`child_of`): with `D:.`, a discard would otherwise
    /// remove a folder outside the workspace root.
    fn dir_of(&self, sandbox: &ExecutionId) -> Result<PathBuf, String> {
        child_of(&self.root, sandbox.as_str()).map_err(|refusal| format!("Sandbox {sandbox} has no workspace folder: {refusal}"))
    }

    /// Imports `source` for `sandbox`'s boot `boot` (module notes). Refused when the
    /// sandbox has a workspace already, when `source` is not a real directory, or when it
    /// would be copied into itself.
    pub fn import(
        &self,
        sandbox: &ExecutionId,
        boot: u64,
        source: &Path,
    ) -> Result<Workspace, String> {
        self.import_inner(sandbox, boot, source, false)
    }

    /// Restore only a registered private workspace, never an arbitrary host path.
    /// The caller must stop its old VM first. Credentials created inside this
    /// private copy remain private application state and must survive a restart.
    pub fn restore(&self, sandbox: &ExecutionId, boot: u64, previous: &ExecutionId) -> Result<Workspace, String> {
        if sandbox == previous { return Err("Cannot restore a workspace onto itself".into()); }
        if self.dir_of(sandbox)?.exists() { return Err("The destination VM has a workspace already".into()); }
        let source = self.open(previous)?.ok_or("The previous private workspace is missing")?.staging();
        let restored = self.import_inner(sandbox, boot, &source, true).and_then(|workspace| {
            if !workspace.record.skipped.is_empty() { return Err("The private workspace contains unsupported files; the previous data is retained".into()); }
            Ok(workspace)
        });
        if restored.is_err() { let _ = self.discard(sandbox); }
        restored
    }

    fn import_inner(&self, sandbox: &ExecutionId, boot: u64, source: &Path, private: bool) -> Result<Workspace, String> {
        let source = plain(
            fs::canonicalize(source)
                .map_err(|error| io(&format!("the folder {}", source.display()), error))?,
        );
        let metadata = fs::symlink_metadata(&source).map_err(|error| io("the folder", error))?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a folder", source.display()));
        }
        let root = plain(fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone()));
        if root.starts_with(&source) || !private && source.starts_with(&root) {
            return Err("the folder holds the engine's workspaces, or is one of them".to_owned());
        }
        let dir = self.dir_of(sandbox)?;
        if dir.exists() {
            return Err(format!("sandbox {sandbox} has a workspace already"));
        }
        let staging = dir.join(STAGING);
        fs::create_dir_all(&staging).map_err(|error| io("the staging folder", error))?;
        fs::create_dir_all(dir.join(BACKUP)).map_err(|error| io("the backup folder", error))?;
        fs::create_dir_all(dir.join(UPLOADS)).map_err(|error| io("the upload folder", error))?;
        let mut baseline = BTreeMap::new();
        let mut excluded_names = Vec::new();
        let mut skipped = Vec::new();
        let mut total = 0u64;
        let mut stack = vec![PathBuf::new()];
        while let Some(relative) = stack.pop() {
            let entries = fs::read_dir(source.join(&relative))
                .map_err(|error| io(&format!("reading {}", relative.display()), error))?;
            let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let name = entry.file_name().to_string_lossy().into_owned();
                let child = relative.join(&name);
                let shown = child.to_string_lossy().replace('\\', "/");
                let kind = fs::symlink_metadata(entry.path())
                    .map_err(|error| io(&shown, error))?;
                if kind.file_type().is_symlink() || (!kind.is_dir() && !kind.is_file()) {
                    skipped.push(format!("{shown}: not a regular file or folder"));
                    continue;
                }
                if !private && excluded(&name, kind.is_dir()) {
                    excluded_names.push(shown);
                    continue;
                }
                let guest = match guest_name(&child) {
                    Ok(guest) => guest,
                    Err(refusal) => {
                        skipped.push(format!("{shown}: not a valid guest name ({refusal})"));
                        continue;
                    }
                };
                if kind.is_dir() {
                    fs::create_dir_all(staging.join(&child))
                        .map_err(|error| io(&shown, error))?;
                    stack.push(child);
                    continue;
                }
                if kind.len() > MAX_FILE_BYTES {
                    skipped.push(format!("{shown}: larger than {MAX_FILE_BYTES} bytes"));
                    continue;
                }
                if baseline.len() >= MAX_FILES {
                    return Err(format!("the folder holds more than {MAX_FILES} files"));
                }
                if total.saturating_add(kind.len()) > MAX_TOTAL_BYTES {
                    return Err(format!("the folder holds more than {MAX_TOTAL_BYTES} bytes"));
                }
                let (content, size) = copy_hashed(&entry.path(), &staging.join(&child), &shown)?;
                total = total.saturating_add(size);
                if total > MAX_TOTAL_BYTES {
                    return Err(format!("the folder holds more than {MAX_TOTAL_BYTES} bytes"));
                }
                baseline.insert(
                    guest.as_str().to_owned(),
                    BaselineFile {
                        content: content.digest().to_hex(),
                        size_bytes: size,
                    },
                );
            }
        }
        acceptance_pause(&dir, "import");
        let record = WorkspaceRecord {
            version: RECORD_VERSION,
            sandbox: sandbox.clone(),
            boot,
            source,
            imported_at: chrono::Utc::now().to_rfc3339(),
            baseline,
            excluded: excluded_names,
            skipped,
            state: WorkspaceState::Imported,
        };
        let workspace = Workspace { dir, record };
        workspace.save()?;
        Ok(workspace)
    }

    /// The workspace of `sandbox`, when it has one.
    pub fn open(&self, sandbox: &ExecutionId) -> Result<Option<Workspace>, String> {
        let dir = self.dir_of(sandbox)?;
        let path = dir.join(RECORD);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io("the workspace record", error)),
        };
        let record: WorkspaceRecord = serde_json::from_slice(&bytes)
            .map_err(|error| format!("the workspace record is damaged: {error}"))?;
        Ok(Some(Workspace { dir, record }))
    }

    /// Every workspace's record, by sandbox.
    pub fn list(&self) -> Vec<WorkspaceRecord> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut records: Vec<WorkspaceRecord> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path().join(RECORD)).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect();
        records.sort_by(|a, b| a.imported_at.cmp(&b.imported_at));
        records
    }

    /// Removes `sandbox`'s workspace (its staging copy, backups and review).
    pub fn discard(&self, sandbox: &ExecutionId) -> Result<bool, String> {
        let dir = self.dir_of(sandbox)?;
        if !dir.exists() {
            return Ok(false);
        }
        fs::remove_dir_all(&dir).map_err(|error| io("removing the workspace", error))?;
        Ok(true)
    }

    /// Removes every workspace imported from `folder` or beneath it, and returns their
    /// sandboxes: the copies of throwaway sandboxes whose inputs the engine staged there
    /// (VM-W58's normalization jobs), which no later run uses. `folder` is compared as the
    /// import recorded sources, canonical; a folder that does not exist matches nothing.
    pub fn discard_imported_from(&self, folder: &Path) -> Vec<String> {
        let Ok(folder) = fs::canonicalize(folder).map(plain) else {
            return Vec::new();
        };
        self.list()
            .into_iter()
            .filter(|record| record.source.starts_with(&folder))
            .filter(|record| self.discard(&record.sandbox).unwrap_or(false))
            .map(|record| record.sandbox.as_str().to_owned())
            .collect()
    }

    /// What the last engine run left: an import cut short (no record) is removed; a
    /// promotion cut short is examined file by file and recorded as interrupted.
    pub fn recover(&self) -> Value {
        let mut removed = Vec::new();
        let mut interrupted = Vec::new();
        let mut uploads_removed = 0u64;
        let Ok(entries) = fs::read_dir(&self.root) else {
            return json!({ "removed_incomplete_imports": removed, "interrupted_promotions": interrupted, "uploads_removed": uploads_removed });
        };
        for entry in entries.filter_map(Result::ok) {
            let dir = entry.path();
            if !dir.join(RECORD).exists() {
                if fs::remove_dir_all(&dir).is_ok() {
                    removed.push(entry.file_name().to_string_lossy().into_owned());
                }
                continue;
            }
            let Ok(bytes) = fs::read(dir.join(RECORD)) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<WorkspaceRecord>(&bytes) else {
                continue;
            };
            // An upload the last run left can never be committed: its sandbox is gone.
            if let Ok(leftovers) = fs::read_dir(dir.join(UPLOADS)) {
                for leftover in leftovers.filter_map(Result::ok) {
                    if fs::remove_file(leftover.path()).is_ok() {
                        uploads_removed += 1;
                    }
                }
            }
            let mut workspace = Workspace { dir, record };
            if let WorkspaceState::Promoting { review, approved, label } = workspace.record.state.clone()
            {
                workspace.record.state = match label.and_then(|label| workspace.undo_promotion(&label)) {
                    Some(undo) => WorkspaceState::PromotionUndone {
                        review,
                        restored: undo.restored.iter().map(|name| name.as_str().to_owned()).collect(),
                        removed: undo.removed.iter().map(|name| name.as_str().to_owned()).collect(),
                        not_applied: undo.not_applied.iter().map(|name| name.as_str().to_owned()).collect(),
                        left: undo.left.iter().map(|name| name.as_str().to_owned()).collect(),
                    },
                    None => {
                        let report = workspace.examine_promotion(&approved);
                        WorkspaceState::PromotionInterrupted {
                            review,
                            applied: report.0,
                            not_applied: report.1,
                            changed: report.2,
                        }
                    }
                };
                let _ = workspace.save();
                let _ = fs::remove_file(workspace.dir.join(PROMOTING));
                interrupted.push(json!({ "sandbox": workspace.record.sandbox, "state": workspace.record.state }));
            }
        }
        json!({ "removed_incomplete_imports": removed, "interrupted_promotions": interrupted, "uploads_removed": uploads_removed })
    }
}

/// One file that changed in the workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Changed {
    pub name: String,
    pub change: &'static str,
    pub size_bytes: Option<u64>,
    pub content: Option<String>,
}

impl Workspace {
    pub fn staging(&self) -> PathBuf {
        self.dir.join(STAGING)
    }

    /// Where the guest's uploads are assembled, beside the staging root on its volume.
    pub fn uploads(&self) -> PathBuf {
        let uploads = self.dir.join(UPLOADS);
        // A workspace imported before uploads existed gets its folder now.
        let _ = fs::create_dir_all(&uploads);
        uploads
    }

    fn save(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&self.record).map_err(|error| error.to_string())?;
        write_atomic(&self.dir.join(RECORD), &bytes)
            .map_err(|error| io("writing the workspace record", error))
    }

    /// The staging root's files against the baseline: added, modified and deleted.
    pub fn changes(&self) -> Result<Vec<Changed>, String> {
        let staging = self.staging();
        let mut seen = BTreeSet::new();
        let mut changed = Vec::new();
        let mut stack = vec![PathBuf::new()];
        while let Some(relative) = stack.pop() {
            let entries = fs::read_dir(staging.join(&relative))
                .map_err(|error| io("reading the workspace", error))?;
            let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let child = relative.join(entry.file_name());
                let kind = fs::symlink_metadata(entry.path()).map_err(|error| io("the workspace", error))?;
                if kind.is_dir() {
                    stack.push(child);
                    continue;
                }
                if !kind.is_file() {
                    continue;
                }
                let name = guest_name(&child)?.as_str().to_owned();
                let (content, size_bytes) = read_key(&entry.path())?;
                let content = content.digest().to_hex();
                seen.insert(name.clone());
                let change = match self.record.baseline.get(&name) {
                    None => "added",
                    Some(base) if base.content != content => "modified",
                    Some(_) => continue,
                };
                changed.push(Changed {
                    name,
                    change,
                    size_bytes: Some(size_bytes),
                    content: Some(content),
                });
            }
        }
        for name in self.record.baseline.keys() {
            if !seen.contains(name) {
                changed.push(Changed {
                    name: name.clone(),
                    change: "deleted",
                    size_bytes: None,
                    content: None,
                });
            }
        }
        changed.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(changed)
    }

    /// The bytes of `name` in the staged workspace as the guest left them, at most
    /// `max_bytes`, with what produced them (the sandbox, its boot, a fresh operation and its
    /// trust scope): the raw input of a normalization job (VM-W58). Read beneath the staging
    /// root without following any link; nothing here parses them.
    pub fn read_produced(&self, name: &str, max_bytes: u64) -> Result<(Vec<u8>, Provenance), String> {
        let name = GuestName::parse(name)
            .map_err(|refusal| format!("{name} is not a name in the workspace: {refusal}"))?;
        let staging = GrantedRoot::open(&self.staging())
            .map_err(|error| format!("the staged workspace could not be opened: {error:?}"))?;
        let bytes = staging.read_whole(&name, max_bytes)?;
        Ok((bytes, self.provenance().0))
    }

    /// What the guest's files are attributed to: the sandbox, its boot and its trust scope.
    fn provenance(&self) -> (Provenance, ExpectedProvenance) {
        let execution = self.record.sandbox.clone();
        let scope = TrustScope::named(ExecutionCategory::VmSandbox, execution.as_str());
        (
            Provenance {
                execution: execution.clone(),
                boot: SandboxBootGeneration::new(self.record.boot),
                operation: OperationId::generate(),
                scope: scope.clone(),
            },
            ExpectedProvenance { execution, scope },
        )
    }

    /// Reviews every added or modified file against the user's folder (module notes) and
    /// keeps the review.
    pub fn review(&mut self) -> Result<Value, String> {
        let changes = self.changes()?;
        let candidates: Vec<&Changed> = changes.iter().filter(|c| c.change != "deleted").collect();
        let deleted: Vec<&str> = changes
            .iter()
            .filter(|c| c.change == "deleted")
            .map(|c| c.name.as_str())
            .collect();
        if candidates.is_empty() {
            return Ok(json!({ "files": [], "deleted": deleted, "review": Value::Null }));
        }
        let (provenance, expected) = self.provenance();
        let mut prefixes = BTreeSet::new();
        let mut proposal = Vec::new();
        for candidate in &candidates {
            let name = GuestName::parse(&candidate.name).map_err(|refusal| format!("{refusal:?}"))?;
            let first = name.components().next().unwrap_or_default().to_owned();
            prefixes.insert(first);
            proposal.push(ProposedFile {
                name,
                declared_size_bytes: candidate.size_bytes,
                declared_content: None,
            });
        }
        let policy = PromotionPolicy {
            allowed_prefixes: prefixes
                .iter()
                .map(|prefix| GuestName::parse(prefix).map_err(|refusal| format!("{refusal:?}")))
                .collect::<Result<_, _>>()?,
            max_entries: MAX_FILES,
            max_file_bytes: MAX_FILE_BYTES,
            max_total_bytes: MAX_TOTAL_BYTES,
            allow_executable: true,
            expected,
        };
        let staging = GrantedRoot::open(&self.staging())
            .map_err(|error| format!("the workspace could not be opened: {error:?}"))?;
        let destination = GrantedRoot::open(&self.record.source)
            .map_err(|error| format!("the folder {} could not be opened: {error:?}", self.record.source.display()))?;
        let manifest = freeze_in(&staging, &proposal, provenance, &policy).map_err(|refusal| refusal.to_string())?;
        validate_manifest(&manifest, &policy).map_err(|refusal| refusal.to_string())?;
        let snapshot = observe_destination_in(&destination, &manifest).map_err(|refusal| refusal.to_string())?;
        let reviewed = review(&manifest, &snapshot).map_err(|refusal| refusal.to_string())?;
        let digest = reviewed.digest().to_hex();
        let mut files = Vec::new();
        for change in reviewed.changes() {
            let name = change.name.as_str();
            let state = snapshot.entries().get(&change.name);
            let since_import = match (self.record.baseline.get(name), state) {
                (Some(base), Some(DestinationState::File { content, .. })) => {
                    base.content != content.digest().to_hex()
                }
                (Some(_), _) => true,
                (None, Some(DestinationState::Absent { .. })) => false,
                (None, _) => true,
            };
            files.push(json!({
                "name": name,
                "change": match change.change { ChangeKind::Add => "add", ChangeKind::Modify { .. } => "modify", ChangeKind::Unchanged => "unchanged" },
                "size_bytes": change.size_bytes,
                "content": change.content.digest().to_hex(),
                "flags": change.flags,
                "folder_changed_since_import": since_import,
                "diff": self.diff(name, state),
            }));
        }
        let kept = KeptReview {
            manifest,
            snapshot,
            review: reviewed,
            policy,
        };
        let bytes = serde_json::to_vec(&kept).map_err(|error| error.to_string())?;
        write_atomic(&self.dir.join(REVIEW), &bytes).map_err(|error| io("keeping the review", error))?;
        self.record.state = WorkspaceState::Reviewed {
            review: digest.clone(),
        };
        self.save()?;
        Ok(json!({ "review": digest, "files": files, "deleted": deleted, "folder": self.record.source }))
    }

    /// A unified text diff of the folder's file against the staged one, when both are
    /// small text.
    fn diff(&self, name: &str, state: Option<&DestinationState>) -> Option<String> {
        let staged_path = self.staging().join(name);
        if fs::metadata(&staged_path).ok()?.len() > MAX_DIFF_BYTES {
            return None;
        }
        let staged = fs::read(staged_path).ok()?;
        let before = match state {
            Some(DestinationState::File { size_bytes, .. }) if *size_bytes <= MAX_DIFF_BYTES => {
                fs::read(self.record.source.join(name)).ok()?
            }
            Some(DestinationState::Absent { .. }) | None => Vec::new(),
            _ => return None,
        };
        if staged.len() as u64 > MAX_DIFF_BYTES || staged.contains(&0) || before.contains(&0) {
            return None;
        }
        let (a, b) = (String::from_utf8(before).ok()?, String::from_utf8(staged).ok()?);
        Some(
            similar::TextDiff::from_lines(&a, &b)
                .unified_diff()
                .context_radius(3)
                .header(&format!("a/{name}"), &format!("b/{name}"))
                .to_string(),
        )
    }

    /// Promotes the approved files of the kept review `review_digest` (module notes).
    #[allow(clippy::too_many_arguments)]
    pub fn promote(
        &mut self,
        review_digest: &str,
        approved: &[String],
        audit: &mut dyn PromotionAudit,
        clock: &dyn Clock,
        session: ClockSession,
    ) -> Result<Value, String> {
        let bytes = fs::read(self.dir.join(REVIEW)).map_err(|_| "no review is kept; review first".to_owned())?;
        let kept: KeptReview = serde_json::from_slice(&bytes).map_err(|error| format!("the kept review is damaged: {error}"))?;
        if kept.review.digest().to_hex() != review_digest {
            return Err("that review is not the latest one; review again".to_owned());
        }
        if approved.is_empty() {
            return Err("no file was approved".to_owned());
        }
        let mut proposal = Vec::new();
        let mut keys = BTreeMap::new();
        for name in approved {
            let entry = kept
                .manifest
                .entries()
                .iter()
                .find(|entry| entry.name.as_str() == name)
                .ok_or_else(|| format!("{name} is not in the review"))?;
            proposal.push(ProposedFile {
                name: entry.name.clone(),
                declared_size_bytes: Some(entry.size_bytes),
                declared_content: Some(entry.content),
            });
            keys.insert(name.clone(), entry.content.digest().to_hex());
        }
        let staging = GrantedRoot::open(&self.staging())
            .map_err(|error| format!("the workspace could not be opened: {error:?}"))?;
        let destination = GrantedRoot::open(&self.record.source)
            .map_err(|error| format!("the folder could not be opened: {error:?}"))?;
        let backup = GrantedRoot::open(&self.dir.join(BACKUP))
            .map_err(|error| format!("the backup folder could not be opened: {error:?}"))?;
        // The approved files exactly as reviewed: a changed byte refuses here.
        let manifest = freeze_in(&staging, &proposal, kept.manifest.provenance().clone(), &kept.policy)
            .map_err(|refusal| format!("the workspace changed since the review: {refusal}"))?;
        let snapshot = observe_destination_in(&destination, &manifest).map_err(|refusal| refusal.to_string())?;
        for (name, state) in snapshot.entries() {
            if kept.snapshot.entries().get(name) != Some(state) {
                return Err(format!(
                    "{} changed in the folder since the review; review again",
                    name.as_str()
                ));
            }
        }
        let reviewed = review(&manifest, &snapshot).map_err(|refusal| refusal.to_string())?;
        let authorization = authorize(
            &reviewed,
            reviewed.flagged(),
            OperationId::generate(),
            clock,
            session,
            APPROVAL_VALID_FOR,
        )
        .map_err(|refusal| refusal.to_string())?;
        // The intent, journaled before the first write: what is applied, against what, and
        // where its originals go, so a stop part way is undone at the next start.
        let intent = Intent {
            manifest: manifest.clone(),
            snapshot: snapshot.clone(),
            review: reviewed.clone(),
        };
        let bytes = serde_json::to_vec(&intent).map_err(|error| error.to_string())?;
        write_atomic(&self.dir.join(PROMOTING), &bytes).map_err(|error| io("journaling the promotion", error))?;
        self.record.state = WorkspaceState::Promoting {
            review: review_digest.to_owned(),
            approved: keys,
            label: Some(backup_label(&manifest, &authorization)),
        };
        self.save()?;
        acceptance_pause(&self.dir, "promote");
        let roots = PromotionRoots {
            source: &staging,
            destination: &destination,
            backup: &backup,
        };
        let outcome = apply_in(&roots, &manifest, &reviewed, &snapshot, &authorization, &kept.policy, audit, clock, session);
        // Whole, or undone in process: the intent is no longer needed.
        let _ = fs::remove_file(self.dir.join(PROMOTING));
        match outcome {
            Ok(receipt) => {
                let applied: Vec<Value> = receipt
                    .applied
                    .iter()
                    .map(|change| match change {
                        AppliedChange::Added { name } => json!({ "name": name.as_str(), "applied": "added" }),
                        AppliedChange::Modified { name, backup } => json!({ "name": name.as_str(), "applied": "modified", "original_kept_at": backup }),
                        AppliedChange::Unchanged { name } => json!({ "name": name.as_str(), "applied": "unchanged" }),
                    })
                    .collect();
                self.record.state = WorkspaceState::Promoted {
                    review: review_digest.to_owned(),
                    applied: applied.clone(),
                };
                self.save()?;
                Ok(json!({
                    "applied": applied,
                    "manifest": receipt.manifest.to_hex(),
                    "authorization": receipt.authorization.to_hex(),
                    "audit_admission": receipt.admission.sequence,
                    "audit_outcome": receipt.outcome.as_ref().map(|r| r.sequence).ok(),
                }))
            }
            Err(refusal) => {
                // Nothing of a refused promotion stays applied (`apply_in` undoes what it did).
                self.record.state = WorkspaceState::Reviewed {
                    review: review_digest.to_owned(),
                };
                let _ = self.save();
                Err(format!("the promotion was refused and nothing was applied: {refusal}"))
            }
        }
    }

    /// Undoes a promotion cut short from its journaled intent (`files::undo_interrupted`);
    /// `None` when the intent or a root cannot be read, and nothing was done.
    fn undo_promotion(&self, label: &str) -> Option<crate::sandbox_contract::files::InterruptedUndo> {
        let bytes = fs::read(self.dir.join(PROMOTING)).ok()?;
        let intent: Intent = serde_json::from_slice(&bytes).ok()?;
        let destination = GrantedRoot::open(&self.record.source).ok()?;
        let backup = GrantedRoot::open(&self.dir.join(BACKUP)).ok()?;
        Some(undo_interrupted(&destination, &backup, label, &intent.review, &intent.snapshot))
    }

    /// For a promotion cut short: which approved files the folder holds as approved, which
    /// it holds as before, and which changed otherwise.
    fn examine_promotion(&self, approved: &BTreeMap<String, String>) -> (Vec<String>, Vec<String>, Vec<String>) {
        let kept: Option<KeptReview> = fs::read(self.dir.join(REVIEW))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let (mut applied, mut not_applied, mut changed) = (Vec::new(), Vec::new(), Vec::new());
        for (name, key) in approved {
            let now = read_key(&self.record.source.join(name)).ok().map(|(key, _)| key.digest().to_hex());
            if now.as_deref() == Some(key.as_str()) {
                applied.push(name.clone());
                continue;
            }
            let before = kept.as_ref().and_then(|kept| {
                GuestName::parse(name).ok().and_then(|guest| kept.snapshot.entries().get(&guest).cloned())
            });
            let unchanged = match (before, &now) {
                (Some(DestinationState::Absent { .. }), None) => true,
                (Some(DestinationState::File { content, .. }), Some(now)) => content.digest().to_hex() == *now,
                _ => false,
            };
            if unchanged {
                not_applied.push(name.clone());
            } else {
                changed.push(name.clone());
            }
        }
        (applied, not_applied, changed)
    }

    /// The workspace for the status: its folder, counts and state.
    pub fn view(&self) -> Value {
        json!({
            "sandbox": self.record.sandbox,
            "folder": self.record.source,
            "imported_at": self.record.imported_at,
            "files": self.record.baseline.len(),
            "excluded": self.record.excluded,
            "skipped": self.record.skipped,
            "state": self.record.state,
        })
    }
}

/// Acceptance builds: when `YOUGORI_ACCEPTANCE_WORKSPACE_PAUSE` names `point` ("import":
/// every file copied, the record not yet written; "promote": the intent journaled, nothing
/// written yet), the call waits there (`YOUGORI_ACCEPTANCE_WORKSPACE_PAUSE_SECONDS`, default
/// 60) after leaving `paused-<point>` in the workspace's folder, so an acceptance run can
/// kill the engine at that boundary and check what the next start recovers.
#[cfg(feature = "acceptance")]
fn acceptance_pause(dir: &Path, point: &str) {
    if std::env::var("YOUGORI_ACCEPTANCE_WORKSPACE_PAUSE").ok().as_deref() != Some(point) {
        return;
    }
    let seconds = std::env::var("YOUGORI_ACCEPTANCE_WORKSPACE_PAUSE_SECONDS")
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(60);
    let _ = fs::write(dir.join(format!("paused-{point}")), b"");
    std::thread::sleep(Duration::from_secs(seconds));
}

#[cfg(not(feature = "acceptance"))]
fn acceptance_pause(_: &Path, _: &str) {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::foundation::events::{AuditReceipt, AuditRefusal, Field};
    use crate::foundation::ids::{ManualClock, MonotonicTime};

    /// Admits every promotion with a fresh receipt.
    struct Admit(u64);

    impl PromotionAudit for Admit {
        fn admit(&mut self, _: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
            self.0 += 1;
            Ok(receipt(self.0))
        }
        fn record_outcome(&mut self, _: bool, _: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
            self.0 += 1;
            Ok(receipt(self.0))
        }
    }

    fn receipt(sequence: u64) -> AuditReceipt {
        AuditReceipt {
            sequence: crate::foundation::events::EventSequence::new(sequence).unwrap(),
            digest: crate::foundation::ids::digest("yougori/test/v1", &[b"r"]),
            durability: crate::foundation::events::Durability::Durable,
        }
    }

    fn setup() -> (tempfile::TempDir, PathBuf, WorkspaceStore, ExecutionId) {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("project");
        fs::create_dir_all(folder.join("src")).unwrap();
        fs::create_dir_all(folder.join(".ssh")).unwrap();
        fs::write(folder.join("src/main.py"), "print('hello')\n").unwrap();
        fs::write(folder.join("README.md"), "# Project\n").unwrap();
        fs::write(folder.join(".env"), "TOKEN=secret\n").unwrap();
        fs::write(folder.join(".env.example"), "TOKEN=\n").unwrap();
        fs::write(folder.join(".ssh/id_ed25519"), "key").unwrap();
        fs::write(folder.join("server.pem"), "cert").unwrap();
        let store = WorkspaceStore::new(temp.path().join("workspaces"));
        (temp, folder, store, ExecutionId::new("exe-ws-1").unwrap())
    }

    #[test]
    fn private_restore_retains_application_credentials_without_opening_host_imports() {
        let (_temp, folder, store, previous) = setup();
        let old = store.import(&previous, 1, &folder).unwrap();
        fs::write(old.staging().join(".env"), "PRIVATE_APP_VALUE=kept").unwrap();
        fs::create_dir_all(old.staging().join(".yougori")).unwrap();
        fs::write(old.staging().join(".yougori/answers.json"), "{\"fixture\":true}").unwrap();
        let next = ExecutionId::new("exe-ws-next").unwrap();
        assert!(store.import(&next, 2, &old.staging()).is_err(), "host-folder import remains refused");
        let restored = store.restore(&next, 2, &previous).unwrap();
        assert_eq!(fs::read(restored.staging().join(".env")).unwrap(), b"PRIVATE_APP_VALUE=kept");
        assert!(restored.record.excluded.is_empty());
        fs::write(restored.staging().join(".yougori/answers.json"), "changed").unwrap();
        assert_eq!(fs::read(old.staging().join(".yougori/answers.json")).unwrap(), b"{\"fixture\":true}");
        assert!(store.restore(&next, 3, &previous).is_err());
        assert_eq!(fs::read(restored.staging().join(".yougori/answers.json")).unwrap(), b"changed", "a refused restore never discards existing data");
        assert!(store.restore(&previous, 3, &previous).is_err());
    }

    /// PROVES a sandbox id that is not one plain path component never reaches the file system:
    /// the shared grammar allows `D:.` and `C:.`, which Windows would join as a drive-relative
    /// path outside the workspace root, so a discard of one would delete a folder elsewhere.
    #[test]
    fn a_sandbox_id_that_is_not_a_plain_folder_name_is_refused_before_any_file_is_touched() {
        let (temp, folder, store, sandbox) = setup();
        store.import(&sandbox, 1, &folder).unwrap();
        for id in ["D:.", "C:.", "c:..", "a:b", "nul", "con.txt", "name.", "x."] {
            let odd = ExecutionId::new(id).unwrap();
            assert!(store.discard(&odd).is_err(), "{id}");
            assert!(store.open(&odd).is_err(), "{id}");
            assert!(store.import(&odd, 1, &folder).is_err(), "{id}");
            assert!(store.restore(&odd, 1, &sandbox).is_err(), "{id}");
        }
        assert!(folder.join("src/main.py").exists() && temp.path().join("workspaces").join(sandbox.as_str()).exists(), "nothing else was removed");
        assert!(plain_component("exe-ws-1").is_ok() && plain_component("combine-0123abcd").is_ok());
        for refused in ["", ".", "..", "a/b", "a\\b", "D:", "D:.", "x ", "COM1"] {
            assert!(plain_component(refused).is_err(), "{refused:?}");
        }
        let root = temp.path().join("workspaces");
        assert_eq!(child_of(&root, "exe-ws-1").unwrap(), root.join("exe-ws-1"));
        assert!(child_of(&root, "D:.").is_err());
    }

    /// PROVES the import copies the folder without its credential locations, records the
    /// baseline, and refuses a second import for the same sandbox.
    #[test]
    fn the_import_leaves_credentials_out_and_records_the_baseline() {
        let (_temp, folder, store, sandbox) = setup();
        let workspace = store.import(&sandbox, 1, &folder).unwrap();
        let names: Vec<&str> = workspace.record.baseline.keys().map(String::as_str).collect();
        assert_eq!(names, vec![".env.example", "README.md", "src/main.py"]);
        assert_eq!(workspace.record.excluded.len(), 3, "{:?}", workspace.record.excluded);
        assert!(workspace.staging().join("src/main.py").exists());
        assert!(!workspace.staging().join(".env").exists());
        assert!(store.import(&sandbox, 1, &folder).unwrap_err().contains("has a workspace already"));
        assert!(workspace.changes().unwrap().is_empty());
        assert_eq!(store.open(&sandbox).unwrap().unwrap().record, workspace.record);
    }

    /// PROVES the copies imported from beneath a folder (a normalization job's staged
    /// inputs) are removed and named, and every other workspace is left as it was.
    #[test]
    fn copies_imported_from_beneath_a_folder_are_discarded_alone() {
        let (temp, folder, store, sandbox) = setup();
        let inputs = temp.path().join("normalized").join("sources");
        let job = inputs.join("job-1");
        fs::create_dir_all(&job).unwrap();
        fs::write(job.join("input"), "<p>x</p>").unwrap();
        let throwaway = ExecutionId::new("exe-ws-throwaway").unwrap();
        store.import(&sandbox, 1, &folder).unwrap();
        store.import(&throwaway, 1, &job).unwrap();
        assert_eq!(store.discard_imported_from(&inputs), vec!["exe-ws-throwaway".to_owned()]);
        assert!(store.open(&throwaway).unwrap().is_none());
        assert!(store.open(&sandbox).unwrap().is_some(), "another workspace was removed");
        assert!(store.discard_imported_from(&temp.path().join("absent")).is_empty());
    }

    /// PROVES a file the guest left in the staged workspace is read back whole with what
    /// produced it (the sandbox and its boot, a fresh operation each time), and that a file
    /// past the bound, a name outside the workspace, a missing file, a directory and a link
    /// are refused, the link never followed (VM-W58's raw input).
    #[test]
    fn a_produced_file_is_read_whole_with_its_provenance() {
        let (temp, folder, store, sandbox) = setup();
        let workspace = store.import(&sandbox, 3, &folder).unwrap();
        fs::write(workspace.staging().join("page.html"), "<p>made in the guest</p>").unwrap();
        let (bytes, provenance) = workspace.read_produced("page.html", 1 << 20).unwrap();
        assert_eq!(bytes, b"<p>made in the guest</p>");
        assert_eq!(provenance.execution, sandbox);
        assert_eq!(provenance.boot, SandboxBootGeneration::new(3));
        assert_eq!(provenance.scope, TrustScope::named(ExecutionCategory::VmSandbox, sandbox.as_str()));
        let (_, again) = workspace.read_produced("page.html", 1 << 20).unwrap();
        assert_ne!(again.operation, provenance.operation);
        assert!(workspace.read_produced("page.html", 4).unwrap_err().contains("at most 4 are read"));
        let outside = workspace.read_produced("../outside.html", 1 << 20).unwrap_err();
        assert!(outside.contains("is not a name in the workspace"), "{outside}");
        assert!(workspace.read_produced("missing.html", 1 << 20).unwrap_err().contains("was refused"));
        assert!(workspace.read_produced("src", 1 << 20).unwrap_err().contains("not a regular file"));
        fs::write(temp.path().join("secret"), "host secret").unwrap();
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(temp.path().join("secret"), workspace.staging().join("link")).is_ok();
        // A file symbolic link needs Developer Mode or the privilege on Windows.
        #[cfg(windows)]
        let linked =
            std::os::windows::fs::symlink_file(temp.path().join("secret"), workspace.staging().join("link")).is_ok();
        if linked {
            let refused = workspace.read_produced("link", 1 << 20).unwrap_err();
            assert!(refused.contains("not followed"), "{refused}");
        }
    }

    /// PROVES the whole path: changes in the staging root are reviewed, only the approved
    /// file is promoted into the folder (the original kept in the backup root), the other
    /// changed file and the deletion stay out, and a second promotion of the same review
    /// is refused because the folder no longer holds what the review saw.
    #[test]
    fn only_approved_files_are_promoted_exactly_as_reviewed() {
        let (_temp, folder, store, sandbox) = setup();
        let mut workspace = store.import(&sandbox, 1, &folder).unwrap();
        let staging = workspace.staging();
        fs::write(staging.join("src/main.py"), "print('hello, world')\n").unwrap();
        fs::write(staging.join("NOTES.txt"), "new file\n").unwrap();
        fs::remove_file(staging.join("README.md")).unwrap();
        let changes = workspace.changes().unwrap();
        assert_eq!(
            changes.iter().map(|c| (c.name.as_str(), c.change)).collect::<Vec<_>>(),
            vec![("NOTES.txt", "added"), ("README.md", "deleted"), ("src/main.py", "modified")]
        );
        let review = workspace.review().unwrap();
        let digest = review["review"].as_str().unwrap().to_owned();
        assert_eq!(review["files"].as_array().unwrap().len(), 2);
        assert_eq!(review["deleted"], json!(["README.md"]));
        let main = review["files"].as_array().unwrap().iter().find(|f| f["name"] == "src/main.py").unwrap();
        assert_eq!(main["change"], "modify");
        assert!(main["diff"].as_str().unwrap().contains("+print('hello, world')"));
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
        let session = ClockSession::generate();
        let promoted = workspace
            .promote(&digest, &["src/main.py".to_owned()], &mut Admit(0), clock.as_ref(), session)
            .unwrap();
        assert_eq!(promoted["applied"][0]["applied"], "modified");
        assert_eq!(fs::read_to_string(folder.join("src/main.py")).unwrap(), "print('hello, world')\n");
        assert!(!folder.join("NOTES.txt").exists(), "an unapproved file was promoted");
        assert!(folder.join("README.md").exists(), "a deletion was promoted");
        assert!(matches!(workspace.record.state, WorkspaceState::Promoted { .. }));
        // The folder now holds the promoted bytes: the old review no longer matches it.
        let again = workspace
            .promote(&digest, &["src/main.py".to_owned()], &mut Admit(10), clock.as_ref(), session)
            .unwrap_err();
        assert!(again.contains("changed in the folder since the review"), "{again}");
    }

    /// PROVES VM-CP-16's host side: after the review, a changed staged byte or a changed
    /// file in the folder refuses the promotion, and the folder's files keep their bytes.
    #[test]
    fn a_change_after_the_review_refuses_the_promotion() {
        let (_temp, folder, store, sandbox) = setup();
        let mut workspace = store.import(&sandbox, 1, &folder).unwrap();
        fs::write(workspace.staging().join("src/main.py"), "print('v2')\n").unwrap();
        let digest = workspace.review().unwrap()["review"].as_str().unwrap().to_owned();
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
        let session = ClockSession::generate();
        // The guest changes the file after the review.
        fs::write(workspace.staging().join("src/main.py"), "print('v3')\n").unwrap();
        let refused = workspace
            .promote(&digest, &["src/main.py".to_owned()], &mut Admit(0), clock.as_ref(), session)
            .unwrap_err();
        assert!(refused.contains("changed since the review"), "{refused}");
        assert_eq!(fs::read_to_string(folder.join("src/main.py")).unwrap(), "print('hello')\n");
        // Reviewed again, then the user's folder changes before the promotion.
        let digest = workspace.review().unwrap()["review"].as_str().unwrap().to_owned();
        fs::write(folder.join("src/main.py"), "print('edited by the user')\n").unwrap();
        let refused = workspace
            .promote(&digest, &["src/main.py".to_owned()], &mut Admit(0), clock.as_ref(), session)
            .unwrap_err();
        assert!(refused.contains("changed in the folder since the review"), "{refused}");
        assert_eq!(fs::read_to_string(folder.join("src/main.py")).unwrap(), "print('edited by the user')\n");
    }

    /// PROVES recovery: an import without a record is removed, and a promotion journaled
    /// but cut short is reported file by file.
    #[test]
    fn recovery_removes_cut_imports_and_reports_cut_promotions() {
        let (_temp, folder, store, sandbox) = setup();
        let mut workspace = store.import(&sandbox, 1, &folder).unwrap();
        fs::write(workspace.staging().join("src/main.py"), "print('v2')\n").unwrap();
        fs::write(workspace.staging().join("NOTES.txt"), "n\n").unwrap();
        workspace.review().unwrap();
        // A promotion that wrote one file and stopped.
        let key = |text: &str| ContentKey::of(text.as_bytes()).digest().to_hex();
        workspace.record.state = WorkspaceState::Promoting {
            review: "r".to_owned(),
            approved: BTreeMap::from([
                ("src/main.py".to_owned(), key("print('v2')\n")),
                ("NOTES.txt".to_owned(), key("n\n")),
            ]),
            // A record from before the intent was journaled: reported, not undone.
            label: None,
        };
        workspace.save().unwrap();
        fs::write(folder.join("src/main.py"), "print('v2')\n").unwrap();
        // An import cut short.
        fs::create_dir_all(store.root.join("exe-cut").join(STAGING)).unwrap();
        let report = store.recover();
        assert_eq!(report["removed_incomplete_imports"], json!(["exe-cut"]));
        let state = &report["interrupted_promotions"][0]["state"];
        assert_eq!(state["applied"], json!(["src/main.py"]));
        assert_eq!(state["not_applied"], json!(["NOTES.txt"]));
        assert!(!store.root.join("exe-cut").exists());
    }

    /// PROVES a promotion an engine stop cut short is undone at the next start from its
    /// journaled intent: a replaced file gets its verified original back, an added file and
    /// the directories made for it go, and a file someone changed since is left alone.
    #[test]
    fn a_promotion_cut_short_is_undone_at_the_next_start() {
        let (_temp, folder, store, sandbox) = setup();
        let mut workspace = store.import(&sandbox, 1, &folder).unwrap();
        let staging = workspace.staging();
        fs::write(staging.join("src/main.py"), "print('v2')\n").unwrap();
        fs::write(staging.join("README.md"), "# Project v2\n").unwrap();
        fs::create_dir_all(staging.join("docs/new")).unwrap();
        fs::write(staging.join("docs/new/NOTES.txt"), "notes\n").unwrap();
        let digest = workspace.review().unwrap()["review"].as_str().unwrap().to_owned();
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
        let session = ClockSession::generate();
        let files = ["README.md".to_owned(), "docs/new/NOTES.txt".to_owned(), "src/main.py".to_owned()];
        let promoted = workspace.promote(&digest, &files, &mut Admit(0), clock.as_ref(), session).unwrap();
        assert!(!workspace.dir.join(PROMOTING).exists(), "a whole promotion leaves no intent");
        // As if the engine stopped before the promotion's record was saved: its intent and
        // state are what it journaled before its first write.
        let kept: KeptReview = serde_json::from_slice(&fs::read(workspace.dir.join(REVIEW)).unwrap()).unwrap();
        let intent = Intent { manifest: kept.manifest, snapshot: kept.snapshot, review: kept.review };
        fs::write(workspace.dir.join(PROMOTING), serde_json::to_vec(&intent).unwrap()).unwrap();
        let backup = promoted["applied"].as_array().unwrap().iter().find_map(|applied| applied["original_kept_at"].as_str()).unwrap().to_owned();
        let label = Path::new(&backup).parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        workspace.record.state = WorkspaceState::Promoting { review: digest, approved: BTreeMap::new(), label: Some(label) };
        workspace.save().unwrap();
        // Someone changes one promoted file before the next start.
        fs::write(folder.join("README.md"), "# edited by the user\n").unwrap();
        let report = store.recover();
        let state = &report["interrupted_promotions"][0]["state"];
        assert_eq!(state["state"], "promotion_undone", "{report}");
        assert_eq!(state["restored"], json!(["src/main.py"]));
        assert_eq!(state["removed"], json!(["docs/new/NOTES.txt"]));
        assert_eq!(state["left"], json!(["README.md"]));
        assert_eq!(fs::read_to_string(folder.join("src/main.py")).unwrap(), "print('hello')\n");
        assert!(!folder.join("docs").exists(), "the directories made for the added file go with it");
        assert_eq!(fs::read_to_string(folder.join("README.md")).unwrap(), "# edited by the user\n");
        assert!(!workspace.dir.join(PROMOTING).exists());
    }

    /// PROVES the bound a template's review states is the bound the import and the guest's
    /// grant apply.
    #[test]
    fn the_review_states_the_bound_applied() {
        assert_eq!(MAX_TOTAL_BYTES as f64, yougori_setup::resource::VM_WORKSPACE_MOST_GB * f64::from(1u32 << 30));
    }

    /// PROVES files past the old 8 MiB bound are imported, scanned and promoted in bounded
    /// chunks: the copy, the baseline and the promoted file are exact.
    #[test]
    fn files_larger_than_the_old_bound_import_and_promote_exactly() {
        let (_temp, folder, store, sandbox) = setup();
        let large: Vec<u8> = (0..(9u32 << 20) + 5).map(|at| (at.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        fs::write(folder.join("model.bin"), &large).unwrap();
        let mut workspace = store.import(&sandbox, 1, &folder).unwrap();
        assert!(workspace.record.skipped.is_empty(), "{:?}", workspace.record.skipped);
        assert_eq!(workspace.record.baseline["model.bin"].size_bytes, large.len() as u64);
        assert_eq!(fs::read(workspace.staging().join("model.bin")).unwrap(), large);
        let mut changed = large.clone();
        changed[8 << 20] ^= 1;
        changed.extend_from_slice(&[9u8; 1 << 20]);
        fs::write(workspace.staging().join("model.bin"), &changed).unwrap();
        let review = workspace.review().unwrap();
        let file = &review["files"][0];
        assert_eq!((file["name"].as_str(), file["size_bytes"].as_u64()), (Some("model.bin"), Some(changed.len() as u64)));
        assert!(file["diff"].is_null(), "no diff of a large binary file");
        let digest = review["review"].as_str().unwrap().to_owned();
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
        workspace.promote(&digest, &["model.bin".to_owned()], &mut Admit(0), clock.as_ref(), ClockSession::generate()).unwrap();
        assert_eq!(fs::read(folder.join("model.bin")).unwrap(), changed);
    }

    #[test]
    fn credential_locations_are_recognised() {
        for (name, directory) in [(".ssh", true), (".env", false), (".env.local", false), ("id_rsa", false), ("tls.KEY", false), (".npmrc", false)] {
            assert!(excluded(name, directory), "{name}");
        }
        for (name, directory) in [("src", true), (".env.example", false), ("keys.rs", false), ("README.md", false)] {
            assert!(!excluded(name, directory), "{name}");
        }
    }
}
