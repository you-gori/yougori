use crate::{
    platform,
    policy::{safe_text, Identity},
};
use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const DATA_LIMIT: u64 = 8 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Item {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub resource: String,
    pub value: String,
}
impl Drop for Item {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
impl Item {
    pub fn validate(&self) -> Result<(), String> {
        if !safe_text(&self.label, 100) || self.value.is_empty() || self.value.len() > 32 * 1024 {
            return Err("Enter a name and a value of at most 32 KB".into());
        }
        match self.kind.as_str() {
            "cloudflare" => {
                if self.resource.len() != 32
                    || !self.resource.bytes().all(|b| b.is_ascii_hexdigit())
                    || self.value.len() > 512
                    || self.value.bytes().any(|b| b.is_ascii_whitespace())
                {
                    return Err(
                        "Cloudflare needs a 32-character zone ID and a valid API token".into(),
                    );
                }
            }
            "personal" => {
                let data: BTreeMap<String, String> =
                    serde_json::from_str(&self.value).map_err(|_| {
                        "Personal information must be a JSON object containing text fields"
                    })?;
                if data.is_empty()
                    || data.len() > 64
                    || data
                        .iter()
                        .any(|(k, v)| !safe_text(k, 100) || !safe_text(v, 4096))
                {
                    return Err(
                        "Use 1–64 named personal-information fields, each up to 4 KB".into(),
                    );
                }
                // Personal information supports user-defined names such as
                // openSourceName. Credential storage remains a separate kind.
                if data.keys().any(|k| {
                    let key: String = k
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect();
                    [
                        "password",
                        "passwd",
                        "secret",
                        "token",
                        "apikey",
                        "privatekey",
                        "credential",
                    ]
                    .iter()
                    .any(|word| key.contains(word))
                }) || data
                    .values()
                    .any(|v| v.contains("PRIVATE KEY") || v.contains("-----BEGIN"))
                {
                    return Err("Store passwords, tokens and keys as credential items, never personal information. Personal information accepts named text fields such as name, email or openSourceName.".into());
                }
            }
            "password" | "api_key" | "token" | "private_key" | "credential" => (),
            _ => return Err("Unsupported vault item type".into()),
        }
        Ok(())
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"id":self.id,"label":self.label,"kind":self.kind,"resource":self.resource,"fields":if self.kind=="personal" {serde_json::from_str::<BTreeMap<String,String>>(&self.value).unwrap_or_default().keys().cloned().collect::<Vec<_>>()} else {vec![]}})
    }
    pub fn validate_personal_fields(&self, fields: &[String]) -> Result<(), String> {
        if self.kind != "personal" {
            return Err("This is a credential item. Use read_credential with this exact item name or ID to request one-time disclosure approval. Do not copy credentials into personal information.".into());
        }
        let values: BTreeMap<String, String> = serde_json::from_str(&self.value)
            .map_err(|_| "This personal-information item is invalid. Recreate it in Yougori.")?;
        if fields.iter().any(|field| !values.contains_key(field)) {
            return Err("A requested field does not exist in this item. In Yougori, choose View items and check the field names shown under the item. Use those exact names; do not automatically retry guessed spellings.".into());
        }
        Ok(())
    }
    pub fn is_credential(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "password" | "api_key" | "token" | "private_key" | "credential" | "cloudflare"
        )
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contents {
    pub items: BTreeMap<String, Item>,
    pub clients: BTreeMap<String, Identity>,
}
impl Contents {
    pub fn resolve_item(&self, name_or_id: &str) -> Result<&Item, String> {
        if let Some(item) = self.items.get(name_or_id) {
            return Ok(item);
        }
        let mut matches = self.items.values().filter(|item| item.label == name_or_id);
        let item = matches.next().ok_or("No item matches that name or ID. In Yougori Personal Vault, choose View items and copy the item ID or use its exact name.")?;
        if matches.next().is_some() {
            return Err("Several items have that name. Copy the intended item ID from Yougori Personal Vault instead.".into());
        }
        Ok(item)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Audit {
    pub time: String,
    pub client: String,
    pub request: String,
    pub operation: String,
    pub outcome: String,
}
/// What opening the vault does about its key.
#[derive(Debug, PartialEq)]
enum KeyStep {
    /// Read the key that is there.
    Read,
    /// Mint a new one: there is certainly none, and certainly no data without it.
    Mint,
}

/// Whether opening reads the vault's key or mints one. Only a key file certainly absent is ever
/// minted, and only beside data certainly absent: a key written over one that merely could not
/// be checked would leave every secret it protects unreadable for good, so creating refuses
/// loudly rather than guessing.
fn key_step(key: &Path, data: &Path, create: bool) -> Result<KeyStep, String> {
    let checked = |path: &Path| {
        present(path).map_err(|reason| {
            if create {
                format!("Personal Vault did not create a key: a new key written over an existing one would leave every secret it protects unreadable for good. {reason}")
            } else {
                reason
            }
        })
    };
    if checked(key)? {
        return Ok(KeyStep::Read);
    }
    new_key(checked(data)?, create)?;
    Ok(KeyStep::Mint)
}

/// Whether a missing vault key may be created now. Data without its key is never replaced,
/// and only creating the vault mints a key: a connection or tool call before setup, or after
/// the vault was destroyed, is refused instead of starting a new, empty vault.
fn new_key(data_without_key: bool, create: bool) -> Result<(), String> {
    if data_without_key {
        return Err("The vault key is missing. Existing vault data was left untouched.".into());
    }
    if !create {
        return Err("Create your Personal Vault first".into());
    }
    Ok(())
}
pub(crate) struct Store {
    root: PathBuf,
    key: age::x25519::Identity,
    pub contents: Contents,
}
impl Store {
    /// `create`: only creating the vault may mint a key. Anything else finding none (a vault
    /// never made, or one destroyed) is refused rather than starting a new, empty vault.
    pub fn open(create: bool) -> Result<Self, String> {
        let root = platform::data_directory()?;
        platform::verify_protected(root.parent().unwrap(), false)?;
        platform::verify_protected(&root, false)?;
        let marker = root.join(DESTROYING);
        // Three ways, never two: a note that could not be checked refuses with that reason, and
        // is never read as a delete that began, whose advice would be to delete again.
        if present(&marker)? {
            if !secrets_left(&root).none() {
                return Err(UNFINISHED_OPEN.into());
            }
            // Every secret went and only the note stayed behind: it goes before anything new.
            std::fs::remove_file(&marker).map_err(|_| {
                format!("The note left by deleting the last vault could not be removed: {}. Delete that file as an administrator, then try again.", marker.display())
            })?;
        }
        let key_path = root.join(KEY_FILE);
        let data_path = root.join("contents.age");
        let key = if key_step(&key_path, &data_path, create)? == KeyStep::Read {
            platform::verify_protected(&key_path, false)?;
            let bytes = bounded_read(&key_path, 16384)?;
            let decrypted = dpapi(&bytes, false)?;
            std::str::from_utf8(&decrypted)
                .map_err(|_| "Invalid vault key")?
                .parse::<age::x25519::Identity>()
                .map_err(|_| "Invalid vault key")?
        } else {
            let identity = age::x25519::Identity::generate();
            let text = identity.to_string();
            atomic_write(&key_path, &dpapi(text.expose_secret().as_bytes(), true)?)?;
            identity
        };
        // Data that could not be checked never opens as empty: the next save would replace it.
        let contents = if present(&data_path)? {
            serde_json::from_slice(&decrypt(&key, &bounded_read(&data_path, DATA_LIMIT)?)?)
                .map_err(|_| "Vault data could not be verified")?
        } else {
            Contents::default()
        };
        Ok(Self {
            root,
            key,
            contents,
        })
    }
    pub fn save(&self) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&self.contents).map_err(|_| "Cannot encode vault data")?,
        );
        if bytes.len() as u64 > DATA_LIMIT / 2 {
            return Err("Vault is full (4 MB). Remove unused items before adding more.".into());
        }
        atomic_write(
            &self.root.join("contents.age"),
            &encrypt(&self.key, &bytes)?,
        )
    }
    pub fn audit(&self, entry: &Audit) -> Result<(), String> {
        record(entry)
    }
    pub fn recent(&self) -> Result<Vec<Audit>, String> {
        recent()
    }
}
static AUDIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static AUDIT_CACHE: std::sync::Mutex<Option<Vec<Audit>>> = std::sync::Mutex::new(None);
static AUDIT_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static AUDIT_CHECKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const AUDIT_LIMIT: u64 = 32 * 1024 * 1024;
const AUDIT_ARCHIVES: usize = 4;
const AUDIT_RECORD_LIMIT: usize = 8192;
/// Where complete records end, and whether the log continues with unreadable
/// framing. A crash can leave one partially written record at the end.
#[derive(Debug, PartialEq)]
struct LogShape {
    complete: u64,
    damaged: bool,
}
fn log_shape(bytes: &[u8]) -> LogShape {
    let mut offset = 0usize;
    while bytes.len() - offset >= 4 {
        let size = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if size == 0 || size > AUDIT_RECORD_LIMIT {
            return LogShape { complete: offset as u64, damaged: true };
        }
        if bytes.len() - offset - 4 < size {
            break;
        }
        offset += 4 + size;
    }
    LogShape { complete: offset as u64, damaged: false }
}
/// Moves the current log aside, keeping the newest archives within the limit.
fn rotate_audit(root: &Path, path: &Path) -> Result<(), String> {
    let archive = root.join(format!(
        "activity-{}.dpapi-log",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    ));
    std::fs::rename(path, &archive).map_err(|_| "Cannot archive the protected audit log")?;
    let mut archives: Vec<_> = std::fs::read_dir(root)
        .map_err(|_| "Cannot list protected audit archives")?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("activity-") && name.ends_with(".dpapi-log"))
        .collect();
    archives.sort();
    for name in archives.iter().take(archives.len().saturating_sub(AUDIT_ARCHIVES)) {
        let _ = std::fs::remove_file(root.join(name));
    }
    *AUDIT_CACHE.lock().unwrap() = Some(vec![]);
    Ok(())
}
/// Before the first append in a process, drop a torn trailing record and set
/// aside a log whose framing cannot be read, so new records stay readable.
fn repair_audit(root: &Path, path: &Path) -> Result<(), String> {
    // Deliberately `exists()`: a log that cannot be checked is not repaired here, and the append
    // that follows fails on it instead. Nothing is written on this answer; keep it that way.
    if AUDIT_CHECKED.load(std::sync::atomic::Ordering::SeqCst) || !path.exists() {
        AUDIT_CHECKED.store(true, std::sync::atomic::Ordering::SeqCst);
        return Ok(());
    }
    let bytes = std::fs::read(path).map_err(|_| "Cannot read protected audit log")?;
    let shape = log_shape(&bytes);
    if shape.damaged {
        rotate_audit(root, path)?;
    } else if shape.complete < bytes.len() as u64 {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| "Cannot repair protected audit log")?;
        file.set_len(shape.complete)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Cannot repair protected audit log")?;
        *AUDIT_CACHE.lock().unwrap() = None;
    }
    AUDIT_CHECKED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}
pub(crate) fn record(entry: &Audit) -> Result<(), String> {
    let _guard = AUDIT_LOCK.lock().map_err(|_| "Audit lock unavailable")?;
    if AUDIT_FAILED.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("An audit write failed. Protected operations are disabled until the log is inspected and the broker restarted.".into());
    }
    let root = platform::data_directory()?;
    platform::verify_protected(&root, false)?;
    let bytes = serde_json::to_vec(entry).map_err(|_| "Cannot encode audit entry")?;
    let encrypted = dpapi(&bytes, true)?;
    let path = root.join("activity.dpapi-log");
    if present(&path)? {
        platform::verify_protected(&path, false)?;
    }
    repair_audit(&root, &path)?;
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > AUDIT_LIMIT) {
        rotate_audit(&root, &path)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|_| "Cannot open protected audit log; request blocked")?;
    platform::secure(&path, false)?;
    let committed = file
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .and_then(|_| file.write_all(&encrypted))
        .and_then(|_| file.sync_all());
    if committed.is_err() {
        AUDIT_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
        return Err("Cannot commit audit record; request blocked".into());
    }
    if let Some(cache) = AUDIT_CACHE.lock().unwrap().as_mut() {
        cache.insert(0, entry.clone());
        cache.truncate(100);
    }
    Ok(())
}
pub(crate) fn recent() -> Result<Vec<Audit>, String> {
    let _guard = AUDIT_LOCK.lock().map_err(|_| "Audit lock unavailable")?;
    if let Some(cache) = AUDIT_CACHE.lock().unwrap().as_ref() {
        return Ok(cache.clone());
    }
    let path = platform::data_directory()?.join("activity.dpapi-log");
    // Deliberately `exists()`: a log that cannot be checked shows no activity, and nothing is
    // ever written on this answer; it only feeds what the status shows. Keep it read-only.
    if !path.exists() {
        *AUDIT_CACHE.lock().unwrap() = Some(vec![]);
        return Ok(vec![]);
    }
    platform::verify_protected(&path, false)?;
    let mut bytes = vec![];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| "Cannot open audit log")?;
    let records: Vec<Audit> = audit_records(&bytes, |encrypted| {
        dpapi(encrypted, false)
            .ok()
            .and_then(|plain| serde_json::from_slice(&plain).ok())
    });
    *AUDIT_CACHE.lock().unwrap() = Some(records.clone());
    Ok(records)
}

/// The newest 100 readable records, newest first. A torn final record or
/// unreadable framing ends the log instead of disabling the broker; a single
/// undecryptable record is skipped.
fn audit_records(bytes: &[u8], decode: impl Fn(&[u8]) -> Option<Audit>) -> Vec<Audit> {
    let end = log_shape(bytes).complete as usize;
    let mut records = std::collections::VecDeque::new();
    let mut offset = 0;
    while offset < end {
        let size = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if let Some(record) = decode(&bytes[offset + 4..offset + 4 + size]) {
            records.push_back(record);
            if records.len() > 100 {
                records.pop_front();
            }
        }
        offset += 4 + size;
    }
    records.into_iter().rev().collect()
}

/// The vault's key. Everything else the vault holds is encrypted to it, so once it is gone what
/// remains can no longer be read.
const KEY_FILE: &str = "key.dpapi";

/// Files that hold the vault's keys or anything they protect. The activity log stays: it holds
/// no secrets and records the deletion. `desktops.json` names the trusted Yougori, not vault
/// data.
///
/// [`KEY_FILE`] must stay first. `wipe_secrets` deletes in this order, after any interrupted
/// save (which may be a copy of the key), and only a key destroyed before what it protects makes
/// whatever a destroy that stops part way leaves unreadable; a test pins it.
const SECRET_FILES: &[&str] = &[KEY_FILE, "contents.age", "http-key.dpapi", "oauth.dpapi", "server-identity.dpapi"];

/// Whether `path` is certainly gone. A file that cannot be inspected might still be there, so
/// only "not found" counts: a destroy must never call a secret gone that it could not check.
fn gone(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

/// Whether `path` is there, for a decision to create, mint or start empty: `Ok(false)` only when
/// it is certainly absent. A file that could not be checked is an error, so nothing mistakes an
/// unreadable file for a missing one and writes over it.
pub(crate) fn present(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "Personal Vault could not check {} ({error}), so it changed nothing. Try again; if it keeps happening, check that drive.",
            path.display()
        )),
    }
}

/// Left in the vault folder while a destroy is under way, so one that stops part way is still
/// known after a restart, and the vault is not opened again until it finishes. It holds nothing.
const DESTROYING: &str = "destroying";

const UNFINISHED_OPEN: &str = "Deleting Personal Vault did not finish, so it stays closed. Run Delete my vault again to finish; deleting again is safe.";

/// Why a destroy did not finish.
#[derive(Debug, PartialEq)]
pub(crate) enum Unfinished {
    /// Nothing was deleted, for this reason, said in full.
    NotStarted(String),
    /// Deleting began and stopped for `reason`, and `left` may still hold secrets; `unlisted`
    /// says why the folder could not be listed, when other files may remain unseen. The key goes
    /// first, so once `key_gone` (and no copy of it can remain) what remains can no longer be read.
    Partial { key_gone: bool, left: Vec<PathBuf>, unlisted: Option<String>, reason: String },
}

/// What may still hold secrets in a vault folder: every secret file not certainly gone, and why
/// the folder could not be listed, if it could not, in which case more may remain unseen.
#[derive(Debug, PartialEq)]
struct Left {
    files: Vec<PathBuf>,
    unlisted: Option<String>,
}

impl Left {
    /// Whether no secret can remain: nothing listed, and nothing unseen.
    fn none(&self) -> bool {
        self.files.is_empty() && self.unlisted.is_none()
    }
}

/// Starts destroying the vault on disk. The folder must still be protected the way the broker
/// left it, and a note that deleting has begun goes in first. Returns the folder, or `None`
/// when there is no vault on disk. Nothing has been deleted when this fails.
pub(crate) fn begin_destroy() -> Result<Option<PathBuf>, Unfinished> {
    let root = platform::data_directory().map_err(|reason| Unfinished::NotStarted(format!("The vault folder could not be found ({reason}).")))?;
    begin_destroy_at(&root)
}

fn begin_destroy_at(root: &Path) -> Result<Option<PathBuf>, Unfinished> {
    // Only a folder certainly absent means there is no vault to delete; one that could not be
    // checked is never reported as deleted.
    if !present(root).map_err(Unfinished::NotStarted)? {
        return Ok(None);
    }
    begin_destroy_in(root, |path| platform::verify_protected(path, false), |path| atomic_write(path, b""))
}

fn begin_destroy_in(
    root: &Path,
    verify: impl Fn(&Path) -> Result<(), String>,
    mark: impl Fn(&Path) -> Result<(), String>,
) -> Result<Option<PathBuf>, Unfinished> {
    // A folder whose protection changed is never deleted from, so asking again cannot help:
    // say so, and how to remove it anyway.
    verify(root).map_err(|reason| Unfinished::NotStarted(format!(
        "The vault folder {} is not protected the way Yougori left it ({reason}), so Yougori will not delete files in it. To remove the vault anyway, delete that folder yourself as an administrator.",
        root.display()
    )))?;
    mark(&root.join(DESTROYING)).map_err(|reason| Unfinished::NotStarted(format!(
        "Deleting could not begin: Yougori could not write its note in {} ({reason}). Try again once that drive has space.",
        root.display()
    )))?;
    Ok(Some(root.to_owned()))
}

/// Destroys the vault on disk once [`begin_destroy`] has begun: any interrupted save first, since
/// one may be a copy of the key, then the key, so anything that survives on the drive can no
/// longer be read, then its data, connection keys and sign-ins. Destroying twice is harmless.
/// Returns a sentence for anything small left behind once every secret is gone. A destroy that
/// stops before it has touched a file deleted nothing, and says so.
///
/// Each file is overwritten in place, flushed and emptied before it is removed. On an SSD the
/// drive may keep the old blocks elsewhere, so no overwrite is guaranteed there; destroying the
/// key first is what makes the data unreadable. Windows shadow copies of ProgramData, where the
/// computer keeps them, are outside the broker's reach.
pub(crate) fn finish_destroy(root: &Path) -> Result<Vec<String>, Unfinished> {
    finish_destroy_in(root, |path| platform::verify_protected(path, false))
}

fn finish_destroy_in(root: &Path, verify: impl Fn(&Path) -> Result<(), String>) -> Result<Vec<String>, Unfinished> {
    let marker = root.join(DESTROYING);
    if let Err((begun, reason)) = wipe_secrets(root, verify) {
        if begun == 0 {
            // Nothing was touched: the note goes, so the vault opens as it did.
            let way_out = format!("If it stops the same way again, delete the folder {} yourself as an administrator to remove the vault.", root.display());
            return Err(Unfinished::NotStarted(match std::fs::remove_file(&marker) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => format!(
                    "Deleting stopped before any file was touched: {reason}. A note that deleting had begun is still at {}, so the vault stays closed until it is removed: delete that file as an administrator. {way_out}",
                    marker.display()
                ),
                _ => format!("Deleting stopped before any file was touched: {reason}. {way_out}"),
            }));
        }
        let left = secrets_left(root);
        return Err(Unfinished::Partial { key_gone: key_gone(root, &left), left: left.files, unlisted: left.unlisted, reason });
    }
    Ok(match std::fs::remove_file(&marker) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => vec![format!(
            "A note that deleting was under way is still at {}. It holds nothing secret, and Yougori removes it the next time it starts.",
            marker.display()
        )],
        _ => Vec::new(),
    })
}

/// Whether a destroy began and stopped part way, leaving secrets. A destroy that removed every
/// secret but not its note is finished: the note goes now.
pub(crate) fn destroy_unfinished() -> bool {
    platform::data_directory().is_ok_and(|root| unfinished_in(&root))
}

/// Whether a note says a destroy began while secrets may remain. A folder that cannot be listed
/// may hold an interrupted save, so it counts as holding secrets and the note stays.
fn unfinished_in(root: &Path) -> bool {
    let marker = root.join(DESTROYING);
    // Only a note certainly there says a delete began. One that could not be checked says
    // nothing either way: never "deleting did not finish", whose advice is to delete again.
    if present(&marker) != Ok(true) {
        return false;
    }
    if secrets_left(root).none() {
        let _ = std::fs::remove_file(&marker);
        return false;
    }
    true
}

/// What the vault folder holds, read from disk so that a status never guesses: "vault" when
/// secrets are there and no destroy has begun, "partial" when a destroy began and secrets may
/// remain, "none" when no secret can remain (or there never was a vault), and "unknown" when the
/// folder cannot be found. A folder that cannot be listed counts as holding secrets.
pub(crate) fn on_disk() -> &'static str {
    platform::data_directory().map_or("unknown", |root| on_disk_in(&root))
}

fn on_disk_in(root: &Path) -> &'static str {
    if secrets_left(root).none() {
        return "none";
    }
    // Secrets may be there; whether a delete began is the note's to say, three ways.
    match present(&root.join(DESTROYING)) {
        Ok(true) => "partial",
        Ok(false) => "vault",
        Err(_) => "unknown",
    }
}

/// What may still hold secrets in `root`: interrupted saves, then the key and what it protects.
/// A file that cannot be inspected is listed, since it may still be there, and a folder that
/// cannot be listed is said, since an interrupted save may be in it.
fn secrets_left(root: &Path) -> Left {
    let (saves, unlisted) = match interrupted_saves(root) {
        Ok(saves) => (saves, None),
        Err(reason) => (Vec::new(), Some(reason)),
    };
    let files = saves
        .into_iter()
        .chain(SECRET_FILES.iter().map(|name| root.join(name)))
        .filter(|path| !gone(path))
        .collect();
    Left { files, unlisted }
}

/// Whether the key is certainly gone: its file, and every interrupted save, since one may be a
/// copy of it, with nothing unseen in a folder that could not be listed.
fn key_gone(root: &Path, left: &Left) -> bool {
    gone(&root.join(KEY_FILE)) && left.unlisted.is_none() && !left.files.iter().any(|path| interrupted_save(path))
}

/// Whether `path` is a temporary copy an interrupted atomic save left.
fn interrupted_save(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(".tmp"))
}

/// The temporary copies an interrupted atomic save left in `root`. A folder that is not there
/// holds none; one that cannot be listed is an error, never an empty list.
fn interrupted_saves(root: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("Cannot list vault files".into()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "Cannot list vault files")?;
        if interrupted_save(&entry.path()) {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

/// Overwrites and removes every secret file in `root`: interrupted saves first, since one may be
/// a copy of the key, then the key, then what it protects. Stops at the first file it cannot
/// inspect, verify, overwrite or remove, with the number of files it had begun to overwrite.
fn wipe_secrets(root: &Path, verify: impl Fn(&Path) -> Result<(), String>) -> Result<(), (usize, String)> {
    let mut paths = interrupted_saves(root).map_err(|reason| (0, reason))?;
    paths.extend(SECRET_FILES.iter().map(|name| root.join(name)));
    let mut begun = 0;
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err((begun, "Cannot inspect vault file".into())),
            Ok(_) => {}
        }
        verify(&path).map_err(|reason| (begun, reason))?;
        begun += 1;
        overwrite(&path).map_err(|reason| (begun, reason))?;
        std::fs::remove_file(&path).map_err(|_| (begun, "Cannot remove vault file".to_owned()))?;
    }
    Ok(())
}

/// Replaces a file's bytes where they lie and empties it, before it is removed.
fn overwrite(path: &Path) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| "Cannot open vault file for deletion")?;
    let mut left = file.metadata().map_err(|_| "Cannot inspect vault file")?.len();
    let block = [0u8; 64 * 1024];
    while left > 0 {
        let size = left.min(block.len() as u64) as usize;
        file.write_all(&block[..size])
            .map_err(|_| "Cannot overwrite vault file")?;
        left -= size as u64;
    }
    file.sync_all()
        .and_then(|_| file.set_len(0))
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot overwrite vault file".into())
}

pub(crate) fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    platform::verify_protected(path, false)?;
    let mut bytes = vec![];
    std::fs::File::open(path)
        .map_err(|_| "Cannot open vault file")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read vault file")?;
    if bytes.len() as u64 > limit {
        return Err("Vault file exceeds size limit".into());
    }
    Ok(bytes)
}
/// Replaces `path` in one step without reading or checking what is there, for a file that holds
/// no vault data (the trusted Desktops list), so an unreadable one can always be replaced. The
/// rename replaces the path itself and never follows it; the folder must still be protected.
pub(crate) fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    platform::verify_protected(path.parent().unwrap(), false)?;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())
        .map_err(|_| "Cannot create protected vault file")?;
    platform::secure(file.path(), false)?;
    file.write_all(bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "Cannot write protected vault file")?;
    file.persist(path).map_err(|_| "Cannot replace protected vault file")?;
    Ok(())
}
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    platform::verify_protected(path.parent().unwrap(), false)?;
    if present(path)? {
        platform::verify_protected(path, false)?;
    }
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())
        .map_err(|_| "Cannot create protected vault file")?;
    platform::secure(file.path(), false)?;
    file.write_all(bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "Cannot commit encrypted vault data")?;
    file.persist(path)
        .map_err(|_| "Cannot replace encrypted vault data")?;
    Ok(())
}
fn encrypt(key: &age::x25519::Identity, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let recipient = key.to_public();
    let mut encrypted = vec![];
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|_| "Vault encryption unavailable")?;
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|_| "Vault encryption failed")?;
    writer
        .write_all(bytes)
        .map_err(|_| "Vault encryption failed")?;
    writer.finish().map_err(|_| "Vault encryption failed")?;
    Ok(encrypted)
}
fn decrypt(key: &age::x25519::Identity, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let decryptor = age::Decryptor::new(bytes).map_err(|_| "Invalid encrypted vault file")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(key as &dyn age::Identity))
        .map_err(|_| "Cannot authenticate encrypted vault data")?;
    let mut plain = Zeroizing::new(vec![]);
    reader
        .read_to_end(&mut plain)
        .map_err(|_| "Cannot decrypt vault data")?;
    Ok(plain)
}
pub(crate) fn dpapi(bytes: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let okay = if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if okay == 0 {
            return Err("Windows could not protect or unlock the vault encryption key".into());
        }
        let buffer = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let result = Zeroizing::new(buffer.to_vec());
        buffer.zeroize();
        LocalFree(output.pbData.cast());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_encryption_rejects_tampering_and_other_keys() {
        let key = age::x25519::Identity::generate();
        let secret = b"a-secret-not-in-the-file";
        let mut bytes = encrypt(&key, secret).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        assert_eq!(&**decrypt(&key, &bytes).unwrap(), secret);
        assert!(decrypt(&age::x25519::Identity::generate(), &bytes).is_err());
        let end = bytes.len() - 1;
        bytes[end] ^= 1;
        assert!(decrypt(&key, &bytes).is_err());
    }
    fn framed(records: &[&[u8]]) -> Vec<u8> {
        records
            .iter()
            .flat_map(|record| (record.len() as u32).to_be_bytes().into_iter().chain(record.iter().copied()))
            .collect()
    }
    fn entry(outcome: &str) -> Vec<u8> {
        serde_json::to_vec(&Audit {
            time: "t".into(),
            client: "c".into(),
            request: "r".into(),
            operation: "o".into(),
            outcome: outcome.into(),
        })
        .unwrap()
    }
    #[test]
    fn torn_and_damaged_audit_logs_stay_readable() {
        let decode = |bytes: &[u8]| serde_json::from_slice::<Audit>(bytes).ok();
        let (first, second) = (entry("first"), entry("second"));
        let complete = framed(&[&first, &second]);
        assert_eq!(log_shape(&complete), LogShape { complete: complete.len() as u64, damaged: false });
        // A crash after the length prefix, or partway through the data.
        for cut in [complete.len() - 3, complete.len() - second.len() - 2] {
            let mut torn = complete.clone();
            torn.truncate(cut);
            let shape = log_shape(&torn);
            assert!(!shape.damaged);
            assert_eq!(shape.complete as usize, first.len() + 4);
            let outcomes: Vec<_> = audit_records(&torn, decode).into_iter().map(|a| a.outcome).collect();
            assert_eq!(outcomes, ["first"]);
        }
        // An undecryptable record is skipped; later records are still read.
        let skipped = framed(&[b"not json", &second]);
        assert_eq!(audit_records(&skipped, decode).len(), 1);
        // Impossible framing ends the readable log and marks it for rotation.
        let mut damaged = framed(&[&first]);
        damaged.extend_from_slice(&u32::MAX.to_be_bytes());
        damaged.extend_from_slice(&second);
        assert_eq!(log_shape(&damaged), LogShape { complete: first.len() as u64 + 4, damaged: true });
        assert_eq!(audit_records(&damaged, decode).len(), 1);
    }
    #[test]
    fn destroying_wipes_every_secret_file_keeps_the_record_and_can_run_twice() {
        let root = tempfile::tempdir().unwrap();
        let secret = b"vault-secret-material";
        for name in SECRET_FILES.iter().chain([".tmpA1b2C3"].iter()) {
            std::fs::write(root.path().join(name), secret.repeat(100)).unwrap();
        }
        std::fs::write(root.path().join("activity.dpapi-log"), b"record").unwrap();
        std::fs::write(root.path().join("desktops.json"), b"[]").unwrap();
        let verify = |path: &Path| platform::no_reparse(path);
        wipe_secrets(root.path(), verify).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(root.path()).unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["activity.dpapi-log", "desktops.json"]);
        // A second destroy finds nothing to do.
        wipe_secrets(root.path(), verify).unwrap();
        assert_eq!(std::fs::read(root.path().join("activity.dpapi-log")).unwrap(), b"record");
    }
    #[test]
    fn the_key_is_destroyed_before_anything_it_protects() {
        // `wipe_secrets` deletes in this order, so a destroy that stops after its first file has
        // already made the rest unreadable. Reordering this list breaks that promise.
        assert_eq!(SECRET_FILES[0], KEY_FILE, "the key file must stay first");
        let root = tempfile::tempdir().unwrap();
        for name in SECRET_FILES {
            std::fs::write(root.path().join(name), b"secret").unwrap();
        }
        let checked = std::cell::Cell::new(0);
        let only_the_first = |_: &Path| -> Result<(), String> {
            checked.set(checked.get() + 1);
            if checked.get() > 1 { Err("stopped".into()) } else { Ok(()) }
        };
        let Err(Unfinished::Partial { key_gone, left, unlisted, .. }) = finish_destroy_in(root.path(), only_the_first) else { panic!("it stopped after one file") };
        assert!(key_gone && unlisted.is_none(), "the one file deleted before stopping is the key");
        assert!(!left.contains(&root.path().join(KEY_FILE)) && left.len() == SECRET_FILES.len() - 1, "{left:?}");
        // Only a key that is certainly gone counts as gone.
        assert!(gone(&root.path().join(KEY_FILE)) && !gone(&root.path().join("contents.age")));
    }
    #[test]
    fn a_destroy_that_cannot_begin_deletes_nothing_and_says_why() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(KEY_FILE), b"key").unwrap();
        let fine = |_: &Path| -> Result<(), String> { Ok(()) };
        // A folder whose protection changed is never deleted from, and asking again cannot help.
        let changed = begin_destroy_in(root.path(), |_| Err("Unexpected vault file access rule".into()), fine).unwrap_err();
        let reason = match changed { Unfinished::NotStarted(reason) => reason, other => panic!("{other:?}") };
        assert!(reason.contains(&root.path().display().to_string()) && reason.contains("delete that folder yourself as an administrator"), "{reason}");
        assert!(!reason.contains("again"), "asking again cannot help: {reason}");
        // No note, no deletion.
        let unwritable = begin_destroy_in(root.path(), fine, |_| Err("disk full".into())).unwrap_err();
        assert!(matches!(&unwritable, Unfinished::NotStarted(reason) if reason.contains("disk full")), "{unwritable:?}");
        assert!(root.path().join(KEY_FILE).exists() && !root.path().join(DESTROYING).exists());
    }
    #[test]
    fn a_destroy_that_stops_part_way_names_what_is_left_and_is_remembered() {
        let root = tempfile::tempdir().unwrap();
        for name in SECRET_FILES {
            std::fs::write(root.path().join(name), b"secret").unwrap();
        }
        begin_destroy_in(root.path(), |_| Ok(()), |path| std::fs::write(path, b"").map_err(|e| e.to_string())).unwrap();
        // The data file cannot be deleted; the key before it already went.
        let stuck = root.path().join("contents.age");
        let verify = |path: &Path| -> Result<(), String> { if path == stuck { Err("Cannot open vault file for deletion".into()) } else { Ok(()) } };
        let Err(Unfinished::Partial { key_gone, left, unlisted, reason }) = finish_destroy_in(root.path(), verify) else { panic!("it stopped part way") };
        assert!(key_gone && unlisted.is_none(), "the key goes first");
        assert_eq!(left, ["contents.age", "http-key.dpapi", "oauth.dpapi", "server-identity.dpapi"].map(|name| root.path().join(name)));
        assert_eq!(reason, "Cannot open vault file for deletion");
        // The note survives a restart: the vault stays closed and reads as unfinished.
        assert!(unfinished_in(root.path()));
        // Running it again finishes, and the note goes.
        assert_eq!(finish_destroy_in(root.path(), |_| Ok(())), Ok(Vec::new()));
        assert!(secrets_left(root.path()).none() && !root.path().join(DESTROYING).exists());
        assert!(!unfinished_in(root.path()));
        // Stopped at the key before touching any file: nothing was deleted, and the note goes.
        std::fs::write(root.path().join(KEY_FILE), b"secret").unwrap();
        std::fs::write(root.path().join(DESTROYING), b"").unwrap();
        let key = root.path().join(KEY_FILE);
        let untouched = finish_destroy_in(root.path(), |path| -> Result<(), String> { if path == key { Err("locked".into()) } else { Ok(()) } }).unwrap_err();
        let reason = match untouched { Unfinished::NotStarted(reason) => reason, other => panic!("{other:?}") };
        assert!(reason.contains("before any file was touched") && reason.contains("locked") && reason.contains("as an administrator"), "{reason}");
        assert!(key.exists() && !root.path().join(DESTROYING).exists(), "the vault opens as it did");
    }
    #[test]
    fn a_copy_of_the_key_in_an_interrupted_save_goes_first_and_counts_as_the_key() {
        let root = tempfile::tempdir().unwrap();
        for name in SECRET_FILES {
            std::fs::write(root.path().join(name), b"secret").unwrap();
        }
        let copy = root.path().join(".tmpK3y");
        std::fs::write(&copy, b"a copy of the key").unwrap();
        // The interrupted save goes before the key: stopping right after it, the key is untouched.
        let checked = std::cell::Cell::new(0);
        let only_the_first = |_: &Path| -> Result<(), String> {
            checked.set(checked.get() + 1);
            if checked.get() > 1 { Err("stopped".into()) } else { Ok(()) }
        };
        let Err(Unfinished::Partial { key_gone: said_gone, left, .. }) = finish_destroy_in(root.path(), only_the_first) else { panic!("it stopped after one file") };
        assert!(!copy.exists() && !said_gone && left[0] == root.path().join(KEY_FILE), "{left:?}");
        // With the key file gone, a copy that stays, or a folder that could not be looked in,
        // still means the key may be readable.
        std::fs::remove_file(root.path().join(KEY_FILE)).unwrap();
        let data = root.path().join("contents.age");
        assert!(key_gone(root.path(), &Left { files: vec![data.clone()], unlisted: None }));
        assert!(!key_gone(root.path(), &Left { files: vec![copy.clone(), data.clone()], unlisted: None }));
        assert!(!key_gone(root.path(), &Left { files: vec![data], unlisted: Some("Cannot list vault files".into()) }));
    }
    #[test]
    fn a_folder_that_cannot_be_listed_may_still_hold_secrets() {
        let root = tempfile::tempdir().unwrap();
        // Not a folder at all, so it cannot be listed: never an empty list, never "none".
        let unlistable = root.path().join("not-a-folder");
        std::fs::write(&unlistable, b"").unwrap();
        let left = secrets_left(&unlistable);
        assert!(left.unlisted.is_some() && !left.none(), "{left:?}");
        assert_eq!(on_disk_in(&unlistable), "vault");
        // A folder that is not there holds nothing.
        assert!(secrets_left(&root.path().join("gone")).none());
        assert_eq!(on_disk_in(&root.path().join("gone")), "none");
        // With a note, an unlistable folder keeps the destroy unfinished and the note in place.
        let folder = root.path().join("vault");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join(DESTROYING), b"").unwrap();
        std::fs::write(folder.join("contents.age"), b"secret").unwrap();
        assert_eq!(on_disk_in(&folder), "partial");
        assert!(unfinished_in(&folder) && folder.join(DESTROYING).exists());
        std::fs::remove_file(folder.join("contents.age")).unwrap();
        assert_eq!(on_disk_in(&folder), "none");
    }
    #[test]
    fn a_key_is_minted_only_where_none_can_be_and_never_over_one_that_could_not_be_checked() {
        let root = tempfile::tempdir().unwrap();
        let (key, data) = (root.path().join(KEY_FILE), root.path().join("contents.age"));
        // Nothing there: creating mints, anything else is refused.
        assert_eq!(key_step(&key, &data, true), Ok(KeyStep::Mint));
        assert_eq!(key_step(&key, &data, false).unwrap_err(), "Create your Personal Vault first");
        // Data without its key is never given a new one.
        std::fs::write(&data, b"sealed").unwrap();
        assert!(key_step(&key, &data, true).unwrap_err().contains("left untouched"));
        // A key that is there is read.
        std::fs::write(&key, b"key").unwrap();
        assert_eq!(key_step(&key, &data, true), Ok(KeyStep::Read));
        // A key file whose state cannot be determined is never minted over, and says why.
        let unknowable = root.path().join("key\0.dpapi");
        let refused = key_step(&unknowable, &data, true).unwrap_err();
        assert!(refused.starts_with("Personal Vault did not create a key") && refused.contains("unreadable for good"), "{refused}");
        // Nor beside data whose state cannot be determined.
        let fresh = root.path().join("fresh-key.dpapi");
        let refused = key_step(&fresh, &root.path().join("contents\0.age"), true).unwrap_err();
        assert!(refused.starts_with("Personal Vault did not create a key"), "{refused}");
        // Opening without creating says only that it could not check.
        assert!(key_step(&unknowable, &data, false).unwrap_err().starts_with("Personal Vault could not check"));
    }
    #[test]
    fn a_note_that_could_not_be_checked_never_says_to_delete_again() {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("vault");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join(KEY_FILE), b"key").unwrap();
        // No note: a vault. A note: a delete that began. Neither knowable: unknown, never partial.
        assert_eq!(on_disk_in(&folder), "vault");
        assert!(!unfinished_in(&folder));
        std::fs::write(folder.join(DESTROYING), b"").unwrap();
        assert_eq!(on_disk_in(&folder), "partial");
        assert!(unfinished_in(&folder));
        // Here the folder name itself cannot be looked up, so neither can the note in it.
        let unknowable = root.path().join("vault\0");
        assert_ne!(on_disk_in(&unknowable), "partial");
        assert!(!unfinished_in(&unknowable), "an unknowable note is never \"deleting did not finish\"");
    }
    #[test]
    fn every_loader_refuses_a_file_it_could_not_check() {
        // One path no system can look up stands in for a file whose state cannot be determined.
        // Each place that would create, mint or start empty on "absent" refuses it instead.
        let root = tempfile::tempdir().unwrap();
        let unknowable = root.path().join("unknowable\0");
        assert!(present(&unknowable).is_err());
        assert!(key_step(&unknowable, &root.path().join("contents.age"), true).is_err(), "the vault key");
        assert!(key_step(&root.path().join("fresh"), &unknowable, true).is_err(), "the vault data");
        assert!(begin_destroy_at(&unknowable).is_err(), "the vault folder, before a delete");
        assert!(atomic_write(&unknowable, b"x").is_err(), "any protected write over it");
    }
    #[test]
    fn a_vault_folder_that_could_not_be_checked_is_never_reported_deleted() {
        let root = tempfile::tempdir().unwrap();
        // No folder at all: nothing to delete.
        assert_eq!(begin_destroy_at(&root.path().join("never-made")), Ok(None));
        // A folder whose state cannot be determined: nothing was deleted, and it says so.
        let refused = begin_destroy_at(&root.path().join("vault\0")).unwrap_err();
        assert!(matches!(&refused, Unfinished::NotStarted(reason) if reason.contains("could not check")), "{refused:?}");
    }
    #[test]
    fn only_a_file_certainly_absent_reads_as_missing() {
        let root = tempfile::tempdir().unwrap();
        let there = root.path().join(KEY_FILE);
        std::fs::write(&there, b"key").unwrap();
        assert_eq!(present(&there), Ok(true));
        assert_eq!(present(&root.path().join("contents.age")), Ok(false));
        // A path whose state cannot be determined, here one the system cannot even look up, is
        // an error rather than "missing", so no key is minted and no data started empty over it.
        let unknowable = root.path().join("contents\0.age");
        let error = present(&unknowable).unwrap_err();
        assert!(error.contains("could not check") && error.contains("changed nothing"), "{error}");
        // The same path read by `gone` is not gone either.
        assert!(!gone(&unknowable));
    }
    #[test]
    fn a_note_left_without_secrets_is_finished_not_a_trap() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(DESTROYING), b"").unwrap();
        // Every secret went: the note goes, and nothing reads as unfinished.
        assert!(!unfinished_in(root.path()));
        assert!(!root.path().join(DESTROYING).exists());
    }
    #[test]
    fn a_wiped_file_holds_none_of_its_bytes_before_it_goes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(KEY_FILE);
        std::fs::write(&path, b"AGE-SECRET-KEY-1-not-a-real-key".repeat(4000)).unwrap();
        overwrite(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        let mut file = std::fs::File::open(&path).unwrap();
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }
    #[test]
    fn only_creating_the_vault_mints_a_key() {
        // A connection or tool call before setup, or after a destroy, is refused.
        assert_eq!(new_key(false, false).unwrap_err(), "Create your Personal Vault first");
        // First-time setup: creating mints the key, and the connection after it finds that key.
        assert!(new_key(false, true).is_ok());
        // Data without its key is never replaced, not even by creating.
        assert!(new_key(true, true).unwrap_err().contains("left untouched"));
        assert!(new_key(true, false).unwrap_err().contains("left untouched"));
    }
    #[test]
    fn metadata_never_serializes_values() {
        let item = Item {
            id: "id".into(),
            label: "account".into(),
            kind: "api_key".into(),
            resource: "".into(),
            value: "super-secret".into(),
        };
        assert!(!item.summary().to_string().contains("super-secret"));
    }
    #[test]
    fn personal_item_names_custom_fields_and_credentials_stay_distinct() {
        let mut contents = Contents::default();
        let id = uuid::Uuid::new_v4().to_string();
        let item = Item {
            id: id.clone(),
            label: "openSourceName".into(),
            kind: "personal".into(),
            resource: String::new(),
            value: r#"{"openSourceName":"fixture-profile"}"#.into(),
        };
        assert!(item.validate().is_ok());
        contents.items.insert(id.clone(), item);
        assert_eq!(contents.resolve_item("openSourceName").unwrap().id, id);
        let item = contents.resolve_item(&id).unwrap();
        assert!(item
            .validate_personal_fields(&["openSourceName".into()])
            .is_ok());
        let error = item
            .validate_personal_fields(&["open_source_name".into()])
            .unwrap_err();
        assert!(error.contains("View items"));
        assert!(!error.contains("fixture-profile"));
        assert!(contents.resolve_item("missing").is_err());
        assert!(contents.resolve_item("opensourcename").is_err());
        let other = uuid::Uuid::new_v4().to_string();
        contents.items.insert(
            other.clone(),
            Item {
                id: other.clone(),
                label: "openSourceName".into(),
                kind: "api_key".into(),
                resource: String::new(),
                value: "never-disclose".into(),
            },
        );
        assert!(contents
            .resolve_item("openSourceName")
            .err()
            .unwrap()
            .contains("Several items"));
        assert!(contents.resolve_item(&id).is_ok());
        let error = contents
            .resolve_item(&other)
            .unwrap()
            .validate_personal_fields(&["openSourceName".into()])
            .unwrap_err();
        assert!(error.contains("credential"));
        assert!(!error.contains("never-disclose"));
    }
    #[test]
    fn credentials_cannot_use_the_personal_information_tool() {
        for value in [
            r#"{"api_key":"secret"}"#,
            r#"{"name":"-----BEGIN PRIVATE KEY-----"}"#,
            r#"{"password":"secret"}"#,
        ] {
            let item = Item {
                id: "id".into(),
                label: "Personal".into(),
                kind: "personal".into(),
                resource: "".into(),
                value: value.into(),
            };
            assert!(item.validate().is_err());
        }
        let item = Item {
            id: "id".into(),
            label: "Personal".into(),
            kind: "personal".into(),
            resource: "".into(),
            value: r#"{"email":"person@example.com","name":"Person"}"#.into(),
        };
        assert!(item.validate().is_ok());
        assert!(!item.is_credential());
        for kind in [
            "api_key",
            "password",
            "token",
            "private_key",
            "credential",
            "cloudflare",
        ] {
            let item = Item {
                id: "id".into(),
                label: "OpenSourceName".into(),
                kind: kind.into(),
                resource: String::new(),
                value: "fixture-credential".into(),
            };
            assert!(item.is_credential());
            assert!(item
                .validate_personal_fields(&["value".into()])
                .unwrap_err()
                .contains("read_credential"));
            assert!(!item.summary().to_string().contains("fixture-credential"));
        }
    }
}
