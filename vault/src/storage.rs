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
pub(crate) struct Store {
    root: PathBuf,
    key: age::x25519::Identity,
    pub contents: Contents,
}
impl Store {
    pub fn open() -> Result<Self, String> {
        let root = platform::data_directory()?;
        platform::verify_protected(root.parent().unwrap(), false)?;
        platform::verify_protected(&root, false)?;
        let key_path = root.join("key.dpapi");
        let key = if key_path.exists() {
            platform::verify_protected(&key_path, false)?;
            let bytes = bounded_read(&key_path, 16384)?;
            let decrypted = dpapi(&bytes, false)?;
            std::str::from_utf8(&decrypted)
                .map_err(|_| "Invalid vault key")?
                .parse::<age::x25519::Identity>()
                .map_err(|_| "Invalid vault key")?
        } else {
            if root.join("contents.age").exists() {
                return Err(
                    "The vault key is missing. Existing vault data was left untouched.".into(),
                );
            }
            let identity = age::x25519::Identity::generate();
            let text = identity.to_string();
            atomic_write(&key_path, &dpapi(text.expose_secret().as_bytes(), true)?)?;
            identity
        };
        let path = root.join("contents.age");
        let contents = if path.exists() {
            serde_json::from_slice(&decrypt(&key, &bounded_read(&path, DATA_LIMIT)?)?)
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
    if path.exists() {
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
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    platform::verify_protected(path.parent().unwrap(), false)?;
    if path.exists() {
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
