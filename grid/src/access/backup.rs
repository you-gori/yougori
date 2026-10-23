//! Moving or restoring an Access Grid: one file with the hub's record, its activity log and both
//! of its keys, encrypted with a passphrase (scrypt, then ChaCha20-Poly1305). The certificate
//! goes with it, so people's computers keep trusting the hub at its new address; they only need
//! the new invite. Without the passphrase the file is useless, and so is the passphrase alone.
use super::seal::Sealer;
use crate::password;
use serde_json::{json, Value};
use std::path::Path;

const FORMAT: &str = "yougori-access-backup";
const AAD: &str = "yougori-access-backup-v1";
const AAD_V2: &str = "yougori-access-backup-v2";

/// What a backup holds.
pub struct Contents {
    /// The hub's record as saved, with credentials still sealed with `seal_key`.
    pub record: Value,
    /// The activity log's lines.
    pub activity: String,
    pub tls_key: String,
    pub seal_key: String,
    pub created_at: i64,
}

impl std::fmt::Debug for Contents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contents").field("company", &self.record["company"]).field("created_at", &self.created_at).finish_non_exhaustive()
    }
}

/// The backup file's bytes for the hub at `record_path`. Slow on purpose (scrypt): run it on a
/// blocking thread.
pub fn create(record_path: &Path, tls_key: &str, seal_key: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    password::validate(passphrase).map_err(|_| format!("The backup passphrase must be {}–{} characters on one line; long passphrases are best", password::MIN_LENGTH, password::MAX_LENGTH))?;
    let record: Value = serde_json::from_slice(&std::fs::read(record_path).map_err(|error| format!("Cannot read the Access Grid's record: {error}"))?).map_err(|_| "The Access Grid's record is damaged")?;
    let activity = std::fs::read_to_string(super::hub::activity_path(record_path)).unwrap_or_default();
    let plain = json!({"record": record, "activity": activity, "tlsKey": tls_key, "sealKey": seal_key, "createdAt": crate::now()}).to_string();
    let salt = password::new_salt();
    // The file is the whole grid, so a thief can guess at it offline for as long as they like:
    // the key costs far more than a sign-in key.
    let key = password::derive_with(passphrase, &salt, password::OFFLINE_LOG_N)?;
    let sealed = Sealer::new(&key)?.seal(AAD_V2, &plain)?;
    let file = json!({"format": FORMAT, "v": 2, "company": record["company"], "createdAt": crate::now(), "kdf": {"name": "scrypt", "logN": password::OFFLINE_LOG_N, "r": 8, "p": 1}, "salt": salt, "sealed": sealed});
    serde_json::to_vec_pretty(&file).map_err(|error| error.to_string())
}

/// Opens a backup with its passphrase. Slow on purpose: run it on a blocking thread.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<Contents, String> {
    let file: Value = serde_json::from_slice(bytes).map_err(|_| "This is not an Access Grid backup")?;
    if file["format"] != FORMAT {
        return Err("This is not an Access Grid backup".into());
    }
    // Version 1 used the sign-in cost (N = 2^15); version 2 names its own, within what this
    // computer will spend on one attempt.
    let (log_n, aad) = match file["v"].as_u64() {
        Some(1) => (15, AAD),
        Some(2) => {
            let kdf = &file["kdf"];
            let log_n = kdf["logN"].as_u64().filter(|log_n| (15..=18).contains(log_n)).ok_or("The backup is damaged")?;
            if kdf["name"] != "scrypt" || kdf["r"] != 8 || kdf["p"] != 1 {
                return Err("The backup is damaged".into());
            }
            (log_n as u8, AAD_V2)
        }
        _ => return Err("This backup comes from a newer Yougori; update Yougori first".into()),
    };
    let salt = file["salt"].as_str().filter(|salt| !salt.is_empty() && salt.len() <= 128).ok_or("The backup is damaged")?;
    let key = password::derive_with(passphrase, salt, log_n)?;
    let plain = Sealer::new(&key)?.open(aad, file["sealed"].as_str().unwrap_or_default()).map_err(|_| "The passphrase is wrong, or the backup is damaged".to_owned())?;
    let inner: Value = serde_json::from_str(&plain).map_err(|_| "The backup is damaged")?;
    let text = |key: &str| inner[key].as_str().filter(|text| !text.is_empty()).map(str::to_owned).ok_or_else(|| "The backup is damaged".to_owned());
    if !inner["record"].is_object() {
        return Err("The backup is damaged".into());
    }
    Ok(Contents { record: inner["record"].clone(), activity: inner["activity"].as_str().unwrap_or_default().to_owned(), tls_key: text("tlsKey")?, seal_key: text("sealKey")?, created_at: inner["createdAt"].as_i64().unwrap_or_default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_opens_only_with_its_passphrase_and_holds_everything() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("access-hub.json");
        // Markers with a `-`, which neither a hex salt nor the base64 ciphertext can contain by chance.
        std::fs::write(&path, r#"{"company":"Acme","credentials":[{"sealed":"a-sealed-credential"}]}"#).unwrap();
        std::fs::write(super::super::hub::activity_path(&path), "{\"line\":1}\n").unwrap();
        let bytes = create(&path, "tls-key", "seal-key", "a long backup passphrase").unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Acme") && !text.contains("tls-key") && !text.contains("seal-key") && !text.contains("a-sealed-credential"), "{text}");
        let contents = open(&bytes, "a long backup passphrase").unwrap();
        assert_eq!((contents.tls_key.as_str(), contents.seal_key.as_str(), contents.record["company"].as_str()), ("tls-key", "seal-key", Some("Acme")));
        assert_eq!(contents.activity, "{\"line\":1}\n");
        assert!(open(&bytes, "the wrong passphrase!").unwrap_err().contains("wrong"));
        assert!(create(&path, "a", "b", "short").is_err());
        assert!(open(b"{}", "a long backup passphrase").is_err());
    }

    #[test]
    fn new_backups_use_a_slow_offline_key_and_older_backups_still_open() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("access-hub.json");
        std::fs::write(&path, r#"{"company":"Acme"}"#).unwrap();
        let bytes = create(&path, "tls-key", "seal-key", "a long backup passphrase").unwrap();
        let mut file: Value = serde_json::from_slice(&bytes).unwrap();
        // The file holds every credential and key, so it is guessed offline: 128 MiB per try, not 32.
        assert_eq!((file["v"].as_u64(), file["kdf"]["logN"].as_u64()), (Some(2), Some(17)), "{file}");
        assert!(open(&bytes, "a long backup passphrase").is_ok());
        // A file asking for an absurd cost is refused before any work.
        file["kdf"]["logN"] = json!(30);
        assert!(open(&serde_json::to_vec(&file).unwrap(), "a long backup passphrase").unwrap_err().contains("damaged"));

        // A backup made before: version 1, N = 2^15 and no kdf field.
        let plain = json!({"record": {"company": "Acme"}, "activity": "", "tlsKey": "tls-key", "sealKey": "seal-key", "createdAt": 1}).to_string();
        let salt = password::new_salt();
        let key = password::derive("a long backup passphrase", &salt).unwrap();
        let sealed = Sealer::new(&key).unwrap().seal(AAD, &plain).unwrap();
        let older = serde_json::to_vec(&json!({"format": FORMAT, "v": 1, "company": "Acme", "createdAt": 1, "salt": salt, "sealed": sealed})).unwrap();
        assert_eq!(open(&older, "a long backup passphrase").unwrap().seal_key, "seal-key");
    }
}
