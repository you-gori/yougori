//! Windows secure-VM profile. Persistent identities are never silently reset.
//! TPM commands run in QEMU's private native library, not over a host TCP port.
use super::{command_output, path_string, RuntimeLayout};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub(super) const PROFILE: &str = "vm-security.json";
const MAX_VARS: usize = 1024 * 1024;
const NV_SIZE: usize = 2 * (64 + 16384);
pub(super) const MAX_BACKUP: usize = 2 * 1024 * 1024;
const BACKUP_EXTENSION: u32 = 0x4f445343; // ODSC; unknown QCOW2 extensions are preserved/ignored by readers.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Profile {
    version: u32,
    generation: String,
    firmware_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Backup {
    version: u32,
    firmware_sha256: String,
    nv: String,
    variables: String,
}

pub(super) fn read_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Read VM security state: {e}"))?;
    if !meta.is_file() || redirected(&meta) || meta.len() > maximum as u64 {
        return Err("VM security state is not a bounded regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    // Inspect the opened descriptor as well as the path; do not follow a
    // substituted link between metadata validation and the actual read.
    let file = options.open(path).map_err(|e| format!("Read VM security state: {e}"))?;
    let opened = file.metadata().map_err(|e| format!("Inspect VM security state: {e}"))?;
    if !opened.is_file() || redirected(&opened) || opened.len() > maximum as u64 {
        return Err("VM security state is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)
        .map_err(|e| format!("Read VM security state: {e}"))?;
    if bytes.len() > maximum {
        return Err("VM security state exceeds its limit".into());
    }
    Ok(bytes)
}

fn redirected(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() { return true; }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        return meta.file_attributes() & 0x400 != 0;
    }
    #[cfg(not(windows))]
    false
}

fn create_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = super::boot_token::create_private(path)
        .map_err(|e| format!("Create VM security state: {e}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Save VM security state: {e}"))
}

pub(super) fn profile(directory: &Path) -> Result<Option<Profile>, String> {
    match fs::symlink_metadata(directory.join(PROFILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let result: Profile = serde_json::from_slice(&read_regular(&directory.join(PROFILE), 4096)?)
        .map_err(|e| format!("Invalid VM security profile: {e}"))?;
    if result.version != 1
        || uuid::Uuid::parse_str(&result.generation).is_err()
        || result.generation.len() != 36
        || !valid_hash(&result.firmware_sha256)
    {
        return Err("Unsupported VM security profile; its identity was preserved".into());
    }
    Ok(Some(result))
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Profile {
    /// Firmware updates must not silently change an existing TPM measured-boot
    /// profile. Retained images are content-addressed and verified on use.
    pub(super) fn firmware(&self, root: &Path) -> Result<PathBuf, String> {
        if !valid_hash(&self.firmware_sha256) {
            return Err("Invalid VM firmware fingerprint".into());
        }
        for candidate in [
            root.join("OVMF.qemuvars.fd"),
            root.join("firmware").join(format!("{}.fd", self.firmware_sha256)),
        ] {
            if !candidate.exists() {
                continue;
            }
            let digest = hex::encode(Sha256::digest(read_regular(
                &candidate, 8 * 1024 * 1024,
            )?));
            if digest.eq_ignore_ascii_case(&self.firmware_sha256) {
                return Ok(candidate);
            }
        }
        Err("The secure VM requires its original firmware version. Its TPM identity was preserved; restore the matching runtime before starting it.".into())
    }

    pub(super) fn directory(&self, parent: &Path) -> Result<PathBuf, String> {
        if self.version != 1
            || self.generation.len() != 36
            || uuid::Uuid::parse_str(&self.generation).is_err()
        {
            return Err("Invalid VM security generation".into());
        }
        let path = parent.join(format!("security-{}", self.generation));
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Missing VM security identity: {e}"))?;
        if !meta.is_dir()
            || redirected(&meta)
            || fs::canonicalize(&path).map_err(|e| e.to_string())?.parent()
                != Some(
                    fs::canonicalize(parent)
                        .map_err(|e| e.to_string())?
                        .as_path(),
                )
        {
            return Err("VM security identity must stay inside its environment".into());
        }
        Ok(path)
    }
}

/// Official Windows 10/11 x64 media share this volume identifier. Original
/// filenames are also used during provisioning. Unknown/custom media retain
/// the existing compatible firmware; this is an OS hint, not a trust decision.
pub(super) fn modern_windows_media(source: &Path) -> bool {
    if !source
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("iso"))
    {
        return false;
    }
    let name = source
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace([' ', '_', '-'], "");
    if ["win11", "windows11", "win10", "windows10"]
        .iter()
        .any(|s| name.starts_with(s))
    {
        return true;
    }
    let mut bytes = Vec::new();
    if File::open(source)
        .and_then(|file| file.take(2 * 1024 * 1024).read_to_end(&mut bytes))
        .is_err()
    {
        return false;
    }
    bytes
        .windows(b"CCCOMA_X64FRE".len())
        .any(|s| s == b"CCCOMA_X64FRE")
}

fn validate_nv(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != NV_SIZE {
        return Err(
            "The VM's TPM state is incomplete; refusing to create a different identity".into(),
        );
    }
    let valid = bytes.chunks_exact(NV_SIZE / 2).any(|slot| {
        &slot[..8] == b"ODTPM001"
            && u64::from_le_bytes(slot[8..16].try_into().unwrap()) != 0
            && u64::from_le_bytes(slot[16..24].try_into().unwrap()) == 16384
            && slot[24..32] == [0; 8]
            && {
                let mut hash = Sha256::new();
                hash.update(&slot[..32]);
                hash.update(&slot[64..]);
                hash.finalize().as_slice() == &slot[32..64]
            }
    });
    if valid {
        Ok(())
    } else {
        Err(
            "The VM's TPM state is corrupt; restore a complete backup instead of resetting it"
                .into(),
        )
    }
}

fn validate_vars(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_VARS {
        return Err("VM firmware state exceeds its limit".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid VM firmware state: {e}"))?;
    if !matches!(value["version"].as_u64(), Some(2)) {
        return Err("Unsupported VM firmware variable format".into());
    }
    let vars = value["variables"]
        .as_array()
        .ok_or("Missing VM firmware variables")?;
    let mut names = std::collections::HashSet::new();
    let mut total = 0_usize;
    for var in vars {
        let name = var["name"]
            .as_str()
            .ok_or("Invalid firmware variable name")?;
        let guid = var["guid"]
            .as_str()
            .ok_or("Invalid firmware variable GUID")?;
        let data = var["data"]
            .as_str()
            .ok_or("Invalid firmware variable data")?;
        if name.len() > 1024
            || !name.is_ascii()
            || name.contains('\0')
            || uuid::Uuid::parse_str(guid).is_err()
            || !names.insert((guid.to_ascii_lowercase(), name))
            || data.len() % 2 != 0
            || !data.bytes().all(|b| b.is_ascii_hexdigit())
            || !var["attr"].as_u64().is_some_and(|n| n <= u32::MAX as u64)
        {
            return Err("Invalid or duplicate VM firmware variable".into());
        }
        total += data.len() / 2 + name.len() * 2 + 64;
    }
    if total > 256 * 1024 {
        return Err("VM firmware variable capacity exceeded".into());
    }
    for required in ["PK", "KEK", "db", "dbx"] {
        let guid = if matches!(required, "PK" | "KEK") {
            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        } else {
            "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        };
        if !vars.iter().any(|var| {
            var["name"] == required
                && var["guid"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(guid))
                && var["data"].as_str().is_some_and(|s| !s.is_empty())
        }) {
            return Err(format!(
                "Secure Boot state is missing {required}; refusing an insecure fallback"
            ));
        }
    }
    Ok(())
}

/// Only carry forward boot options when enabling security on an older VM.
/// Never import its old unsigned key database or SetupMode policy.
fn migrate_boot_options(vars: &mut serde_json::Value, flash: &[u8]) {
    const AUTH_STORE: [u8; 16] = [
        0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77,
        0x92,
    ];
    let Some(start) = flash.windows(16).position(|s| s == AUTH_STORE) else {
        return;
    };
    let Some(header) = flash.get(start..start + 28) else {
        return;
    };
    let size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let Some(store) = flash.get(start..start.saturating_add(size)) else {
        return;
    };
    let Some(list) = vars["variables"].as_array_mut() else {
        return;
    };
    let mut offset = 28_usize;
    while let Some(entry) = store.get(offset..offset.saturating_add(60)) {
        if entry[..2] != [0xaa, 0x55] {
            break;
        }
        let name_size = u32::from_le_bytes(entry[36..40].try_into().unwrap()) as usize;
        let data_size = u32::from_le_bytes(entry[40..44].try_into().unwrap()) as usize;
        if name_size > 2048 || name_size % 2 != 0 || data_size > 65536 {
            break;
        }
        let data_at = (offset + 60 + name_size).div_ceil(4) * 4;
        let Some(name) = store.get(offset + 60..offset + 60 + name_size) else {
            break;
        };
        let Some(data) = store.get(data_at..data_at + data_size) else {
            break;
        };
        let name = String::from_utf16_lossy(
            &name
                .chunks_exact(2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]))
                .collect::<Vec<_>>(),
        );
        let name = name.trim_end_matches('\0');
        const GLOBAL: [u8; 16] = [
            0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03,
            0x2b, 0x8c,
        ];
        if entry[2] == 0x3f
            && entry[44..60] == GLOBAL
            && (name == "BootOrder"
                || (name.len() == 8
                    && name.starts_with("Boot")
                    && name[4..].bytes().all(|b| b.is_ascii_hexdigit())))
        {
            list.retain(|v| v["name"] != name);
            list.push(serde_json::json!({"name":name,"guid":"8be4df61-93ca-11d2-aa0d-00e098032b8c","attr":7,"data":hex::encode(data)}));
        }
        offset = (data_at + data_size).div_ceil(4) * 4;
    }
}

pub(super) async fn activate(directory: &Path, new: Option<&Profile>) -> Result<(), String> {
    if let Some(new) = new {
        new.directory(directory)?;
        super::vm::write_durable_file(
            directory.join(PROFILE),
            serde_json::to_vec(new).map_err(|e| e.to_string())?,
        )
        .await
    } else {
        if profile(directory)?.is_some() {
            fs::remove_file(directory.join(PROFILE)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

fn new_generation(directory: &Path, digest: String) -> Result<(Profile, PathBuf), String> {
    let profile = Profile {
        version: 1,
        generation: uuid::Uuid::new_v4().to_string(),
        firmware_sha256: digest,
    };
    let target = directory.join(format!("security-{}", profile.generation));
    fs::create_dir(&target).map_err(|e| format!("Create private VM security directory: {e}"))?;
    Ok((profile, target))
}

pub(super) async fn prepare(
    layout: &RuntimeLayout,
    directory: &Path,
    source: &Path,
) -> Result<(), String> {
    prepare_required(layout, directory, source, false).await
}

pub(super) async fn prepare_required(layout: &RuntimeLayout, directory: &Path, source: &Path, require_secure: bool) -> Result<(), String> {
    let current = profile(directory)?;
    if current.is_none() && !require_secure && !modern_windows_media(source) {
        return Ok(());
    }
    if !cfg!(target_os = "windows") {
        return Err("Windows 10/11 secure VMs are not supported by this macOS/Linux package yet. Their TPM/Secure Boot runtime is Windows-only. Use a Linux guest, or run this VM in Yougori on Windows; no insecure fallback or identity reset was attempted.".into());
    }
    let root = layout.root.join("qemu-secure");
    for file in [
        "qemu-system-x86_64.exe",
        "opendock-tpm.dll",
        "opendock-tpm-init.exe",
        "opendock-tpm-worker.exe",
        "OVMF.qemuvars.fd",
        "secure-vars.json",
    ] {
        if !root.join(file).is_file() {
            return Err("Windows VM security runtime is missing. Build it with scripts/build-secure-runtime.ps1 before starting Windows Setup.".into());
        }
    }
    let digest = hex::encode(Sha256::digest(read_regular(
        &root.join("OVMF.qemuvars.fd"),
        8 * 1024 * 1024,
    )?));
    if let Some(current) = current {
        current.firmware(&root)?;
        capture(directory)?.ok_or("Missing VM security state")?;
        return Ok(());
    }
    let (new, target) = new_generation(directory, digest)?;
    let mut vars: serde_json::Value =
        serde_json::from_slice(&read_regular(&root.join("secure-vars.json"), MAX_VARS)?)
            .map_err(|e| e.to_string())?;
    let legacy = directory.join("uefi-vars.fd");
    if legacy.exists() {
        migrate_boot_options(&mut vars, &read_regular(&legacy, 2 * 1024 * 1024)?);
    }
    let vars = serde_json::to_vec(&vars).map_err(|e| e.to_string())?;
    validate_vars(&vars)?;
    create_file(&target.join("uefi-vars.json"), &vars)?;
    command_output(
        &root.join("opendock-tpm-init.exe"),
        &[path_string(&target.join("tpm.nv"))],
        "create private TPM 2.0 identity",
    )
    .await?;
    validate_nv(&read_regular(&target.join("tpm.nv"), NV_SIZE)?)?;
    // The record is published only after every component is durable. No VM has
    // seen a half-created identity, and old pflash/disk files remain untouched.
    activate(directory, Some(&new)).await
}

pub(super) fn capture(directory: &Path) -> Result<Option<Backup>, String> {
    let Some(profile) = profile(directory)? else {
        return Ok(None);
    };
    let generation = profile.directory(directory)?;
    let nv = read_regular(&generation.join("tpm.nv"), NV_SIZE)?;
    let variables = read_regular(&generation.join("uefi-vars.json"), MAX_VARS)?;
    validate_nv(&nv)?;
    validate_vars(&variables)?;
    Ok(Some(Backup {
        version: 1,
        firmware_sha256: profile.firmware_sha256,
        nv: STANDARD.encode(nv),
        variables: STANDARD.encode(variables),
    }))
}

impl Backup {
    pub(super) fn validate(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        if self.version != 1
            || !valid_hash(&self.firmware_sha256)
            || self.nv.len() > NV_SIZE * 2
            || self.variables.len() > MAX_VARS * 2
        {
            return Err("Unsupported or oversized VM security backup".into());
        }
        let nv = STANDARD.decode(&self.nv).map_err(|e| e.to_string())?;
        let vars = STANDARD
            .decode(&self.variables)
            .map_err(|e| e.to_string())?;
        validate_nv(&nv)?;
        validate_vars(&vars)?;
        Ok((nv, vars))
    }
    pub(super) fn stage(&self, directory: &Path) -> Result<Profile, String> {
        let (nv, vars) = self.validate()?;
        let (profile, target) = new_generation(directory, self.firmware_sha256.clone())?;
        create_file(&target.join("tpm.nv"), &nv)?;
        create_file(&target.join("uefi-vars.json"), &vars)?;
        Ok(profile)
    }
}

// Portable backups remain standalone QCOW2 images. Security state is carried
// in a bounded header extension, and extracted BEFORE qemu-img conversion
// (which intentionally does not copy unknown extensions). Never edit a live
// disk header: embed_backup is only used on freshly converted backup files.
fn extensions(path: &Path) -> Result<(Vec<u8>, usize, Option<Backup>), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut header = [0_u8; 104];
    file.read_exact(&mut header)
        .map_err(|e| format!("Read backup header: {e}"))?;
    let word = |at| u32::from_be_bytes(header[at..at + 4].try_into().unwrap());
    if &header[..4] != b"QFI\xfb" || !matches!(word(4), 2 | 3) || !(9..=21).contains(&word(20)) {
        return Err("VM backup is not a supported QCOW2 image".into());
    }
    let cluster = 1_usize << word(20);
    let mut offset = if word(4) == 2 { 72 } else { word(100) as usize };
    if offset < (if word(4) == 2 { 72 } else { 104 }) || offset % 8 != 0 || offset > cluster - 8 {
        return Err("Invalid QCOW2 extension area".into());
    }
    let backing = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let end = if backing == 0 {
        cluster
    } else {
        usize::try_from(backing)
            .ok()
            .filter(|n| *n >= offset && *n <= cluster)
            .ok_or("Invalid QCOW2 backing offset")?
    };
    let mut bytes = vec![0_u8; end];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    let mut found = None;
    loop {
        let entry = bytes
            .get(offset..offset.saturating_add(8))
            .ok_or("Unterminated QCOW2 extensions")?;
        let kind = u32::from_be_bytes(entry[..4].try_into().unwrap());
        let size = u32::from_be_bytes(entry[4..].try_into().unwrap()) as usize;
        if kind == 0 {
            if size != 0 {
                return Err("Invalid QCOW2 extension terminator".into());
            }
            return Ok((bytes, offset, found));
        }
        if size > MAX_BACKUP {
            return Err("Oversized QCOW2 extension".into());
        }
        let data = bytes
            .get(offset + 8..offset + 8 + size)
            .ok_or("Truncated QCOW2 extension")?;
        if kind == BACKUP_EXTENSION {
            if found.is_some()
                || backing != 0
                || (word(4) == 3 && u64::from_be_bytes(header[72..80].try_into().unwrap()) & 4 != 0)
            {
                return Err(
                    "Secure backups must contain exactly one identity and a standalone disk".into(),
                );
            }
            let backup: Backup = serde_json::from_slice(data)
                .map_err(|e| format!("Invalid VM security backup: {e}"))?;
            backup.validate()?;
            found = Some(backup);
        }
        offset += 8 + size.div_ceil(8) * 8;
    }
}

pub(super) fn read_backup(path: &Path) -> Result<Option<Backup>, String> {
    extensions(path).map(|(_, _, backup)| backup)
}

pub(super) fn embed_backup(path: &Path, backup: &Backup) -> Result<(), String> {
    backup.validate()?;
    let (header, offset, previous) = extensions(path)?;
    let data = serde_json::to_vec(backup).map_err(|e| e.to_string())?;
    let length = 8 + data.len().div_ceil(8) * 8 + 8;
    if previous.is_some()
        || header[8..20] != [0; 12]
        || data.len() > MAX_BACKUP
        || offset + length > header.len()
        || header[offset..offset + length].iter().any(|n| *n != 0)
    {
        return Err("Backup header has no safe space for its TPM identity".into());
    }
    let mut entry = vec![0_u8; length];
    entry[..4].copy_from_slice(&BACKUP_EXTENSION.to_be_bytes());
    entry[4..8].copy_from_slice(&(data.len() as u32).to_be_bytes());
    entry[8..8 + data.len()].copy_from_slice(&data);
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(offset as u64))
        .and_then(|_| file.write_all(&entry))
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firmware_updates_preserve_pinned_images_and_reject_mismatches() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let old = b"old firmware";
        let pinned = Profile { version: 1, generation: uuid::Uuid::new_v4().to_string(), firmware_sha256: hex::encode(Sha256::digest(old)) };
        fs::write(root.join("OVMF.qemuvars.fd"), old).unwrap();
        assert_eq!(pinned.firmware(root).unwrap(), root.join("OVMF.qemuvars.fd"));
        fs::write(root.join("OVMF.qemuvars.fd"), b"updated firmware").unwrap();
        assert!(pinned.firmware(root).is_err());
        fs::create_dir(root.join("firmware")).unwrap();
        let retained = root.join("firmware").join(format!("{}.fd", pinned.firmware_sha256));
        fs::write(&retained, old).unwrap();
        assert_eq!(pinned.firmware(root).unwrap(), retained);
        fs::write(&retained, b"tampered").unwrap();
        assert!(pinned.firmware(root).is_err());
    }

    #[test]
    fn security_profiles_reject_path_traversal_and_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let malicious = Profile {
            version: 1,
            generation: "../outside".into(),
            firmware_sha256: "a".repeat(64),
        };
        assert!(malicious.directory(temp.path()).is_err());
        assert!(validate_nv(&vec![0; NV_SIZE]).is_err());
        assert!(validate_nv(&[]).is_err());
        assert!(validate_vars(br#"{"version":2,"variables":[]}"#).is_err());
        assert!(!modern_windows_media(Path::new("alpine.iso")));
        assert!(!modern_windows_media(Path::new("Win7.iso")));
        assert!(modern_windows_media(Path::new("Win11_25H2_x64.iso")));
    }
    #[test]
    fn boot_migration_is_bounded() {
        let mut vars = serde_json::json!({"version":2,"variables":[]});
        for size in [0, 15, 60, 128, 1024] {
            migrate_boot_options(&mut vars, &vec![0; size]);
        }
        assert_eq!(vars["variables"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn backup_headers_are_bounded_and_reject_truncation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.qcow2");
        let mut data = vec![0_u8; 65536];
        data[..4].copy_from_slice(b"QFI\xfb");
        data[4..8].copy_from_slice(&3_u32.to_be_bytes());
        data[20..24].copy_from_slice(&16_u32.to_be_bytes());
        data[100..104].copy_from_slice(&104_u32.to_be_bytes());
        fs::write(&path, &data).unwrap();
        assert!(read_backup(&path).unwrap().is_none());
        data[104..108].copy_from_slice(&BACKUP_EXTENSION.to_be_bytes());
        data[108..112].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(&path, &data).unwrap();
        assert!(read_backup(&path).is_err());
        for length in [0, 8, 103, 112] {
            fs::write(&path, &data[..length]).unwrap();
            assert!(read_backup(&path).is_err());
        }
    }

    #[tokio::test]
    #[ignore = "requires bundled native secure runtime; uses only disposable disks and identities"]
    async fn secure_vm_backups_preserve_identity_and_roll_back() {
        let temp = tempfile::tempdir().unwrap();
        let manager =
            super::super::RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())
                .unwrap();
        let source = temp.path().join("source.qcow2");
        command_output(
            &manager.layout.qemu_img,
            &[
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                path_string(&source),
                "64M".into(),
            ],
            "create disposable backup test disk",
        )
        .await
        .unwrap();
        let id = "env-security-backup-test";
        let disk = manager
            .provision_vm(id, source.to_str().unwrap())
            .await
            .unwrap();
        let directory = disk.disk_path.parent().unwrap();
        // OS hint only; this test does not boot or install an operating system.
        prepare(&manager.layout, directory, Path::new("Win11.iso"))
            .await
            .unwrap();
        let before_profile = profile(directory).unwrap().unwrap();
        let before = capture(directory).unwrap().unwrap();
        let exported = manager
            .export_vm_disk(id, &disk.disk_path, &source, "snap-security-test")
            .await
            .unwrap();
        let saved = read_backup(&exported.path).unwrap().unwrap();
        assert_eq!(before.validate().unwrap(), saved.validate().unwrap());
        assert!(manager
            .create_vm_snapshot(id, &disk.disk_path, "snap-disk-only")
            .await
            .unwrap_err()
            .contains("virtual TPM"));
        assert!(manager
            .install_vm_backup(id, &source)
            .await
            .unwrap_err()
            .contains("disk-only"));
        manager.install_vm_backup(id, &exported.path).await.unwrap();
        let new_profile = profile(directory).unwrap().unwrap();
        assert_ne!(before_profile.generation, new_profile.generation);
        assert_eq!(
            before.validate().unwrap(),
            capture(directory).unwrap().unwrap().validate().unwrap()
        );
        assert!(manager.has_pending_vm_backup_install(id).unwrap());
        manager.rollback_vm_backup_install(id).await.unwrap();
        assert_eq!(profile(directory).unwrap().unwrap(), before_profile);
        assert!(!manager.has_pending_vm_backup_install(id).unwrap());
        manager.install_vm_backup(id, &exported.path).await.unwrap();
        // Simulate interruption between disk activation and security activation.
        activate(directory, Some(&before_profile)).await.unwrap();
        manager.finalize_vm_backup_install(id).await.unwrap();
        assert_ne!(
            profile(directory).unwrap().unwrap().generation,
            before_profile.generation
        );
        assert_eq!(
            before.validate().unwrap(),
            capture(directory).unwrap().unwrap().validate().unwrap()
        );
        assert!(!manager.has_pending_vm_backup_install(id).unwrap());
        let restored = "env-security-restored";
        let restored_disk = manager
            .install_vm_backup(restored, &exported.path)
            .await
            .unwrap();
        manager.finalize_vm_backup_install(restored).await.unwrap();
        assert_eq!(
            before.validate().unwrap(),
            capture(restored_disk.parent().unwrap())
                .unwrap()
                .unwrap()
                .validate()
                .unwrap()
        );
        let mut invalid = saved.clone();
        invalid.nv = STANDARD.encode(vec![0; NV_SIZE]);
        assert!(invalid.stage(directory).is_err());
        assert!(embed_backup(&exported.path, &saved).is_err());
        // A missing TPM must never be silently remanufactured on the next start.
        let active = profile(directory)
            .unwrap()
            .unwrap()
            .directory(directory)
            .unwrap();
        fs::rename(active.join("tpm.nv"), active.join("preserved-test.nv")).unwrap();
        assert!(prepare(&manager.layout, directory, Path::new("Win11.iso"))
            .await
            .is_err());
        assert!(!active.join("tpm.nv").exists());
        manager.shutdown_all().await;
    }
}
