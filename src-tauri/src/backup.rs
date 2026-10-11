use std::{
    io::Read as _,
    path::{Path as FilePath, PathBuf},
    str::FromStr,
    time::Duration,
};

use age::secrecy::ExposeSecret;
use object_store::{path::Path as ObjectPath, ObjectStore, ObjectStoreExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

use crate::models::{
    AddDestinationRequest, BackupDestination, BackupProvider, Connection, Environment, Snapshot,
};

const CREDENTIAL_SERVICE: &str = "com.yougori.desktop.backup";
const PREVIOUS_CREDENTIAL_SERVICE: &str = yougori_cli::legacy_names::BACKUP_CREDENTIAL_SERVICE;
const MASTER_KEY_ACCOUNT: &str = "device-encryption-key";
const CHUNK_SIZE: usize = 8 * 1024 * 1024;
const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;
const NANOSECONDS_PER_BYTE_AT_ONE_MEGABIT: u128 = 8_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCredentials {
    provider: BackupProvider,
    location: String,
    access_key: String,
    secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupChunk {
    plaintext_sha256: String,
    plaintext_size: u64,
    object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupManifest {
    version: u32,
    backup_id: String,
    created_at: String,
    environment: Environment,
    snapshot: Snapshot,
    connections: Vec<Connection>,
    artifact_name: String,
    artifact_size: u64,
    chunk_size: usize,
    compression: String,
    encryption: String,
    chunks: Vec<BackupChunk>,
}

pub struct BackupRestore {
    pub environment: Environment,
    pub snapshot: Snapshot,
    pub connections: Vec<Connection>,
    pub artifact_path: PathBuf,
}

pub struct BackupUpload {
    pub remote_object: String,
    pub checksum_sha256: String,
    pub transferred_bytes: u64,
    pub deduplicated_bytes: u64,
}

struct Remote {
    store: Box<dyn ObjectStore>,
    prefix: ObjectPath,
}

/// Caps the average encrypted payload rate across one backup upload.
///
/// Object stores accept complete payloads rather than an asynchronous byte
/// stream, so pacing happens immediately before each object is submitted. The
/// cumulative deadline counts compression and network time already spent, and
/// keeps the whole-upload average at or below the configured rate at object
/// boundaries. Providers can still transmit within one object in a burst. A
/// zero limit disables pacing.
struct UploadRateLimiter {
    limit_mbps: Option<u128>,
    started_at: Option<tokio::time::Instant>,
    accounted_bytes: u128,
}

impl UploadRateLimiter {
    fn new(limit_mbps: usize) -> Self {
        Self {
            limit_mbps: (limit_mbps != 0).then_some(limit_mbps as u128),
            started_at: None,
            accounted_bytes: 0,
        }
    }

    async fn throttle(&mut self, payload_bytes: usize) {
        if self.limit_mbps.is_none() || payload_bytes == 0 {
            return;
        }

        let now = tokio::time::Instant::now();
        let started_at = *self.started_at.get_or_insert(now);
        let delay = self.required_delay(payload_bytes, now.duration_since(started_at));
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    fn required_delay(&mut self, payload_bytes: usize, elapsed: Duration) -> Duration {
        let Some(limit_mbps) = self.limit_mbps else {
            return Duration::ZERO;
        };
        self.accounted_bytes = self.accounted_bytes.saturating_add(payload_bytes as u128);
        let target_nanoseconds = self
            .accounted_bytes
            .saturating_mul(NANOSECONDS_PER_BYTE_AT_ONE_MEGABIT)
            / limit_mbps;
        duration_from_nanoseconds(target_nanoseconds).saturating_sub(elapsed)
    }
}

fn duration_from_nanoseconds(nanoseconds: u128) -> Duration {
    let seconds = nanoseconds / NANOSECONDS_PER_SECOND;
    if seconds > u64::MAX as u128 {
        return Duration::MAX;
    }
    Duration::new(
        seconds as u64,
        (nanoseconds % NANOSECONDS_PER_SECOND) as u32,
    )
}

pub struct BackupManager {
    pub(crate) restore_root: PathBuf,
}

impl BackupManager {
    pub fn new(app_data_directory: &FilePath) -> Result<Self, String> {
        let restore_root = app_data_directory.join("backup-restore");
        std::fs::create_dir_all(&restore_root)
            .map_err(|error| format!("create backup restore directory: {error}"))?;
        Ok(Self { restore_root })
    }

    pub async fn verify_and_store(
        &self,
        id: &str,
        request: &AddDestinationRequest,
    ) -> Result<(), String> {
        let credentials = StoredCredentials {
            provider: request.provider.clone(),
            location: request.location.trim().to_owned(),
            access_key: request.access_key.clone(),
            secret_key: request.secret_key.clone(),
        };
        let remote = build_remote(&credentials)?;
        let identity = device_identity()?;
        let probe_plaintext = format!("Yougori storage verification {}", Uuid::new_v4());
        let probe_ciphertext = encrypt(&identity, probe_plaintext.as_bytes())?;
        let probe_name = format!("probes/{}.age", Uuid::new_v4());
        let probe_path = join_object_path(&remote.prefix, &probe_name)?;
        remote
            .store
            .put(&probe_path, probe_ciphertext.into())
            .await
            .map_err(|error| format!("write storage verification object: {error}"))?;
        let metadata = remote
            .store
            .head(&probe_path)
            .await
            .map_err(|error| format!("verify storage object: {error}"));
        let cleanup = remote.store.delete(&probe_path).await;
        metadata?;
        cleanup.map_err(|error| format!("remove storage verification object: {error}"))?;
        store_credentials(id, &credentials)
    }

    pub fn delete_credentials(&self, id: &str) -> Result<(), String> {
        for service in [CREDENTIAL_SERVICE, PREVIOUS_CREDENTIAL_SERVICE] {
            let entry = keyring::Entry::new(service, &format!("destination:{id}"))
                .map_err(|error| format!("open the operating system credential vault: {error}"))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(format!(
                    "remove credentials from the operating system vault: {error}"
                )),
            }
        }
        Ok(())
    }

    pub async fn delete_restore_artifact(&self, path: &FilePath) -> Result<(), String> {
        if !path.starts_with(&self.restore_root) || path == self.restore_root {
            return Ok(());
        }
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove restored backup artifact: {error}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload(
        &self,
        destination: &BackupDestination,
        backup_id: &str,
        snapshot: &Snapshot,
        environment: &Environment,
        connections: &[Connection],
        bandwidth_limit_mbps: usize,
        artifact_path: &FilePath,
    ) -> Result<BackupUpload, String> {
        if !artifact_path.is_file() {
            return Err(format!(
                "backup artifact is missing: {}",
                artifact_path.display()
            ));
        }
        let credentials = load_credentials(&destination.id)?;
        if credentials.provider != destination.provider
            || credentials.location != destination.location
        {
            return Err("stored credentials do not match this backup destination".into());
        }
        let remote = build_remote(&credentials)?;
        let identity = device_identity()?;
        let mut source = tokio::fs::File::open(artifact_path)
            .await
            .map_err(|error| format!("open backup artifact: {error}"))?;
        let mut chunks = Vec::new();
        let mut transferred_bytes = 0_u64;
        let mut deduplicated_bytes = 0_u64;
        let mut artifact_size = 0_u64;
        let mut rate_limiter = UploadRateLimiter::new(bandwidth_limit_mbps);
        let chunk_names = chunk_name_key(&identity);
        loop {
            let mut chunk = vec![0_u8; CHUNK_SIZE];
            let mut filled = 0;
            while filled < chunk.len() {
                let count = source
                    .read(&mut chunk[filled..])
                    .await
                    .map_err(|error| format!("read backup artifact: {error}"))?;
                if count == 0 {
                    break;
                }
                filled += count;
            }
            if filled == 0 {
                break;
            }
            chunk.truncate(filled);
            artifact_size = artifact_size.saturating_add(filled as u64);
            let plaintext_sha256 = hex::encode(Sha256::digest(&chunk));
            let object = chunk_object(&chunk_names, &plaintext_sha256);
            let object_path = join_object_path(&remote.prefix, &object)?;
            match remote.store.head(&object_path).await {
                Ok(_) => {
                    deduplicated_bytes = deduplicated_bytes.saturating_add(filled as u64);
                }
                Err(object_store::Error::NotFound { .. }) => {
                    let compressed = zstd::stream::encode_all(&chunk[..], 3)
                        .map_err(|error| format!("compress backup chunk: {error}"))?;
                    let ciphertext = encrypt(&identity, &compressed)?;
                    transferred_bytes = transferred_bytes.saturating_add(ciphertext.len() as u64);
                    rate_limiter.throttle(ciphertext.len()).await;
                    remote
                        .store
                        .put(&object_path, ciphertext.into())
                        .await
                        .map_err(|error| format!("upload encrypted backup chunk: {error}"))?;
                }
                Err(error) => return Err(format!("check remote backup chunk: {error}")),
            }
            chunks.push(BackupChunk {
                plaintext_sha256,
                plaintext_size: filled as u64,
                object,
            });
            if filled < CHUNK_SIZE {
                break;
            }
        }
        let artifact_name = artifact_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("environment.artifact")
            .to_owned();
        let manifest = BackupManifest {
            version: if environment.provider == Some(crate::models::RuntimeProviderKind::Qemu)
                && crate::runtime::backup_has_vm_security(artifact_path)? { 2 } else { 1 },
            backup_id: backup_id.to_owned(),
            created_at: chrono::Utc::now().to_rfc3339(),
            environment: environment.clone(),
            snapshot: snapshot.clone(),
            connections: connections.to_vec(),
            artifact_name,
            artifact_size,
            chunk_size: CHUNK_SIZE,
            compression: "zstd-3".into(),
            encryption: "age-x25519".into(),
            chunks,
        };
        let manifest_plaintext = serde_json::to_vec(&manifest)
            .map_err(|error| format!("serialize backup manifest: {error}"))?;
        let manifest_ciphertext = encrypt(&identity, &manifest_plaintext)?;
        let checksum_sha256 = hex::encode(Sha256::digest(&manifest_ciphertext));
        let remote_object = format!("manifests/{}/{}.manifest.age", environment.id, backup_id);
        let manifest_path = join_object_path(&remote.prefix, &remote_object)?;
        transferred_bytes = transferred_bytes.saturating_add(manifest_ciphertext.len() as u64);
        rate_limiter.throttle(manifest_ciphertext.len()).await;
        remote
            .store
            .put(&manifest_path, manifest_ciphertext.into())
            .await
            .map_err(|error| format!("upload encrypted backup manifest: {error}"))?;
        Ok(BackupUpload {
            remote_object: manifest_path.to_string(),
            checksum_sha256,
            transferred_bytes,
            deduplicated_bytes,
        })
    }

    pub async fn download(
        &self,
        destination: &BackupDestination,
        backup_id: &str,
        remote_object: &str,
        manifest_checksum: &str,
    ) -> Result<BackupRestore, String> {
        validate_identifier("backup", backup_id)?;
        let credentials = load_credentials(&destination.id)?;
        if credentials.provider != destination.provider
            || credentials.location != destination.location
        {
            return Err("stored credentials do not match this backup destination".into());
        }
        let remote = build_remote(&credentials)?;
        let manifest_path = ObjectPath::parse(remote_object)
            .map_err(|error| format!("invalid remote manifest path: {error}"))?;
        let manifest_root = join_object_path(&remote.prefix, "manifests")?;
        let manifest_root = format!("{}/", manifest_root.as_ref());
        if !manifest_path.as_ref().starts_with(&manifest_root) {
            return Err("backup manifest is outside the configured destination prefix".into());
        }
        let manifest_ciphertext = remote
            .store
            .get(&manifest_path)
            .await
            .map_err(|error| format!("download encrypted backup manifest: {error}"))?
            .bytes()
            .await
            .map_err(|error| format!("read encrypted backup manifest: {error}"))?;
        if manifest_ciphertext.len() > 16 * 1024 * 1024 {
            return Err("encrypted backup manifest exceeds the 16 MiB safety limit".into());
        }
        let actual_manifest_checksum = hex::encode(Sha256::digest(&manifest_ciphertext));
        if !actual_manifest_checksum.eq_ignore_ascii_case(manifest_checksum) {
            return Err("encrypted backup manifest checksum does not match backup history".into());
        }
        let identity = device_identity()?;
        let manifest_plaintext = decrypt(&identity, &manifest_ciphertext)?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_plaintext)
            .map_err(|error| format!("decode backup manifest: {error}"))?;
        validate_manifest(&manifest, backup_id)?;

        let extension = match manifest.environment.provider {
            Some(crate::models::RuntimeProviderKind::Qemu) => "vm.qcow2",
            _ => "oci.tar",
        };
        let artifact_path = self.restore_root.join(format!("{backup_id}.{extension}"));
        let temporary_path = self
            .restore_root
            .join(format!("{backup_id}.{extension}.part"));
        let _ = tokio::fs::remove_file(&temporary_path).await;
        let result = async {
            let mut output = tokio::fs::File::create(&temporary_path)
                .await
                .map_err(|error| format!("create restore artifact: {error}"))?;
            let mut reconstructed = 0_u64;
            for chunk in &manifest.chunks {
                if !chunk.object.starts_with("chunks/") || chunk.object.contains("..") {
                    return Err("backup manifest contains an unsafe chunk path".into());
                }
                let object_path = join_object_path(&remote.prefix, &chunk.object)?;
                let ciphertext = remote
                    .store
                    .get(&object_path)
                    .await
                    .map_err(|error| format!("download encrypted backup chunk: {error}"))?
                    .bytes()
                    .await
                    .map_err(|error| format!("read encrypted backup chunk: {error}"))?;
                if ciphertext.len() > CHUNK_SIZE * 2 {
                    return Err("encrypted backup chunk exceeds the safety limit".into());
                }
                let compressed = decrypt(&identity, &ciphertext)?;
                let plaintext = decompress_limited(&compressed, CHUNK_SIZE + 1)?;
                if plaintext.len() as u64 != chunk.plaintext_size
                    || plaintext.len() > CHUNK_SIZE
                {
                    return Err("backup chunk size does not match its manifest".into());
                }
                let checksum = hex::encode(Sha256::digest(&plaintext));
                if !checksum.eq_ignore_ascii_case(&chunk.plaintext_sha256) {
                    return Err("backup chunk failed plaintext integrity verification".into());
                }
                output
                    .write_all(&plaintext)
                    .await
                    .map_err(|error| format!("write restored backup artifact: {error}"))?;
                reconstructed = reconstructed.saturating_add(plaintext.len() as u64);
            }
            if reconstructed != manifest.artifact_size {
                return Err(format!(
                    "restored artifact is incomplete: expected {} bytes, reconstructed {reconstructed}",
                    manifest.artifact_size
                ));
            }
            output
                .sync_all()
                .await
                .map_err(|error| format!("flush restored backup artifact: {error}"))?;
            drop(output);
            if manifest.version == 2 && (manifest.environment.provider != Some(crate::models::RuntimeProviderKind::Qemu)
                || !crate::runtime::backup_has_vm_security(&temporary_path)?) {
                return Err("Secure VM backup is missing its TPM and firmware identity".into());
            }
            let _ = tokio::fs::remove_file(&artifact_path).await;
            tokio::fs::rename(&temporary_path, &artifact_path)
                .await
                .map_err(|error| format!("finalize restored backup artifact: {error}"))?;
            Ok(BackupRestore {
                environment: manifest.environment,
                snapshot: manifest.snapshot,
                connections: manifest.connections,
                artifact_path,
            })
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary_path).await;
        }
        result
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("invalid {label} identifier"));
    }
    Ok(())
}

fn validate_manifest(manifest: &BackupManifest, backup_id: &str) -> Result<(), String> {
    if !matches!(manifest.version, 1 | 2) {
        return Err(format!(
            "unsupported backup manifest version {}",
            manifest.version
        ));
    }
    if manifest.backup_id != backup_id {
        return Err("backup manifest identifier does not match backup history".into());
    }
    if manifest.compression != "zstd-3" || manifest.encryption != "age-x25519" {
        return Err("backup manifest uses an unsupported codec".into());
    }
    if manifest.chunk_size != CHUNK_SIZE {
        return Err("backup manifest uses an unsupported chunk size".into());
    }
    let declared_size = manifest
        .chunks
        .iter()
        .try_fold(0_u64, |total, chunk| {
            if chunk.plaintext_size == 0 || chunk.plaintext_size > CHUNK_SIZE as u64 {
                return None;
            }
            total.checked_add(chunk.plaintext_size)
        })
        .ok_or_else(|| "backup manifest contains invalid chunk sizes".to_string())?;
    if declared_size != manifest.artifact_size {
        return Err("backup manifest artifact size is inconsistent".into());
    }
    Ok(())
}

fn credential_entry(id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(CREDENTIAL_SERVICE, &format!("destination:{id}"))
        .map_err(|error| format!("open the operating system credential vault: {error}"))
}

fn migrated_password(account: &str) -> Result<String, String> {
    let current = keyring::Entry::new(CREDENTIAL_SERVICE, account)
        .map_err(|error| format!("open the operating system credential vault: {error}"))?;
    match current.get_password() {
        Ok(value) => Ok(value),
        Err(keyring::Error::NoEntry) => {
            let previous = keyring::Entry::new(PREVIOUS_CREDENTIAL_SERVICE, account)
                .map_err(|error| format!("open the previous credential vault: {error}"))?;
            let value = previous.get_password()
                .map_err(|error| format!("read previous credentials from the operating system vault: {error}"))?;
            current.set_password(&value)
                .map_err(|error| format!("move credentials into the Yougori vault: {error}"))?;
            Ok(value)
        }
        Err(error) => Err(format!("read credentials from the operating system vault: {error}")),
    }
}

fn store_credentials(id: &str, credentials: &StoredCredentials) -> Result<(), String> {
    let serialized = serde_json::to_string(credentials)
        .map_err(|error| format!("serialize destination credentials: {error}"))?;
    credential_entry(id)?
        .set_password(&serialized)
        .map_err(|error| format!("save credentials in the operating system vault: {error}"))
}

fn load_credentials(id: &str) -> Result<StoredCredentials, String> {
    let serialized = migrated_password(&format!("destination:{id}"))?;
    serde_json::from_str(&serialized)
        .map_err(|error| format!("decode stored destination credentials: {error}"))
}

fn device_identity() -> Result<age::x25519::Identity, String> {
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, MASTER_KEY_ACCOUNT)
        .map_err(|error| format!("open the device encryption key: {error}"))?;
    match entry.get_password() {
        Ok(value) => age::x25519::Identity::from_str(&value)
            .map_err(|error| format!("decode the device encryption key: {error}")),
        Err(keyring::Error::NoEntry) => {
            let previous = keyring::Entry::new(PREVIOUS_CREDENTIAL_SERVICE, MASTER_KEY_ACCOUNT)
                .map_err(|error| format!("open the previous device encryption key: {error}"))?;
            match previous.get_password() {
                Ok(value) => {
                    let identity = age::x25519::Identity::from_str(&value)
                        .map_err(|error| format!("decode the previous device encryption key: {error}"))?;
                    entry.set_password(&value)
                        .map_err(|error| format!("move the device encryption key to Yougori: {error}"))?;
                    Ok(identity)
                }
                Err(keyring::Error::NoEntry) => {
                    let identity = age::x25519::Identity::generate();
                    entry.set_password(identity.to_string().expose_secret())
                        .map_err(|error| format!("store the device encryption key: {error}"))?;
                    Ok(identity)
                }
                Err(error) => Err(format!("read the previous device encryption key: {error}")),
            }
        }
        Err(error) => Err(format!("read the device encryption key: {error}")),
    }
}

/// Deduplication names are keyed by the device encryption key. A reinstalled
/// device key can never reuse chunks it cannot decrypt, and anyone else with
/// bucket access can neither predict names to plant data nor learn plaintext
/// hashes. Older manifests keep their recorded unkeyed chunk names.
fn chunk_name_key(identity: &age::x25519::Identity) -> [u8; 32] {
    let mut key = Sha256::new();
    key.update(b"yougori-backup-chunk-names-v1\0");
    key.update(identity.to_string().expose_secret().as_bytes());
    key.finalize().into()
}

fn chunk_object(key: &[u8; 32], plaintext_sha256: &str) -> String {
    let name = hex::encode(hmac_sha256(key, plaintext_sha256.as_bytes()));
    format!("chunks/k1/{}/{name}.zst.age", &name[..2])
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn encrypt(identity: &age::x25519::Identity, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    age::encrypt(&identity.to_public(), plaintext)
        .map_err(|error| format!("encrypt backup data locally: {error}"))
}

fn build_remote(credentials: &StoredCredentials) -> Result<Remote, String> {
    let url = Url::parse(credentials.location.trim())
        .map_err(|error| format!("backup location must be a complete storage URL: {error}"))?;
    let options = match credentials.provider {
        BackupProvider::AwsS3 => vec![
            ("aws_access_key_id", credentials.access_key.clone()),
            ("aws_secret_access_key", credentials.secret_key.clone()),
            (
                "aws_region",
                query_value(&url, "region").unwrap_or_else(|| "us-east-1".into()),
            ),
        ],
        BackupProvider::AzureBlob => vec![
            ("azure_storage_account_name", credentials.access_key.clone()),
            ("azure_storage_account_key", credentials.secret_key.clone()),
        ],
        BackupProvider::GoogleCloud => {
            vec![("google_service_account_key", credentials.secret_key.clone())]
        }
        BackupProvider::S3Compatible => return build_s3_compatible(credentials, &url),
    };
    let (store, prefix) = object_store::parse_url_opts(&url, options)
        .map_err(|error| format!("configure backup destination: {error}"))?;
    Ok(Remote { store, prefix })
}

fn build_s3_compatible(credentials: &StoredCredentials, url: &Url) -> Result<Remote, String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("S3-compatible locations must use an http:// or https:// endpoint URL".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "S3-compatible location is missing a host".to_string())?;
    let mut segments = url
        .path_segments()
        .ok_or_else(|| "S3-compatible location is missing a bucket".to_string())?
        .filter(|value| !value.is_empty());
    let bucket = segments
        .next()
        .ok_or_else(|| "S3-compatible URL must include the bucket as its first path".to_string())?;
    let prefix = segments.collect::<Vec<_>>().join("/");
    let endpoint = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };
    let store = object_store::aws::AmazonS3Builder::new()
        .with_endpoint(endpoint)
        .with_bucket_name(bucket)
        .with_region(query_value(url, "region").unwrap_or_else(|| "us-east-1".into()))
        .with_access_key_id(&credentials.access_key)
        .with_secret_access_key(&credentials.secret_key)
        .with_virtual_hosted_style_request(false)
        .with_allow_http(url.scheme() == "http")
        .build()
        .map_err(|error| format!("configure S3-compatible destination: {error}"))?;
    Ok(Remote {
        store: Box::new(store),
        prefix: ObjectPath::parse(prefix)
            .map_err(|error| format!("invalid backup path prefix: {error}"))?,
    })
}

fn join_object_path(prefix: &ObjectPath, child: &str) -> Result<ObjectPath, String> {
    let value = if prefix.as_ref().is_empty() {
        child.to_owned()
    } else {
        format!("{prefix}/{child}")
    };
    ObjectPath::parse(value).map_err(|error| format!("invalid remote object path: {error}"))
}

fn query_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn decrypt(identity: &age::x25519::Identity, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    age::decrypt(identity, ciphertext).map_err(|error| format!("decrypt backup data: {error}"))
}

fn decompress_limited(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let decoder = zstd::stream::read::Decoder::new(bytes)
        .map_err(|error| format!("open compressed backup data: {error}"))?;
    let mut limited = decoder.take(limit as u64);
    let mut output = Vec::new();
    limited
        .read_to_end(&mut output)
        .map_err(|error| format!("decompress backup data: {error}"))?;
    if output.len() >= limit {
        return Err("decompressed backup chunk exceeds the safety limit".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_chunks_round_trip() {
        let identity = age::x25519::Identity::generate();
        let plaintext = b"real encrypted Yougori backup";
        let ciphertext = encrypt(&identity, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(decrypt(&identity, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn chunk_names_are_scoped_to_the_device_key_and_hide_plaintext_hashes() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let plaintext_sha256 = hex::encode(Sha256::digest(b"identical chunk"));
        let first = age::x25519::Identity::generate();
        let reinstalled = age::x25519::Identity::generate();
        let name = chunk_object(&chunk_name_key(&first), &plaintext_sha256);
        assert_eq!(name, chunk_object(&chunk_name_key(&first), &plaintext_sha256));
        assert_ne!(name, chunk_object(&chunk_name_key(&reinstalled), &plaintext_sha256));
        assert!(name.starts_with("chunks/k1/") && name.ends_with(".zst.age"));
        assert!(!name.contains(&plaintext_sha256));
    }

    #[test]
    fn joins_remote_prefixes_without_absolute_paths() {
        let prefix = ObjectPath::parse("team/yougori").unwrap();
        assert_eq!(
            join_object_path(&prefix, "chunks/ab/value.age")
                .unwrap()
                .as_ref(),
            "team/yougori/chunks/ab/value.age"
        );
    }

    #[test]
    fn upload_rate_limiter_uses_decimal_megabits_per_second() {
        let mut limiter = UploadRateLimiter::new(8);

        assert_eq!(
            limiter.required_delay(1_000_000, Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            limiter.required_delay(1_000_000, Duration::from_millis(1_250)),
            Duration::from_millis(750)
        );
    }

    #[test]
    fn upload_rate_limiter_counts_elapsed_upload_time() {
        let mut limiter = UploadRateLimiter::new(1);

        assert_eq!(
            limiter.required_delay(125_000, Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            limiter.required_delay(125_000, Duration::from_secs(10)),
            Duration::ZERO
        );
        assert_eq!(
            limiter.required_delay(125_000, Duration::from_secs(10)),
            Duration::ZERO
        );
    }

    #[test]
    fn zero_upload_rate_limit_is_unlimited() {
        let mut limiter = UploadRateLimiter::new(0);

        assert_eq!(
            limiter.required_delay(usize::MAX, Duration::ZERO),
            Duration::ZERO
        );
        assert_eq!(limiter.accounted_bytes, 0);
    }
}
