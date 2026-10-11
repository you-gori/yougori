use super::{appliance::{successful_response, SnapshotArtifact}, RuntimeManager};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio_util::io::SyncIoBridge;
use tokio_util::sync::CancellationToken;
use std::{collections::HashMap, sync::{Arc, Mutex}};

const MAGIC: &[u8] = b"YOUGORI-SNAPSHOT\0\x01";
const CONTENT_TYPE: &str = "application/vnd.yougori.snapshot.v1";
const SPACE_RESERVE: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Default)]
struct ExportResource {
    active: HashMap<String, CancellationToken>,
    interruptions: usize,
}
#[derive(Clone, Default)]
pub(crate) struct SnapshotExports(Arc<Mutex<HashMap<String, ExportResource>>>);
pub(crate) struct ExportLease {
    registry: SnapshotExports,
    environment: String,
    id: String,
    pub(crate) cancellation: CancellationToken,
}
pub(crate) struct SnapshotStopLease {
    registry: SnapshotExports,
    environment: String,
    pub(crate) cancelled_exports: usize,
}
impl SnapshotExports {
    pub(crate) fn begin(&self, environment: &str) -> Result<ExportLease, String> {
        let cancellation = crate::automation::context::current()
            .map(|operation| operation.cancellation.child_token())
            .unwrap_or_default();
        if cancellation.is_cancelled() {
            return Err("YOUGORI_OPERATION_CANCELLED: snapshot export cancelled before it started; no snapshot published".into());
        }
        let mut resources = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let resource = resources.entry(environment.to_owned()).or_default();
        if resource.interruptions > 0 {
            return Err("YOUGORI_OPERATION_CANCELLED: snapshot export cancelled before it started; lifecycle change is pending; no snapshot published".into());
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        resource.active.insert(id.clone(), cancellation.clone());
        Ok(ExportLease { registry: self.clone(), environment: environment.into(), id, cancellation })
    }
    pub(crate) fn interrupt(&self, environment: &str) -> SnapshotStopLease {
        let mut resources = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let resource = resources.entry(environment.to_owned()).or_default();
        resource.interruptions += 1;
        for cancellation in resource.active.values() {
            cancellation.cancel();
        }
        SnapshotStopLease {
            registry: self.clone(), environment: environment.into(),
            cancelled_exports: resource.active.len(),
        }
    }
}
impl Drop for ExportLease {
    fn drop(&mut self) {
        self.cancellation.cancel();
        let mut resources = self.registry.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(resource) = resources.get_mut(&self.environment) {
            resource.active.remove(&self.id);
            if resource.active.is_empty() && resource.interruptions == 0 {
                resources.remove(&self.environment);
            }
        }
    }
}
impl Drop for SnapshotStopLease {
    fn drop(&mut self) {
        let mut resources = self.registry.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(resource) = resources.get_mut(&self.environment) {
            resource.interruptions = resource.interruptions.saturating_sub(1);
            if resource.active.is_empty() && resource.interruptions == 0 {
                resources.remove(&self.environment);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct StreamLimits { total: Duration, inactivity: Duration, cleanup: Duration }
impl Default for StreamLimits {
    fn default() -> Self {
        Self { total: Duration::from_secs(24 * 60 * 60), inactivity: Duration::from_secs(90), cleanup: Duration::from_secs(3) }
    }
}

fn cancelled_export() -> String {
    "YOUGORI_OPERATION_CANCELLED: snapshot export interrupted; no snapshot published; originals preserved; unverified host archive removed after its writer closes".into()
}

impl RuntimeManager {
    pub(crate) fn interrupt_snapshot_exports(&self, id: &str) -> SnapshotStopLease {
        self.snapshot_exports.interrupt(id)
    }
    pub(super) async fn stream_container_snapshot(&self, id: &str, snapshot_id: &str) -> Result<SnapshotArtifact, String> {
        let export = self.snapshot_exports.begin(id)?;
        self.register_snapshot_provider(snapshot_id, &self.container_provider(id)?)?;
        let directory = self.data_root.join("snapshots");
        check_space(&directory)?;
        let file = NamedTempFile::new_in(&directory).map_err(|e| format!("Create snapshot file: {e}"))?;
        let tag = format!("{}{}", yougori_cli::legacy_names::SNAPSHOT_TAG_PREFIX, snapshot_id.to_lowercase());
        let _lease = tokio::select! {
            biased;
            _ = export.cancellation.cancelled() => return Err(cancelled_export()),
            lease = self.appliance_operations.read() => lease,
        };
        let endpoint = self.container_endpoint(id).await?;
        crate::automation::context::progress(json!({"phase":"snapshotExport","cancellable":true}));
        let result = stream_archive(&self.client, &endpoint.base_url, &endpoint.token,
            id, snapshot_id, file, &directory, &tag, &export.cancellation, StreamLimits::default()).await;
        crate::automation::context::progress(json!({"phase":"snapshotExportFinished","cancellable":false}));
        let (file, size_bytes, checksum_sha256) = result?;
        let path = self.data_root.join("snapshots").join(format!("{snapshot_id}.oci.tar"));
        file.persist_noclobber(&path).map_err(|e| format!("Finalize snapshot: {}", e.error))?;
        Ok(SnapshotArtifact { provider_snapshot_id: tag, path, size_bytes, checksum_sha256 })
    }
}

async fn cancel_guest_export(client: &reqwest::Client, base: &str, token: &str, id: &str, snapshot_id: &str) {
    let _ = tokio::time::timeout(Duration::from_secs(2), client
        .post(format!("{base}/v1/snapshots/export/cancel")).bearer_auth(token)
        .json(&json!({"id":id,"snapshotId":snapshot_id})).send()).await;
}

async fn discard_snapshot_writer(
    worker: &mut tokio::task::JoinHandle<Result<(NamedTempFile, u64, String), String>>,
    cleanup: Duration,
) -> Result<(), String> {
    match tokio::time::timeout(cleanup, worker).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err("YOUGORI_OPERATION_INTERRUPTED: snapshot archive writer failed during cleanup; no snapshot published; inspect private staging before retrying".into()),
        Err(_) => Err("YOUGORI_OPERATION_INTERRUPTED: snapshot archive writer did not stop before its cleanup deadline; no snapshot published; private staging is removed when pending disk I/O returns".into()),
    }
}

async fn stream_archive(
    client: &reqwest::Client, base: &str, token: &str, id: &str, snapshot_id: &str,
    file: NamedTempFile, directory: &Path, tag: &str,
    cancellation: &CancellationToken, limits: StreamLimits,
) -> Result<(NamedTempFile, u64, String), String> {
        let deadline = tokio::time::Instant::now() + limits.total;
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(cancelled_export()),
            response = tokio::time::timeout_at(deadline, client.post(format!("{base}/v1/snapshots/export"))
                .bearer_auth(token).json(&json!({"id":id,"snapshotId":snapshot_id}))
                .timeout(limits.total).send()) => match response {
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(error)) if !error.is_timeout() || tokio::time::Instant::now() < deadline => Err(format!("Start snapshot export: {error}")),
                    _ => Err("YOUGORI_TRANSFER_DEADLINE: snapshot export exceeded its total duration; no snapshot published; originals preserved".into()),
                },
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                cancel_guest_export(client, base, token, id, snapshot_id).await;
                return Err(error);
            }
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("This container runtime needs the updated guest agent. Restart Yougori, then retry the snapshot or backup.".into());
        }
        let error_deadline = deadline.min(tokio::time::Instant::now() + limits.inactivity);
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(cancelled_export()),
            response = tokio::time::timeout_at(error_deadline, successful_response(response)) => match response {
                Ok(result) => result,
                Err(_) if tokio::time::Instant::now() >= deadline => Err("YOUGORI_TRANSFER_DEADLINE: snapshot export exceeded its total duration; no snapshot published; originals preserved".into()),
                Err(_) => Err("YOUGORI_TRANSFER_INACTIVE: snapshot export error response stalled; no snapshot published; originals preserved".into()),
            },
        };
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                cancel_guest_export(client, base, token, id, snapshot_id).await;
                return Err(error);
            }
        };
        if response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some(CONTENT_TYPE) {
            return Err("The runtime returned an unsupported snapshot stream".into());
        }
        // One bounded network buffer and one host archive. Guest files are
        // never extracted on the host or duplicated inside the container disk.
        let (mut sender, receiver) = tokio::io::duplex(512 * 1024);
        let archive_tag = tag.to_owned();
        let archive_directory = directory.to_owned();
        let archive_cancellation = cancellation.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            build_archive_cancellable(SyncIoBridge::new(receiver), file, &archive_directory, &archive_tag, archive_cancellation)
        });
        let transfer = async {
            loop {
                let copy_chunk = async {
                    let Some(chunk) = response.chunk().await.map_err(|error| format!("Snapshot transfer was interrupted: {error}"))? else { return Ok(false); };
                    sender.write_all(&chunk).await.map_err(|_| "Snapshot archive writer stopped".to_string())?;
                    Ok::<_, String>(true)
                };
                match tokio::time::timeout(limits.inactivity, copy_chunk).await {
                    Ok(Ok(true)) => {},
                    Ok(Ok(false)) => return Ok(()),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err("YOUGORI_TRANSFER_INACTIVE: snapshot export made no progress; no snapshot published; originals preserved".into()),
                }
            }
        };
        let transfer_error = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Some(cancelled_export()),
            result = tokio::time::timeout_at(deadline, transfer) => match result {
                Ok(result) => result.err(),
                Err(_) => Some("YOUGORI_TRANSFER_DEADLINE: snapshot export exceeded its total duration; no snapshot published; originals preserved".into()),
            }
        };
        drop(sender);
        drop(response); // Cancels the exporter if the disk writer failed.
        if let Some(error) = transfer_error {
            cancellation.cancel();
            cancel_guest_export(client, base, token, id, snapshot_id).await;
            discard_snapshot_writer(&mut worker, limits.cleanup).await?;
            return Err(error);
        }
        let completed = tokio::select! {
            biased;
            _ = cancellation.cancelled() => None,
            result = tokio::time::timeout_at(deadline, &mut worker) => match result {
                Ok(result) => Some(result.map_err(|error| format!("Snapshot writer stopped: {error}"))?),
                Err(_) => None,
            }
        };
        if let Some(result) = completed { return result; }
        let cancelled = cancellation.is_cancelled();
        cancellation.cancel();
        cancel_guest_export(client, base, token, id, snapshot_id).await;
        discard_snapshot_writer(&mut worker, limits.cleanup).await?;
        Err(if cancelled { cancelled_export() } else { "YOUGORI_TRANSFER_DEADLINE: snapshot verification exceeded its total duration; no snapshot published; originals preserved".into() })
}

fn check_space(directory: &Path) -> Result<(), String> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = super::storage::runtime_disk(&disks, directory).ok_or("Cannot determine free space on the snapshot drive")?;
    if disk.available_space() < SPACE_RESERVE + 16 * 1024 * 1024 {
        return Err("Not enough free space on the computer's snapshot drive. Free space there and retry; Yougori keeps 2 GB available for the computer. The container and its files were kept.".into());
    }
    Ok(())
}

struct LayerReceiver<R> {
    input: R,
    output: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
    directory: PathBuf,
    checked_at: Instant,
    checked_bytes: u64,
    cancellation: CancellationToken,
}

impl<R: Read> Read for LayerReceiver<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() { return Err(io::Error::other(cancelled_export())); }
        let n = self.input.read(bytes)?;
        if n == 0 { return Ok(0); }
        if self.bytes - self.checked_bytes >= 64 * 1024 * 1024 || self.checked_at.elapsed() >= Duration::from_secs(3) {
            check_space(&self.directory).map_err(io::Error::other)?;
            self.checked_at = Instant::now();
            self.checked_bytes = self.bytes;
        }
        self.output.write_all(&bytes[..n])?;
        self.hash.update(&bytes[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

// Reserve one tar header, stream the compressed layer once, then fill in its
// final name/size and append OCI metadata. No second large host staging file.
#[cfg(test)]
fn build_archive<R: Read>(mut input: R, file: NamedTempFile, directory: &Path, tag: &str) -> Result<(NamedTempFile, u64, String), String> {
    build_archive_cancellable(&mut input, file, directory, tag, CancellationToken::new())
}
fn build_archive_cancellable<R: Read>(mut input: R, file: NamedTempFile, directory: &Path, tag: &str, cancellation: CancellationToken) -> Result<(NamedTempFile, u64, String), String> {
    if cancellation.is_cancelled() { return Err(cancelled_export()); }
    let mut magic = vec![0; MAGIC.len()];
    input.read_exact(&mut magic).map_err(|e| format!("Incomplete snapshot header: {e}"))?;
    if magic != MAGIC { return Err("Invalid snapshot stream version".into()); }
    let mut length = [0u8; 4];
    input.read_exact(&mut length).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 1024 * 1024 { return Err("Invalid snapshot metadata length".into()); }
    let mut metadata = vec![0; length];
    input.read_exact(&mut metadata).map_err(|e| e.to_string())?;
    let mut image: Value = serde_json::from_slice(&metadata).map_err(|e| format!("Invalid snapshot metadata: {e}"))?;
    if !image["config"].is_object() || image["architecture"].as_str().is_none_or(str::is_empty) || image["os"].as_str().is_none_or(str::is_empty) {
        return Err("Snapshot is missing its image configuration or platform".into());
    }
    let mut output = BufWriter::with_capacity(256 * 1024, file.reopen().map_err(|e| e.to_string())?);
    output.write_all(&[0u8; 512]).map_err(|e| e.to_string())?;
    let receiver = LayerReceiver { input, output, hash: Sha256::new(), bytes: 0, directory: directory.to_owned(), checked_at: Instant::now(), checked_bytes: 0, cancellation: cancellation.clone() };
    let mut decoder = flate2::bufread::GzDecoder::new(BufReader::with_capacity(128 * 1024, receiver));
    let mut raw_hash = Sha256::new();
    let mut raw_bytes = 0u64;
    let mut buffer = vec![0; 128 * 1024];
    loop {
        let n = decoder.read(&mut buffer).map_err(|e| format!("Snapshot export did not finish or could not be saved: {e}. No partial snapshot was kept."))?;
        if n == 0 { break; }
        raw_hash.update(&buffer[..n]);
        raw_bytes += n as u64;
    }
    let mut buffered = decoder.into_inner();
    if !buffered.fill_buf().map_err(|e| e.to_string())?.is_empty() || raw_bytes < 1024 || raw_bytes % 512 != 0 {
        return Err("Snapshot export returned an incomplete or invalid filesystem archive".into());
    }
    let receiver = buffered.into_inner();
    let compressed_digest = hex::encode(receiver.hash.finalize());
    let compressed_bytes = receiver.bytes;
    let mut output = receiver.output.into_inner().map_err(|e| e.to_string())?;
    let layer_header = tar_header(&format!("blobs/sha256/{compressed_digest}"), compressed_bytes)?;
    output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    output.write_all(layer_header.as_bytes()).map_err(|e| e.to_string())?;
    output.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    output.write_all(&vec![0; ((512 - compressed_bytes % 512) % 512) as usize]).map_err(|e| e.to_string())?;
    image["rootfs"] = json!({"type":"layers", "diff_ids":[format!("sha256:{}", hex::encode(raw_hash.finalize()))]});
    // Flattening produces one complete filesystem layer; discard old history.
    image["history"] = json!([{"created":image["created"],"created_by":"Yougori snapshot"}]);
    let mut archive = tar::Builder::new(&mut output);
    let config = append_blob(&mut archive, &image, "application/vnd.oci.image.config.v1+json")?;
    let manifest = append_blob(&mut archive, &json!({
        "schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json", "config":config,
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{compressed_digest}"),"size":compressed_bytes}]
    }), "application/vnd.oci.image.manifest.v1+json")?;
    let mut manifest = manifest;
    manifest["annotations"] = json!({"io.containerd.image.name":tag,"org.opencontainers.image.ref.name":tag});
    append_json(&mut archive, "index.json", &json!({"schemaVersion":2,"manifests":[manifest]}))?;
    append_json(&mut archive, "oci-layout", &json!({"imageLayoutVersion":"1.0.0"}))?;
    archive.finish().map_err(|e| e.to_string())?;
    drop(archive);
    output.sync_all().map_err(|e| format!("Flush snapshot: {e}"))?;
    output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let size = output.metadata().map_err(|e| e.to_string())?.len();
    let mut hash = Sha256::new();
    loop {
        if cancellation.is_cancelled() { return Err(cancelled_export()); }
        let n = output.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        hash.update(&buffer[..n]);
    }
    Ok((file, size, hex::encode(hash.finalize())))
}

fn tar_header(path: &str, size: u64) -> Result<tar::Header, String> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).map_err(|e| e.to_string())?;
    header.set_size(size);
    header.set_mode(0o600);
    header.set_cksum();
    Ok(header)
}

fn append_json<W: Write>(archive: &mut tar::Builder<W>, path: &str, value: &Value) -> Result<(), String> {
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    archive.append(&tar_header(path, data.len() as u64)?, data.as_slice()).map_err(|e| e.to_string())
}

fn append_blob<W: Write>(archive: &mut tar::Builder<W>, value: &Value, media_type: &str) -> Result<Value, String> {
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let hash = hex::encode(Sha256::digest(&data));
    archive.append(&tar_header(&format!("blobs/sha256/{hash}"), data.len() as u64)?, data.as_slice()).map_err(|e| e.to_string())?;
    Ok(json!({"mediaType":media_type,"digest":format!("sha256:{hash}"),"size":data.len()}))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration;
