use super::*;

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let mut rootfs = tar::Builder::new(Vec::new());
    let mut header = tar_header("project/database", 13).unwrap();
    header.set_mode(0o640);
    header.set_uid(1000);
    header.set_gid(1001);
    header.set_cksum();
    rootfs.append(&header, &b"database-data"[..]).unwrap();
    let rootfs = rootfs.into_inner().unwrap();
    let metadata = serde_json::to_vec(&json!({
        "architecture":"amd64", "os":"linux", "created":"2026-09-11T00:00:00Z",
        "config":{"WorkingDir":"/project", "User":"1000:1001", "Env":["MODE=production"], "Entrypoint":["/entrypoint"], "Cmd":["node", "server.js"]}
    })).unwrap();
    let mut wire = MAGIC.to_vec();
    wire.extend((metadata.len() as u32).to_be_bytes());
    wire.extend(metadata);
    let mut gzip = flate2::write::GzEncoder::new(wire, flate2::Compression::fast());
    gzip.write_all(&rootfs).unwrap();
    (gzip.finish().unwrap(), rootfs)
}

#[test]
fn streaming_snapshot_is_a_valid_oci_archive_with_preserved_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let (wire, rootfs) = fixture();
    let (file, size, checksum) = build_archive(wire.as_slice(), NamedTempFile::new_in(directory.path()).unwrap(), directory.path(), "yougori.local/snapshots:test").unwrap();
    let bytes = std::fs::read(file.path()).unwrap();
    assert_eq!(size, bytes.len() as u64);
    assert_eq!(checksum, hex::encode(Sha256::digest(&bytes)));
    let mut files = std::collections::HashMap::new();
    for entry in tar::Archive::new(bytes.as_slice()).entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        files.insert(path, data);
    }
    let blob = |descriptor: &Value| {
        let digest = descriptor["digest"].as_str().unwrap().strip_prefix("sha256:").unwrap();
        let data = &files[&format!("blobs/sha256/{digest}")];
        assert_eq!(descriptor["size"], data.len());
        assert_eq!(digest, hex::encode(Sha256::digest(data)));
        data
    };
    let index: Value = serde_json::from_slice(&files["index.json"]).unwrap();
    assert_eq!(index["manifests"][0]["annotations"]["io.containerd.image.name"], "yougori.local/snapshots:test");
    let manifest: Value = serde_json::from_slice(blob(&index["manifests"][0])).unwrap();
    let config: Value = serde_json::from_slice(blob(&manifest["config"])).unwrap();
    assert_eq!(config["config"]["WorkingDir"], "/project");
    assert_eq!(config["config"]["User"], "1000:1001");
    assert_eq!(config["config"]["Env"], json!(["MODE=production"]));
    assert_eq!(config["config"]["Entrypoint"], json!(["/entrypoint"]));
    assert_eq!(config["config"]["Cmd"], json!(["node", "server.js"]));
    assert_eq!(config["rootfs"]["diff_ids"][0], format!("sha256:{}", hex::encode(Sha256::digest(&rootfs))));
    let mut expanded = Vec::new();
    flate2::read::GzDecoder::new(blob(&manifest["layers"][0]).as_slice()).read_to_end(&mut expanded).unwrap();
    assert_eq!(expanded, rootfs);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1, "must not create a second staging copy");
}

#[test]
fn failed_snapshot_streams_leave_no_archive() {
    let directory = tempfile::tempdir().unwrap();
    let (wire, _) = fixture();
    let mut corrupt = wire.clone();
    let last = corrupt.len() - 5;
    corrupt[last] ^= 0xff;
    let mut extra = wire.clone();
    extra.extend(b"trailing incomplete export");
    for bad in [wire[..wire.len() - 8].to_vec(), corrupt, extra, b"wrong version".to_vec()] {
        assert!(build_archive(bad.as_slice(), NamedTempFile::new_in(directory.path()).unwrap(), directory.path(), "yougori.local/snapshots:test").is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[test]
fn stop_barriers_target_one_environment_and_remain_until_all_lifecycle_requests_end() {
    let exports = SnapshotExports::default();
    let separate_runtime = SnapshotExports::default();
    let first = exports.begin("env-a").unwrap();
    let second = exports.begin("env-b").unwrap();
    let outside = separate_runtime.begin("env-a").unwrap();
    let first_stop = exports.interrupt("env-a");
    let second_stop = exports.clone().interrupt("env-a");
    assert_eq!(first_stop.cancelled_exports, 1);
    assert!(first.cancellation.is_cancelled());
    assert!(!second.cancellation.is_cancelled());
    assert!(!outside.cancellation.is_cancelled());
    drop(first);
    drop(first_stop);
    assert!(exports.begin("env-a").is_err());
    drop(second_stop);
    assert!(exports.begin("env-a").is_ok());
    assert!(!second.cancellation.is_cancelled());
    assert!(!outside.cancellation.is_cancelled());
}

struct HttpFixture {
    cancel_requests: Mutex<Vec<Value>>,
    stream_closed: std::sync::atomic::AtomicBool,
    started: tokio::sync::Notify,
}
#[derive(Clone, Copy)]
enum StalledResponse { Prefix, Idle, BeforeHeaders, ErrorBody }
async fn stalled_guest(mode: StalledResponse) -> (String, Arc<HttpFixture>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(HttpFixture {
        cancel_requests: Mutex::new(Vec::new()),
        stream_closed: std::sync::atomic::AtomicBool::new(false),
        started: tokio::sync::Notify::new(),
    });
    let shared = state.clone();
    let (wire, _) = fixture();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    let state = shared.clone();
                    let wire = wire.clone();
                    tasks.spawn(async move {
                        let mut header = Vec::new();
                        loop {
                            let byte = socket.read_u8().await.ok()?;
                            header.push(byte);
                            if header.ends_with(b"\r\n\r\n") { break; }
                            if header.len() > 16384 { return None; }
                        }
                        let header = String::from_utf8(header).ok()?;
                        let path = header.lines().next()?.split_whitespace().nth(1)?;
                        let length = header.lines().find_map(|line| line.to_ascii_lowercase()
                            .strip_prefix("content-length:").and_then(|value| value.trim().parse::<usize>().ok())).unwrap_or(0);
                        let mut request = vec![0; length];
                        socket.read_exact(&mut request).await.ok()?;
                        if path == "/v1/snapshots/export/cancel" {
                            state.cancel_requests.lock().unwrap().push(serde_json::from_slice(&request).ok()?);
                            let body = b"{\"cancelRequested\":true}";
                            socket.write_all(format!("HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.ok()?;
                            socket.write_all(body).await.ok()?;
                        } else {
                            assert_eq!(path, "/v1/snapshots/export");
                            if !matches!(mode, StalledResponse::BeforeHeaders) {
                                let status = if matches!(mode, StalledResponse::ErrorBody) { "500 Failure" } else { "200 OK" };
                                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: {CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", wire.len()).as_bytes()).await.ok()?;
                            }
                            if matches!(mode, StalledResponse::Prefix) { socket.write_all(&wire[..wire.len()-8]).await.ok()?; }
                            state.started.notify_one();
                            let _ = socket.read_u8().await;
                            state.stream_closed.store(true, std::sync::atomic::Ordering::Release);
                        }
                        Some(())
                    });
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    });
    (base, state, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_a_stalled_snapshot_closes_the_stream_cancels_exact_guest_export_and_removes_staging() {
    let directory = tempfile::tempdir().unwrap();
    let exports = SnapshotExports::default();
    let export = exports.begin("env-snapshot-stall").unwrap();
    let other = exports.begin("env-unrelated").unwrap();
    let (base, state, server) = stalled_guest(StalledResponse::Prefix).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let file = NamedTempFile::new_in(directory.path()).unwrap();
    let root = directory.path().to_owned();
    let task = tokio::spawn(async move {
        stream_archive(&client, &base, "disposable-fixture-token", "env-snapshot-stall", "snap-stalled",
            file, &root, "snapshot-fixture", &export.cancellation,
            StreamLimits { total: Duration::from_secs(10), inactivity: Duration::from_secs(5), cleanup: Duration::from_secs(1) }).await
    });
    tokio::time::timeout(Duration::from_secs(2), state.started.notified()).await.unwrap();
    let start = Instant::now();
    let barrier = exports.interrupt("env-snapshot-stall");
    let error = tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap_err();
    assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED: snapshot export interrupted;"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(3));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !state.stream_closed.load(std::sync::atomic::Ordering::Acquire) { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert_eq!(*state.cancel_requests.lock().unwrap(), vec![json!({"id":"env-snapshot-stall","snapshotId":"snap-stalled"})]);
    assert!(!other.cancellation.is_cancelled());
    assert!(exports.begin("env-snapshot-stall").is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    drop(barrier);
    assert!(exports.begin("env-snapshot-stall").is_ok());
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_snapshot_times_out_cancels_the_guest_and_never_publishes_an_archive() {
    let directory = tempfile::tempdir().unwrap();
    let (base, state, server) = stalled_guest(StalledResponse::Idle).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let error = stream_archive(&client, &base, "disposable-fixture-token", "env-idle", "snap-idle",
        NamedTempFile::new_in(directory.path()).unwrap(), directory.path(), "snapshot-fixture", &CancellationToken::new(),
        StreamLimits { total: Duration::from_secs(10), inactivity: Duration::from_millis(50), cleanup: Duration::from_secs(1) }).await.unwrap_err();
    assert!(error.starts_with("YOUGORI_TRANSFER_INACTIVE"), "{error}");
    assert_eq!(*state.cancel_requests.lock().unwrap(), vec![json!({"id":"env-idle","snapshotId":"snap-idle"})]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_deadline_before_response_headers_retains_partial_failure_and_removes_staging() {
    let directory = tempfile::tempdir().unwrap();
    let (base, state, server) = stalled_guest(StalledResponse::BeforeHeaders).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let error = stream_archive(&client, &base, "disposable-fixture-token", "env-headers", "snap-headers",
        NamedTempFile::new_in(directory.path()).unwrap(), directory.path(), "snapshot-fixture", &CancellationToken::new(),
        StreamLimits { total: Duration::from_millis(50), inactivity: Duration::from_secs(10), cleanup: Duration::from_secs(1) }).await.unwrap_err();
    assert!(error.starts_with("YOUGORI_TRANSFER_DEADLINE"), "{error}");
    assert_eq!(*state.cancel_requests.lock().unwrap(), vec![json!({"id":"env-headers","snapshotId":"snap-headers"})]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_cancellation_interrupts_a_stalled_error_response_body() {
    let directory = tempfile::tempdir().unwrap();
    let (base, state, server) = stalled_guest(StalledResponse::ErrorBody).await;
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let file = NamedTempFile::new_in(directory.path()).unwrap();
    let root = directory.path().to_owned();
    let task = tokio::spawn(async move {
        stream_archive(&client, &base, "disposable-fixture-token", "env-error-body", "snap-error-body",
            file, &root, "snapshot-fixture", &cancellation,
            StreamLimits { total: Duration::from_secs(10), inactivity: Duration::from_secs(5), cleanup: Duration::from_secs(1) }).await
    });
    tokio::time::timeout(Duration::from_secs(2), state.started.notified()).await.unwrap();
    trigger.cancel();
    let error = tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap_err();
    assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED"), "{error}");
    assert_eq!(*state.cancel_requests.lock().unwrap(), vec![json!({"id":"env-error-body","snapshotId":"snap-error-body"})]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    server.abort();
}
