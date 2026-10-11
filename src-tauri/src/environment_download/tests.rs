use super::*;

async fn request(method: &str, path: &str, extra: &str) -> (Vec<u8>, Result<bool, String>) {
    let temporary = tempfile::tempdir().unwrap();
    let artifact = temporary.path().join("environment.yougori");
    tokio::fs::write(&artifact, b"complete-copy\0with-hidden-files").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_request(&mut stream, &artifact, 31, "<script> & \"name\"", "secret").await
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").as_bytes()).await.unwrap();
    let mut reply = Vec::new(); client.read_to_end(&mut reply).await.unwrap();
    (reply, worker.await.unwrap())
}

#[tokio::test]
async fn downloads_serve_exact_bytes_and_count_only_complete_gets() {
    let (reply, counted) = request("GET", "/secret/environment.yougori", "").await;
    assert_eq!(counted.unwrap(), true);
    let split = reply.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&reply[split..], b"complete-copy\0with-hidden-files");
    let (head, counted) = request("HEAD", "/secret/environment.yougori", "").await;
    assert!(!counted.unwrap());
    assert!(head.ends_with(b"\r\n\r\n"));
    for (method, path, extra, status) in [
        ("GET", "/wrong/environment.yougori", "", "404"),
        ("GET", "/secret/../disk.data", "", "404"),
        ("POST", "/secret/environment.yougori", "", "405"),
        ("GET", "/secret/environment.yougori", "Range: bytes=0-9\r\n", "416"),
    ] {
        let (reply, counted) = request(method, path, extra).await;
        assert!(!counted.unwrap()); assert!(String::from_utf8_lossy(&reply).starts_with(&format!("HTTP/1.1 {status}")));
    }
}

#[tokio::test]
async fn landing_page_is_escaped_private_and_not_a_download() {
    let (reply, counted) = request("GET", "/secret", "").await;
    assert!(!counted.unwrap());
    let text = String::from_utf8(reply).unwrap();
    assert!(text.contains("&lt;script&gt; &amp; &quot;name&quot;"));
    assert!(!text.contains("<script>"));
    assert!(text.contains("Cache-Control: no-store"));
    assert!(text.contains("frame-ancestors 'none'"));
    assert!(text.contains("yougori backup import"));
}

#[tokio::test]
async fn aborted_downloads_do_not_count() {
    let directory = tempfile::tempdir().unwrap(); let path = directory.path().join("large");
    let file = std::fs::File::create(&path).unwrap(); file.set_len(32 * 1024 * 1024).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_request(&mut stream, &path, 32 * 1024 * 1024, "Test", "secret").await
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"GET /secret/environment.yougori HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut first = [0; 1024]; client.read(&mut first).await.unwrap();
    #[allow(deprecated)] client.set_linger(Some(Duration::ZERO)).unwrap();
    drop(client);
    assert!(worker.await.unwrap().is_err());
}

#[test]
fn lifetime_counts_survive_new_sessions_and_store_reload() {
    let directory = tempfile::tempdir().unwrap(); let path = directory.path().join("state.json");
    let store = PlatformStore::load(path.clone()).unwrap();
    record_download(&store, "env-one").unwrap(); record_download(&store, "env-two").unwrap();
    drop(store);
    let store = PlatformStore::load(path).unwrap(); record_download(&store, "env-one").unwrap();
    assert_eq!(store.snapshot().unwrap().environment_downloads["env-one"], 2);
    assert_eq!(store.snapshot().unwrap().environment_downloads["env-two"], 1);
}

#[test]
fn process_ownership_and_request_validation_reject_invalid_links() {
    assert!(process_identity(std::process::id()).is_some()); assert!(process_identity(u32::MAX).is_none());
    let mut request = StartRequest { environment_id: "env-one".into(), owner_id: uuid::Uuid::new_v4().to_string(), domain: None, process_id: None };
    assert!(validate(&request).is_ok()); request.owner_id = "bad".into(); assert!(validate(&request).is_err());
}

#[test]
fn stale_copy_cleanup_preserves_live_sessions_and_unowned_folders() {
    let directory = tempfile::tempdir().unwrap();
    for (name, owner) in [("session-expired", Some((u32::MAX, 1))), ("session-live", Some((std::process::id(), process_identity(std::process::id()).unwrap()))), ("session-unowned", None)] {
        let folder = directory.path().join(name); std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("environment.yougori"), b"copy").unwrap();
        if let Some(owner) = owner { std::fs::write(folder.join("owner.json"), serde_json::to_vec(&owner).unwrap()).unwrap(); }
    }
    clean_stale_copies(directory.path());
    assert!(!directory.path().join("session-expired").exists());
    assert!(directory.path().join("session-live/environment.yougori").exists());
    assert!(directory.path().join("session-unowned/environment.yougori").exists());
}

#[tokio::test]
async fn off_cancels_queued_and_preparing_links_without_blocking_a_new_request() {
    let directory = tempfile::tempdir().unwrap(); let downloads = Downloads::new(directory.path());
    let request = StartRequest { environment_id: "env-one".into(), owner_id: uuid::Uuid::new_v4().to_string(), domain: None, process_id: None };
    let queued = downloads.queued_generation("env-one").unwrap();
    // Nothing was live or preparing yet, so Off reports false but still cancels the queued start.
    assert!(!downloads.stop("env-one").await);
    assert!(downloads.prepare(&request, Some(queued)).unwrap_err().contains("cancelled"));
    let pending = downloads.prepare(&request, None).unwrap();
    assert!(downloads.stop("env-one").await);
    assert!(pending.is_cancelled());
}
