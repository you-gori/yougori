use super::*;
use tokio::io::AsyncBufReadExt;

#[tokio::test]
async fn a_forwarded_reply_finishing_after_suspension_cannot_release_its_body() {
    let called = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (started, gate) = (called.clone(), release.clone());
    let forward: FileForward = Arc::new(move |_| {
        let (started, gate) = (started.clone(), gate.clone());
        Box::pin(async move {
            started.notify_one();
            gate.notified().await;
            Ok((
                200,
                serde_json::to_vec(&json!({"data":STANDARD.encode(b"private content")})).unwrap(),
            ))
        })
    });
    let server = HostFolderServer::start_forward(forward).await.unwrap();
    let pending = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{}/files", server.port))
        .bearer_auth(&server.token)
        .json(&json!({"operation":"read","path":"private","length":100}))
        .send();
    let client = tokio::spawn(pending);
    tokio::time::timeout(Duration::from_secs(2), called.notified())
        .await
        .unwrap();
    server.set_suspended(true);
    release.notify_one();
    let reply = client.await.unwrap().unwrap();
    assert_eq!(reply.status(), 403);
    let body = reply.bytes().await.unwrap();
    assert!(!body.windows(7).any(|bytes| bytes == b"private"));
    assert!(!body.windows(8).any(|bytes| bytes == b"cHJpdmF0"));
}

fn request(token: &str, value: Value) -> Vec<u8> {
    let body = serde_json::to_vec(&value).unwrap();
    let mut bytes = format!("POST /files HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/octet-stream\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend(body);
    bytes
}

async fn read_reply(stream: &mut BufReader<TcpStream>) -> (String, Vec<u8>) {
    let mut header = String::new();
    loop {
        let mut line = String::new();
        assert!(stream.read_line(&mut line).await.unwrap() > 0);
        header.push_str(&line);
        assert!(header.len() < 16 * 1024);
        if line == "\r\n" {
            break;
        }
    }
    let size: usize = header_value(&header, "content-length")
        .unwrap()
        .parse()
        .unwrap();
    assert!(size <= MAX_READ_BYTES + 1024);
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.unwrap();
    (header, body)
}

#[tokio::test]
async fn pipelined_binary_reads_preserve_framing_and_recheck_the_capability() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("weights"), b"first-second").unwrap();
    let server = HostFolderServer::start(directory.path().into(), true)
        .await
        .unwrap();
    let mut stream = BufReader::new(
        TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap(),
    );
    let mut pipeline = request(
        &server.token,
        json!({"operation":"read","path":"weights","offset":0,"length":5}),
    );
    pipeline.extend(request(
        &server.token,
        json!({"operation":"read","path":"weights","offset":6,"length":6}),
    ));
    pipeline.extend(request(
        "wrong-capability",
        json!({"operation":"read","path":"weights","length":100}),
    ));
    stream.get_mut().write_all(&pipeline).await.unwrap();
    for expected in [b"first".as_slice(), b"second".as_slice()] {
        let (header, bytes) = read_reply(&mut stream).await;
        assert!(header.starts_with("HTTP/1.1 200 "));
        assert_eq!(
            header_value(&header, "content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(header_value(&header, "connection"), Some("keep-alive"));
        assert_eq!(bytes, expected);
    }
    let (header, bytes) = read_reply(&mut stream).await;
    assert!(header.starts_with("HTTP/1.1 403 "));
    assert!(!bytes.windows(5).any(|w| w == b"first"));
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn binary_and_legacy_reads_share_bounds_and_confinement() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("share");
    std::fs::create_dir(&root).unwrap();
    let data: Vec<u8> = (0..600_000).map(|n| (n % 251) as u8).collect();
    std::fs::write(root.join("weights"), &data).unwrap();
    std::fs::write(directory.path().join("private"), b"private").unwrap();
    std::fs::hard_link(directory.path().join("private"), root.join("linked")).unwrap();
    let server = HostFolderServer::start(root, true).await.unwrap();
    let base = format!("http://127.0.0.1:{}/files", server.port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let value = json!({"operation":"read","path":"weights","offset":65537,"length":1_000_000});
    let legacy = client
        .post(&base)
        .bearer_auth(&server.token)
        .json(&value)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.headers()["connection"], "close");
    let legacy = STANDARD
        .decode(
            legacy.json::<Value>().await.unwrap()["data"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let binary = client
        .post(&base)
        .bearer_auth(&server.token)
        .header("accept", "application/octet-stream")
        .json(&value)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(binary.as_ref(), &data[65537..65537 + MAX_READ_BYTES]);
    assert_eq!(binary.as_ref(), legacy);
    for value in [
        json!({"operation":"read","path":"../private","length":100}),
        json!({"operation":"read","path":"linked","length":100}),
        json!({"operation":"read","path":"weights","offset":u64::MAX,"length":100}),
        json!({"operation":"write","path":"weights","data":STANDARD.encode(b"changed")}),
    ] {
        let response = client
            .post(&base)
            .bearer_auth(&server.token)
            .header("accept", "application/octet-stream")
            .json(&value)
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success());
    }
    let end = client
        .post(&base)
        .bearer_auth(&server.token)
        .header("accept", "application/octet-stream")
        .json(&json!({"operation":"read","path":"weights","offset":600_000,"length":100}))
        .send()
        .await
        .unwrap();
    assert_eq!(end.status(), 200);
    assert!(end.bytes().await.unwrap().is_empty());
    assert_eq!(
        std::fs::read(directory.path().join("private")).unwrap(),
        b"private"
    );
}

#[tokio::test]
async fn malformed_next_request_cannot_smuggle_a_read_on_a_pooled_connection() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("file"), b"visible").unwrap();
    let server = HostFolderServer::start(directory.path().into(), true)
        .await
        .unwrap();
    for extra in [
        "Content-Length: 0\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Authorization: Bearer forged\r\n",
    ] {
        let mut socket = BufReader::new(
            TcpStream::connect(("127.0.0.1", server.port))
                .await
                .unwrap(),
        );
        let first = request(
            &server.token,
            json!({"operation":"read","path":"file","length":7}),
        );
        socket.get_mut().write_all(&first).await.unwrap();
        assert_eq!(read_reply(&mut socket).await.1, b"visible");
        let mut malformed = format!("POST /files HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n{extra}\r\n", server.token).into_bytes();
        malformed.extend(&first);
        socket.get_mut().write_all(&malformed).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn suspension_and_stop_end_backpressured_downloads_before_the_full_file() {
    for stop in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let length = 64 * 1024 * 1024;
        std::fs::File::create(directory.path().join("large"))
            .unwrap()
            .set_len(length)
            .unwrap();
        let server = HostFolderServer::start(directory.path().into(), true)
            .await
            .unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut response = client
            .get(format!(
                "http://127.0.0.1:{}/{}/large",
                server.port, server.token
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        // Positive control: the real server has opened and begun a file reply.
        let first = response.chunk().await.unwrap().unwrap();
        assert!(!first.is_empty());
        if stop {
            server.stop();
        } else {
            server.set_suspended(true);
        }
        let received = tokio::time::timeout(Duration::from_secs(3), async {
            let mut count = first.len() as u64;
            while let Ok(Some(chunk)) = response.chunk().await {
                count += chunk.len() as u64;
            }
            count
        })
        .await
        .expect("Revoked download never ended");
        assert!(
            received < length,
            "Revoked transfer delivered the complete file"
        );
        if !stop {
            let denied = client
                .get(format!(
                    "http://127.0.0.1:{}/{}/large",
                    server.port, server.token
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(denied.status(), 403);
            server.set_suspended(false);
            let resumed = client
                .post(format!("http://127.0.0.1:{}/files", server.port))
                .bearer_auth(&server.token)
                .header("accept", "application/octet-stream")
                .json(&json!({"operation":"read","path":"large","length":1}))
                .send()
                .await
                .unwrap();
            assert_eq!(resumed.bytes().await.unwrap().as_ref(), &[0]);
        }
    }
}
