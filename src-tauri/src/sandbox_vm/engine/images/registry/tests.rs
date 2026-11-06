use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_importer_cancels_even_while_the_server_is_not_answering() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let reference = Reference::parse(&format!(
        "https://127.0.0.1:{}/team/app@{}",
        listener.local_addr().unwrap().port(),
        OciDigest::of(b"image")
    ))
    .unwrap();
    let mut download = Download::new(reference, None, None, Handle::current()).unwrap();
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let worker = alive.clone();
    let task = tokio::task::spawn_blocking(move || {
        download.fetch(&image_platform(), &|| {
            worker.load(std::sync::atomic::Ordering::SeqCst)
        })
    });
    let (_connection, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let start = std::time::Instant::now();
    alive.store(false, std::sync::atomic::Ordering::SeqCst);
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("importer VM stopped"));
    assert!(start.elapsed() < Duration::from_secs(2));
}

struct Server {
    url: String,
    certificate: reqwest::Certificate,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(handler: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> Server {
    use tokio_rustls::{
        rustls::{self, pki_types::PrivatePkcs8KeyDer},
        TlsAcceptor,
    };
    let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![key.cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 65536);
            }
            let request = String::from_utf8(request).unwrap();
            let response = handler(&request);
            seen.lock().unwrap().push(request);
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        }
    });
    Server {
        url,
        certificate,
        requests,
        task,
    }
}

fn response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn downloader(server: &Server, others: &[&Server]) -> Download {
    let reference = Reference::parse(&format!(
        "{}/team/app@{}",
        server.url,
        OciDigest::of(b"manifest")
    ))
    .unwrap();
    let mut download = Download::new(
        reference,
        Some("disposable-registry-token".into()),
        None,
        Handle::current(),
    )
    .unwrap();
    let mut client = Client::builder()
        .https_only(true)
        .no_proxy()
        .cookie_store(false)
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .add_root_certificate(server.certificate.clone());
    for other in others {
        client = client.add_root_certificate(other.certificate.clone());
    }
    download.client = client.build().unwrap();
    download
}

#[test]
fn reference_and_challenge_do_not_accept_ambient_authority() {
    let digest = OciDigest::of(b"image");
    assert!(Reference::parse(&format!("registry.example/team/app@{digest}")).is_ok());
    for value in [
        "https://user:password@registry.example/team/app",
        "http://registry.example/team/app",
        "https://registry.example/team/../app",
        "https://registry.example/team/%2e%2e/app",
        "https://registry.example/team/app?secret=1",
        "https://registry.example/team/app#part",
        "https://registry.example/team/app:latest",
    ] {
        assert!(
            Reference::parse(&format!("{value}@{digest}")).is_err(),
            "{value}"
        );
    }
    let tagged = Reference::parse("registry.example/team/app:latest").unwrap();
    assert!(matches!(tagged.selector, Selector::Tag(ref tag) if tag == "latest"));
    let docker = Reference::parse("docker.io/library/alpine:3.24").unwrap();
    assert_eq!(docker.origin.as_str(), "https://registry-1.docker.io/");
    for invalid in [
        "registry.example/team/app:",
        "registry.example/team/app:-bad",
        "registry.example/team/app:has space",
    ] {
        assert!(Reference::parse(invalid).is_err());
    }
    for challenge in [
        "Basic realm=\"registry\"", "Bearer realm=\"http://registry.example/token\",service=\"registry\"",
        "Bearer realm=\"https://registry.example/token?scope=admin\",service=\"registry\"",
        "Bearer realm=\"https://registry.example/token\",realm=\"https://other.example\",service=\"registry\"",
        "Bearer realm=\"https://registry.example/token\",service=\"registry\",scope=\"repository:other:pull\"",
        "Bearer realm=\"https://registry.example/token\",service=\"registry\",scope=\"repository:team/app:pull,push\"",
    ] { assert!(challenge_url(challenge, "team/app").is_err(), "{challenge}"); }
    let url = challenge_url(
        "Bearer realm=\"https://registry.example/token\",service=\"a&scope=admin\"",
        "team/app",
    )
    .unwrap();
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        [
            ("service".into(), "a&scope=admin".into()),
            ("scope".into(), "repository:team/app:pull".into())
        ]
    );
}

#[tokio::test]
async fn cross_origin_redirect_drops_token_and_cookies() {
    let sink = server(|_| response(200, "", b"blob")).await;
    let location = format!(
        "Location: {}/object?grant=disposable\r\nSet-Cookie: session=private\r\n",
        sink.url
    );
    let source = server(move |_| response(307, &location, b"")).await;
    let mut download = downloader(&source, &[&sink]);
    let result = download
        .get(
            download
                .reference
                .endpoint(false, &download.reference.selector),
        )
        .await
        .unwrap();
    assert_eq!(body(result, 4).await.unwrap(), b"blob");
    let source_requests = source.requests.lock().unwrap();
    assert!(source_requests[0]
        .to_ascii_lowercase()
        .contains("authorization: bearer disposable-registry-token"));
    let sink_requests = sink.requests.lock().unwrap();
    let received = sink_requests[0].to_ascii_lowercase();
    assert!(
        !received.contains("authorization:")
            && !received.contains("cookie:")
            && !received.contains("referer:"),
        "{received}"
    );
}

#[tokio::test]
async fn cross_origin_token_realm_requires_explicit_choice() {
    let realm = server(|_| response(200, "", b"{\"token\":\"unexpected\"}")).await;
    let challenge = format!("WWW-Authenticate: Bearer realm=\"{}/token\",service=\"fixture\",scope=\"repository:team/app:pull\"\r\n", realm.url);
    let source = server(move |_| response(401, &challenge, b"")).await;
    let mut download = downloader(&source, &[&realm]);
    download.supplied_token = false;
    download.authorization = None;
    assert!(download
        .get(
            download
                .reference
                .endpoint(true, &download.reference.selector)
        )
        .await
        .err()
        .unwrap()
        .contains("explicitly choose"));
    assert!(realm.requests.lock().unwrap().is_empty());
    download.auth_origin = Url::parse(&realm.url).unwrap();
    assert!(download
        .get(
            download
                .reference
                .endpoint(true, &download.reference.selector)
        )
        .await
        .is_err());
    let requests = realm.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("scope=repository%3Ateam%2Fapp%3Apull"));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
}

#[tokio::test]
async fn anonymous_pull_challenge_retries_with_only_the_issued_pull_token() {
    let origin = Arc::new(Mutex::new(String::new()));
    let address = origin.clone();
    let source = server(move |request| {
        if request.starts_with("GET /token?") {
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(request.contains("scope=repository%3Ateam%2Fapp%3Apull"));
            response(200, "", b"{\"token\":\"issued-pull-token\"}")
        } else if request.to_ascii_lowercase().contains("authorization: bearer issued-pull-token") {
            response(200, "", b"blob")
        } else {
            response(401, &format!("WWW-Authenticate: Bearer realm=\"{}/token\",service=\"fixture\",scope=\"repository:team/app:pull\"\r\n", address.lock().unwrap()), b"")
        }
    }).await;
    *origin.lock().unwrap() = source.url.clone();
    let mut download = downloader(&source, &[]);
    download.supplied_token = false;
    download.authorization = None;
    let response = download
        .get(
            download
                .reference
                .endpoint(false, &download.reference.selector),
        )
        .await
        .unwrap();
    assert_eq!(body(response, 4).await.unwrap(), b"blob");
    assert_eq!(source.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn streamed_and_declared_overruns_are_refused_and_errors_hide_body_and_url() {
    let source = server(|request| {
        if request.contains("/chunked") {
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n".to_vec()
        } else if request.contains("/error") { response(403, "", b"private-server-detail") }
        else { response(200, "", b"12345") }
    }).await;
    let mut download = downloader(&source, &[]);
    for path in ["/chunked", "/declared"] {
        let response = download
            .get(Url::parse(&format!("{}{path}", source.url)).unwrap())
            .await
            .unwrap();
        assert!(body(response, 4).await.unwrap_err().contains("byte budget"));
    }
    let error = download
        .get(Url::parse(&format!("{}/error?secret=hidden", source.url)).unwrap())
        .await
        .err()
        .unwrap();
    assert_eq!(error, "Registry download refused (HTTP 403)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls_pull_verifies_each_pinned_object_on_the_blocking_worker() {
    fn descriptor(bytes: &[u8], media: MediaType) -> Value {
        json!({"mediaType":media,"digest":OciDigest::of(bytes),"size":bytes.len()})
    }
    for (manifest_media, config_media, layer_media) in [
        (
            MediaType::ImageManifest,
            MediaType::ImageConfig,
            MediaType::LayerTar,
        ),
        (
            MediaType::DockerManifest,
            MediaType::DockerConfig,
            MediaType::DockerLayerGzip,
        ),
    ] {
        let config = b"{}".to_vec();
        let layer = b"fixture-layer".to_vec();
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":manifest_media,
        "config":descriptor(&config, config_media),"layers":[descriptor(&layer, layer_media)]}))
        .unwrap();
        let manifest_digest = OciDigest::of(&manifest);
        let config_digest = OciDigest::of(&config);
        let layer_digest = OciDigest::of(&layer);
        let layer_expected = layer.clone();
        let source = server(move |request| {
            let (bytes, media) = if request.contains(&manifest_digest.to_string())
                || request.contains("/manifests/demo ")
            {
                (&manifest, manifest_media)
            } else if request.contains(&config_digest.to_string()) {
                (&config, config_media)
            } else if request.contains(&layer_digest.to_string()) {
                (&layer, layer_media)
            } else {
                return response(404, "", b"");
            };
            response(200, &format!("Content-Type: {media}\r\n"), bytes)
        })
        .await;
        let mut download = downloader(&source, &[]);
        download.reference.selector = Selector::Digest(manifest_digest);
        let mut tagged = downloader(&source, &[]);
        tagged.reference.selector = Selector::Tag("demo".into());
        let (tag_root, _) =
            tokio::task::spawn_blocking(move || tagged.fetch(&image_platform(), &|| true))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(tag_root.digest, manifest_digest);
        let (root, mut blobs) =
            tokio::task::spawn_blocking(move || download.fetch(&image_platform(), &|| true))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(root.media_type, manifest_media);
        assert_eq!(root.digest, manifest_digest);
        assert_eq!(blobs.read_blob(&layer_digest, 100).unwrap(), layer_expected);
        assert_eq!(source.requests.lock().unwrap().len(), 6);
    }
}

#[tokio::test]
async fn digest_mismatch_and_insecure_redirect_do_not_reach_the_importer() {
    let source = server(|request| {
        if request.contains("/redirect") {
            response(302, "Location: http://127.0.0.1/secret\r\n", b"")
        } else {
            response(
                200,
                "Content-Type: application/vnd.oci.image.manifest.v1+json\r\n",
                b"corrupt",
            )
        }
    })
    .await;
    let mut download = downloader(&source, &[]);
    assert!(download
        .fetch_async(&image_platform())
        .await
        .unwrap_err()
        .contains("bytes hash"));
    let error = download
        .get(Url::parse(&format!("{}/redirect", source.url)).unwrap())
        .await
        .err()
        .unwrap();
    assert!(error.contains("HTTPS"));
    assert_eq!(source.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn tagged_pull_refuses_a_false_digest_header() {
    let source = server(|_| response(200,
        &format!("Content-Type: application/vnd.oci.image.manifest.v1+json\r\nDocker-Content-Digest: {}\r\n", OciDigest::of(b"different")), b"{}" )).await;
    let mut download = downloader(&source, &[]);
    download.reference.selector = Selector::Tag("latest".into());
    assert!(download
        .fetch_async(&image_platform())
        .await
        .unwrap_err()
        .contains("digest header"));
    assert_eq!(source.requests.lock().unwrap().len(), 1);
}
