use super::*;

#[tokio::test]
async fn rate_limit_is_reported_without_leaking_helper_output() {
    for line in [
        "{\"level\":\"error\",\"message\":\"Error unmarshaling QuickTunnel response: error code: 1015\\n private-value\"}\n",
        "429 Too Many Requests private-value\n",
    ] {
        let error = connected_url(&mut BufReader::new(line.as_bytes()), None).await.unwrap_err();
        assert_eq!(error, QUICK_RATE_LIMIT);
        assert!(!error.contains("private-value"));
        let named = connected_url(&mut BufReader::new(line.as_bytes()), Some("https://named.example.com".into())).await.unwrap_err();
        assert!(named.contains("account tunnel"));
        assert!(!named.contains(QUICK_RATE_LIMIT));
    }
}

#[test]
fn quick_tunnel_backoff_is_shared_bounded_and_not_extended_by_deferred_retries() {
    let mut retry = QuickRetry::default();
    let mut now = std::time::Instant::now();
    assert!(retry.deferred(now).is_none());
    for seconds in [120, 240, 480, 900, 900] {
        retry.finished(now, false, true);
        assert_eq!(retry.remaining(now), Some(Duration::from_secs(seconds)));
        let deadline = retry.next;
        assert!(retry.deferred(now + Duration::from_secs(15)).unwrap().contains(QUICK_RATE_LIMIT));
        assert_eq!(retry.next, deadline, "A background poll must not extend the block");
        now += Duration::from_secs(seconds);
        assert!(retry.deferred(now).is_none());
    }
    retry.finished(now, true, false);
    assert_eq!(retry.rate_failures, 0);
    assert_eq!(retry.remaining(now), Some(Duration::from_secs(15)));
    now += Duration::from_secs(15);
    retry.finished(now, false, false);
    assert_eq!(retry.remaining(now), Some(Duration::from_secs(30)));
    assert!(!retry.deferred(now).unwrap().contains(QUICK_RATE_LIMIT));
}

fn test_token() -> String {
    STANDARD.encode(serde_json::to_vec(&json!({"a":"0123456789abcdef0123456789abcdef", "t":"01234567-89ab-4def-8123-456789abcdef", "s":STANDARD.encode([7u8;32])})).unwrap())
}

fn options(token: &str) -> AccountOptions {
    AccountOptions {
        hostname: "App.Example.com".into(),
        token: Some(token.into()),
        preset_id: None,
        preset_source_environment_id: None,
        preset_port: None,
        remember: false,
        routes_reviewed: true,
    }
}

// A local helper emits the same registration event as cloudflared. It never
// contacts Cloudflare or accepts real credentials.
fn fake_setup_helper(root: &Path, connected: bool) -> PathBuf {
    #[cfg(windows)]
    let (name, contents) = if connected {
        ("connector.cmd", "@echo off\r\necho {\"message\":\"Registered tunnel connection\"} 1>&2\r\n:wait\r\nping -n 2 127.0.0.1 >nul\r\ngoto wait\r\n")
    } else {
        ("rejected.cmd", "@echo off\r\necho {\"message\":\"Authentication failed\"} 1>&2\r\nexit /b 1\r\n")
    };
    #[cfg(not(windows))]
    let (name, contents) = if connected {
        ("connector.sh", "#!/bin/sh\necho '{\"message\":\"Registered tunnel connection\"}' >&2\nexec sleep 60\n")
    } else {
        ("rejected.sh", "#!/bin/sh\necho '{\"message\":\"Authentication failed\"}' >&2\nexit 1\n")
    };
    let path = root.join(name);
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

async fn setup_account() -> Account {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    Account::resolve("public-presets", 3000, Some(port), options(&test_token())).unwrap()
}

#[tokio::test]
async fn setup_connector_registers_serves_placeholder_and_releases_port_for_publication() {
    let temp = tempfile::tempdir().unwrap();
    let executable = fake_setup_helper(temp.path(), true);
    let account = setup_account().await;
    let setup = SetupTunnel::connect(&executable, temp.path(), &account).await.unwrap();
    let config = setup.started.config.0.clone();
    let port = account.credentials.host_port;
    let response = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .get(format!("http://127.0.0.1:{port}/")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    assert!(response.text().await.unwrap().contains("Connect an environment"));
    assert!(TcpListener::bind(("127.0.0.1", port)).await.is_err());
    let manager = WorkspaceManager::new(temp.path());
    manager.setup_tunnels.lock().await.insert("setup-test".into(), setup);
    let mut different = Account::resolve("public-presets", 3000, Some(port), options(&test_token())).unwrap();
    different.credentials.hostname = "other.example.com".into();
    assert!(finish_setup(&manager, &different).await.is_err());
    assert_eq!(manager.setup_tunnels.lock().await.len(), 1);
    finish_setup(&manager, &account).await.unwrap();
    assert!(manager.setup_tunnels.lock().await.is_empty());
    assert!(!config.exists());
    assert!(TcpListener::bind(("127.0.0.1", port)).await.is_ok());
}

#[tokio::test]
async fn failed_setup_connector_releases_port_and_session_config() {
    let temp = tempfile::tempdir().unwrap();
    let executable = fake_setup_helper(temp.path(), false);
    let account = setup_account().await;
    let error = SetupTunnel::connect(&executable, temp.path(), &account).await.err().unwrap();
    assert!(error.contains("exited before connecting"));
    assert!(!error.contains(&test_token()));
    assert!(TcpListener::bind(("127.0.0.1", account.credentials.host_port)).await.is_ok());
    assert_eq!(std::fs::read_dir(temp.path().join("tools/cloudflare-sessions")).unwrap().count(), 0);
}

#[tokio::test]
async fn setup_connector_cannot_use_an_existing_host_service() {
    let temp = tempfile::tempdir().unwrap();
    let account = setup_account().await;
    let _occupied = TcpListener::bind(("127.0.0.1", account.credentials.host_port)).await.unwrap();
    let error = SetupTunnel::connect(Path::new("must-not-start"), temp.path(), &account).await.err().unwrap();
    assert!(error.contains("already in use"));
    assert!(!temp.path().join("tools/cloudflare-sessions").exists());
}

#[test]
fn preset_credential_keys_require_a_valid_identifier() {
    assert!(preset_key("env-test", 4200, "not-a-preset").is_err());
    assert!(preset_key("../other", 4200, "01234567-89ab-4def-8123-456789abcdef").is_err());
    assert!(preset_key("env-test", 7443, "01234567-89ab-4def-8123-456789abcdef").is_err());
    assert_eq!(preset_key("env-test", 4200, "01234567-89ab-4def-8123-456789abcdef").unwrap(), "env-test:4200:preset:01234567-89ab-4def-8123-456789abcdef");
}

#[test]
fn accepts_variable_length_tunnel_secrets_and_rejects_malformed_values() {
    // Synthetic credentials only: dashboard tokens can contain a UUID-sized secret.
    for secret in [STANDARD.encode([7u8; 32]), STANDARD.encode([9u8; 36])] {
        let token = STANDARD.encode(serde_json::to_vec(&json!({
            "a": "0123456789abcdef0123456789abcdef",
            "t": "01234567-89ab-4def-8123-456789abcdef",
            "s": secret
        })).unwrap());
        assert_eq!(token_id(&token).unwrap(), "01234567-89ab-4def-8123-456789abcdef");
    }
    for secret in ["", "not base64!"] {
        let token = STANDARD.encode(serde_json::to_vec(&json!({
            "a": "0123456789abcdef0123456789abcdef",
            "t": "01234567-89ab-4def-8123-456789abcdef",
            "s": secret
        })).unwrap());
        assert!(token_id(&token).is_err());
    }
}

#[test]
fn validates_hosts_and_tokens_without_echoing_secrets() {
    assert_eq!(hostname(" App.Example.com ").unwrap(), "app.example.com");
    for name in [
        "http://app.example.com",
        "app.example.com:443",
        "app.example.com/path",
        "user@app.example.com",
        "127.0.0.1",
        "x.local",
        "x.trycloudflare.com",
        "*.example.com",
        "example..com",
        "-bad.example.com",
    ] {
        assert!(hostname(name).is_err(), "{name}");
    }
    assert_eq!(
        token_id(&test_token()).unwrap(),
        "01234567-89ab-4def-8123-456789abcdef"
    );
    for secret in [
        "secret-test-do-not-print",
        "cloudflared service install token",
        "eyJhIjoibm90LXZhbGlkIn0=",
    ] {
        let error = token_id(secret).unwrap_err();
        assert!(!error.contains(secret));
    }
    assert!(Account::resolve("env-test", 4200, None, options(&test_token())).is_err());
    let mut not_reviewed = options(&test_token());
    not_reviewed.routes_reviewed = false;
    assert!(Account::resolve("env-test", 4200, Some(45000), not_reviewed).is_err());
}

#[test]
fn named_token_is_passed_only_as_a_child_environment_variable() {
    let token = test_token();
    let account = Account::resolve("env-test", 4200, Some(45000), options(&token)).unwrap();
    let named = command(
        Path::new("cloudflared.exe"),
        Path::new("empty.json"),
        45000,
        Some(&account),
    );
    let args = named
        .as_std()
        .get_args()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            "tunnel",
            "--no-autoupdate",
            "--config",
            "empty.json",
            "--output",
            "json",
            "run"
        ]
    );
    assert!(args.iter().all(|value| !value.contains(&token)));
    assert!(named
        .as_std()
        .get_envs()
        .any(|(key, value)| key == "TUNNEL_TOKEN" && value == Some(std::ffi::OsStr::new(&token))));
    let quick = command(
        Path::new("cloudflared.exe"),
        Path::new("empty.json"),
        45000,
        None,
    );
    assert!(quick.as_std().get_args().any(|value| value == "--url"));
    assert!(!quick
        .as_std()
        .get_envs()
        .any(|(key, value)| key == "TUNNEL_TOKEN" && value.is_some()));
    assert_eq!(account.public_url(), "https://app.example.com");
    assert!(
        account.remember("env-test", 4200).is_ok(),
        "session-only auth must not need a vault"
    );
}

#[test]
fn anonymous_urls_cannot_be_replaced_with_other_origins() {
    assert_eq!(
        quick_url(r#"{"message":"Visit https://small-blue-cat.trycloudflare.com"}"#).as_deref(),
        Some("https://small-blue-cat.trycloudflare.com")
    );
    for text in [
        "https://trycloudflare.com",
        "https://a.trycloudflare.com.evil.test",
        "https://a.trycloudflare.com:8443",
        "https://a.b.trycloudflare.com",
        "http://a.trycloudflare.com",
    ] {
        assert!(quick_url(text).is_none(), "{text}");
    }
}

#[tokio::test]
async fn status_reader_is_bounded_and_empty_configs_are_removed() {
    let mut reader = BufReader::new(&b"first\nsecond\n"[..]);
    assert_eq!(
        bounded_line(&mut reader).await.unwrap().as_deref(),
        Some("first\n")
    );
    assert_eq!(
        bounded_line(&mut reader).await.unwrap().as_deref(),
        Some("second\n")
    );
    assert!(bounded_line(&mut reader).await.unwrap().is_none());
    let large = vec![b'x'; 65537];
    assert!(bounded_line(&mut BufReader::new(&large[..])).await.is_err());
    let temp = tempfile::tempdir().unwrap();
    let config = ConfigFile::create(temp.path()).await.unwrap();
    let path = config.0.clone();
    assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    drop(config);
    assert!(!path.exists());
}

#[tokio::test]
async fn readiness_requires_registration_and_never_substitutes_a_quick_url_for_an_account() {
    let registered = "{\"message\":\"Registered tunnel connection\"}\n";
    let quick = "{\"message\":\"https://test-only.trycloudflare.com\"}\n";
    let mut reader = BufReader::new(quick.as_bytes());
    assert!(
        connected_url(&mut reader, None).await.is_err(),
        "a reserved URL is not a registered connection"
    );
    let log = format!("{quick}{registered}");
    assert_eq!(
        connected_url(&mut BufReader::new(log.as_bytes()), None)
            .await
            .unwrap(),
        "https://test-only.trycloudflare.com"
    );
    assert_eq!(
        connected_url(
            &mut BufReader::new(log.as_bytes()),
            Some("https://app.example.com".into())
        )
        .await
        .unwrap(),
        "https://app.example.com"
    );
    let error = connected_url(
        &mut BufReader::new(&b"{\"error\":\"fake-secret-token\"}\n"[..]),
        Some("https://app.example.com".into()),
    )
    .await
    .unwrap_err();
    assert!(!error.contains("fake-secret-token"));
    assert!(error.contains("No Quick Tunnel fallback"));
}

#[test]
fn startup_errors_only_request_credentials_for_account_tunnels() {
    for timed_out in [false, true] {
        let quick = startup_error(false, timed_out);
        assert!(quick.contains("Quick Tunnel"));
        assert!(quick.contains("No account or tunnel token is required"));
        assert!(!quick.contains("dashboard"));
        assert!(!quick.contains("fallback"));
        let named = startup_error(true, timed_out);
        assert!(named.contains("account tunnel"));
        assert!(named.contains("Check the tunnel token"));
        assert!(named.contains("No Quick Tunnel fallback"));
    }
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "runs the installed helper against a loopback-only fake Quick Tunnel API; never publishes a service"]
async fn installed_quick_tunnel_reaches_local_api_with_isolated_config() {
    let root = PathBuf::from(std::env::var_os("APPDATA").unwrap()).join("com.yougori.desktop");
    let executable = super::super::cloudflared(&root).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let config = ConfigFile::create(temp.path()).await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = api.local_addr().unwrap();
    let mut server = tokio::spawn(async move {
        let (mut stream, _) = api.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let size = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..size]).starts_with("POST /tunnel "));
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
    });
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        command(&executable, &config.0, 45000, None)
            .args(["--quick-service", &format!("http://{address}")])
            .stdout(Stdio::piped())
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let reached = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
    server.abort();
    assert!(
        matches!(reached, Ok(Ok(()))),
        "Helper did not reach the loopback-only API. stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .is_some_and(|value| {
                    value["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("Requesting new quick Tunnel"))
                })
        }),
        "The actual helper must emit JSON status messages for the readiness reader"
    );
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "creates a real temporary no-account tunnel serving only a test string, then closes it; requires Internet"]
async fn live_quick_tunnel_serves_only_a_test_fixture_and_closes() {
    let root = PathBuf::from(std::env::var_os("APPDATA").unwrap()).join("com.yougori.desktop");
    let executable = super::super::cloudflared(&root).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let body = format!("Yougori tunnel regression test {}", Uuid::new_v4());
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    struct TestServer(JoinHandle<()>);
    impl Drop for TestServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = TestServer(tokio::spawn(async move {
        while let Ok((mut stream, _)) = origin.accept().await {
            let response = &response;
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let mut request = [0u8; 4096];
                let _read = stream.read(&mut request).await?;
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await
            })
            .await;
        }
    }));
    let mut tunnel = start(&executable, temp.path(), port, None)
        .await
        .expect("The no-account helper must connect");
    let config_path = tunnel.config.0.clone();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    // A local resolver may cache NXDOMAIN for a newly reserved Quick Tunnel.
    // This diagnostic-only override preserves HTTPS hostname verification and
    // does not modify the app's resolver or this PC's network settings.
    let public_host = url::Url::parse(&tunnel.url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    let mut clients = vec![("system DNS", client.clone())];
    let mut dns_url = url::Url::parse("https://cloudflare-dns.com/dns-query").unwrap();
    dns_url
        .query_pairs_mut()
        .append_pair("name", &public_host)
        .append_pair("type", "A");
    if let Ok(response) = client
        .get(dns_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        if let Ok(data) = response.json::<Value>().await {
            let addresses: Vec<std::net::SocketAddr> = data["Answer"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|answer| answer["type"] == 1)
                .filter_map(|answer| {
                    answer["data"]
                        .as_str()?
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| (ip, 443).into())
                })
                .collect();
            if !addresses.is_empty() {
                clients.push((
                    "Cloudflare public DNS",
                    reqwest::Client::builder()
                        .timeout(Duration::from_secs(5))
                        .resolve_to_addrs(&public_host, &addresses)
                        .build()
                        .unwrap(),
                ));
            }
        }
    }
    let mut last_failure = String::from("No request completed");
    let verified = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for (resolver, client) in &clients {
                match client.get(&tunnel.url).send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success()
                            && response.text().await.ok().as_deref() == Some(&body)
                        {
                            eprintln!("Verified temporary test page over HTTPS using {resolver}");
                            return;
                        }
                        last_failure = format!("HTTP {status}; fixture body not received");
                    }
                    Err(error) => last_failure = format!("{:?}", error.without_url()),
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .is_ok();
    tunnel.child.kill().await.unwrap();
    assert!(tunnel.child.try_wait().unwrap().is_some());
    tunnel.logs.abort();
    drop(tunnel);
    assert!(!config_path.exists());
    assert!(
        verified,
        "A real HTTPS request must return only the fixture body through the no-account tunnel: {last_failure}"
    );
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "runs the installed account connector with an invalid test token; fails before any connection"]
async fn installed_account_connector_validates_token_without_connecting() {
    let root = PathBuf::from(std::env::var_os("APPDATA").unwrap()).join("com.yougori.desktop");
    assert!(
        root.join("tools/cloudflared-2026.8.3.exe").is_file(),
        "Install the pinned helper before running this local CLI test"
    );
    let executable = super::super::cloudflared(&root).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let config = ConfigFile::create(temp.path()).await.unwrap();
    let account = Account::resolve("env-test", 4200, Some(45000), options(&test_token())).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        command(&executable, &config.0, 45000, Some(&account))
            .env("TUNNEL_TOKEN", "invalid-test-token")
            .stdout(Stdio::piped())
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result.status.success());
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.contains("flag provided but not defined"));
    assert!(
        output.contains("Provided Tunnel token is not valid"),
        "The account connector must reach token validation"
    );
}

#[cfg(windows)]
#[test]
#[ignore = "writes then removes an isolated fake credential in the Windows credential vault"]
fn windows_vault_round_trip_uses_only_a_unique_test_credential() {
    let id = format!("env-cloudflare-test-{}", Uuid::new_v4().simple());
    let vault = entry(&id, 4200).unwrap();
    struct Cleanup(keyring::Entry);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.delete_credential();
        }
    }
    assert!(load(&id, 4200).unwrap().is_none());
    let cleanup = Cleanup(vault);
    let mut saved_options = options(&test_token());
    saved_options.remember = true;
    let account = Account::resolve(&id, 4200, Some(45000), saved_options).unwrap();
    account.remember(&id, 4200).unwrap();
    let saved = load(&id, 4200).unwrap().unwrap();
    assert_eq!(saved.hostname, "app.example.com");
    assert_eq!(saved.host_port, 45000);
    assert!(saved.token == test_token());
    // Reconnecting reads the token natively from this node/port's vault entry.
    let mut reconnect = options("");
    reconnect.token = None;
    let account = Account::resolve(&id, 4200, Some(45000), reconnect).unwrap();
    assert!(account.credentials.token == test_token());
    assert_eq!(account.public_url(), "https://app.example.com");
    assert!(load(&id, 4201).unwrap().is_none());
    assert!(load(&format!("{id}-other"), 4200).unwrap().is_none());
    let preset_id = Uuid::new_v4().to_string();
    let preset = Cleanup(preset_entry(&id, 4200, &preset_id).unwrap());
    preset.0.set_password(&serde_json::to_string(&Credentials {
        hostname: "preset.example.com".into(), host_port: 45001, token: test_token(),
    }).unwrap()).unwrap();
    let mut preset_options = options("");
    preset_options.hostname = "preset.example.com".into();
    preset_options.token = None;
    preset_options.preset_id = Some(preset_id.clone());
    let resolved = Account::resolve(&id, 4200, Some(45001), preset_options).unwrap();
    assert_eq!(resolved.public_url(), "https://preset.example.com");
    assert_eq!(resolved.credentials.token, test_token());
    let mut other_environment = options("");
    other_environment.hostname = "preset.example.com".into();
    other_environment.token = None;
    other_environment.preset_id = Some(preset_id.clone());
    other_environment.preset_source_environment_id = Some(id.clone());
    let reused = Account::resolve("another-environment", 4200, Some(45001), other_environment).unwrap();
    assert_eq!(reused.credentials.token, test_token());
    let mut wrong_route = options("");
    wrong_route.token = None;
    wrong_route.preset_id = Some(preset_id);
    assert!(Account::resolve(&id, 4200, Some(45001), wrong_route).is_err());
    drop(preset);
    drop(cleanup);
    assert!(load(&id, 4200).unwrap().is_none());
}

#[test]
fn saved_domains_keep_one_hostname_and_one_tunnel_port_each() {
    let domain = |id: &str, hostname: &str, host_port: u16| crate::models::SavedDomain {
        id: id.into(), credential_environment_id: "public-presets".into(), port: 3000, hostname: hostname.into(), host_port,
    };
    let saved = vec![domain("a", "app.example.com", 45000)];
    assert!(domain_conflict(&saved, &domain("a", "app.example.com", 45000)).is_ok(), "re-saving the same domain replaces it");
    assert!(domain_conflict(&saved, &domain("b", "APP.example.com", 45001)).is_err());
    assert!(domain_conflict(&saved, &domain("b", "api.example.com", 45000)).is_err());
    assert!(domain_conflict(&saved, &domain("b", "api.example.com", 45001)).is_ok());
    let full = (0..200).map(|i| domain(&i.to_string(), &format!("d{i}.example.com"), 10_000 + i)).collect::<Vec<_>>();
    assert!(domain_conflict(&full, &domain("new", "new.example.com", 60000)).is_err());
    assert!(domain_conflict(&full, &domain("0", "d0.example.com", 10_000)).is_ok());
}
