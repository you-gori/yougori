use super::*;

fn grant(permission: Permission) -> Grant {
    Grant {
        id: "share-test".into(),
        target_id: "env-test".into(),
        username: "alice".into(),
        permission,
        expires_at: Some(now() + 3600),
        folder: Some("/workspace".into()),
        salt: "salt".into(),
        verifier: "hash".into(),
        revoked: false,
        acknowledge_existing_access: false,
    }
}
#[test]
fn permissions_never_turn_file_editing_into_execution() {
    for permission in [Permission::View, Permission::Edit] {
        let g = grant(permission.clone());
        for method in [
            "exec",
            "terminal",
            "power",
            "apps",
            "skills",
            "installer",
            "desktop",
            "get_platform_state",
            "vault_control",
            "approve",
            "host_terminal_action",
            "create_remote_share",
        ] {
            assert!(g.authorize(method, &json!({})).is_err(), "{method}");
        }
        assert!(g.authorize("files", &json!({"operation":"read"})).is_ok());
        assert_eq!(
            g.authorize("files", &json!({"operation":"write"})).is_ok(),
            permission == Permission::Edit
        );
    }
    let g = grant(Permission::Control);
    assert!(g.authorize("terminal", &json!({})).is_ok());
    for method in ["apps", "skills", "installer", "desktop"] {
        assert!(g.authorize(method, &json!({})).is_ok());
    }
    assert!(g.authorize("vault_control", &json!({})).is_err());
    let mut pc = g.clone();
    pc.target_id = "my-pc".into();
    for method in ["exec", "terminal", "power", "console", "desktop", "apps", "skills", "installer"] {
        assert!(pc.authorize(method, &json!({})).is_err());
    }
}
#[test]
fn expiration_and_revocation_deny_every_request() {
    for method in ["inspect", "console", "files", "exec", "terminal", "power", "apps", "skills", "installer", "desktop"] {
        let mut g = grant(Permission::Control);
        g.revoked = true;
        assert!(g.authorize(method, &json!({"operation":"read"})).is_err());
        g.revoked = false;
        g.expires_at = Some(now() - 1);
        assert!(g.authorize(method, &json!({"operation":"read"})).is_err());
    }
    let cancel = CancellationToken::new();
    let session = Session {
        grant: "g".into(),
        owner: "s".into(),
        seen: now(),
        expires: now() + 60,
        cancel: cancel.clone(),
    };
    drop(session);
    assert!(cancel.is_cancelled());
}
#[test]
fn strong_salted_verifiers_and_no_plaintext_persistence() {
    let password = "a long test password";
    let first = verifier(password, "one").unwrap();
    let second = verifier(password, "two").unwrap();
    assert_ne!(first, second);
    assert!(equal(&first, &verifier(password, "one").unwrap()));
    assert!(!equal(&first, &verifier("wrong password", "one").unwrap()));
    assert!(validate_password("short").is_err());
    let dir = tempfile::tempdir().unwrap();
    let manager = RemoteAccess::new(dir.path().to_owned()).unwrap();
    let mut g = grant(Permission::View);
    g.verifier = first;
    let db = Database {
        grants: vec![g],
        ..Default::default()
    };
    manager.save(&db).unwrap();
    let stored = std::fs::read_to_string(dir.path().join("remote-access.json")).unwrap();
    assert!(!stored.contains(password));
    assert_eq!(
        RemoteAccess::new(dir.path().to_owned())
            .unwrap()
            .db
            .blocking_lock()
            .grants
            .len(),
        1
    );
}
#[tokio::test]
async fn sign_in_rate_limit_is_per_recipient_and_client_so_floods_cannot_lock_out_everyone() {
    let dir = tempfile::tempdir().unwrap();
    let manager = RemoteAccess::new(dir.path().to_owned()).unwrap();
    for n in 0..5 {
        manager.rate_limit(&format!("198.51.100.{n}"), "share\nalice").await.unwrap();
    }
    assert!(manager.rate_limit("198.51.100.9", "share\nalice").await.is_err());
    // One client spraying invented shares is stopped without affecting other recipients or clients.
    for n in 0..10 {
        manager.rate_limit("203.0.113.7", &format!("invented-{n}\nuser")).await.unwrap();
    }
    assert!(manager.rate_limit("203.0.113.7", "share\nbob").await.is_err());
    assert!(manager.rate_limit("192.0.2.1", "share\nbob").await.is_ok());
    manager
        .attempts
        .lock()
        .await
        .iter_mut()
        .for_each(|(at, _, _)| *at = now() - 61);
    assert!(manager.rate_limit("198.51.100.9", "share\nalice").await.is_ok());
    assert_eq!(client_address("POST / HTTP/1.1\r\nCF-Connecting-IP: 2001:db8::1\r\n"), "2001:db8::1");
    assert_eq!(client_address("POST / HTTP/1.1\r\nCF-Connecting-IP: not an address\r\n"), "direct");
    assert_eq!(client_address("POST / HTTP/1.1\r\n"), "direct");
}
#[test]
fn unreadable_sharing_state_is_kept_aside_and_sharing_resets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("remote-access.json"), b"{ damaged").unwrap();
    let manager = RemoteAccess::new(dir.path().to_owned()).unwrap();
    assert!(manager.db.blocking_lock().grants.is_empty());
    assert!(!dir.path().join("remote-access.json").exists());
    let kept = std::fs::read_dir(dir.path()).unwrap().filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("remote-access.json.unreadable-"))
        .expect("damaged state is kept for inspection");
    assert_eq!(std::fs::read(kept.path()).unwrap(), b"{ damaged");
}
#[test]
fn share_urls_cannot_contain_passwords_or_redirect_to_plaintext() {
    let path = format!("/share/share-{}", "a".repeat(32));
    assert!(client::share_url(&format!("https://example.com{path}")).is_ok());
    for url in [
        format!("http://example.com{path}"),
        format!("https://user:password@example.com{path}"),
        format!("https://example.com{path}?password=secret"),
        format!("https://example.com{path}#fragment"),
        format!("https://example.com:444{path}"),
        "https://example.com/share/../../rpc".into(),
    ] {
        assert!(client::share_url(&url).is_err(), "{url}");
    }
}
#[test]
fn pc_files_are_scoped_read_only_and_chunk_bounded() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let folder = root.path().to_str().unwrap();
    std::fs::write(root.path().join("hello"), b"hello world").unwrap();
    std::fs::write(outside.path().join("private"), b"secret").unwrap();
    let result = files::pc_operation(
        folder,
        &Permission::View,
        json!({"operation":"read","path":"hello","length":5}),
    )
    .unwrap();
    assert_eq!(result["data"], "aGVsbG8=");
    for path in ["../private", "/private", "C:/private", "..\\private"] {
        assert!(files::pc_operation(
            folder,
            &Permission::Control,
            json!({"operation":"read","path":path})
        )
        .is_err());
    }
    assert!(files::pc_operation(
        folder,
        &Permission::View,
        json!({"operation":"write","path":"hello","data":"eA=="})
    )
    .is_err());
    files::pc_operation(
        folder,
        &Permission::Edit,
        json!({"operation":"create","path":"new"}),
    )
    .unwrap();
    files::pc_operation(
        folder,
        &Permission::Edit,
        json!({"operation":"write","path":"new","data":"aGVsbG8="}),
    )
    .unwrap();
    assert_eq!(std::fs::read(root.path().join("new")).unwrap(), b"hello");
    files::pc_operation(
        folder,
        &Permission::Edit,
        json!({"operation":"replace","path":"new","expectedData":"aGVsbG8=","data":"bmV3"}),
    )
    .unwrap();
    assert_eq!(std::fs::read(root.path().join("new")).unwrap(), b"new");
    assert!(files::pc_operation(
        folder,
        &Permission::Edit,
        json!({"operation":"replace","path":"new","expectedData":"aGVsbG8=","data":"bG9zdA=="})
    )
    .is_err());
    std::fs::hard_link(outside.path().join("private"), root.path().join("hard")).unwrap();
    assert!(files::pc_operation(
        folder,
        &Permission::View,
        json!({"operation":"read","path":"hard","length":5})
    )
    .is_err());

    assert!(files::pc_operation(
        folder,
        &Permission::Edit,
        json!({"operation":"remove","path":""})
    )
    .is_err());
    assert!(files::validate_pc_root(folder, &[root.path().to_owned()]).is_err());
}
#[test]
fn activity_is_bounded_and_contains_no_request_payloads() {
    let mut db = Database::default();
    for _ in 0..600 {
        push_audit(&mut db, "share-test", "file operation", true);
    }
    assert_eq!(db.audit.len(), 500);
    assert!(!serde_json::to_string(&db.audit)
        .unwrap()
        .contains("password"));
}

#[cfg(windows)]
#[test]
fn gateway_authentication_and_revocation_over_real_http() {
    let directory = tempfile::tempdir().unwrap();
    // The OS temp directory can be inside LOCALAPPDATA, which the share
    // validator correctly rejects. Keep the test folder outside that tree.
    let shared = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    std::fs::write(shared.path().join("hello.txt"), "hello").unwrap();
    let mut context = tauri::generate_context!();
    context.config_mut().app.windows.clear();
    let app = tauri::Builder::default()
        .any_thread()
        .manage(PlatformStore::load(directory.path().join("state.json")).unwrap())
        .manage(
            RuntimeManager::new(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
                directory.path(),
            )
            .unwrap(),
        )
        .manage(WorkspaceManager::new(directory.path()))
        .manage(RemoteAccess::new(directory.path().to_owned()).unwrap())
        .build(context)
        .unwrap();
    tauri::async_runtime::block_on(async {
        let handle = app.handle().clone();
        let value = create_remote_share(
            CreateShare {
                target_id: "my-pc".into(),
                username: "alice".into(),
                password: "strong initial password".into(),
                permission: Permission::View,
                expires_at: Some(now() + 3600),
                folder: Some(shared.path().to_str().unwrap().into()),
                confirm_pc_files: true,
                acknowledge_existing_access: false,
            },
            handle.clone(),
            handle.state::<RemoteAccess>(),
        )
        .await
        .unwrap();
        let id = value["id"].as_str().unwrap();
        if std::env::var("YOUGORI_TEST_REMOTE_TUNNEL").as_deref() == Ok("1") {
            let tunnel =
                start_remote_tunnel(None, None, handle.clone(), handle.state::<RemoteAccess>())
                    .await
                    .unwrap();
            let link = format!("{}/share/{id}", tunnel["url"].as_str().unwrap());
            let mut result = None;
            let mut last_error = String::new();
            for _ in 0..4 {
                match connect_remote_share(
                    link.clone(),
                    "alice".into(),
                    "strong initial password".into(),
                    None,
                    handle.state::<PlatformStore>(),
                    handle.state::<RuntimeManager>(),
                )
                .await
                {
                    Ok(state) => {
                        result = Some(state);
                        break;
                    }
                    Err(error) => {
                        last_error = error;
                        tokio::time::sleep(Duration::from_secs(5)).await
                    }
                }
            }
            let state =
                result.unwrap_or_else(|| panic!("Cloudflare HTTPS sign-in failed: {last_error}"));
            let remote = state
                .environments
                .iter()
                .find(|e| e.runtime.starts_with("shared://tunnel/"))
                .unwrap();
            let read = request_saved(
                remote,
                "files",
                json!({"operation":"read","path":"hello.txt","length":5}),
            )
            .await
            .unwrap();
            assert_eq!(read["data"], "aGVsbG8=");
            let download = client::download_remote_folder(
                remote.id.clone(),
                String::new(),
                directory.path().to_str().unwrap().into(),
                handle.state::<PlatformStore>(),
            )
            .await
            .unwrap();
            let downloaded = PathBuf::from(download["folder"].as_str().unwrap());
            assert_eq!(
                std::fs::read_to_string(downloaded.join("hello.txt")).unwrap(),
                "hello"
            );
            request_saved(remote, "logout", json!({})).await.unwrap();
            forget(&remote.id).unwrap();
            stop_remote_tunnel(handle.clone(), handle.state::<RemoteAccess>())
                .await
                .unwrap();
            handle.state::<RemoteAccess>().attempts.lock().await.clear();
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(serve(listener, handle.clone()));
        let client = reqwest::Client::new();
        let sign_in = |password: &'static str| {
            client
                .post(format!("{base}/remote/login"))
                .json(&json!({"shareId":id,"username":"alice","password":password}))
                .send()
        };
        assert_eq!(sign_in("wrong").await.unwrap().status(), 403);
        let response: Value = sign_in("strong initial password")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = response["token"].as_str().unwrap();
        let rpc = |method: &str, params: Value| {
            client
                .post(format!("{base}/remote/rpc"))
                .bearer_auth(token)
                .json(&json!({"method":method,"params":params}))
                .send()
        };
        assert!(rpc("inspect", json!({}))
            .await
            .unwrap()
            .status()
            .is_success());
        assert_eq!(
            rpc("exec", json!({"command":"not executed"}))
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(rpc("vault_control", json!({})).await.unwrap().status(), 403);
        let file: Value = rpc(
            "files",
            json!({"operation":"read","path":"hello.txt","length":5,"root":"C:/"}),
        )
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(file["data"], "aGVsbG8=");
        assert_eq!(
            rpc(
                "files",
                json!({"operation":"write","path":"hello.txt","data":"eA=="})
            )
            .await
            .unwrap()
            .status(),
            403
        );
        let cross_origin = client
            .post(format!("{base}/remote/rpc"))
            .header("Origin", "https://untrusted.example")
            .bearer_auth(token)
            .json(&json!({"method":"inspect","params":{}}))
            .send()
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), 403);
        update_remote_share(
            id.into(),
            None,
            Some("replacement password".into()),
            false,
            handle.clone(),
            handle.state::<RemoteAccess>(),
        )
        .await
        .unwrap();
        assert_eq!(rpc("inspect", json!({})).await.unwrap().status(), 403);
        assert_eq!(
            sign_in("strong initial password").await.unwrap().status(),
            403
        );
        assert!(sign_in("replacement password")
            .await
            .unwrap()
            .status()
            .is_success());
        update_remote_share(
            id.into(),
            None,
            None,
            true,
            handle.clone(),
            handle.state::<RemoteAccess>(),
        )
        .await
        .unwrap();
        handle.state::<RemoteAccess>().attempts.lock().await.clear();
        assert_eq!(sign_in("replacement password").await.unwrap().status(), 403);
        assert_eq!(
            std::fs::read_to_string(shared.path().join("hello.txt")).unwrap(),
            "hello"
        );
        let audit =
            serde_json::to_string(&handle.state::<RemoteAccess>().db.lock().await.audit).unwrap();
        assert!(!audit.contains(token));
        assert!(!audit.contains("strong initial password"));
        task.abort();
    });
}
