use super::*;

#[test]
fn automatic_storage_cleanup_waits_for_idle_containers_and_finished_startup() {
    use crate::models::EnvironmentStatus;
    let data = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let mut state = store.snapshot().unwrap();
    state.environments.clear();
    assert!(storage_maintenance_idle(&state));
    state.environments.push(serde_json::from_value(json!({
        "id":"env-maintenance", "name":"test", "kind":"container", "provider":"yougoriCuda", "status":"stopped",
        "runtime":"ubuntu", "description":"fixture", "createdAt":"test", "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
        "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":true}
    })).unwrap());
    for status in [EnvironmentStatus::Running, EnvironmentStatus::Paused, EnvironmentStatus::Provisioning] {
        state.environments[0].status = status;
        assert!(!storage_maintenance_idle(&state));
    }
    state.environments[0].status = EnvironmentStatus::Stopped;
    assert!(storage_maintenance_idle(&state));
    state.startup_report = Some(crate::lifecycle::StartupReport {
        started_at:"test".into(), completed_at:None, status:"running".into(), trigger:"engineLaunch".into(),
        starts_before_sign_in:false, service_registration:None, environments:vec![],
    });
    assert!(!storage_maintenance_idle(&state));
}

#[cfg(all(windows, not(feature = "engine-only")))]
#[test]
#[ignore = "opens isolated native windows and a disposable OCI container; tests background close through the real CLI transport without user data or public tunnels"]
fn desktop_close_keeps_environments_shares_and_services_running() {
    use crate::{backup::BackupManager, workspace::WorkspaceManager};
    crate::install_async_runtime();
    let data = tempfile::tempdir().unwrap();
    let share = tempfile::tempdir().unwrap();
    std::fs::write(share.path().join("marker.txt"), "HOST_SHARE_STILL_AVAILABLE").unwrap();
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
    store.mutate(|state| {
        state.host = crate::commands::collect_host_metrics(&state.host, runtime.storage_root());
        state.providers = runtime.provider_statuses();
        Ok(())
    }).unwrap();
    let endpoint = format!("{}-background-close-{}", wire::endpoint().unwrap(), uuid::Uuid::new_v4().simple());
    let result = Arc::new(std::sync::Mutex::new(None));
    let test_result = result.clone();
    let mut context = tauri::generate_context!();
    context.config_mut().identifier = format!("com.yougori.background-close-test-{}", uuid::Uuid::new_v4().simple());
    context.config_mut().app.windows.clear();
    let backup = BackupManager::new(data.path()).unwrap();
    let workspace = WorkspaceManager::new(data.path());
    let app = tauri::Builder::default().any_thread()
        .manage(store).manage(runtime).manage(backup).manage(workspace)
        .manage(crate::peer_sharing::Sharing::default())
        .manage(crate::host_terminal::HostTerminalManager::default())
        .setup(move |app| {
            for label in ["main", "guest-background-close"] {
                tauri::WebviewWindowBuilder::new(app, label, tauri::WebviewUrl::External("about:blank".parse().unwrap()))
                    .visible(false).data_directory(data.path().join(label)).build()?;
            }
            start_at(app.handle(), false, endpoint.clone()).map_err(std::io::Error::other)?;
            let app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let exercise_app = app.clone();
                let share_path = share.path().to_owned();
                let outcome = tokio::spawn(exercise_background_close(exercise_app, endpoint, share_path))
                    .await.map_err(|error| error.to_string()).and_then(|result| result);
                app.state::<WorkspaceManager>().shutdown(&app.state::<RuntimeManager>()).await;
                app.state::<RuntimeManager>().shutdown_all().await;
                *test_result.lock().unwrap() = Some(outcome);
                // Native WebView profiles must remain until the windows exit.
                app.manage((data, share));
                app.exit(0);
            });
            Ok(())
        }).build(context).unwrap();
    assert_eq!(app.run_return(|_, _| {}), 0);
    result.lock().unwrap().take().expect("background close test did not finish").unwrap();
}

#[cfg(all(windows, not(feature = "engine-only")))]
async fn exercise_background_close(app: AppHandle, endpoint: String, share: std::path::PathBuf) -> Result<(), String> {
    use crate::models::EnvironmentStatus;
    use yougori_cli::client::{call_at, request, wait_job_at};
    async fn call(endpoint: &str, method: &str, params: Value) -> Result<Value, String> {
        let mut req = request(method, params);
        req.confirmed = true;
        let reply = call_at(endpoint, &req).await?;
        if reply["accepted"] == true {
            wait_job_at(endpoint, reply["jobId"].as_str().ok_or("Missing job ID")?, 180).await
        } else { Ok(reply) }
    }
    eprintln!("Background close: creating an isolated container");
    let created = call(&endpoint, "create_environment", json!({"request":{
        "name":"background-close-test","kind":"container","provider":"yougoriOci",
        "runtime":"quay.io/libpod/alpine:latest","storageGb":6,"description":"Temporary close regression test",
        "networkAccess":false,"gpuAccess":false,
        "resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":2},"memoryGb":{"min":0.5,"preferred":0.5,"max":1},"priority":"normal"}
    }})).await?;
    let id = created["environments"].as_array().ok_or("Missing environments")?.iter()
        .find(|env| env["name"] == "background-close-test").and_then(|env| env["id"].as_str())
        .ok_or("Missing test environment")?.to_owned();
    call(&endpoint, "set_environment_status", json!({"environmentId":id,"status":"running"})).await?;
    // This minimal image includes netcat but has no httpd applet. Validate the
    // response inside the guest before relying on the host publication.
    let server = r#"set -e; printf ENVIRONMENT_STILL_RUNNING > /tmp/background-close-marker; printf '%s\n' '#!/bin/sh' 'while IFS= read -r header; do [ "$header" = "$(printf "\r")" ] && break; done' 'printf "HTTP/1.0 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\nENVIRONMENT_STILL_RUNNING"' 'cat >/dev/null' > /tmp/background-close-http; chmod 700 /tmp/background-close-http; sh -c 'while true; do nc -l -p 8090 -e /tmp/background-close-http; done' </dev/null >/tmp/background-close-http.log 2>&1 &"#;
    let started = call(&endpoint, "execute_environment_command", json!({"request":{"environmentId":id,"command":server}})).await?;
    assert_eq!(started["exitCode"], 0, "{started}");
    let local = call(&endpoint, "execute_environment_command", json!({"request":{"environmentId":id,"command":"wget -T 5 -qO- http://127.0.0.1:8090/"}})).await?;
    assert_eq!(local["exitCode"], 0, "{local}");
    assert_eq!(local["stdout"], "ENVIRONMENT_STILL_RUNNING");
    let host = call(&endpoint, "attach_host_folder", json!({"environmentId":id,"path":share.to_string_lossy(),"readOnly":true})).await?;
    let mount = host["mountPath"].as_str().ok_or("Missing share mount")?.to_owned();
    let host_port = {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        reservation.local_addr().map_err(|e| e.to_string())?.port()
    };
    let publication = call(&endpoint, "publish_environment_service", json!({"environmentId":id,"port":8090,"kind":"loopback","hostPort":host_port})).await?;
    let url = publication["urls"][0].as_str().ok_or("Missing local service URL")?.to_owned();
    let http = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    assert_eq!(http.get(&url).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?, "ENVIRONMENT_STILL_RUNNING");
    let main = app.get_webview_window("main").ok_or("Missing dashboard")?;
    let guest = app.get_webview_window("guest-background-close").ok_or("Missing guest window")?;
    main.show().map_err(|e| e.to_string())?;
    guest.show().map_err(|e| e.to_string())?;
    assert!(main.is_visible().map_err(|e| e.to_string())?);
    assert!(guest.is_visible().map_err(|e| e.to_string())?);

    // Provisioning and paused nodes also permit closing only the UI. These
    // state-only fixtures must never be started, stopped or attached to disks.
    app.state::<PlatformStore>().mutate(|state| {
        let fixture = state.environments.iter().find(|env| env.id == id).ok_or("Missing fixture")?.clone();
        for (suffix, status) in [("paused", EnvironmentStatus::Paused), ("provisioning", EnvironmentStatus::Provisioning)] {
            let mut env = fixture.clone();
            env.id = format!("env-close-fixture-{suffix}");
            env.runtime_id = None;
            env.status = status;
            state.environments.push(env);
        }
        Ok(())
    })?;
    let before = serde_json::to_value(app.state::<PlatformStore>().snapshot()?).map_err(|e| e.to_string())?;
    eprintln!("Background close: hiding both windows while services keep running");
    call(&endpoint, "finish_app_close", json!({"keepRunning":true})).await?;
    assert!(!main.is_visible().map_err(|e| e.to_string())?);
    assert!(!guest.is_visible().map_err(|e| e.to_string())?);
    assert_eq!(serde_json::to_value(app.state::<PlatformStore>().snapshot()?).map_err(|e| e.to_string())?, before);
    assert_eq!(call(&endpoint, "app_status", json!({})).await?["running"], true);
    let output = call(&endpoint, "execute_environment_command", json!({"request":{"environmentId":id,"command":format!("cat '{mount}/marker.txt'")}})).await?;
    assert_eq!(output["exitCode"], 0, "{output}");
    assert_eq!(output["stdout"], "HOST_SHARE_STILL_AVAILABLE");
    let marker = call(&endpoint, "execute_environment_command", json!({"request":{"environmentId":id,"command":"cat /tmp/background-close-marker"}})).await?;
    assert_eq!(marker["exitCode"], 0, "{marker}");
    assert_eq!(marker["stdout"], "ENVIRONMENT_STILL_RUNNING");
    assert_eq!(http.get(&url).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?, "ENVIRONMENT_STILL_RUNNING");
    call(&endpoint, "app_show", json!({})).await?;
    assert!(main.is_visible().map_err(|e| e.to_string())?);
    assert!(main.is_visible().map_err(|e| e.to_string())?);
    // Reopening must not make the next background close stop the engine.
    call(&endpoint, "finish_app_close", json!({"keepRunning":true})).await?;
    call(&endpoint, "app_show", json!({})).await?;
    assert!(main.is_visible().map_err(|e| e.to_string())?);
    app.state::<PlatformStore>().mutate(|state| {
        state.environments.retain(|env| !env.id.starts_with("env-close-fixture-"));
        Ok(())
    })?;
    call(&endpoint, "finish_app_close", json!({"keepRunning":true})).await?;
    headless_tick(&app).await;
    assert_eq!(app.state::<PlatformStore>().snapshot()?.environments[0].status, EnvironmentStatus::Running);
    call(&endpoint, "app_show", json!({})).await?;
    eprintln!("Background close passed: CLI, container data, host share, publication and reopen remained available");
    Ok(())
}

#[test]
fn job_snapshots_expose_latest_copy_measurement_without_changing_results() {
    let (sender, progress) = tokio::sync::watch::channel(None);
    let mut job = Job {
        id: "copy".into(), method: "copy_files_to_environment".into(), status: "running",
        created: "now".into(), completed: None, completed_at: None, result: None,
        error: None, bytes: 0, progress,
        ..Job::default()
    };
    assert!(job.value(true).get("progress").is_none());
    sender.send_replace(Some(serde_json::to_value(crate::file_import::CopyProgress {
        phase: "copying", completed_bytes: 45, total_bytes: 100, scanned_entries: None, ..Default::default()
    }).unwrap()));
    assert_eq!(job.value(true)["progress"]["completedBytes"], 45);
    sender.send_replace(Some(json!({"phase":"finishing","completedBytes":100,"totalBytes":100})));
    job.status = "complete";
    job.result = Some(json!({"destination":"/copied","files":2,"bytes":90}));
    assert_eq!(job.value(true)["progress"]["phase"], "finishing");
    assert_eq!(job.value(true)["result"]["destination"], "/copied");
    assert!(job.value(false).get("result").is_none());
    assert_eq!(job.value(false)["progress"], job.value(true)["progress"]);
}

#[test]
fn job_history_is_bounded_and_never_drops_running_operations() {
    let mut jobs = VecDeque::new();
    for index in 0..80 {
        jobs.push_back(Job {
            id: index.to_string(),
            method: "test".into(),
            status: if index == 0 { "running" } else { "complete" },
            created: "now".into(),
            completed: if index == 0 {
                None
            } else {
                Some(Instant::now())
            },
            completed_at: None,
            result: None,
            error: None,
            bytes: 1024 * 1024,
            progress: tokio::sync::watch::channel(None).1,
            ..Job::default()
        });
    }
    Control::prune(&mut jobs);
    assert!(jobs.len() <= HISTORY);
    assert!(jobs.iter().any(|j| j.id == "0"));
    assert!(jobs.iter().map(|j| j.bytes).sum::<usize>() <= RESULT_BUDGET);
    assert!(!jobs[0].value(false).to_string().contains("result"));
}

#[cfg(windows)]
#[tokio::test]
async fn named_pipe_is_exclusive_and_exchanges_real_bounded_frames() {
    let endpoint = format!(
        "{}-test-{}",
        wire::endpoint().unwrap(),
        uuid::Uuid::new_v4().simple()
    );
    let server = transport::bind(&endpoint, true).unwrap();
    assert!(transport::bind(&endpoint, true).is_err());
    let task = tokio::spawn(async move {
        server.connect().await.unwrap();
        let mut server = server;
        let bytes = wire::read_frame(&mut server, wire::MAX_REQUEST)
            .await
            .unwrap();
        let request: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request.method, "app_status");
        wire::write_frame(
            &mut server,
            &serde_json::to_vec(&Response::success(json!({"realPipe":true}))).unwrap(),
            wire::MAX_RESPONSE,
        )
        .await
        .unwrap();
        // Windows pipe writes complete before the client necessarily reads. Keep
        // the server handle alive until the client disconnects.
        let mut byte = [0];
        let _ = tokio::io::AsyncReadExt::read(&mut server, &mut byte).await;
    });
    let result = yougori_cli::client::call_at(
        &endpoint,
        &yougori_cli::client::request("app_status", json!({})),
    )
    .await
    .unwrap();
    assert_eq!(result["realPipe"], true);
    task.await.unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "boots temporary OCI/microVM/VM workloads through the real CLI transport; no user environments, public tunnels, screenshots, or downloaded models"]
fn automation_real_cli_lifecycle_and_connections() {
    use crate::{backup::BackupManager, workspace::WorkspaceManager};
    // Guest provisioning uses the same deep async path as the app. Match the
    // production worker stack instead of Tokio's 2 MiB test default.
    crate::install_async_runtime();
    let data = tempfile::tempdir().unwrap();
    let share = tempfile::tempdir().unwrap();
    let result = Arc::new(std::sync::Mutex::new(None));
    let test_result = result.clone();
    let endpoint = format!(
        "{}-integration-{}",
        wire::endpoint().unwrap(),
        uuid::Uuid::new_v4().simple()
    );
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        data.path(),
    )
    .unwrap();
    // Match production startup; the seed's 1 CPU/1 GB placeholders are not
    // runtime capacity and must not be used for snapshot restoration checks.
    store
        .mutate(|state| {
            state.host = crate::commands::collect_host_metrics(&state.host, runtime.storage_root());
            state.providers = runtime.provider_statuses();
            Ok(())
        })
        .unwrap();
    let backup = BackupManager::new(data.path()).unwrap();
    let workspace = WorkspaceManager::new(data.path());
    let mut context = tauri::generate_context!();
    context.config_mut().identifier =
        format!("com.opendock.cli-test-{}", uuid::Uuid::new_v4().simple());
    context.config_mut().app.windows.clear();
    let app = tauri::Builder::default()
        .any_thread()
        .manage(store)
        .manage(runtime)
        .manage(backup)
        .manage(workspace)
        .manage(crate::peer_sharing::Sharing::default())
        .setup(move |app| {
            start_at(app.handle(), true, endpoint.clone()).map_err(std::io::Error::other)?;
            let app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let outcome = tokio::spawn(exercise(endpoint, share.path().to_owned()))
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r);
                app.state::<WorkspaceManager>()
                    .shutdown(&app.state::<RuntimeManager>())
                    .await;
                app.state::<RuntimeManager>().shutdown_all().await;
                *test_result.lock().unwrap() = Some(outcome);
                // Keep test files until all guests and file servers have stopped.
                drop(share);
                drop(data);
                app.exit(0);
            });
            Ok(())
        })
        .build(context)
        .unwrap();
    assert_eq!(app.run_return(|_, _| {}), 0);
    result
        .lock()
        .unwrap()
        .take()
        .expect("test did not complete")
        .unwrap();
}

#[cfg(windows)]
async fn exercise(endpoint: String, share: std::path::PathBuf) -> Result<(), String> {
    use yougori_cli::client::{call_at, request, wait_job_at};
    async fn call(endpoint: &str, name: &str, p: Value) -> Result<Value, String> {
        let mut req = request(name, p);
        req.confirmed = true;
        let reply = call_at(endpoint, &req).await?;
        if reply["accepted"] == true {
            wait_job_at(endpoint, reply["jobId"].as_str().unwrap(), 180)
                .await
                .map_err(|error| format!("{name}: {error}"))
        } else {
            Ok(reply)
        }
    }
    let status = call(&endpoint, "app_status", json!({})).await?;
    assert_eq!(status["headless"], true);
    assert!(
        call(&endpoint, "get_platform_state", json!({})).await?["environments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let denied = call_at(
        &endpoint,
        &request("delete_environment", json!({"environmentId":"env-nothing"})),
    )
    .await
    .unwrap_err();
    assert!(denied.contains("confirmation"));
    let mut dry = request(
        "create_environment",
        yougori_cli::catalog::find("create_environment")?.example,
    );
    dry.dry_run = true;
    assert_eq!(call_at(&endpoint, &dry).await?["runtimeChecked"], false);
    assert!(
        call(&endpoint, "get_platform_state", json!({})).await?["environments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mut ids = Vec::new();
    for name in ["cli-source", "cli-target"] {
        eprintln!("CLI integration: creating {name}");
        let p = json!({"request":{"name":name,"kind":"container","provider":"yougoriOci","runtime":"quay.io/libpod/alpine:latest","storageGb":6,"description":"Temporary CLI test","networkAccess":false,"gpuAccess":false,"resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":2},"memoryGb":{"min":0.5,"preferred":0.5,"max":1},"priority":"normal"}}});
        let state = call(&endpoint, "create_environment", p).await?;
        let id = state["environments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        ids.push(id);
    }
    // Size the shared OCI pool while its containers are all stopped. The CLI
    // must not secretly stop unrelated running workloads to enlarge that pool.
    for id in &ids {
        call(
            &endpoint,
            "set_environment_status",
            json!({"environmentId":id,"status":"running"}),
        )
        .await?;
    }
    let source = &ids[0];
    let target = &ids[1];
    eprintln!("CLI integration: pinned sharing, remote control, revocation and OCI catalog");
    let images = call(&endpoint, "manage_oci_images", json!({"action":"list"})).await?;
    assert!(images.as_array().is_some());
    let _ = call(&endpoint, "get_environment_logs", json!({"environmentId":source})).await?;
    let grant = call(&endpoint, "create_environment_share", json!({"environmentId":source,"address":"127.0.0.1","permission":"control"})).await?;
    let imported = call(&endpoint, "import_environment_share", json!({"invitation":grant["invitation"]})).await?;
    let remote = imported["environments"].as_array().unwrap().iter().find(|e|e["runtime"].as_str().is_some_and(|s|s.starts_with("shared://"))).unwrap()["id"].as_str().unwrap();
    let output = call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":remote,"command":"printf SHARED_GUEST_OK"}})).await?;
    assert_eq!(output["stdout"],"SHARED_GUEST_OK");
    call(&endpoint,"revoke_environment_share",json!({"shareId":grant["share"]["id"]})).await?;
    assert!(call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":remote,"command":"true"}})).await.is_err());
    call(&endpoint,"delete_environment",json!({"environmentId":remote})).await?;
    assert_eq!(call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":source,"command":"printf OWNER_OK"}})).await?["stdout"],"OWNER_OK");
    eprintln!("CLI integration: isolated CLI has no PC folders and only explicit guest grants");
    let cli=match call(&endpoint,"open_isolated_cli",json!({})).await {
        Ok(cli) => cli,
        Err(error) => {
            let state = call(&endpoint,"get_platform_state",json!({})).await.unwrap_or(Value::Null);
            let id = state["cliEnvironmentId"].as_str().unwrap_or("");
            let console = if id.is_empty() { Value::Null } else {
                call(&endpoint,"read_environment_console",json!({"environmentId":id})).await.unwrap_or(Value::Null)
            };
            let serial = console.as_str().unwrap_or("unavailable");
            let tail = serial.chars().rev().take(6000).collect::<String>().chars().rev().collect::<String>();
            return Err(format!("{error}\nIsolated CLI serial tail: {tail}"));
        }
    };
    let cli_id=cli.as_str().unwrap();
    let services=call(&endpoint,"list_environment_services",json!({"environmentId":cli_id})).await?;
    assert!(services["shares"].as_array().unwrap().is_empty());
    let view=call(&endpoint,"grant_isolated_cli_environment",json!({"environmentId":source,"permission":"view"})).await?;
    let command=format!("yougori exec {source} -- sh -lc 'printf ISOLATED_OK'");
    let denied=call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":cli_id,"command":command}})).await?;
    assert_ne!(denied["exitCode"],0);
    call(&endpoint,"revoke_environment_share",json!({"shareId":view["grant"]["id"]})).await?;
    let control=call(&endpoint,"grant_isolated_cli_environment",json!({"environmentId":source,"permission":"control"})).await?;
    let result=call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":cli_id,"command":command}})).await?;
    assert_eq!(result["stdout"],"ISOLATED_OK","{result}");
    call(&endpoint,"revoke_environment_share",json!({"shareId":control["grant"]["id"]})).await?;
    let denied=call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":cli_id,"command":command}})).await?;
    assert_ne!(denied["exitCode"],0);
    call(&endpoint,"set_environment_status",json!({"environmentId":cli_id,"status":"stopped"})).await?;
    call(&endpoint,"delete_environment",json!({"environmentId":cli_id})).await?;
    call(
        &endpoint,
        "set_manual_service_port",
        json!({"environmentId":source,"port":3000,"present":true}),
    )
    .await?;
    assert_eq!(
        call(&endpoint, "get_manual_service_ports", json!({})).await?[source],
        json!([3000])
    );
    eprintln!("CLI integration: resources, private connection, terminal and My PC");
    let state = call(
        &endpoint,
        "configure_resource_limits",
        json!({"environmentId":source,"cpu":{"preferred":1.5},"priority":"high"}),
    )
    .await?;
    let env = state["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == *source)
        .unwrap();
    assert_eq!(env["resourcePolicy"]["memoryGb"]["preferred"], 0.5);
    let linked=call(&endpoint,"create_connection",json!({"request":{"sourceId":source,"targetId":target,"direction":"bidirectional","permissions":["files","ports"],"ports":["3000"]}})).await?;
    let connection = linked["connections"][0]["id"].as_str().unwrap().to_string();
    let skills = call(
        &endpoint,
        "get_connection_skills",
        json!({"environmentId":source}),
    )
    .await?;
    assert!(skills.as_str().unwrap().contains(target));
    let host = call(
        &endpoint,
        "attach_host_folder",
        json!({"environmentId":source,"path":share.to_string_lossy(),"readOnly":false}),
    )
    .await?;
    let mount = host["mountPath"].as_str().ok_or("No host folder mount")?;
    let command =
        format!("set -e; printf CLI_HOST_OK > '{mount}/from-guest.txt'; printf CLI_EXEC_OK");
    let output = call(
        &endpoint,
        "execute_environment_command",
        json!({"request":{"environmentId":source,"command":command}}),
    )
    .await?;
    assert_eq!(output["exitCode"], 0);
    assert!(output["stdout"].as_str().unwrap().contains("CLI_EXEC_OK"));
    assert_eq!(
        std::fs::read_to_string(share.join("from-guest.txt")).map_err(|e| e.to_string())?,
        "CLI_HOST_OK"
    );
    // The small OCI test image has no httpd applet. Use its existing netcat,
    // without downloading a package or treating 'last echo succeeded' as proof
    // that a web server started.
    let server = r#"printf '%s\n' '#!/bin/sh' 'while IFS= read -r header; do [ "$header" = "$(printf "\r")" ] && break; done' 'printf "HTTP/1.0 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nCLI_HTTP_OK"' 'cat >/dev/null' > /tmp/cli-http; chmod 700 /tmp/cli-http; sh -c 'while true; do nc -l -p 3000 -e /tmp/cli-http; done' </dev/null >/tmp/cli-http.log 2>&1 &"#;
    let server_output = call(
        &endpoint,
        "execute_environment_command",
        json!({"request":{"environmentId":source,"command":server}}),
    )
    .await?;
    assert_eq!(server_output["exitCode"], 0);
    let local_check=call(&endpoint,"execute_environment_command",json!({"request":{"environmentId":source,"command":"wget -T 5 -qO- http://127.0.0.1:3000/"}})).await?;
    assert_eq!(
        local_check["stdout"], "CLI_HTTP_OK",
        "guest server failed: {local_check}"
    );
    call(
        &endpoint,
        "terminal_action",
        json!({"environmentId":source,"sessionId":"term-cli-test","action":"create"}),
    )
    .await?;
    use base64::Engine;
    let input = base64::engine::general_purpose::STANDARD.encode("echo CLI_TERMINAL_OK\r");
    call(
        &endpoint,
        "terminal_action",
        json!({"environmentId":source,"sessionId":"term-cli-test","action":"write","data":input}),
    )
    .await?;
    let terminal = call(
        &endpoint,
        "terminal_action",
        json!({"environmentId":source,"sessionId":"term-cli-test","action":"read","offset":0}),
    )
    .await?;
    let text = base64::engine::general_purpose::STANDARD
        .decode(terminal["data"].as_str().unwrap())
        .map_err(|e| e.to_string())?;
    assert!(String::from_utf8_lossy(&text).contains("CLI_TERMINAL_OK"));
    call(
        &endpoint,
        "terminal_action",
        json!({"environmentId":source,"sessionId":"term-cli-test","action":"close"}),
    )
    .await?;
    let publication = call(
        &endpoint,
        "publish_environment_service",
        json!({"environmentId":source,"port":3000,"kind":"local"}),
    )
    .await?;
    let url = publication["urls"][0].as_str().unwrap();
    let body = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("CLI local publication: {e:?}"))?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(body, "CLI_HTTP_OK");
    call(
        &endpoint,
        "unpublish_environment_service",
        json!({"publicationId":publication["id"]}),
    )
    .await?;
    call(
        &endpoint,
        "detach_host_folder",
        json!({"shareId":host["id"]}),
    )
    .await?;
    call(
        &endpoint,
        "update_container_network",
        json!({"environmentId":source,"enabled":true}),
    )
    .await?;
    call(
        &endpoint,
        "update_container_network",
        json!({"environmentId":source,"enabled":false}),
    )
    .await?;
    call(
        &endpoint,
        "delete_connection",
        json!({"connectionId":connection}),
    )
    .await?;
    for id in &ids {
        call(
            &endpoint,
            "set_environment_status",
            json!({"environmentId":id,"status":"stopped"}),
        )
        .await?;
    }
    eprintln!("CLI integration: snapshots, backup and factory reset");
    let snap = call(
        &endpoint,
        "create_snapshot",
        json!({"environmentId":source,"name":"cli-before-reset"}),
    )
    .await?;
    let snapshot = snap["snapshots"][0]["id"].clone();
    call(
        &endpoint,
        "restore_snapshot",
        json!({"snapshotId":snapshot}),
    )
    .await?;
    let backup = call(
        &endpoint,
        "export_local_backup",
        json!({"environmentId":source,"folder":share.to_string_lossy()}),
    )
    .await?;
    assert!(std::path::Path::new(backup.as_str().unwrap()).is_file());
    call(
        &endpoint,
        "factory_reset_environment",
        json!({"environmentId":source,"confirmation":"cli-source"}),
    )
    .await?;
    // All mutations above use real command dispatch, native jobs and framed IPC.
    for id in &ids {
        call(&endpoint, "delete_environment", json!({"environmentId":id})).await?;
    }
    eprintln!("CLI integration: built-in microVM create/start/exec/stop/delete");
    let p = json!({"request":{"name":"cli-micro","kind":"microVm","provider":"qemu","runtime":"builtin:alpine","description":"Temporary CLI test","resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1},"memoryGb":{"min":1,"preferred":1,"max":1},"priority":"normal"}}});
    let micro = call(&endpoint, "create_environment", p).await?;
    let id = micro["environments"][0]["id"].clone();
    call(
        &endpoint,
        "set_environment_status",
        json!({"environmentId":id,"status":"running"}),
    )
    .await?;
    let output = call(
        &endpoint,
        "execute_environment_command",
        json!({"request":{"environmentId":id,"command":"printf CLI_MICRO_OK"}}),
    )
    .await?;
    assert_eq!(output["stdout"], "CLI_MICRO_OK");
    call(
        &endpoint,
        "set_environment_status",
        json!({"environmentId":id,"status":"stopped"}),
    )
    .await?;
    let source_disk = micro["environments"][0]["runtimePath"].as_str().unwrap();
    eprintln!("CLI integration: VM disk import and lifecycle (not an OS installation test)");
    let p = json!({"request":{"name":"cli-vm","kind":"fullVm","provider":"qemu","runtime":source_disk,"description":"Temporary lifecycle test","resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1},"memoryGb":{"min":1,"preferred":1,"max":1},"priority":"normal"}}});
    let vm = call(&endpoint, "create_environment", p).await?;
    let vm_id = vm["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "cli-vm")
        .unwrap()["id"]
        .clone();
    call(
        &endpoint,
        "set_environment_status",
        json!({"environmentId":vm_id,"status":"running"}),
    )
    .await?;
    call(
        &endpoint,
        "get_guest_session",
        json!({"environmentId":vm_id}),
    )
    .await?;
    call(
        &endpoint,
        "update_container_network",
        json!({"environmentId":vm_id,"enabled":true}),
    )
    .await?;
    call(
        &endpoint,
        "set_environment_status",
        json!({"environmentId":vm_id,"status":"stopped"}),
    )
    .await?;
    call(
        &endpoint,
        "delete_environment",
        json!({"environmentId":vm_id}),
    )
    .await?;
    call(&endpoint, "delete_environment", json!({"environmentId":id})).await?;
    assert!(
        call(&endpoint, "get_platform_state", json!({})).await?["environments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    eprintln!("CLI integration passed; all temporary workloads deleted through the CLI backend.");
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "boots a private disposable OCI appliance; checks real CLI async output, secret redaction, transfer cancellation and independent control without user environments"]
fn automation_async_execution_transfer_cancellation_isolated_oci() {
    use crate::{backup::BackupManager,workspace::WorkspaceManager};
    crate::install_async_runtime();
    let data=tempfile::tempdir().unwrap();let source=tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("marker.txt"),"CONSISTENT_IMPORTED_FILE").unwrap();
    let store=PlatformStore::load(data.path().join("state.json")).unwrap();
    let runtime=RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")),data.path()).unwrap();
    store.mutate(|state|{state.host=crate::commands::collect_host_metrics(&state.host,runtime.storage_root());state.providers=runtime.provider_statuses();Ok(())}).unwrap();
    let endpoint=format!("{}-async-reliability-{}",wire::endpoint().unwrap(),uuid::Uuid::new_v4().simple());
    let result=Arc::new(std::sync::Mutex::new(None));let test_result=result.clone();
    let backup=BackupManager::new(data.path()).unwrap();let workspace=WorkspaceManager::new(data.path());
    let mut context=tauri::generate_context!();context.config_mut().identifier=format!("com.yougori.async-reliability-test-{}",uuid::Uuid::new_v4().simple());context.config_mut().app.windows.clear();
    let app=tauri::Builder::default().any_thread().manage(store).manage(runtime).manage(backup).manage(workspace).manage(crate::peer_sharing::Sharing::default())
        .setup(move|app|{start_at(app.handle(),true,endpoint.clone()).map_err(std::io::Error::other)?;let app=app.handle().clone();tauri::async_runtime::spawn(async move{
            let exercise_app=app.clone();let source_path=source.path().to_owned();
            let outcome=tokio::spawn(exercise_async_reliability(exercise_app,endpoint,source_path)).await.map_err(|error|error.to_string()).and_then(|result|result);
            app.state::<WorkspaceManager>().shutdown(&app.state::<RuntimeManager>()).await;app.state::<RuntimeManager>().shutdown_all().await;
            *test_result.lock().unwrap()=Some(outcome);drop(source);drop(data);app.exit(0);
        });Ok(())}).build(context).unwrap();
    assert_eq!(app.run_return(|_,_|{}),0);
    result.lock().unwrap().take().expect("isolated async test did not finish").unwrap();
}

#[cfg(windows)]
async fn exercise_async_reliability(app:AppHandle,endpoint:String,source:std::path::PathBuf)->Result<(),String>{
    use yougori_cli::client::{call_at,request,wait_job_at};
    async fn submit(endpoint:&str,method:&str,params:Value)->Result<Value,String>{let mut req=request(method,params);req.confirmed=true;call_at(endpoint,&req).await}
    async fn call(endpoint:&str,method:&str,params:Value)->Result<Value,String>{let reply=submit(endpoint,method,params).await?;if reply["accepted"]==true{wait_job_at(endpoint,reply["jobId"].as_str().ok_or("Missing job ID")?,300).await}else{Ok(reply)}}
    async fn terminal_job(endpoint:&str,id:&str)->Result<Value,String>{
        let deadline=tokio::time::Instant::now()+Duration::from_secs(20);
        loop{let job=call(endpoint,"jobs_get",json!({"jobId":id,"wait":100})).await?;if ["complete","failed","cancelled","interrupted"].contains(&job["status"].as_str().unwrap_or("")){return Ok(job)}if tokio::time::Instant::now()>deadline{return Err("Cancelled fixture did not release its job within twenty seconds".into())}}
    }
    let mut ids=Vec::new();
    for name in ["async-reliability-source","async-reliability-other"]{
        eprintln!("Isolated OCI reliability: creating {name}");
        let state=call(&endpoint,"create_environment",json!({"request":{"name":name,"kind":"container","provider":"yougoriOci","runtime":"quay.io/libpod/alpine:latest","storageGb":6,"description":"Private asynchronous reliability fixture","networkAccess":false,"gpuAccess":false,"resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":2},"memoryGb":{"min":0.5,"preferred":0.5,"max":1},"priority":"normal"},"workload":{"environment":{"API_TOKEN":"ONLY-A-DISPOSABLE-REDACTION-FIXTURE"},"args":["/bin/sh","-c","trap 'exit 0' TERM; while :; do sleep 1; done"]}}})).await?;
        ids.push(state["environments"].as_array().ok_or("Missing environment list")?.iter().find(|env|env["name"]==name).and_then(|env|env["id"].as_str()).ok_or("Missing test environment")?.to_owned());
    }
    for id in &ids{call(&endpoint,"set_environment_status",json!({"environmentId":id,"status":"running"})).await?;}
    let id=&ids[0];
    eprintln!("Isolated OCI reliability: real file import and guest verification");
    let copied=call(&endpoint,"copy_files_to_environment",json!({"environmentId":id,"paths":[source.join("marker.txt")]})).await?;
    let destination=copied["destination"].as_str().ok_or("Missing import destination")?;
    let output=call(&endpoint,"execute_guest_job",json!({"request":{"environmentId":id,"command":format!("cat '{destination}/marker.txt'")}})).await?;
    assert_eq!(output["exitCode"],0,"{output}");assert_eq!(output["stdout"],"CONSISTENT_IMPORTED_FILE");
    eprintln!("Isolated OCI reliability: asynchronous cursors and protected output");
    let began=Instant::now();
    let accepted=submit(&endpoint,"execute_guest_job",json!({"request":{"environmentId":id,"command":"printf first; printf '%s' \"$API_TOKEN\"; sleep 2; printf second; printf stderr-marker >&2; exit 7","timeoutSeconds":30}})).await?;
    assert!(accepted["accepted"]==true&&began.elapsed()<Duration::from_secs(5),"{accepted}");
    let job_id=accepted["jobId"].as_str().ok_or("Missing exec job")?;let execution=format!("exec-{job_id}");
    let deadline=tokio::time::Instant::now()+Duration::from_secs(10);let cursor;
    loop{match call(&endpoint,"guest_execution_output",json!({"environmentId":id,"executionId":execution,"limit":65536})).await{Ok(window)=>{assert!(!window.to_string().contains("ONLY-A-DISPOSABLE"));if window["stdout"].as_str().unwrap_or("").contains("first"){cursor=window["stdoutCursor"].as_u64().unwrap();break;}},Err(_)if tokio::time::Instant::now()<deadline=>{},Err(error)=>return Err(error)}if tokio::time::Instant::now()>deadline{return Err("Guest output did not become available".into())}tokio::time::sleep(Duration::from_millis(50)).await;}
    let completed=wait_job_at(&endpoint,job_id,30).await?;assert_eq!(completed["exitCode"],7,"{completed}");assert!(!completed.to_string().contains("ONLY-A-DISPOSABLE"));assert_eq!(completed["stderr"],"stderr-marker");
    let later=call(&endpoint,"guest_execution_output",json!({"environmentId":id,"executionId":execution,"stdoutCursor":cursor,"stderrCursor":0})).await?;assert!(!later["stdout"].as_str().unwrap_or("").contains("first"));assert!(later["done"]==true);
    for offset in 5..39{let window=call(&endpoint,"guest_execution_output",json!({"environmentId":id,"executionId":execution,"stdoutCursor":offset,"limit":2})).await?;assert!(!window["stdout"].as_str().unwrap_or("").contains(|c:char|c.is_ascii_uppercase()||c=='-'),"offset {offset}: {window}");}
    call(&endpoint,"release_guest_execution",json!({"environmentId":id,"executionId":execution})).await?;
    eprintln!("Isolated OCI reliability: output overflow preserves guest exit code");
    let overflow=call(&endpoint,"execute_guest_job",json!({"request":{"environmentId":id,"command":"head -c 1600000 /dev/zero; printf kept-error >&2; exit 9"}})).await?;assert_eq!(overflow["exitCode"],9);assert!(overflow["truncated"]==true);assert_eq!(overflow["stderr"],"kept-error");
    eprintln!("Isolated OCI reliability: cooperative process-group cancellation");
    let accepted=submit(&endpoint,"execute_guest_job",json!({"request":{"environmentId":id,"command":"printf active; sleep 120 & wait"}})).await?;let job_id=accepted["jobId"].as_str().unwrap();let execution=format!("exec-{job_id}");
    let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
    loop{if call(&endpoint,"guest_execution_output",json!({"environmentId":id,"executionId":execution})).await.is_ok_and(|v|v["stdout"].as_str().unwrap_or("").contains("active")){break}if tokio::time::Instant::now()>deadline{return Err("Cancel fixture did not launch".into())}tokio::time::sleep(Duration::from_millis(50)).await;}
    call(&endpoint,"jobs_cancel",json!({"jobId":job_id})).await?;let cancelled=terminal_job(&endpoint,job_id).await?;assert_eq!(cancelled["status"],"cancelled","{cancelled}");
    let retained=call(&endpoint,"guest_execution_output",json!({"environmentId":id,"executionId":execution})).await?;assert!(retained["done"]==true);assert_eq!(retained["errorCode"],"EXECUTION_CANCELLED");
    eprintln!("Isolated OCI reliability: archive cancellation keeps configuration and Stop available");
    let large=source.join("large-owned-fixture.bin");std::fs::File::create(&large).map_err(|e|e.to_string())?.set_len(2*1024*1024*1024).map_err(|e|e.to_string())?;
    let transfer=submit(&endpoint,"copy_files_to_environment",json!({"environmentId":id,"paths":[large]})).await?;let transfer_id=transfer["jobId"].as_str().ok_or("Missing transfer job")?;
    let deadline=tokio::time::Instant::now()+Duration::from_secs(20);
    loop{let job=call(&endpoint,"jobs_get",json!({"jobId":transfer_id})).await?;if job["progress"]["phase"]=="archiving"{break}if ["complete","failed"].contains(&job["status"].as_str().unwrap_or("")){return Err(format!("Archive fixture finished before cancellation: {job}"))}if tokio::time::Instant::now()>deadline{return Err("Transfer never reached archiving".into())}tokio::time::sleep(Duration::from_millis(10)).await;}
    let settings=call(&endpoint,"get_settings_snapshot",json!({})).await?;
    let changed=tokio::time::timeout(Duration::from_secs(5),call(&endpoint,"patch_settings",json!({"patch":{"theme":"dark"},"expectedRevision":settings["revision"]}))).await.map_err(|_|"Configuration blocked behind file archive")??;assert_eq!(changed["applied"],true);
    let stop_began=Instant::now();
    let stopping=tokio::time::timeout(Duration::from_secs(3),submit(&endpoint,"set_environment_status",json!({"environmentId":id,"status":"stopped"}))).await.map_err(|_|"Stop request blocked behind file archive")??;
    let stop_id=stopping["jobId"].as_str().ok_or("Missing Stop job")?;
    // Native container stop includes a thirty-second graceful process deadline.
    // Assert dispatch/cancellation separately so that grace is not confused
    // with waiting behind the unrelated transfer resource.
    let cancelled=tokio::time::timeout(Duration::from_secs(5),terminal_job(&endpoint,transfer_id)).await.map_err(|_|"Stop did not cancel the archived transfer promptly")??;assert!(["cancelled","interrupted"].contains(&cancelled["status"].as_str().unwrap_or("")),"{cancelled}");
    let stop_job=call(&endpoint,"jobs_get",json!({"jobId":stop_id})).await?;
    eprintln!("Isolated OCI reliability: Stop while archive cancelled in {:.2}s: {stop_job}",stop_began.elapsed().as_secs_f64());
    assert!(!stop_job["waitingFor"].as_str().is_some_and(|v|v.contains("transfer")),"{stop_job}");
    tokio::time::timeout(Duration::from_secs(45),wait_job_at(&endpoint,stop_id,45)).await.map_err(|_|"Native container Stop exceeded its graceful deadline")??;
    assert_eq!(std::fs::metadata(&large).map_err(|e|e.to_string())?.len(),2*1024*1024*1024);assert_eq!(std::fs::read_to_string(source.join("marker.txt")).unwrap(),"CONSISTENT_IMPORTED_FILE");
    let state=call(&endpoint,"get_platform_state",json!({})).await?;assert_eq!(state["environments"].as_array().unwrap().iter().find(|e|e["id"]==ids[1]).unwrap()["status"],"running");
    // Engine journal contains only allowlisted metadata, even when the guest
    // printed an application credential. This is a fake fixture, never a vault value.
    let journal=app.state::<PlatformStore>().data_folder("operations").join("operations.json");assert!(!std::fs::read_to_string(journal).map_err(|e|e.to_string())?.contains("ONLY-A-DISPOSABLE"));
    for id in &ids{call(&endpoint,"delete_environment",json!({"environmentId":id})).await?;}
    eprintln!("Isolated OCI reliability passed: import, cursors, redaction, real exit codes, cancellation, independent settings/Stop and untouched originals");Ok(())
}
