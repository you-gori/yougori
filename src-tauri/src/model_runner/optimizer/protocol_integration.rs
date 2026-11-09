//! Cross-language execution of the real Rust watcher/admission logic and Python
//! HTTP handlers. Only weights and generation are replaced with tiny stubs.
use super::{capacity, control, events, Seen};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Notify};
use tokio_util::sync::CancellationToken;

struct Runners {
    child: Child,
    _folder: tempfile::TempDir,
    ports: [u16; 2],
}

#[tokio::test]
async fn actual_runner_grant_requires_host_ledger_and_persisted_intent() {
    let fixture = Runners::start().await;
    let ports = fixture.ports;
    http(
        ports[1],
        "/v1/yougori/prepare",
        Some(json!({"lease":"synthetic_lease_12345678"})),
    )
    .await
    .unwrap();
    let target = http(ports[1], "/health", None).await.unwrap();
    let old = http(ports[0], "/health", None).await.unwrap();
    let (sample, account) = capacity::test_accounting();
    let account = std::sync::Mutex::new(account);
    let intent = fixture._folder.path().join("capacity-intent.json");
    let reserved = std::sync::atomic::AtomicBool::new(false);
    let send = |id: String, body: Value| {
        if body["action"] == "grant" {
            assert!(reserved.load(std::sync::atomic::Ordering::SeqCst));
            let saved: Value = serde_json::from_slice(&std::fs::read(&intent).unwrap()).unwrap();
            assert_eq!(saved["optimizer"]["sequence"], body["expectedSequence"]);
            assert_eq!(saved["optimizer"]["instanceId"], body["expectedInstanceId"]);
        }
        http(ports[index(&id)], "/v1/yougori/optimizer", Some(body))
    };
    capacity::switch(
        "second",
        &target,
        &[("first".into(), old)],
        &[],
        &std::collections::BTreeMap::new(),
        &[],
        Some(4 * 1024 * 1024 * 1024),
        &CancellationToken::new(),
        &send,
        || async { Ok(sample.clone()) },
        |_, marker| {
            use std::io::Write;
            let mut file = std::fs::File::create(&intent).map_err(|e| e.to_string())?;
            file.write_all(marker.unwrap().as_bytes())
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())
        },
        |s, bytes| {
            account
                .lock()
                .unwrap()
                .settle_and_reserve(s, "second", bytes)?;
            reserved.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .unwrap();
    let answer = http(
        ports[1],
        "/v1/chat/completions",
        Some(json!({"messages":[{"role":"user","content":"synthetic"}]})),
    )
    .await
    .unwrap();
    assert_eq!(
        answer["choices"][0]["message"]["content"],
        "synthetic complete reply"
    );
}

impl Drop for Runners {
    fn drop(&mut self) {
        // This fixture starts no grandchildren. Reap before deleting its cache,
        // including when an assertion unwinds the test.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Runners {
    async fn start() -> Self {
        let scratch = PathBuf::from("D:/YougoriBuildCache/scratch");
        let folder = if scratch.is_dir() {
            tempfile::tempdir_in(scratch)
        } else {
            tempfile::tempdir()
        }
        .unwrap();
        let ready = folder.path().join("ready.json");
        let errors = folder.path().join("errors.txt");
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/model_runner/optimizer/protocol_fixture.py");
        let mut command = Command::new("python");
        command.env_clear();
        for (name, value) in std::env::vars_os() {
            if [
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "SYSTEMDRIVE",
            ]
            .contains(&name.to_string_lossy().to_ascii_uppercase().as_str())
            {
                command.env(name, value);
            }
        }
        for name in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TMP",
            "TEMP",
            "TMPDIR",
        ] {
            command.env(name, folder.path());
        }
        let child = command
            .args(["-I", "-B", "-u"])
            .arg(fixture)
            .arg(&ready)
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("CUDA_VISIBLE_DEVICES", "")
            .env("PYTHONIOENCODING", "utf-8")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&errors).unwrap())
            .spawn()
            .expect("Python 3.12+ is required by the offline model integration gate");
        let mut this = Self {
            child,
            _folder: folder,
            ports: [0, 0],
        };
        let ready_result = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Ok(bytes) = std::fs::read(&ready) {
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        return Some(value);
                    }
                }
                if this.child.try_wait().unwrap().is_some() {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let value = ready_result.ok().flatten().unwrap_or_else(|| {
            panic!(
                "Runner fixture failed: {}",
                std::fs::read_to_string(errors).unwrap_or_default()
            )
        });
        for (index, port) in this.ports.iter_mut().enumerate() {
            *port = value["ports"][index]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n != 0)
                .expect("fixture loopback port");
        }
        this
    }
}

async fn http(port: u16, path: &str, body: Option<Value>) -> Result<Value, String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
        let data = body.as_ref().map(serde_json::to_vec).transpose().map_err(|e| e.to_string())?.unwrap_or_default();
        // Synthetic fixture credentials only, never inherited user credentials.
        let headers = format!("{} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-model-token\r\nX-Yougori-GPU-Control: fixture-control-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if body.is_some() { "POST" } else { "GET" }, data.len());
        stream.write_all(headers.as_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&data).await.map_err(|e| e.to_string())?;
        super::super::model_response(Box::new(stream), super::super::reply_seconds(path, body.is_some())).await
    }).await.map_err(|_| "Fixture HTTP timeout".to_owned())?
}

fn index(id: &str) -> usize {
    if id == "first" {
        0
    } else {
        1
    }
}

#[tokio::test]
async fn delayed_configuration_cannot_reload_a_resident_after_confirmed_unload() {
    let fixture = Runners::start().await;
    let ports = fixture.ports;
    let resident = http(ports[0], "/health", None).await.unwrap();
    // This is the mutation that a timed-out engine request may deliver late.
    let delayed = json!({"action":"configure", "enabled":false, "pinned":false,
        "idleTimeoutSeconds":0,
        "expectedInstanceId":resident["optimizer"]["instanceId"],
        "expectedSequence":resident["optimizer"]["sequence"]});
    http(
        ports[1],
        "/v1/yougori/prepare",
        Some(json!({"lease":"synthetic_lease_12345678"})),
    )
    .await
    .unwrap();
    let target = http(ports[1], "/health", None).await.unwrap();
    control::switch(
        "second",
        &target,
        &[("first".into(), resident)],
        &CancellationToken::new(),
        Duration::from_secs(3),
        &|id, body| http(ports[index(&id)], "/v1/yougori/optimizer", Some(body)),
    )
    .await
    .unwrap();
    assert!(http(ports[0], "/v1/yougori/optimizer", Some(delayed))
        .await
        .is_err());
    let health = http(ports[0], "/health", None).await.unwrap();
    assert_eq!(health["optimizer"]["enabled"], true);
    assert_eq!(health["optimizer"]["resident"], false);
    assert_eq!(health["optimizer"]["loading"], false);
}

#[tokio::test]
async fn direct_api_demand_wakes_real_host_manager_then_fenced_switch_completes_chat() {
    let fixture = Runners::start().await;
    let ports = fixture.ports;
    let mut seen = Vec::new();
    for (i, id) in ["first", "second"].iter().enumerate() {
        seen.push(Seen {
            id: (*id).into(),
            health: Some(http(ports[i], "/health", None).await.unwrap()),
        });
    }
    let (_updates, receiver) = tokio::sync::watch::channel(events::members(&seen));
    let stop = CancellationToken::new();
    let _cancel_on_exit = stop.clone().drop_guard();
    let notified = Arc::new(Notify::new());
    let started = Arc::new(Notify::new());
    let event_stop = stop.clone();
    let event_signal = notified.clone();
    let request_started = started.clone();
    let watcher = tokio::spawn(async move {
        events::run(
            receiver,
            &event_stop,
            || event_signal.notify_one(),
            move |id, body| {
                let started = request_started.clone();
                async move {
                    started.notify_one();
                    http(ports[index(&id)], "/v1/yougori/optimizer", Some(body)).await
                }
            },
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    let chat = tokio::spawn(http(
        ports[1],
        "/v1/chat/completions",
        Some(json!({
            "messages":[{"role":"user","content":"synthetic request"}]
        })),
    ));
    // There is no periodic scheduler in this test: only a real watch response
    // can wake this callback. This is functional evidence, not a GPU benchmark.
    tokio::time::timeout(Duration::from_secs(3), notified.notified())
        .await
        .unwrap();
    let target = http(ports[1], "/health", None).await.unwrap();
    let resident = http(ports[0], "/health", None).await.unwrap();
    assert!(target["optimizer"]["pending"].as_u64().unwrap() > 0);
    control::switch(
        "second",
        &target,
        &[("first".into(), resident)],
        &stop,
        Duration::from_secs(3),
        &|id, body| http(ports[index(&id)], "/v1/yougori/optimizer", Some(body)),
    )
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), chat)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        result["choices"][0]["message"]["content"],
        "synthetic complete reply"
    );
    assert_eq!(
        http(ports[0], "/health", None).await.unwrap()["optimizer"]["resident"],
        false
    );
    assert_eq!(
        http(ports[1], "/health", None).await.unwrap()["optimizer"]["resident"],
        true
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn real_restarted_runner_refuses_grant_from_previous_phase_instance() {
    let old = Runners::start().await;
    let replacement = Runners::start().await;
    for port in [old.ports[1], replacement.ports[1]] {
        http(
            port,
            "/v1/yougori/prepare",
            Some(json!({"lease":"synthetic_lease_12345678"})),
        )
        .await
        .unwrap();
    }
    let target = http(old.ports[1], "/health", None).await.unwrap();
    let resident = http(old.ports[0], "/health", None).await.unwrap();
    let result = control::switch(
        "second",
        &target,
        &[("first".into(), resident)],
        &CancellationToken::new(),
        Duration::from_secs(3),
        &|id, body: Value| {
            // The endpoint resolves to a fresh real process instance at grant,
            // after phase and unload were acknowledged by the previous one.
            let port = if body["action"] == "grant" {
                replacement.ports[1]
            } else {
                old.ports[index(&id)]
            };
            http(port, "/v1/yougori/optimizer", Some(body))
        },
    )
    .await;
    assert_eq!(result, Err(control::Failure::Rejected));
    let health = http(replacement.ports[1], "/health", None).await.unwrap();
    assert_eq!(health["optimizer"]["resident"], false);
    assert_eq!(health["optimizer"]["loading"], false);
    assert_ne!(
        health["optimizer"]["instanceId"],
        target["optimizer"]["instanceId"]
    );
}

#[tokio::test]
async fn real_target_request_release_between_phase_and_grant_refuses_admission() {
    let fixture = Runners::start().await;
    let ports = fixture.ports;
    let lease = json!({"lease":"synthetic_lease_12345678"});
    http(ports[1], "/v1/yougori/prepare", Some(lease.clone()))
        .await
        .unwrap();
    let target = http(ports[1], "/health", None).await.unwrap();
    let resident = http(ports[0], "/health", None).await.unwrap();
    let result = control::switch(
        "second",
        &target,
        &[("first".into(), resident)],
        &CancellationToken::new(),
        Duration::from_secs(3),
        &|id, body: Value| {
            let lease = lease.clone();
            async move {
                if body["action"] == "grant" {
                    http(ports[1], "/v1/yougori/release", Some(lease)).await?;
                }
                http(ports[index(&id)], "/v1/yougori/optimizer", Some(body)).await
            }
        },
    )
    .await;
    assert_eq!(result, Err(control::Failure::Rejected));
    let health = http(ports[1], "/health", None).await.unwrap();
    assert_eq!(health["optimizer"]["resident"], false);
    assert_eq!(health["optimizer"]["loading"], false);
    assert_eq!(health["optimizer"]["pending"], 0);
}
