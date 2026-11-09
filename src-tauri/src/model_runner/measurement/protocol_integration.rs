//! Actual Python timing HTTP handlers -> Rust collection -> durable report sink.
//! Only the model is synthetic. These fixtures back no hardware/performance claim.
use super::{
    collector::{self, End, Failure, Limits},
    cursor::CursorStore,
    sink::{tests::context, DurableSink},
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::sync::CancellationToken;

struct Fixture {
    child: Child,
    root: tempfile::TempDir,
    port: u16,
    session: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Fixture {
    async fn start() -> Self {
        Self::start_mode(false).await
    }
    async fn start_mode(demand: bool) -> Self {
        let scratch = Path::new("D:/YougoriBuildCache/scratch");
        let root = if scratch.is_dir() {
            tempfile::tempdir_in(scratch)
        } else {
            tempfile::tempdir()
        }
        .unwrap();
        let session = "a".repeat(32);
        let child = spawn(root.path(), &session, demand);
        let mut result = Self {
            child,
            root,
            port: 0,
            session,
        };
        result.ready().await;
        result
    }
    async fn ready(&mut self) {
        self.port = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read(self.root.path().join("ready.json")) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(port) = v["port"]
                            .as_u64()
                            .and_then(|n| u16::try_from(n).ok())
                            .filter(|p| *p != 0)
                        {
                            return port;
                        }
                    }
                }
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "measurement fixture exited"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("measurement fixture readiness deadline");
    }
    async fn restart(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        std::fs::remove_file(self.root.path().join("ready.json")).unwrap();
        self.child = spawn(self.root.path(), &self.session, false);
        self.ready().await;
    }
}
fn spawn(root: &Path, session: &str, demand: bool) -> Child {
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
        command.env(name, root);
    }
    command
        .args(["-I", "-B", "-u"])
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/model_runner/measurement/protocol_fixture.py"),
        )
        .arg(root.join("ready.json"))
        .arg(root.join("cache"))
        .arg(session)
        .arg(if demand { "demand" } else { "ready" })
        .env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("CUDA_VISIBLE_DEVICES", "")
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(root.join("errors.txt")).unwrap(),
        ))
        .spawn()
        .expect("Python required by offline integration gate")
}
async fn http(port: u16, path: &str, body: Option<Value>, admin: bool) -> Result<Value, String> {
    tokio::time::timeout(Duration::from_secs(5),async {
        let mut socket=TcpStream::connect(("127.0.0.1",port)).await.map_err(|_|"fixture connect".to_owned())?;
        let bytes=body.as_ref().map(serde_json::to_vec).transpose().map_err(|_|"fixture encode".to_owned())?.unwrap_or_default();
        let private=if admin {"X-Yougori-Admin: fixture-admin-token\r\n"} else {""};
        let headers=format!("{} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-model-token\r\n{private}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",if body.is_some(){"POST"}else{"GET"},bytes.len());
        socket.write_all(headers.as_bytes()).await.map_err(|_|"fixture write".to_owned())?;
        socket.write_all(&bytes).await.map_err(|_|"fixture write".to_owned())?;
        super::super::model_response(Box::new(socket),super::super::reply_seconds(path,body.is_some())).await
    }).await.map_err(|_|"fixture HTTP deadline".to_owned())?
}
fn limits(seal: bool, page_size: usize) -> Limits {
    Limits {
        page_size,
        max_pages: 64,
        deadline: Duration::from_secs(20),
        seal,
    }
}

#[tokio::test]
async fn durable_window_exceeds_ring_and_preserves_success_failure_and_conversion_gaps() {
    let fixture = Fixture::start().await;
    let port = fixture.port;
    assert!(http(port, "/v1/diagnostics/timings?journal=1", None, false)
        .await
        .is_err());
    assert!(http(
        port,
        "/v1/diagnostics/timings?journal=1&limit=0",
        None,
        true
    )
    .await
    .is_err());
    for i in 0..70 {
        let body = if i % 2 == 0 {
            json!({"messages":[{"role":"user","content":"synthetic fixture"}],"max_tokens":1})
        } else {
            json!({"messages":[]})
        };
        assert_eq!(
            http(port, "/v1/chat/completions", Some(body), false)
                .await
                .is_ok(),
            i % 2 == 0
        );
    }
    let timing = http(port, "/v1/diagnostics/timings", None, true)
        .await
        .unwrap();
    assert_eq!(timing["completed"], 71);
    assert_eq!(timing["retained"], 64);
    for row in timing["recent"].as_array().unwrap() {
        let observation = super::report::parse_completed(row).unwrap();
        if row["outcome"] == "ok" {
            let boundaries = observation.boundaries.unwrap();
            assert!(boundaries.admitted_nanos.is_some());
            assert!(boundaries.completed_nanos.is_some());
            assert!(observation.first_output_nanos.is_none());
        } else {
            // Invalid JSON/schema never reaches request acceptance.
            assert!(observation.boundaries.is_none());
        }
    }
    let mut cursor = CursorStore::open(
        &fixture.root.path().join("cursor"),
        "env-1",
        &fixture.session,
    )
    .unwrap();
    let sink =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let save = |batch| async {
        sink.persist(batch, &context)
            .map_err(|_| "fixture persistence".to_owned())
    };
    let result = collector::collect(
        "env-1",
        &fixture.session,
        &mut cursor,
        limits(true, 17),
        &CancellationToken::new(),
        &send,
        &save,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::Sealed);
    let saved = sink.summary().unwrap();
    assert_eq!(
        (saved.started, saved.completed, saved.inflight),
        (71, 71, 0)
    );
    assert_eq!((saved.converted, saved.with_gaps), (36, 71));
    assert!(saved.sealed);
    let before = saved.events;
    drop(cursor);
    drop(sink);
    let sink =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    // A lost cursor is safe: re-fetch the same journal under different page boundaries.
    let mut replay = CursorStore::open(
        &fixture.root.path().join("new-cursor"),
        "env-1",
        &fixture.session,
    )
    .unwrap();
    let save = |batch| async {
        sink.persist(batch, &context)
            .map_err(|_| "fixture persistence".to_owned())
    };
    collector::collect(
        "env-1",
        &fixture.session,
        &mut replay,
        limits(false, 11),
        &CancellationToken::new(),
        &send,
        &save,
    )
    .await
    .unwrap();
    assert_eq!(sink.summary().unwrap().events, before);
}

#[tokio::test]
async fn durable_sink_then_lost_ack_replays_without_advancing_or_duplicating() {
    let fixture = Fixture::start().await;
    let port = fixture.port;
    let mut cursor = CursorStore::open(
        &fixture.root.path().join("cursor"),
        "env-1",
        &fixture.session,
    )
    .unwrap();
    let sink =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let lost = |batch| async {
        sink.persist(batch, &context)
            .map_err(|_| "fixture persistence".to_owned())?;
        Err("fixture lost acknowledgement".to_owned())
    };
    assert_eq!(
        collector::collect(
            "env-1",
            &fixture.session,
            &mut cursor,
            limits(false, 64),
            &CancellationToken::new(),
            &send,
            &lost
        )
        .await
        .unwrap_err(),
        Failure::Persistence
    );
    assert_eq!(cursor.current().after, 0);
    assert_eq!(sink.summary().unwrap().completed, 1);
    let save = |batch| async {
        sink.persist(batch, &context)
            .map_err(|_| "fixture persistence".to_owned())
    };
    collector::collect(
        "env-1",
        &fixture.session,
        &mut cursor,
        limits(true, 2),
        &CancellationToken::new(),
        &send,
        &save,
    )
    .await
    .unwrap();
    assert_eq!(sink.summary().unwrap().completed, 1);
    assert!(sink.summary().unwrap().sealed);
}

#[tokio::test]
async fn real_runner_restart_refuses_complete_window_and_preserves_old_evidence() {
    let mut fixture = Fixture::start().await;
    let journal = fixture
        .root
        .path()
        .join("cache/yougori-measurements")
        .join(format!("{}.jsonl", fixture.session));
    let old = std::fs::read(&journal).unwrap();
    fixture.restart().await;
    let port = fixture.port;
    assert_eq!(std::fs::read(journal).unwrap(), old);
    let mut cursor = CursorStore::open(
        &fixture.root.path().join("cursor"),
        "env-1",
        &fixture.session,
    )
    .unwrap();
    let sink =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let save = |batch| async {
        sink.persist(batch, &context)
            .map_err(|_| "fixture persistence".to_owned())
    };
    assert_eq!(
        collector::collect(
            "env-1",
            &fixture.session,
            &mut cursor,
            limits(true, 64),
            &CancellationToken::new(),
            &send,
            &save
        )
        .await
        .unwrap_err(),
        Failure::Loss
    );
    assert_eq!(cursor.current().after, 0);
    assert_eq!(sink.summary().unwrap().events, 0);
}

#[tokio::test]
async fn byte_verified_stream_replays_as_successful_serving_report() {
    serving_replay(false).await;
}

#[tokio::test]
async fn correlated_demand_load_replays_as_successful_serving_report() {
    serving_replay(true).await;
}

async fn serving_replay(demand: bool) {
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::start_mode(demand).await;
    let port = fixture.port;
    // Read the actual public SSE response; the backend alone is a fixture.
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = serde_json::to_vec(&json!({"messages":[{"role":"user","content":"fixture"}],
        "stream":true,"max_tokens":2}))
    .unwrap();
    let headers = format!("POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-model-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.take(65536).read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("[DONE]"));
    assert!(!response.contains("logprobs"));
    let timing = http(port, "/v1/diagnostics/timings", None, true)
        .await
        .unwrap();
    let row = &timing["recent"][1];
    let observation = super::report::parse_completed(row).unwrap();
    assert_eq!(observation.demand_load.is_some(), demand);
    if let Some(load) = &observation.demand_load {
        assert_eq!(load.attempt_id, timing["recent"][0]["id"].as_u64().unwrap());
        assert!(load.ready_nanos >= load.started_nanos);
    }
    let tokens = observation.tokens.as_ref().unwrap();
    assert!(tokens.complete);
    assert_eq!(tokens.output_tokens, Some(2));
    let mut cursor = CursorStore::open(
        &fixture.root.path().join("cursor"),
        "env-1",
        &fixture.session,
    )
    .unwrap();
    let sink =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let ready_context = |identity: &super::report::ObservationIdentity, kind| {
        let mut ctx = context(identity, kind)?;
        if let crate::foundation::report::Measured::Measured { value } = &mut ctx.metadata.state {
            value.model_at_arrival = if demand {
                crate::foundation::report::ModelAtArrival::NotLoaded
            } else {
                crate::foundation::report::ModelAtArrival::ReadyToServe
            };
            value.temperature = if demand {
                crate::foundation::report::StartTemperature::Warm
            } else {
                crate::foundation::report::StartTemperature::Hot
            };
            value.cold_provenance = crate::foundation::report::ColdProvenance::NotCold;
        }
        Ok(ctx)
    };
    let save = |batch| async {
        sink.persist(batch, &ready_context)
            .map_err(|_| "fixture persistence".to_owned())
    };
    collector::collect(
        "env-1",
        &fixture.session,
        &mut cursor,
        limits(true, 1),
        &CancellationToken::new(),
        &send,
        &save,
    )
    .await
    .unwrap();
    let summary = sink.summary().unwrap();
    assert_eq!((summary.completed, summary.converted), (2, 2));
    assert!(summary.sealed);
    drop(sink);
    let reopened =
        DurableSink::open(&fixture.root.path().join("sink"), "env-1", &fixture.session).unwrap();
    assert_eq!(reopened.summary().unwrap(), summary);
}

#[tokio::test]
async fn owner_workflow_collects_seals_exports_and_rotates_real_runner_sessions() {
    let fixture = Fixture::start().await;
    let port = fixture.port;
    let root = fixture.root.path().join("owner");
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let start = super::workflow::execute(
        root.clone(),
        "env-1".into(),
        "start".into(),
        Some(fixture.session.clone()),
        &send,
    )
    .await
    .unwrap();
    assert_eq!(start["state"], "recording");
    http(
        port,
        "/v1/chat/completions",
        Some(json!({"messages":[{"role":"user","content":"fixture"}],"stream":false})),
        false,
    )
    .await
    .unwrap();
    let collected =
        super::workflow::execute(root.clone(), "env-1".into(), "collect".into(), None, &send)
            .await
            .unwrap();
    assert_eq!(collected["summary"]["completed"], 2);
    assert_eq!(collected["summary"]["converted"], 0);
    let resumed =
        super::workflow::execute(root.clone(), "env-1".into(), "collect".into(), None, &send)
            .await
            .unwrap();
    assert_eq!(resumed["summary"], collected["summary"]);
    let sealed = super::workflow::execute(root.clone(), "env-1".into(), "seal".into(), None, &send)
        .await
        .unwrap();
    assert_eq!(sealed["state"], "sealed");
    let exported =
        super::workflow::execute(root.clone(), "env-1".into(), "export".into(), None, &send)
            .await
            .unwrap();
    let evidence: Value =
        serde_json::from_slice(&std::fs::read(exported["path"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(evidence["complete"], true);
    assert_eq!(evidence["summary"]["started"], 2);
    assert_eq!(
        evidence["events"][2]["gaps"],
        json!(["ReportContextUnavailable"])
    );
    assert!(evidence["events"][2]["report"].is_null());
    let next = super::workflow::execute(root.clone(), "env-1".into(), "start".into(), None, &send)
        .await
        .unwrap();
    assert_eq!(next["state"], "recording");
    assert_ne!(next["sessionId"], start["sessionId"]);
    let current = http(port, "/v1/diagnostics/timings?journal=1", None, true)
        .await
        .unwrap();
    assert_eq!(current["journal"]["records"].as_array().unwrap().len(), 1);
    let old = super::workflow::execute(
        root.clone(),
        "env-1".into(),
        "export".into(),
        Some(fixture.session.clone()),
        &send,
    )
    .await
    .unwrap();
    assert_eq!(old["summary"]["completed"], 2);
    assert!(!fixture
        .root
        .path()
        .join("cache/yougori-measurements")
        .join(format!("{}.jsonl", fixture.session))
        .exists());
    let stopped = super::workflow::execute(root, "env-1".into(), "abandon".into(), None, &send)
        .await
        .unwrap();
    assert_eq!(stopped["state"], "abandoned");
    assert_eq!(stopped["runnerStopped"], true);
}

#[tokio::test]
async fn owner_workflow_preserves_partial_output_after_runner_restart() {
    let mut fixture = Fixture::start().await;
    let port = fixture.port;
    let root = fixture.root.path().join("owner");
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    super::workflow::execute(
        root.clone(),
        "env-1".into(),
        "start".into(),
        Some(fixture.session.clone()),
        &send,
    )
    .await
    .unwrap();
    let before =
        super::workflow::execute(root.clone(), "env-1".into(), "collect".into(), None, &send)
            .await
            .unwrap();
    fixture.restart().await;
    let port = fixture.port;
    let send = |_: String, path: String, body| async move { http(port, &path, body, true).await };
    let after = super::workflow::execute(root.clone(), "env-1".into(), "seal".into(), None, &send)
        .await
        .unwrap();
    assert_eq!(after["state"], "incomplete");
    assert_eq!(after["issue"], "Loss");
    assert_eq!(after["summary"], before["summary"]);
    let export = super::workflow::execute(root, "env-1".into(), "export".into(), None, &send)
        .await
        .unwrap();
    let value: Value =
        serde_json::from_slice(&std::fs::read(export["path"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["summary"]["completed"], 1);
}
