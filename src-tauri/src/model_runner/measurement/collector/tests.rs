use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn session() -> String {
    "a".repeat(32)
}
fn instance() -> String {
    "b".repeat(32)
}
fn records() -> Vec<Value> {
    vec![
        json!({"event":"instance","sequence":1,"instanceId":instance()}),
        json!({"event":"start","sequence":2,"instanceId":instance(),"attemptId":1,"kind":"request"}),
        json!({"event":"start","sequence":3,"instanceId":instance(),"attemptId":2,"kind":"request"}),
        finish(4, 2, 1, "error"),
        finish(5, 1, 2, "cancelled"),
        json!({"event":"seal","sequence":6,"instanceId":instance()}),
    ]
}
fn finish(sequence: u64, attempt: u64, completion: u64, outcome: &str) -> Value {
    json!({"event":"finish","sequence":sequence,"instanceId":instance(),"attemptId":attempt,
        "record":{"id":attempt,"completionSequence":completion,"kind":"request","outcome":outcome,
            "elapsedMs":3.5,"firstOutputMs":null,"stages":{}}})
}
fn envelope(all: &[Value], after: u64, limit: usize, sealed: bool, inflight: usize) -> Value {
    let rows: Vec<_> = all
        .iter()
        .filter(|r| r["sequence"].as_u64().unwrap() > after)
        .take(limit)
        .cloned()
        .collect();
    let next_after = rows
        .last()
        .and_then(|r| r["sequence"].as_u64())
        .unwrap_or(after);
    json!({"journal":{"version":1,"scope":"session_window","clock":"process_monotonic","units":"milliseconds",
        "sessionId":session(),"instanceId":instance(),"status":if sealed{"sealed"}else{"recording"},
        "firstSequence":1,"nextSequence":all.len()+1,"after":after,"nextAfter":next_after,
        "hasMore":next_after < all.len() as u64,"loss":false,"complete":sealed,"inflight":inflight,"interrupted":0,"records":rows}})
}
fn path_cursor(path: &str) -> (u64, usize) {
    let query = path.split('?').nth(1).unwrap();
    let fields: Vec<_> = query.split('&').collect();
    (
        fields[1].strip_prefix("after=").unwrap().parse().unwrap(),
        fields[2].strip_prefix("limit=").unwrap().parse().unwrap(),
    )
}
fn ack(batch: &ValidatedBatch) -> PersistAck {
    PersistAck {
        environment_id: batch.environment_id.clone(),
        session_id: batch.session_id.clone(),
        through: batch.through,
    }
}

#[test]
fn previously_advertised_journal_tail_cannot_silently_shrink() {
    let dir = tempfile::tempdir().unwrap();
    let store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let (_, next) = page(envelope(&records(), 0, 3, true, 0), store.current(), 3).unwrap();
    assert_eq!(next.observed_next, 7);
    let shortened = envelope(&records()[..4], 3, 3, false, 1);
    assert!(matches!(page(shortened, &next, 3), Err(Failure::Reordered)));
}

#[tokio::test]
async fn paged_out_of_order_completions_keep_failures_and_checkpoint_after_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let persisted = Mutex::new(Vec::new());
    let send = |_: String, path: String, body: Option<Value>| {
        assert!(body.is_none());
        let (after, limit) = path_cursor(&path);
        std::future::ready(Ok(envelope(&records(), after, limit, true, 0)))
    };
    let sink = |batch: ValidatedBatch| {
        let result = ack(&batch);
        persisted.lock().unwrap().extend(batch.records);
        std::future::ready(Ok(result))
    };
    let result = collect(
        "env-1",
        &session(),
        &mut store,
        Limits {
            page_size: 2,
            ..Limits::default()
        },
        &CancellationToken::new(),
        &send,
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::Sealed);
    assert_eq!(result.events, 6);
    assert_eq!(result.pages, 3);
    assert!(store.current().active.is_empty());
    assert_eq!(store.current().completed, 2);
    assert_eq!(*persisted.lock().unwrap(), records());
    drop(store);
    let recovered = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    assert!(recovered.current().sealed);
    assert_eq!(recovered.current().after, 6);
}

#[tokio::test]
async fn page_cap_then_resume_preserves_inflight_across_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let send = |_: String, path: String, _: Option<Value>| {
        let (after, limit) = path_cursor(&path);
        std::future::ready(Ok(envelope(&records(), after, limit, true, 0)))
    };
    let sink = |batch: ValidatedBatch| std::future::ready(Ok(ack(&batch)));
    let result = collect(
        "env-1",
        &session(),
        &mut store,
        Limits {
            page_size: 3,
            max_pages: 1,
            ..Limits::default()
        },
        &CancellationToken::new(),
        &send,
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::PageLimit);
    assert_eq!(result.inflight, 2);
    drop(store);
    let mut recovered = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let result = collect(
        "env-1",
        &session(),
        &mut recovered,
        Limits::default(),
        &CancellationToken::new(),
        &send,
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::Sealed);
    assert_eq!(result.events, 3);
}

#[tokio::test]
async fn open_head_and_inflight_are_never_complete_and_no_seal_is_requested() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let send = |_: String, path: String, body: Option<Value>| {
        assert!(body.is_none());
        let (after, limit) = path_cursor(&path);
        std::future::ready(Ok(envelope(&records()[..3], after, limit, false, 2)))
    };
    let sink = |batch: ValidatedBatch| std::future::ready(Ok(ack(&batch)));
    let result = collect(
        "env-1",
        &session(),
        &mut store,
        Limits {
            seal: true,
            ..Limits::default()
        },
        &CancellationToken::new(),
        &send,
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::OpenHead);
    assert_eq!(result.inflight, 2);
    assert!(!store.current().sealed);
}

#[tokio::test]
async fn seal_http_ack_is_not_completion_until_seal_replayed_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let posts = AtomicUsize::new(0);
    let send = |_: String, path: String, body: Option<Value>| {
        let value = if let Some(body) = body {
            assert_eq!(body, json!({"action":"seal","sessionId":session()}));
            posts.fetch_add(1, Ordering::SeqCst);
            json!({"untrusted":"not proof"})
        } else {
            let (after, limit) = path_cursor(&path);
            let all = records();
            if posts.load(Ordering::SeqCst) == 0 {
                envelope(&all[..5], after, limit, false, 0)
            } else {
                envelope(&all, after, limit, true, 0)
            }
        };
        std::future::ready(Ok(value))
    };
    let persisted = Mutex::new(Vec::new());
    let sink = |batch: ValidatedBatch| {
        let reply = ack(&batch);
        persisted.lock().unwrap().push(batch);
        std::future::ready(Ok(reply))
    };
    let result = collect(
        "env-1",
        &session(),
        &mut store,
        Limits {
            seal: true,
            ..Limits::default()
        },
        &CancellationToken::new(),
        &send,
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(result.end, End::Sealed);
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(persisted.lock().unwrap()[1].records[0]["event"], "seal");
}

#[tokio::test]
async fn malformed_loss_restart_downgrade_duplicates_and_missing_finishes_never_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let base = envelope(&records(), 0, 64, true, 0);
    let mut malformed = vec![json!({"recent":[]})];
    for (key, value) in [
        ("version", json!(2)),
        ("loss", json!(true)),
        ("sessionId", json!("c".repeat(32))),
        ("instanceId", json!("c".repeat(32))),
        ("interrupted", json!(1)),
        ("inflight", json!(1)),
        ("clock", json!("cuda")),
        ("units", json!("seconds")),
        ("hasMore", json!(true)),
        ("status", json!("disabled")),
    ] {
        let mut value_page = base.clone();
        value_page["journal"][key] = value;
        malformed.push(value_page);
    }
    for key in ["event", "sequence", "instanceId"] {
        let mut wrong = base.clone();
        wrong["journal"]["records"][2][key] = wrong["journal"]["records"][1][key].clone();
        if key == "event" {
            wrong["journal"]["records"][2][key] = json!("unknown");
        }
        if key == "instanceId" {
            wrong["journal"]["records"][2][key] = json!("c".repeat(32));
        }
        malformed.push(wrong);
    }
    let mut no_finish = base.clone();
    no_finish["journal"]["records"][4] =
        json!({"event":"seal","sequence":5,"instanceId":instance()});
    malformed.push(no_finish);
    // A tag written as a number names no event; it is never read as the variant index
    // (S06): record 0 is the instance event, which plain serde would accept for `0`.
    let mut numeric_tag = base.clone();
    numeric_tag["journal"]["records"][0]["event"] = json!(0);
    malformed.push(numeric_tag);
    let mut leak = base.clone();
    leak["journal"]["records"][3]["record"]["prompt"] = json!("must reject");
    malformed.push(leak);
    for value in malformed {
        let send = |_: String, _: String, _: Option<Value>| std::future::ready(Ok(value.clone()));
        let sink = |_: ValidatedBatch| {
            panic!("invalid page must never reach persistence");
            #[allow(unreachable_code)]
            std::future::ready(Err::<PersistAck, String>("unreachable".into()))
        };
        assert!(collect(
            "env-1",
            &session(),
            &mut store,
            Limits::default(),
            &CancellationToken::new(),
            &send,
            &sink
        )
        .await
        .is_err());
        assert_eq!(store.current().after, 0);
    }
}

#[tokio::test]
async fn sink_failure_bad_ack_and_cancel_after_durable_write_do_not_advance() {
    for mode in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
        let cancel = CancellationToken::new();
        let send = |_: String, _: String, _: Option<Value>| {
            std::future::ready(Ok(envelope(&records(), 0, 64, true, 0)))
        };
        let sink = |batch: ValidatedBatch| {
            let mut result = ack(&batch);
            match mode {
                0 => return std::future::ready(Err("sink failed".into())),
                1 => result.through -= 1,
                2 => result.session_id = "c".repeat(32),
                _ => cancel.cancel(),
            }
            std::future::ready(Ok(result))
        };
        assert!(collect(
            "env-1",
            &session(),
            &mut store,
            Limits::default(),
            &cancel,
            &send,
            &sink
        )
        .await
        .is_err());
        assert_eq!(store.current().after, 0);
        drop(store);
        assert_eq!(
            CursorStore::open(dir.path(), "env-1", &session())
                .unwrap()
                .current()
                .after,
            0
        );
    }
}

#[tokio::test]
async fn report_ack_then_checkpoint_failure_replays_without_assuming_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let calls = AtomicUsize::new(0);
    let durable = Mutex::new(std::collections::BTreeMap::new());
    let send = |_: String, _: String, _: Option<Value>| {
        std::future::ready(Ok(envelope(&records(), 0, 64, true, 0)))
    };
    let sink = |batch: ValidatedBatch| {
        for row in &batch.records {
            durable
                .lock()
                .unwrap()
                .insert(row["sequence"].as_u64().unwrap(), row.clone());
        }
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            std::fs::create_dir(dir.path().join("cursor.json")).unwrap();
        }
        std::future::ready(Ok(ack(&batch)))
    };
    assert_eq!(
        collect(
            "env-1",
            &session(),
            &mut store,
            Limits::default(),
            &CancellationToken::new(),
            &send,
            &sink
        )
        .await,
        Err(Failure::Cursor)
    );
    assert_eq!(store.current().after, 0);
    assert_eq!(durable.lock().unwrap().len(), 6);
    std::fs::remove_dir(dir.path().join("cursor.json")).unwrap();
    drop(store);
    let mut recovered = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    assert_eq!(
        collect(
            "env-1",
            &session(),
            &mut recovered,
            Limits::default(),
            &CancellationToken::new(),
            &send,
            &sink
        )
        .await
        .unwrap()
        .end,
        End::Sealed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(durable.lock().unwrap().len(), 6);
}

#[tokio::test]
async fn cancellation_and_deadline_drop_pending_transport_without_advancing_cursor() {
    struct PendingGuard(Arc<AtomicUsize>);
    impl Drop for PendingGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for cancelled in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        let send = |_: String, _: String, _: Option<Value>| {
            let dropped = dropped.clone();
            let cancel = cancel.clone();
            async move {
                let _guard = PendingGuard(dropped);
                if cancelled {
                    cancel.cancel();
                }
                std::future::pending::<Result<Value, String>>().await
            }
        };
        let sink = |batch: ValidatedBatch| std::future::ready(Ok(ack(&batch)));
        let result = collect(
            "env-1",
            &session(),
            &mut store,
            Limits {
                deadline: Duration::from_millis(10),
                ..Limits::default()
            },
            &cancel,
            &send,
            &sink,
        )
        .await;
        assert_eq!(
            result,
            Err(if cancelled {
                Failure::Cancelled
            } else {
                Failure::TimedOut
            })
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(store.current().after, 0);
    }
}

#[tokio::test]
async fn bad_limits_identity_and_precancel_are_rejected_before_transport() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = CursorStore::open(dir.path(), "env-1", &session()).unwrap();
    let calls = AtomicUsize::new(0);
    let send = |_: String, _: String, _: Option<Value>| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err("unexpected".into()))
    };
    let sink = |batch: ValidatedBatch| std::future::ready(Ok(ack(&batch)));
    for limits in [
        Limits {
            page_size: 129,
            ..Limits::default()
        },
        Limits {
            max_pages: 0,
            ..Limits::default()
        },
        Limits {
            deadline: Duration::from_secs(61),
            ..Limits::default()
        },
    ] {
        assert_eq!(
            collect(
                "env-1",
                &session(),
                &mut store,
                limits,
                &CancellationToken::new(),
                &send,
                &sink
            )
            .await,
            Err(Failure::ResourceLimit)
        );
    }
    assert_eq!(
        collect(
            "env-other",
            &session(),
            &mut store,
            Limits::default(),
            &CancellationToken::new(),
            &send,
            &sink
        )
        .await,
        Err(Failure::Identity)
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        collect(
            "env-1",
            &session(),
            &mut store,
            Limits::default(),
            &cancel,
            &send,
            &sink
        )
        .await,
        Err(Failure::Cancelled)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
