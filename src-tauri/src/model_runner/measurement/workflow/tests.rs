use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn owner_lock_current_identity_and_storage_limits_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = Owner::open(root.path(), "env-1").unwrap();
    assert!(Owner::open(root.path(), "env-1").is_err());
    let id = "a".repeat(32);
    owner.select(Some(id.clone())).unwrap();
    assert!(owner.session("../outside", true).is_err());
    for n in 0..8 {
        owner.session(&format!("{n:032x}"), true).unwrap();
    }
    assert!(owner.session(&"b".repeat(32), true).is_err());
    drop(owner);
    let owner = Owner::open(root.path(), "env-1").unwrap();
    assert_eq!(owner.current, Some(id));
    drop(owner);
    std::fs::write(root.path().join("env-1/current.json"), b"{}").unwrap();
    assert!(Owner::open(root.path(), "env-1").is_err());
    assert!(Owner::open(root.path(), "../escape").is_err());
}

#[tokio::test]
async fn lost_start_ack_keeps_identity_and_retry_does_not_create_a_new_session() {
    let root = tempfile::tempdir().unwrap();
    let count = AtomicUsize::new(0);
    let send = |_: String, _: String, body: Option<Value>| {
        let number = count.fetch_add(1, Ordering::SeqCst);
        async move {
            if number == 0 {
                Err("fixture private failure".into())
            } else {
                Ok(
                    json!({"journal":{"sessionId":body.unwrap()["sessionId"],"status":"recording","loss":false}}),
                )
            }
        }
    };
    let first = execute(
        root.path().into(),
        "env-1".into(),
        "start".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    assert_eq!(first["state"], "startUnconfirmed");
    assert!(!first.to_string().contains("private failure"));
    let second = execute(
        root.path().into(),
        "env-1".into(),
        "start".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    assert_eq!(second["state"], "recording");
    assert_eq!(second["sessionId"], first["sessionId"]);
    assert!(execute(
        root.path().into(),
        "env-1".into(),
        "start".into(),
        Some("f".repeat(32)),
        &send
    )
    .await
    .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_collection_export_and_abandon_remain_explicitly_incomplete() {
    let root = tempfile::tempdir().unwrap();
    let send =
        |_: String, _: String, _: Option<Value>| async { Err("private backend detail".into()) };
    let start = execute(
        root.path().into(),
        "env-1".into(),
        "start".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    let id = start["sessionId"].as_str().unwrap().to_owned();
    let result = execute(
        root.path().into(),
        "env-1".into(),
        "collect".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    assert_eq!(result["state"], "incomplete");
    assert_eq!(result["summary"]["sealed"], false);
    assert!(!result.to_string().contains("private backend detail"));
    let export = execute(
        root.path().into(),
        "env-1".into(),
        "export".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    let evidence: Value =
        serde_json::from_slice(&std::fs::read(export["path"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(evidence["complete"], false);
    assert_eq!(evidence["benchmarkContext"], "unavailable");
    let abandoned = execute(
        root.path().into(),
        "env-1".into(),
        "abandon".into(),
        None,
        &send,
    )
    .await
    .unwrap();
    assert_eq!(abandoned["runnerStopped"], false);
    assert_eq!(Owner::open(root.path(), "env-1").unwrap().current, None);
    let archived = execute(
        root.path().into(),
        "env-1".into(),
        "status".into(),
        Some(id),
        &send,
    )
    .await
    .unwrap();
    assert_eq!(archived["summary"]["sealed"], false);
}

#[tokio::test]
async fn malformed_identity_and_actions_have_no_transport_effects() {
    let root = tempfile::tempdir().unwrap();
    let send = |_: String, _: String, _: Option<Value>| async {
        panic!("unexpected transport");
        #[allow(unreachable_code)]
        Ok(Value::Null)
    };
    for (env, action, session) in [
        ("../outside", "start", None),
        ("env-1", "unknown", None),
        ("env-1", "start", Some("../escape".to_owned())),
    ] {
        assert!(execute(
            root.path().into(),
            env.into(),
            action.into(),
            session,
            &send
        )
        .await
        .is_err());
    }
}
