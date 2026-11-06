use super::*;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn health(instance: char, sequence: u64, resident: bool, pending: u64) -> Value {
    json!({"status": if resident { "ready" } else if pending > 0 { "queued" } else { "idle" },
        "optimizer": {"controlProtocol":1, "instanceId":instance.to_string().repeat(32),
            "sequence":sequence, "enabled":true, "resident":resident, "pending":pending,
            "active":0, "pinned":false, "loading":false, "releaseUncertain":false}})
}

fn target() -> Value {
    health('a', 7, false, 1)
}
fn holders() -> Vec<(String, Value)> {
    vec![
        ("first".into(), health('b', 10, true, 0)),
        ("second".into(), health('c', 20, true, 0)),
    ]
}

fn answer(mut h: Value, body: &Value) -> Value {
    let action = body["action"].as_str().unwrap();
    let sequence = body["expectedSequence"].as_u64().unwrap();
    h["optimizer"]["sequence"] = json!(sequence + 1);
    match action {
        "phase" => {
            h["status"] = json!("freeing_memory");
            h["phased"] = json!(true);
        }
        "unload" => {
            h["status"] = json!("idle");
            h["optimizer"]["resident"] = json!(false);
            h["optimizer"]["releaseUncertain"] = json!(false);
            h["unloaded"] = json!(true);
        }
        "grant" => {
            h["status"] = json!("loading");
            h["optimizer"]["loading"] = json!(true);
            h["granted"] = json!(true);
        }
        _ => panic!("unexpected test action"),
    }
    h["controlAck"] = json!({"action":action, "instanceId":body["expectedInstanceId"],
        "expectedSequence":sequence, "sequence":sequence+1});
    h
}

#[derive(Default)]
struct RunnerSet {
    state: Mutex<BTreeMap<String, Value>>,
    calls: Mutex<Vec<(String, Value)>>,
    accepted_grants: AtomicUsize,
}

impl RunnerSet {
    fn new() -> Self {
        Self {
            state: Mutex::new(
                holders()
                    .into_iter()
                    .chain([("next".into(), target())])
                    .collect(),
            ),
            ..Self::default()
        }
    }
    fn call(&self, id: String, body: Value) -> Result<Value, String> {
        self.calls.lock().unwrap().push((id.clone(), body.clone()));
        let mut state = self.state.lock().unwrap();
        let h = state.get_mut(&id).unwrap();
        if h["optimizer"]["instanceId"] != body["expectedInstanceId"]
            || h["optimizer"]["sequence"] != body["expectedSequence"]
        {
            return Err("stale observation".into());
        }
        if body["action"] == "grant" {
            if h["optimizer"]["pending"] == 0 {
                return Err("demand expired".into());
            }
            self.accepted_grants.fetch_add(1, Ordering::SeqCst);
        }
        *h = answer(h.clone(), &body);
        Ok(h.clone())
    }
    fn actions(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b["action"].as_str().unwrap().into())
            .collect()
    }
}

#[tokio::test]
async fn a_grow_is_fenced_to_a_resident_runner_and_needs_its_own_acknowledgement() {
    let resident = health('b', 10, true, 0);
    let terms = json!({"bytes": 6u64 << 30, "context": 8192});
    let sent = Arc::new(Mutex::new(Vec::new()));
    let grown = |sent: Arc<Mutex<Vec<Value>>>, acknowledged: bool| {
        move |_: String, body: Value| {
            sent.lock().unwrap().push(body.clone());
            let mut h = health('b', 11, true, 0);
            h["grown"] = json!(acknowledged);
            h["terms"] = json!({"bytes": body["bytes"], "context": body["context"]});
            h["controlAck"] = json!({"action": "grow", "instanceId": body["expectedInstanceId"],
                "expectedSequence": body["expectedSequence"], "sequence": 11});
            async move { Ok::<Value, String>(h) }
        }
    };
    let shutdown = CancellationToken::new();
    let send = grown(sent.clone(), true);
    let answer = request_with(
        "m",
        Action::Grow,
        &resident,
        Some(&terms),
        &shutdown,
        TIMEOUT,
        &send,
    )
    .await
    .unwrap();
    assert_eq!(answer["terms"], terms);
    let body = sent.lock().unwrap()[0].clone();
    assert_eq!(body["action"], "grow");
    assert_eq!(
        (
            body["expectedInstanceId"].as_str().unwrap(),
            body["expectedSequence"].as_u64()
        ),
        ("b".repeat(32).as_str(), Some(10))
    );
    assert_eq!(
        (body["bytes"].clone(), body["context"].clone()),
        (terms["bytes"].clone(), terms["context"].clone())
    );
    // Without the runner's word that it grew, nothing is taken.
    let send = grown(sent.clone(), false);
    assert_eq!(
        request_with(
            "m",
            Action::Grow,
            &resident,
            Some(&terms),
            &shutdown,
            TIMEOUT,
            &send
        )
        .await
        .unwrap_err(),
        Failure::StaleAcknowledgement
    );
    // Only a resident runner that is not loading or uncertain is asked at all.
    for mut h in [
        health('b', 10, false, 0),
        health('b', 10, true, 0),
        health('b', 10, true, 0),
    ] {
        if h["optimizer"]["resident"] == true {
            let key = if sent.lock().unwrap().len() == 2 {
                "loading"
            } else {
                "releaseUncertain"
            };
            h["optimizer"][key] = json!(true);
        }
        let before = sent.lock().unwrap().len();
        let send = grown(sent.clone(), true);
        assert_eq!(
            request_with(
                "m",
                Action::Grow,
                &h,
                Some(&terms),
                &shutdown,
                TIMEOUT,
                &send
            )
            .await
            .unwrap_err(),
            Failure::Rejected
        );
        assert_eq!(sent.lock().unwrap().len(), before);
    }
}

#[test]
fn malformed_advertised_protocol_never_becomes_legacy() {
    assert_eq!(
        observation(&json!({"optimizer":{}})),
        Ok(Observation::Legacy)
    );
    for value in [
        Value::Null,
        json!(0),
        json!(2),
        json!("1"),
        json!(true),
        json!(1.0),
    ] {
        let mut h = target();
        h["optimizer"]["controlProtocol"] = value;
        assert_eq!(observation(&h), Err(Failure::UnsupportedProtocol));
    }
    for key in [
        "instanceId",
        "sequence",
        "enabled",
        "pinned",
        "resident",
        "loading",
        "releaseUncertain",
        "active",
        "pending",
    ] {
        let mut h = target();
        h["optimizer"].as_object_mut().unwrap().remove(key);
        assert_eq!(observation(&h), Err(Failure::InvalidObservation), "{key}");
    }
    for (key, value) in [
        ("sequence", json!(MAX_SEQUENCE + 1)),
        ("sequence", json!(-1)),
        ("sequence", json!(1.5)),
        ("instanceId", json!("A".repeat(32))),
        ("instanceId", json!("private/path")),
        ("resident", json!("false")),
        ("active", json!(false)),
    ] {
        let mut h = target();
        h["optimizer"][key] = value;
        assert_eq!(observation(&h), Err(Failure::InvalidObservation), "{key}");
    }
    let mut h = target();
    h["optimizer"]
        .as_object_mut()
        .unwrap()
        .remove("controlProtocol");
    assert_eq!(observation(&h), Err(Failure::InvalidObservation));
}

#[tokio::test]
async fn successful_switch_is_serial_and_uses_phase_revision_for_grant() {
    let runners = RunnerSet::new();
    let active = AtomicUsize::new(0);
    let send = |id, body| {
        let runners = &runners;
        let active = &active;
        async move {
            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
            tokio::task::yield_now().await;
            let result = runners.call(id, body);
            assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
            result
        }
    };
    assert_eq!(
        switch(
            "next",
            &target(),
            &holders(),
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await,
        Ok(())
    );
    assert_eq!(runners.actions(), ["phase", "unload", "unload", "grant"]);
    let calls = runners.calls.lock().unwrap();
    assert_eq!(calls[0].1["expectedSequence"], 7);
    assert_eq!(calls[3].1["expectedSequence"], 8);
    assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn all_observations_and_unique_residents_are_validated_before_effects() {
    let mut malformed = holders();
    malformed[1].1["optimizer"]["controlProtocol"] = json!(2);
    let duplicate = vec![holders()[0].clone(), holders()[0].clone()];
    let self_resident = vec![("next".into(), target())];
    for residents in [malformed, duplicate, self_resident] {
        let runners = RunnerSet::new();
        let send = |id, body| std::future::ready(runners.call(id, body));
        assert!(switch(
            "next",
            &target(),
            &residents,
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await
        .is_err());
        assert!(runners.actions().is_empty());
    }
    let mut overflow = target();
    overflow["optimizer"]["sequence"] = json!(MAX_SEQUENCE);
    let calls = AtomicUsize::new(0);
    let send = |_, _| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(json!({})))
    };
    assert_eq!(
        switch(
            "next",
            &overflow,
            &[],
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await,
        Err(Failure::InvalidObservation)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_or_stale_ack_stops_each_transition_step() {
    for action in ["phase", "unload", "grant"] {
        for fault in 0..10 {
            let runners = RunnerSet::new();
            let send = |id, body: Value| {
                let mut result = runners.call(id, body.clone());
                if body["action"] == action {
                    let ack = result.as_mut().unwrap();
                    match fault {
                        0 => {
                            ack["controlAck"]["action"] = json!("other");
                        }
                        1 => {
                            ack["controlAck"]["instanceId"] = json!("d".repeat(32));
                        }
                        2 => {
                            ack["controlAck"]["expectedSequence"] = json!(0);
                        }
                        3 => {
                            ack["controlAck"]["sequence"] = json!(999);
                        }
                        4 => {
                            ack["optimizer"]["sequence"] = body["expectedSequence"].clone();
                        }
                        5 => {
                            ack["optimizer"]["instanceId"] = json!("d".repeat(32));
                        }
                        6 => {
                            ack.as_object_mut().unwrap().remove("controlAck");
                        }
                        7 => {
                            ack["optimizer"].as_object_mut().unwrap().remove("resident");
                        }
                        8 => {
                            ack[match action {
                                "phase" => "phased",
                                "unload" => "unloaded",
                                _ => "granted",
                            }] = json!("true");
                        }
                        9 => {
                            let later = body["expectedSequence"].as_u64().unwrap() + 2;
                            ack["controlAck"]["sequence"] = json!(later);
                            ack["optimizer"]["sequence"] = json!(later);
                        }
                        _ => unreachable!(),
                    }
                }
                std::future::ready(result)
            };
            assert_eq!(
                switch(
                    "next",
                    &target(),
                    &holders(),
                    &CancellationToken::new(),
                    TIMEOUT,
                    &send
                )
                .await,
                Err(Failure::StaleAcknowledgement),
                "{action}, fault {fault}"
            );
            assert_eq!(
                runners.actions().len(),
                match action {
                    "phase" => 1,
                    "unload" => 2,
                    _ => 4,
                }
            );
        }
    }
}

#[tokio::test]
async fn restarted_or_cancelled_target_never_accepts_stale_phase_or_grant() {
    for moment in ["phase", "grant"] {
        for restart in [false, true] {
            let runners = RunnerSet::new();
            let send = |id: String, body: Value| {
                if id == "next" && body["action"] == moment {
                    let mut state = runners.state.lock().unwrap();
                    let h = state.get_mut("next").unwrap();
                    if restart {
                        h["optimizer"]["instanceId"] = json!("d".repeat(32));
                    } else {
                        h["optimizer"]["pending"] = json!(0);
                        h["optimizer"]["sequence"] = json!(100);
                    }
                }
                std::future::ready(runners.call(id, body))
            };
            assert_eq!(
                switch(
                    "next",
                    &target(),
                    &holders(),
                    &CancellationToken::new(),
                    TIMEOUT,
                    &send
                )
                .await,
                Err(Failure::Rejected)
            );
            assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 0);
            assert_eq!(
                runners.actions().len(),
                if moment == "phase" { 1 } else { 4 }
            );
        }
    }
}

#[tokio::test]
async fn resident_activity_restart_or_failure_after_first_unload_prevents_grant() {
    for fault in ["active", "pending", "pinned", "restart", "transport"] {
        let runners = RunnerSet::new();
        let send = |id: String, body: Value| {
            if id == "second" {
                if fault == "transport" {
                    return std::future::ready(Err("unreachable".into()));
                }
                let mut state = runners.state.lock().unwrap();
                let h = state.get_mut("second").unwrap();
                match fault {
                    "active" => h["optimizer"]["active"] = json!(1),
                    "pending" => h["optimizer"]["pending"] = json!(1),
                    "pinned" => h["optimizer"]["pinned"] = json!(true),
                    "restart" => h["optimizer"]["instanceId"] = json!("d".repeat(32)),
                    _ => unreachable!(),
                }
                h["optimizer"]["sequence"] = json!(21);
            }
            std::future::ready(runners.call(id, body))
        };
        assert_eq!(
            switch(
                "next",
                &target(),
                &holders(),
                &CancellationToken::new(),
                TIMEOUT,
                &send
            )
            .await,
            Err(Failure::Rejected)
        );
        assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 0);
        assert_eq!(
            runners.state.lock().unwrap()["first"]["optimizer"]["resident"],
            false,
            "no rollback fabricated"
        );
    }
}

#[tokio::test]
async fn duplicate_grant_cannot_reuse_consumed_revision() {
    let runners = RunnerSet::new();
    let send = |id, body| std::future::ready(runners.call(id, body));
    assert!(request(
        "next",
        Action::Grant,
        &target(),
        &CancellationToken::new(),
        TIMEOUT,
        &send
    )
    .await
    .is_ok());
    assert_eq!(
        request(
            "next",
            Action::Grant,
            &target(),
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await,
        Err(Failure::Rejected)
    );
    assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ack_does_not_clear_uncertainty_or_recreate_expired_target_demand() {
    for (action, key, value) in [
        ("phase", "pending", json!(0)),
        ("phase", "resident", json!(true)),
        ("unload", "releaseUncertain", json!(true)),
        ("unload", "resident", json!(true)),
        ("unload", "active", json!(1)),
        ("grant", "releaseUncertain", json!(true)),
    ] {
        let runners = RunnerSet::new();
        let send = |id, body: Value| {
            let mut result = runners.call(id, body.clone());
            if body["action"] == action {
                result.as_mut().unwrap()["optimizer"][key] = value.clone();
            }
            std::future::ready(result)
        };
        assert_eq!(
            switch(
                "next",
                &target(),
                &holders(),
                &CancellationToken::new(),
                TIMEOUT,
                &send
            )
            .await,
            Err(Failure::Rejected)
        );
        assert_eq!(
            runners.actions().len(),
            match action {
                "phase" => 1,
                "unload" => 2,
                _ => 4,
            }
        );
    }
}

struct Pending(Arc<AtomicUsize>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn timeout_drops_wait_and_never_continues_to_grant() {
    for stalled in ["phase", "unload", "grant"] {
        let runners = RunnerSet::new();
        let active = Arc::new(AtomicUsize::new(0));
        let send = |id, body: Value| {
            let runners = &runners;
            let active = active.clone();
            async move {
                if body["action"] == stalled {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = Pending(active);
                    std::future::pending().await
                } else {
                    runners.call(id, body)
                }
            }
        };
        assert_eq!(
            switch(
                "next",
                &target(),
                &holders(),
                &CancellationToken::new(),
                Duration::from_millis(10),
                &send
            )
            .await,
            Err(Failure::TimedOut)
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn shutdown_before_and_between_controls_starts_no_more_work() {
    for before in [true, false] {
        let runners = RunnerSet::new();
        let shutdown = CancellationToken::new();
        if before {
            shutdown.cancel();
        }
        let send = |id, body: Value| {
            let answer = runners.call(id, body.clone());
            if body["action"] == "unload" {
                shutdown.cancel();
            }
            std::future::ready(answer)
        };
        assert_eq!(
            switch("next", &target(), &holders(), &shutdown, TIMEOUT, &send).await,
            Err(Failure::Cancelled)
        );
        assert_eq!(runners.actions().len(), if before { 0 } else { 2 });
        assert_eq!(runners.accepted_grants.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn shutdown_during_pending_control_drops_future() {
    let active = Arc::new(AtomicUsize::new(0));
    let shutdown = CancellationToken::new();
    let send = |_, _| {
        let active = active.clone();
        let shutdown = shutdown.clone();
        async move {
            active.fetch_add(1, Ordering::SeqCst);
            let _guard = Pending(active);
            shutdown.cancel();
            std::future::pending().await
        }
    };
    assert_eq!(
        request("next", Action::Phase, &target(), &shutdown, TIMEOUT, &send).await,
        Err(Failure::Cancelled)
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn legacy_polling_remains_explicit_and_upgrade_ack_cannot_downgrade() {
    let legacy = json!({"optimizer":{}});
    let calls = Mutex::new(Vec::new());
    let send = |_: String, body: Value| {
        assert!(body.get("expectedSequence").is_none());
        calls.lock().unwrap().push(body);
        std::future::ready(Ok(json!({"unloaded":true})))
    };
    assert_eq!(
        switch(
            "next",
            &legacy,
            &[("first".into(), legacy.clone())],
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await,
        Ok(())
    );
    assert_eq!(calls.lock().unwrap().len(), 3);
    let upgraded = |_, _| std::future::ready(Ok(target()));
    assert_eq!(
        request(
            "next",
            Action::Phase,
            &legacy,
            &CancellationToken::new(),
            TIMEOUT,
            &upgraded
        )
        .await,
        Err(Failure::StaleAcknowledgement)
    );
    for bad in [
        json!({}),
        json!({"unloaded":false}),
        json!({"unloaded":"true"}),
        Value::Null,
    ] {
        let send = |_, _| std::future::ready(Ok(bad.clone()));
        assert_eq!(
            request(
                "first",
                Action::Unload,
                &legacy,
                &CancellationToken::new(),
                TIMEOUT,
                &send
            )
            .await,
            Err(Failure::StaleAcknowledgement)
        );
    }
}

#[tokio::test]
async fn empty_resident_set_still_fences_phase_before_grant() {
    let runners = RunnerSet::new();
    let send = |id, body| std::future::ready(runners.call(id, body));
    assert_eq!(
        switch(
            "next",
            &target(),
            &[],
            &CancellationToken::new(),
            TIMEOUT,
            &send
        )
        .await,
        Ok(())
    );
    assert_eq!(runners.actions(), ["phase", "grant"]);
}

#[test]
fn unknown_versioned_status_cannot_clear_occupancy() {
    for status in [
        "installing",
        "downloading",
        "verifying",
        "loading",
        "ready",
        "error",
        "idle",
        "queued",
        "freeing_memory",
        "unloading",
    ] {
        let mut h = target();
        h["status"] = json!(status);
        assert!(observation(&h).is_ok());
    }
    for status in [
        json!(""),
        json!("new_unknown_state"),
        json!("private contents"),
        json!(false),
        Value::Null,
    ] {
        let mut h = health('a', 9, false, 0);
        h["status"] = status;
        assert_eq!(observation(&h), Err(Failure::InvalidObservation));
    }
}

#[test]
fn new_configuration_writes_require_versioned_fences_and_correct_action() {
    let settings = json!({"action":"configure", "enabled":false, "pinned":true, "idleTimeoutSeconds":30,
        "expectedInstanceId":"stale", "expectedSequence":0});
    let fenced = fence_configuration(&target(), settings.clone()).unwrap();
    assert_eq!(fenced["expectedInstanceId"], "a".repeat(32));
    assert_eq!(fenced["expectedSequence"], 7);
    assert_eq!(fenced["enabled"], false);
    assert_eq!(fenced["pinned"], true);
    assert_eq!(fenced["idleTimeoutSeconds"], 30);
    assert_eq!(
        fence_configuration(&json!({"optimizer":{}}), settings.clone()),
        Err(Failure::UnsupportedProtocol)
    );
    for invalid in [json!(null), json!([]), json!({}), json!({"action":"grant"})] {
        assert_eq!(
            fence_configuration(&target(), invalid),
            Err(Failure::Rejected)
        );
    }
    let mut overflow = target();
    overflow["optimizer"]["sequence"] = json!(MAX_SEQUENCE);
    assert_eq!(
        fence_configuration(&overflow, settings),
        Err(Failure::InvalidObservation)
    );
}

#[test]
fn configuration_ack_requires_exact_causality_without_claiming_capacity_is_free() {
    let before = target();
    let mut ack = before.clone();
    ack["optimizer"]["sequence"] = json!(8);
    ack["optimizer"]["enabled"] = json!(false);
    ack["optimizer"]["resident"] = json!(true);
    ack["status"] = json!("ready");
    ack["controlAck"] =
        json!({"action":"configure","instanceId":"a".repeat(32),"expectedSequence":7,"sequence":8});
    // Configure has no configured boolean. Acceptance need not mean GPU release.
    assert!(configuration_acknowledged(&before, &ack));
    assert!(!configuration_acknowledged(&json!({"optimizer":{}}), &ack));
    for (section, key, value) in [
        ("controlAck", "action", json!("grant")),
        ("controlAck", "instanceId", json!("b".repeat(32))),
        ("controlAck", "expectedSequence", json!(6)),
        ("controlAck", "sequence", json!(9)),
        ("optimizer", "instanceId", json!("b".repeat(32))),
        ("optimizer", "sequence", json!(7)),
        ("optimizer", "resident", json!("false")),
        ("optimizer", "controlProtocol", json!(2)),
    ] {
        let mut broken = ack.clone();
        broken[section][key] = value;
        assert!(
            !configuration_acknowledged(&before, &broken),
            "{section}.{key}"
        );
    }
    let mut too_late = ack.clone();
    too_late["controlAck"]["sequence"] = json!(9);
    too_late["optimizer"]["sequence"] = json!(9);
    assert!(!configuration_acknowledged(&before, &too_late));
    ack["status"] = json!("unknown_future_state");
    assert!(!configuration_acknowledged(&before, &ack));
}
