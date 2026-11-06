//! Host-evidence release of grants whose runner is gone (S04/G03, `gone.rs`), over
//! `switch` and `release` with closures, as `tests.rs` does.
use super::tests::{ack, health, sample, world, GIB};
use super::*;
use crate::foundation::ids::ManualClock;
use crate::foundation::ledger::CloseReason;
use serde_json::json;
use std::time::Instant;

/// The grant marker of a runner of `instance`, as admission persisted it.
fn marker(instance: char) -> String {
    configuration::record(&health(instance, false, 1)).unwrap()
}

fn observed(environment: &str, how: Gone) -> RunnerGone {
    RunnerGone {
        environment: environment.into(),
        name: format!("Model {}", environment.to_uppercase()),
        how,
    }
}

fn replaced_by(old: char, new: char) -> Gone {
    Gone::Replaced {
        old_instance: old.to_string().repeat(32),
        new_instance: new.to_string().repeat(32),
    }
}

/// The accounting holding model `old`'s grant, as after its admission, and that grant's
/// root.
fn holding(s: &Snapshot) -> (Mutex<Accounting<Arc<ManualClock>>>, ReservationId) {
    let (_, mut a) = world(s);
    a.settle_and_reserve(s, "old", Some(GIB)).unwrap();
    let root = a.roots[0];
    (Mutex::new(a), root)
}

/// Whether the history records `root` released on the host's own observation.
fn released_by_host(a: &Accounting<Arc<ManualClock>>, root: ReservationId) -> bool {
    let _ledger = a.ledger.lock().unwrap();
    a.history.lock().unwrap().records().any(|record| {
        record.id() == root
            && record.close_reason()
                == Some(CloseReason::ReleaseObserved {
                    source: SourceClass::HostProbe,
                })
    })
}

fn reserved(a: &Accounting<Arc<ManualClock>>, s: &Snapshot) -> u64 {
    a.ledger
        .lock()
        .unwrap()
        .reserved(ResourceKey::vram(s.device))
}

/// One admission of `target` over `switch`: what it returned, the actions sent and the
/// markers persisted, in order.
struct Admission {
    result: Result<(), String>,
    sent: Vec<String>,
    persisted: Vec<(String, Option<String>)>,
}

async fn admit(
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    probe: Snapshot,
    account: impl FnOnce(&Snapshot, Option<u64>) -> Result<(), String>,
) -> Admission {
    let target = health('a', false, 1);
    let sent = Mutex::new(Vec::new());
    let persisted = Mutex::new(Vec::new());
    let send = |_: String, body: Value| {
        sent.lock()
            .unwrap()
            .push(body["action"].as_str().unwrap().to_owned());
        let answer = ack(target.clone(), &body);
        async { Ok(answer) }
    };
    let result = switch(
        "target",
        &target,
        &[],
        observations,
        markers,
        gone,
        Some(GIB),
        &CancellationToken::new(),
        &send,
        move || async move { Ok(probe) },
        |id, marker| {
            persisted
                .lock()
                .unwrap()
                .push((id.to_owned(), marker.map(str::to_owned)));
            Ok(())
        },
        account,
    )
    .await;
    Admission {
        result,
        sent: sent.into_inner().unwrap(),
        persisted: persisted.into_inner().unwrap(),
    }
}

#[tokio::test]
async fn a_stopped_environments_grant_is_released_on_the_host_probe_and_the_next_model_granted() {
    for how in [Gone::Stopped, Gone::Error] {
        let s = sample(0);
        let (a, root) = holding(&s);
        let markers = BTreeMap::from([("old".to_owned(), marker('b'))]);
        let admission = admit(
            &[],
            &markers,
            &[observed("old", how.clone())],
            s.clone(),
            |probe, bytes| a.lock().unwrap().settle_and_reserve(probe, "target", bytes),
        )
        .await;
        admission.result.unwrap();
        // Nothing was asked of the gone runner; the probe settled its grant, the marker was
        // cleared and the target granted.
        assert_eq!(admission.sent, ["phase", "grant"], "{how:?}");
        assert_eq!(admission.persisted[0], ("old".to_owned(), None));
        assert_eq!(admission.persisted[1].0, "target");
        assert!(admission.persisted[1].1.is_some());
        let a = a.lock().unwrap();
        assert!(released_by_host(&a, root), "{how:?}");
        assert_eq!(a.roots.len(), 1);
        assert_ne!(a.roots[0], root);
        assert_eq!(a.ledger.lock().unwrap().open_reservations().count(), 2);
    }
}

#[tokio::test]
async fn a_stopped_environments_grant_is_kept_while_the_gpu_still_shows_memory_in_use() {
    let s = sample(0);
    let (a, root) = holding(&s);
    let markers = BTreeMap::from([("old".to_owned(), marker('b'))]);
    let gone = [observed("old", Gone::Stopped)];
    let settle =
        |probe: &Snapshot, bytes| a.lock().unwrap().settle_and_reserve(probe, "target", bytes);
    // The container stopped, but the GPU still shows 20 GiB in use: no room for the target.
    let admission = admit(&[], &markers, &gone, sample(20 * GIB), settle).await;
    let reason = admission.result.unwrap_err();
    assert!(
        reason.starts_with(
            "Model OLD stopped, but the GPU still shows 20480 MiB in use, so its grant is kept."
        ),
        "{reason}"
    );
    assert!(
        reason.contains("close other programs that use the GPU"),
        "{reason}"
    );
    assert!(reason.contains(NOT_AVAILABLE), "{reason}");
    assert_eq!(admission.sent, ["phase"]);
    assert!(admission.persisted.is_empty(), "the marker is kept");
    {
        // The ledger holds the physical truth: the memory in use is unmanaged, the old
        // grant's root is closed on the host's observation and nothing is reserved.
        let a = a.lock().unwrap();
        assert!(released_by_host(&a, root));
        let ledger = a.ledger.lock().unwrap();
        let key = ResourceKey::vram(s.device);
        assert_eq!(ledger.capacity(key).unwrap().unmanaged_in_use, 20 * GIB);
        assert_eq!(ledger.reserved(key), 0);
    }
    // A probe the ledger refuses for another reason keeps the grant and says so too.
    let mut stale = sample(0);
    stale.observed = Instant::now() - Duration::from_secs(6);
    let admission = admit(&[], &markers, &gone, stale, settle).await;
    assert_eq!(
        admission.result.unwrap_err(),
        "Model OLD stopped, but its grant is kept: GPU capacity evidence is stale or its \
         device identity changed. Restart the engine after checking the GPU."
    );
    assert!(admission.persisted.is_empty());
    // Once the GPU shows the memory free, the same observation settles the grant.
    let admission = admit(&[], &markers, &gone, sample(0), settle).await;
    admission.result.unwrap();
    assert_eq!(admission.persisted[0], ("old".to_owned(), None));
    assert_eq!(admission.sent, ["phase", "grant"]);
}

#[tokio::test]
async fn a_paused_environments_grant_is_never_released_on_host_evidence() {
    // A paused environment is not gone (its frozen memory stays allocated), so the pass
    // observes nothing of its runner: its marker stays uncertain, whatever else was seen
    // gone, and nothing is probed, settled or cleared.
    let markers = BTreeMap::from([("paused".to_owned(), marker('b'))]);
    for gone in [vec![], vec![observed("other", Gone::Stopped)]] {
        let admission = admit(&[], &markers, &gone, sample(0), |_, _| {
            panic!("must not settle")
        })
        .await;
        assert!(admission
            .result
            .unwrap_err()
            .starts_with("A previous GPU grant remains uncertain"));
        assert!(admission.persisted.is_empty());
        assert_eq!(admission.sent, ["phase"]);
        let result = release(
            &[],
            &[],
            &markers,
            &gone,
            &CancellationToken::new(),
            || async { panic!("must not probe") },
            |_, _| panic!("must retain marker"),
            |_, _| panic!("must not settle"),
        )
        .await;
        assert_eq!(result.unwrap_err(), "GPU release is not yet confirmed.");
    }
}

#[tokio::test]
async fn a_running_environments_grant_is_released_when_another_runner_answers_holding_no_model() {
    let s = sample(0);
    let markers = BTreeMap::from([("old".to_owned(), marker('b'))]);
    let empty_c = health('c', false, 0);
    assert_eq!(
        replaced(&markers["old"], &empty_c),
        Some(replaced_by('b', 'c'))
    );
    let (a, root) = holding(&s);
    let admission = admit(
        &[("old".to_owned(), empty_c.clone())],
        &markers,
        &[observed("old", replaced_by('b', 'c'))],
        s.clone(),
        |probe, bytes| a.lock().unwrap().settle_and_reserve(probe, "target", bytes),
    )
    .await;
    admission.result.unwrap();
    assert_eq!(admission.persisted[0], ("old".to_owned(), None));
    assert!(released_by_host(&a.lock().unwrap(), root));

    // Kept: the new runner holds its model; the observation names other instances than
    // the marker's or the answer's, or the same instance (today's path needs a higher
    // sequence); or no runner answered at all.
    let holding_c = health('c', true, 0);
    assert_eq!(replaced(&markers["old"], &holding_c), None);
    assert_eq!(replaced(&markers["old"], &health('b', false, 0)), None);
    let kept: Vec<(Vec<(String, Value)>, Gone)> = vec![
        (vec![("old".into(), holding_c)], replaced_by('b', 'c')),
        (vec![("old".into(), empty_c.clone())], replaced_by('b', 'd')),
        (vec![("old".into(), empty_c.clone())], replaced_by('x', 'c')),
        (vec![("old".into(), empty_c)], replaced_by('c', 'c')),
        (vec![], replaced_by('b', 'c')),
    ];
    for (observations, how) in kept {
        let admission = admit(
            &observations,
            &markers,
            &[observed("old", how.clone())],
            s.clone(),
            |_, _| panic!("must not settle"),
        )
        .await;
        assert!(
            admission
                .result
                .unwrap_err()
                .starts_with("A previous GPU grant remains uncertain"),
            "{how:?}"
        );
        assert!(admission.persisted.is_empty());
    }
}

#[tokio::test]
async fn a_runner_settling_its_own_grant_is_unchanged_and_a_contradicted_observation_settles_nothing(
) {
    let s = sample(0);
    let markers = BTreeMap::from([("old".to_owned(), marker('b'))]);
    // Today's path: the granted runner itself answers with a higher sequence and no model,
    // whatever else was observed of its environment.
    let mut unloaded = health('b', false, 0);
    unloaded["optimizer"]["sequence"] = json!(10);
    for gone in [vec![], vec![observed("old", Gone::Stopped)]] {
        let (a, root) = holding(&s);
        let admission = admit(
            &[("old".to_owned(), unloaded.clone())],
            &markers,
            &gone,
            s.clone(),
            |probe, bytes| a.lock().unwrap().settle_and_reserve(probe, "target", bytes),
        )
        .await;
        admission.result.unwrap();
        assert_eq!(admission.persisted[0], ("old".to_owned(), None));
        assert!(released_by_host(&a.lock().unwrap(), root));
    }
    // A stopped environment whose runner answers contradicts the observation: uncertain.
    let admission = admit(
        &[("old".to_owned(), health('b', false, 1))],
        &markers,
        &[observed("old", Gone::Stopped)],
        s.clone(),
        |_, _| panic!("must not settle"),
    )
    .await;
    assert!(admission
        .result
        .unwrap_err()
        .starts_with("A previous GPU grant remains uncertain"));
    assert!(admission.persisted.is_empty());
}

#[tokio::test]
async fn after_an_engine_restart_markers_read_from_options_settle_on_the_same_evidence() {
    // The engine restarted: its accounting is fresh, holding nothing, and the markers come
    // from the saved workload options.
    let mut options = yougori_cli::workload::Options::default();
    options.environment.insert(PENDING.into(), marker('b'));
    options.validate().unwrap();
    let saved = serde_json::to_vec(&options).unwrap();
    let loaded: yougori_cli::workload::Options = serde_json::from_slice(&saved).unwrap();
    let markers = BTreeMap::from([("old".to_owned(), loaded.environment[PENDING].clone())]);
    let fresh = |probe: &Snapshot, bytes| {
        let (_, mut a) = world(probe);
        a.settle_and_reserve(probe, "target", bytes)
    };
    // Stopped, or replaced by a runner holding no model: released through the probe.
    let cases = [
        (vec![], Gone::Stopped),
        (
            vec![("old".to_owned(), health('c', false, 0))],
            replaced_by('b', 'c'),
        ),
    ];
    for (observations, how) in cases {
        let admission = admit(
            &observations,
            &markers,
            &[observed("old", how.clone())],
            sample(0),
            fresh,
        )
        .await;
        admission.result.unwrap();
        assert_eq!(admission.persisted[0], ("old".to_owned(), None), "{how:?}");
        assert_eq!(admission.sent, ["phase", "grant"]);
    }
    // Memory still in use: kept, with what was observed.
    let admission = admit(
        &[],
        &markers,
        &[observed("old", Gone::Stopped)],
        sample(20 * GIB),
        fresh,
    )
    .await;
    assert!(admission
        .result
        .unwrap_err()
        .starts_with("Model OLD stopped, but the GPU still shows 20480 MiB in use"));
    assert!(admission.persisted.is_empty());
    // Paused, so nothing observed of its runner: kept, as before the restart.
    let admission = admit(&[], &markers, &[], sample(0), fresh).await;
    assert!(admission
        .result
        .unwrap_err()
        .starts_with("A previous GPU grant remains uncertain"));
    assert!(admission.persisted.is_empty());
}

#[tokio::test]
async fn idle_release_returns_a_gone_runners_capacity_on_the_host_probe() {
    let s = sample(0);
    let markers = BTreeMap::from([("old".to_owned(), marker('b'))]);
    let cases: Vec<(Vec<(String, Value)>, Vec<RunnerGone>, bool)> = vec![
        // Nothing observed of the runner: kept, as before.
        (vec![], vec![], false),
        (vec![], vec![observed("old", Gone::Stopped)], true),
        (vec![], vec![observed("old", Gone::Error)], true),
        (
            vec![("old".into(), health('c', false, 0))],
            vec![observed("old", replaced_by('b', 'c'))],
            true,
        ),
        (
            vec![("old".into(), health('c', true, 0))],
            vec![observed("old", replaced_by('b', 'c'))],
            false,
        ),
    ];
    for (observations, gone, settles) in cases {
        let (a, root) = holding(&s);
        let cleared = Mutex::new(Vec::new());
        let result = release(
            &[],
            &observations,
            &markers,
            &gone,
            &CancellationToken::new(),
            || async { Ok(s.clone()) },
            |id, marker| {
                assert!(marker.is_none());
                cleared.lock().unwrap().push(id.to_owned());
                Ok(())
            },
            |probe, _| a.lock().unwrap().settle_and_reserve(probe, "idle", None),
        )
        .await;
        assert_eq!(result.is_ok(), settles, "{gone:?}");
        let a = a.lock().unwrap();
        assert_eq!(reserved(&a, &s) == 0, settles, "{gone:?}");
        assert_eq!(released_by_host(&a, root), settles, "{gone:?}");
        let expected: Vec<String> = if settles { vec!["old".into()] } else { vec![] };
        assert_eq!(*cleared.lock().unwrap(), expected);
    }
    // A probe the ledger refuses keeps the grant and says what was observed.
    let (a, _) = holding(&s);
    let mut stale = s.clone();
    stale.observed = Instant::now() - Duration::from_secs(6);
    let result = release(
        &[],
        &[],
        &markers,
        &[observed("old", Gone::Stopped)],
        &CancellationToken::new(),
        || async { Ok(stale) },
        |_, _| panic!("must retain marker"),
        |probe, _| a.lock().unwrap().settle_and_reserve(probe, "idle", None),
    )
    .await;
    assert!(result
        .unwrap_err()
        .starts_with("Model OLD stopped, but its grant is kept: GPU capacity evidence is stale"));
    assert!(reserved(&a.lock().unwrap(), &s) > 0);
}

#[test]
fn the_reason_for_kept_grants_names_each_observation_and_the_memory_the_gpu_shows() {
    let a = observed("a", Gone::Stopped);
    let b = observed("b", Gone::Error);
    let c = observed("c", replaced_by('b', 'c'));
    assert_eq!(gone::kept(&[], 5 * GIB, "refused".into()), "refused");
    assert_eq!(
        gone::kept(&[&a], 5 * GIB, format!("{NOT_AVAILABLE}: no room")),
        "Model A stopped, but the GPU still shows 5120 MiB in use, so its grant is kept. If \
         the memory does not free itself, close other programs that use the GPU. GPU \
         capacity is not available: no room"
    );
    assert_eq!(
        gone::kept(&[&a, &b, &c], GIB, format!("{NOT_AVAILABLE}: no room")),
        "Model A stopped, Model B stopped with an error, Model C's runner was replaced and \
         holds no model, but the GPU still shows 1024 MiB in use, so their grants are kept. \
         If the memory does not free itself, close other programs that use the GPU. GPU \
         capacity is not available: no room"
    );
    assert_eq!(
        gone::kept(&[&a], 0, "GPU capacity is queued.".into()),
        "Model A stopped, but its grant is kept: GPU capacity is queued."
    );
}
