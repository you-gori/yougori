use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{mpsc, oneshot};

fn health(instance: &str, sequence: u64) -> Value {
    json!({"status":"idle","optimizer":{"controlProtocol":1,"instanceId":instance,
        "sequence":sequence,"enabled":true,"pinned":false,"resident":false,"loading":false,
        "releaseUncertain":false,"active":0,"pending":0}})
}

fn cursor(id: &str) -> Cursor {
    Cursor {
        id: id.into(),
        instance_id: "a".repeat(32),
        sequence: 1,
    }
}

#[derive(Default)]
struct Counts {
    active: AtomicUsize,
    peak: AtomicUsize,
    notifications: AtomicUsize,
}
struct Active(Arc<Counts>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Started {
    id: String,
    body: Value,
    reply: oneshot::Sender<Result<Value, String>>,
}

struct Harness {
    updates: Option<watch::Sender<Vec<Cursor>>>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    starts: mpsc::UnboundedReceiver<Started>,
    counts: Arc<Counts>,
}

impl Harness {
    fn new(initial: Vec<Cursor>, settings: Settings) -> Self {
        let (updates, rx) = watch::channel(initial);
        let (started, starts) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let counts = Arc::new(Counts::default());
        let (token, observed, notifying) = (shutdown.clone(), counts.clone(), counts.clone());
        let task = tokio::spawn(async move {
            run_with(
                rx,
                &token,
                move || {
                    notifying.notifications.fetch_add(1, Ordering::SeqCst);
                },
                move |id, body| {
                    let (counts, started) = (observed.clone(), started.clone());
                    async move {
                        let active = counts.active.fetch_add(1, Ordering::SeqCst) + 1;
                        counts.peak.fetch_max(active, Ordering::SeqCst);
                        let _guard = Active(counts);
                        let (reply, receive) = oneshot::channel();
                        started.send(Started { id, body, reply }).unwrap();
                        receive
                            .await
                            .map_err(|_| "fixture connection closed".to_owned())?
                    }
                },
                settings,
            )
            .await;
        });
        Self {
            updates: Some(updates),
            shutdown,
            task,
            starts,
            counts,
        }
    }

    async fn next(&mut self) -> Started {
        tokio::time::timeout(Duration::from_secs(2), self.starts.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn update(&self, rows: Vec<Cursor>) {
        self.updates.as_ref().unwrap().send_replace(rows);
    }
    fn notified(&self) -> usize {
        self.counts.notifications.load(Ordering::SeqCst)
    }

    async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.counts.active.load(Ordering::SeqCst), 0);
    }
}

fn immediate() -> Settings {
    Settings {
        success_gap: Duration::ZERO,
        ..Settings::default()
    }
}

#[tokio::test]
async fn bounded_connections_rotate_fairly_and_shutdown_drops_every_transport() {
    let mut h = Harness::new(
        (0..12).map(|i| cursor(&format!("model-{i:02}"))).collect(),
        immediate(),
    );
    let mut active = Vec::new();
    for _ in 0..4 {
        active.push(h.next().await);
    }
    assert!(h.starts.try_recv().is_err());
    assert_eq!(h.counts.peak.load(Ordering::SeqCst), 4);
    let first = active.remove(0);
    assert_eq!(first.id, "model-00");
    first.reply.send(Ok(health(&"a".repeat(32), 1))).unwrap();
    let replacement = h.next().await;
    assert_eq!(replacement.id, "model-04");
    assert_eq!(h.counts.peak.load(Ordering::SeqCst), 4);
    assert_eq!(h.notified(), 0);
    h.stop().await;
    for waiting in active.into_iter().chain([replacement]) {
        assert!(waiting.reply.is_closed());
    }
}

#[tokio::test]
async fn removal_disable_and_incarnation_replacement_cancel_owned_requests() {
    let mut h = Harness::new(
        vec![cursor("model")],
        Settings {
            concurrency: 1,
            ..immediate()
        },
    );
    let mut old = h.next().await;
    let mut replacement = cursor("model");
    replacement.instance_id = "b".repeat(32);
    h.update(vec![replacement]);
    let mut current = h.next().await;
    assert_eq!(current.body["instanceId"], "b".repeat(32));
    assert!(old.reply.is_closed());
    h.update(Vec::new()); // Disabled/paused/stopped models are omitted by members().
    tokio::time::timeout(Duration::from_secs(2), current.reply.closed())
        .await
        .unwrap();
    assert_eq!(h.counts.active.load(Ordering::SeqCst), 0);
    h.update(vec![cursor("another")]);
    let next = h.next().await;
    assert_eq!(next.id, "another");
    assert_eq!(h.notified(), 0);
    h.stop().await;
    assert!(next.reply.is_closed());
    // Retained old sender is never revived when another generation is scheduled.
    old.reply.closed().await;
}

#[tokio::test]
async fn direct_demand_and_restart_notify_but_initial_and_heartbeats_do_not() {
    let mut h = Harness::new(vec![cursor("model")], immediate());
    let first = h.next().await;
    assert_eq!(
        first.body,
        json!({"action":"watch","instanceId":"a".repeat(32),"since":1,"waitMs":5000})
    );
    first.reply.send(Ok(health(&"a".repeat(32), 1))).unwrap();
    let next = h.next().await;
    assert_eq!(h.notified(), 0);
    let mut demand = health(&"a".repeat(32), 2);
    demand["optimizer"]["pending"] = json!(1);
    demand["status"] = json!("queued");
    next.reply.send(Ok(demand)).unwrap();
    let heartbeat = h.next().await;
    assert_eq!(h.notified(), 1);
    assert_eq!(heartbeat.body["since"], 2);
    heartbeat
        .reply
        .send(Ok(health(&"a".repeat(32), 2)))
        .unwrap();
    let restart = h.next().await;
    assert_eq!(h.notified(), 1);
    restart.reply.send(Ok(health(&"b".repeat(32), 0))).unwrap();
    let current = h.next().await;
    assert_eq!(h.notified(), 2);
    assert_eq!(current.body["instanceId"], "b".repeat(32));
    assert_eq!(current.body["since"], 0);
    h.stop().await;
}

#[tokio::test]
async fn health_poll_that_already_observed_event_suppresses_redundant_wake() {
    let mut h = Harness::new(vec![cursor("model")], immediate());
    let waiting = h.next().await;
    let mut observed = cursor("model");
    observed.sequence = 7;
    h.update(vec![observed]);
    waiting.reply.send(Ok(health(&"a".repeat(32), 7))).unwrap();
    let next = h.next().await;
    assert_eq!(next.body["since"], 7);
    assert_eq!(h.notified(), 0);
    h.stop().await;
}

#[tokio::test]
async fn invalid_or_legacy_watch_replies_back_off_without_downgrading() {
    for reply in [
        json!({"optimizer":{}}),
        health(&"a".repeat(32), 0),
        json!(null),
    ] {
        let mut h = Harness::new(
            vec![cursor("model")],
            Settings {
                retry_base: Duration::from_secs(30),
                retry_max: Duration::from_secs(30),
                ..immediate()
            },
        );
        let first = h.next().await;
        first.reply.send(Ok(reply)).unwrap();
        // Drain completion by letting the task yield; the bounded timeout proves
        // no immediate reconnect loop without waiting out the retry interval.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), h.starts.recv())
                .await
                .is_err()
        );
        assert_eq!(h.notified(), 0);
        assert_eq!(h.counts.active.load(Ordering::SeqCst), 0);
        h.stop().await;
    }
}

#[tokio::test]
async fn request_timeout_drops_transport_and_retries_after_backoff() {
    let mut h = Harness::new(
        vec![cursor("model")],
        Settings {
            timeout: Duration::from_millis(20),
            retry_base: Duration::from_millis(100),
            retry_max: Duration::from_millis(100),
            ..immediate()
        },
    );
    let mut expired = h.next().await;
    tokio::time::timeout(Duration::from_secs(2), expired.reply.closed())
        .await
        .unwrap();
    assert_eq!(h.counts.active.load(Ordering::SeqCst), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), h.starts.recv())
            .await
            .is_err()
    );
    let retry = h.next().await;
    assert_eq!(retry.body["since"], 1);
    assert_eq!(h.notified(), 0);
    h.stop().await;
}

#[tokio::test]
async fn closing_membership_owner_stops_watchers_without_engine_shutdown_signal() {
    let mut h = Harness::new(vec![cursor("model")], immediate());
    let waiting = h.next().await;
    drop(h.updates.take());
    tokio::time::timeout(Duration::from_secs(2), h.task)
        .await
        .unwrap()
        .unwrap();
    assert!(waiting.reply.is_closed());
    assert_eq!(h.counts.active.load(Ordering::SeqCst), 0);
}

#[test]
fn exponential_reconnect_delay_is_bounded() {
    let settings = Settings::default();
    let delays: Vec<_> = (1..=8).map(|n| settings.retry_delay(n).as_secs()).collect();
    assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    assert_eq!(settings.retry_delay(u32::MAX), Duration::from_secs(30));
}

#[test]
fn only_enabled_valid_v1_models_get_bounded_subscription_state() {
    let mut seen = vec![
        Seen {
            id: "paused".into(),
            health: None,
        },
        Seen {
            id: "old".into(),
            health: Some(json!({"optimizer":{"enabled":true}})),
        },
    ];
    let mut disabled = health(&"a".repeat(32), 1);
    disabled["optimizer"]["enabled"] = json!(false);
    seen.push(Seen {
        id: "disabled".into(),
        health: Some(disabled),
    });
    for i in 0..200 {
        seen.push(Seen {
            id: format!("model-{i}"),
            health: Some(health(&"a".repeat(32), 1)),
        });
    }
    let selected = members(&seen);
    assert_eq!(selected.len(), 128);
    assert!(selected.iter().all(|row| row.id.starts_with("model-")));
    let mut manager = Members::new();
    manager.reconcile(
        (0..1000).map(|i| cursor(&format!("model-{i}"))).collect(),
        Instant::now(),
    );
    assert_eq!(manager.rows.len(), 128);
}

#[test]
fn late_completion_cannot_mutate_replacement_membership() {
    let mut members = Members::new();
    let now = Instant::now();
    members.reconcile(vec![cursor("model")], now);
    let (asked, ticket, _) = members.ready(now).unwrap();
    let mut newer = cursor("model");
    newer.instance_id = "b".repeat(32);
    members.reconcile(vec![newer], now);
    let (_, next_ticket, _) = members.ready(now).unwrap();
    assert_ne!(ticket, next_ticket);
    assert!(!members.complete(
        Completion {
            id: "model".into(),
            ticket,
            asked,
            answer: Some(health(&"a".repeat(32), 99))
        },
        Settings::default(),
        now
    ));
    assert_eq!(members.rows["model"].cursor.instance_id, "b".repeat(32));
    assert_eq!(
        members.rows["model"].running.as_ref().unwrap().0,
        next_ticket
    );
}
