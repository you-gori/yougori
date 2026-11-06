//! Bounded observations only: grants and unloads remain serialized by the caller.
use super::Seen;
use futures_util::{stream, StreamExt};
use serde_json::Value;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

const MAX_IN_FLIGHT: usize = 4;

/// Paused models still appear as unknown, without a request. Errors/timeouts also
/// stay unknown; neither implies that a previously resident model freed memory.
/// No probe is spawned: cancellation drops the in-flight request futures and the
/// caller receives no partial snapshot on which it could accidentally grant VRAM.
pub(super) async fn collect<F, Fut>(
    models: Vec<(String, bool)>,
    shutdown: &CancellationToken,
    timeout: Duration,
    probe: F,
) -> Option<Vec<Seen>>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let pending = stream::iter(models.into_iter().enumerate())
        .map(|(index, (id, paused))| {
            let probe = &probe;
            async move {
                let health = if paused {
                    None
                } else {
                    tokio::time::timeout(timeout, probe(id.clone()))
                        .await
                        .ok()
                        .and_then(Result::ok)
                };
                (index, Seen { id, health })
            }
        })
        .buffer_unordered(MAX_IN_FLIGHT)
        .collect::<Vec<_>>();
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => None,
        mut seen = pending => {
            // Completion speed must not break equal-age scheduler tie ordering.
            seen.sort_unstable_by_key(|(index, _)| *index);
            Some(seen.into_iter().map(|(_, model)| model).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::sync::{mpsc, oneshot, Semaphore};

    fn inputs(count: usize) -> Vec<(String, bool)> {
        (0..count).map(|i| (format!("model-{i}"), false)).collect()
    }

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn at_most_four_requests_run_and_results_keep_input_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let permits = Arc::new(Semaphore::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let (a, p, gate) = (active.clone(), peak.clone(), permits.clone());
        let task = tokio::spawn(async move {
            collect(
                inputs(11),
                &CancellationToken::new(),
                Duration::from_secs(30),
                |id| {
                    let (a, p, gate, started) =
                        (a.clone(), p.clone(), gate.clone(), started.clone());
                    async move {
                        let now = a.fetch_add(1, Ordering::SeqCst) + 1;
                        let _active = Active(a);
                        p.fetch_max(now, Ordering::SeqCst);
                        started.send(id.clone()).unwrap();
                        let permit = gate.acquire().await.unwrap();
                        permit.forget();
                        Ok(json!({"id": id}))
                    }
                },
            )
            .await
            .unwrap()
        });
        for _ in 0..MAX_IN_FLIGHT {
            tokio::time::timeout(Duration::from_secs(2), starts.recv())
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(active.load(Ordering::SeqCst), MAX_IN_FLIGHT);
        assert!(starts.try_recv().is_err());
        permits.add_permits(11);
        let seen = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), MAX_IN_FLIGHT);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            seen.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            inputs(11).into_iter().map(|m| m.0).collect::<Vec<_>>()
        );
        assert!(seen
            .iter()
            .all(|s| s.health.as_ref().unwrap()["id"] == s.id));
    }

    #[tokio::test]
    async fn a_later_completion_does_not_block_starting_the_next_probe() {
        let (release, blocked) = oneshot::channel();
        let blocked = Mutex::new(Some(blocked));
        let (started, mut starts) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            collect(
                inputs(9),
                &CancellationToken::new(),
                Duration::from_secs(30),
                |id| {
                    let wait = if id == "model-0" {
                        blocked.lock().unwrap().take()
                    } else {
                        None
                    };
                    let started = started.clone();
                    async move {
                        started.send(id.clone()).unwrap();
                        if let Some(wait) = wait {
                            wait.await.unwrap();
                        }
                        Ok(json!({"id": id}))
                    }
                },
            )
            .await
            .unwrap()
        });
        // All nine probes can start while the first remains pending. Ordered
        // buffering would stall after four; unbounded concurrency has a separate test.
        for _ in 0..9 {
            tokio::time::timeout(Duration::from_secs(2), starts.recv())
                .await
                .unwrap()
                .unwrap();
        }
        assert!(!task.is_finished());
        release.send(()).unwrap();
        let seen = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen.first().unwrap().id, "model-0");
        assert_eq!(seen.last().unwrap().id, "model-8");
    }

    #[tokio::test]
    async fn paused_failed_and_timed_out_models_remain_in_the_snapshot() {
        let called = Mutex::new(Vec::new());
        let seen = collect(
            vec![
                ("paused".into(), true),
                ("error".into(), false),
                ("timeout".into(), false),
                ("ok".into(), false),
            ],
            &CancellationToken::new(),
            Duration::from_millis(10),
            |id| {
                called.lock().unwrap().push(id.clone());
                async move {
                    match id.as_str() {
                        "error" => Err("fixture failure".into()),
                        "timeout" => std::future::pending().await,
                        _ => Ok(json!({"optimizer": {"resident": true, "enabled": true}})),
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*called.lock().unwrap(), ["error", "timeout", "ok"]);
        assert_eq!(seen.len(), 4);
        assert!(seen[..3].iter().all(|s| s.health.is_none()));
        assert!(seen[3].health.is_some());
        let mut resident = [
            "paused".to_owned(),
            "error".to_owned(),
            "timeout".to_owned(),
        ]
        .into_iter()
        .collect();
        let (_, silent) = super::super::observe(&seen, &mut resident);
        assert_eq!(silent, ["paused", "error", "timeout"]);
    }

    #[tokio::test]
    async fn cancellation_drops_in_flight_probes_and_never_returns_partial_state() {
        let active = Arc::new(AtomicUsize::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let (a, cancel) = (active.clone(), shutdown.clone());
        let task = tokio::spawn(async move {
            collect(inputs(20), &cancel, Duration::from_secs(30), |_| {
                let (a, started) = (a.clone(), started.clone());
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(a);
                    started.send(()).unwrap();
                    std::future::pending().await
                }
            })
            .await
        });
        for _ in 0..MAX_IN_FLIGHT {
            tokio::time::timeout(Duration::from_secs(2), starts.recv())
                .await
                .unwrap()
                .unwrap();
        }
        shutdown.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_none());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(starts.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancelled_before_start_never_calls_a_probe() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let called = AtomicUsize::new(0);
        let seen = collect(inputs(5), &shutdown, Duration::from_secs(3), |_| {
            called.fetch_add(1, Ordering::SeqCst);
            async { Ok(json!({})) }
        })
        .await;
        assert!(seen.is_none());
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn empty_input_is_a_complete_empty_snapshot() {
        let seen = collect(
            Vec::new(),
            &CancellationToken::new(),
            Duration::from_secs(3),
            |_| async { panic!("empty input must never probe") },
        )
        .await
        .unwrap();
        assert!(seen.is_empty());
    }
}
