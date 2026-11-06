//! Process-local hints only. Every wake still goes through authenticated status
//! collection and the scheduler's existing admission checks.
use std::time::Duration;
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;

pub(super) struct Wake {
    signal: Notify,
    reconcile: Duration,
    minimum_gap: Duration,
}

impl Wake {
    pub(super) fn new() -> Self {
        Self {
            signal: Notify::new(),
            reconcile: Duration::from_secs(1),
            minimum_gap: Duration::from_millis(100),
        }
    }

    pub(super) fn notify(&self) {
        // Notify stores at most one permit: bursts never allocate an event queue.
        self.signal.notify_one();
    }

    pub(super) fn request_completed(&self, path: &str, posted: bool, succeeded: bool) {
        if posted && succeeded && matches!(path, "/v1/yougori/prepare" | "/v1/yougori/release") {
            self.notify();
        }
    }

    pub(super) async fn wait(
        &self,
        shutdown: &CancellationToken,
        last_started: Option<Instant>,
    ) -> bool {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return false,
            _ = self.signal.notified() => {},
            _ = tokio::time::sleep(self.reconcile) => {},
        }
        if let Some(last_started) = last_started {
            // Bound checks to ten starts per second, even if callers keep sending
            // prepare/release. Work longer than this gap adds no further delay.
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return false,
                _ = tokio::time::sleep_until(last_started + self.minimum_gap) => {},
            }
        }
        !shutdown.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    fn event_only() -> Wake {
        Wake {
            reconcile: Duration::from_secs(30),
            minimum_gap: Duration::ZERO,
            ..Wake::new()
        }
    }

    #[tokio::test]
    async fn acknowledged_prepare_and_release_wake_without_periodic_polling() {
        for path in ["/v1/yougori/prepare", "/v1/yougori/release"] {
            let wake = event_only();
            wake.request_completed(path, true, true);
            assert_eq!(
                wake.wait(&CancellationToken::new(), None).now_or_never(),
                Some(true)
            );
        }
    }

    #[tokio::test]
    async fn failures_reads_and_scheduler_control_do_not_generate_feedback() {
        for (path, posted, succeeded) in [
            ("/v1/yougori/prepare", true, false),
            ("/v1/yougori/release", true, false),
            ("/v1/yougori/prepare", false, true),
            ("/health", false, true),
            ("/v1/yougori/optimizer", true, true),
            ("/v1/chat/completions", true, true),
            ("/v1/yougori/prepare/extra", true, true),
        ] {
            let wake = event_only();
            wake.request_completed(path, posted, succeeded);
            assert_eq!(
                wake.wait(&CancellationToken::new(), None).now_or_never(),
                None,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn notification_bursts_coalesce_to_a_single_pending_round() {
        let wake = event_only();
        for _ in 0..10_000 {
            wake.notify();
        }
        let shutdown = CancellationToken::new();
        assert_eq!(wake.wait(&shutdown, None).now_or_never(), Some(true));
        assert_eq!(wake.wait(&shutdown, None).now_or_never(), None);
    }

    #[tokio::test]
    async fn notification_after_wait_registration_is_not_lost() {
        let wake = event_only();
        let shutdown = CancellationToken::new();
        let waiting = wake.wait(&shutdown, None);
        tokio::pin!(waiting);
        assert_eq!(waiting.as_mut().now_or_never(), None);
        wake.notify();
        assert!(tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn lost_events_still_reconcile_on_the_timer() {
        let wake = Wake {
            reconcile: Duration::from_millis(20),
            ..event_only()
        };
        let started = Instant::now();
        assert!(tokio::time::timeout(
            Duration::from_secs(2),
            wake.wait(&CancellationToken::new(), None)
        )
        .await
        .unwrap());
        assert!(started.elapsed() >= wake.reconcile);
    }

    #[tokio::test]
    async fn rate_limit_is_enforced_and_shutdown_interrupts_the_gap() {
        let wake = Wake {
            minimum_gap: Duration::from_secs(30),
            ..event_only()
        };
        let shutdown = CancellationToken::new();
        wake.notify();
        let waiting = wake.wait(&shutdown, Some(Instant::now()));
        tokio::pin!(waiting);
        assert_eq!(
            waiting.as_mut().now_or_never(),
            None,
            "a hint must not bypass the minimum gap"
        );
        shutdown.cancel();
        assert!(!tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn hints_received_during_work_survive_and_long_work_needs_no_extra_gap() {
        let wake = Wake::new();
        let last_started = Instant::now() - Duration::from_secs(2);
        for _ in 0..100 {
            wake.notify();
        }
        let shutdown = CancellationToken::new();
        let ready = wake.wait(&shutdown, Some(last_started));
        // A sleep_until for a past instant can first register with Tokio's timer;
        // await it without making a sub-millisecond scheduling assertion.
        assert!(tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn shutdown_wins_over_a_pending_hint_and_interrupts_an_empty_wait() {
        let wake = event_only();
        let shutdown = CancellationToken::new();
        let waiting = wake.wait(&shutdown, None);
        tokio::pin!(waiting);
        assert_eq!(waiting.as_mut().now_or_never(), None);
        shutdown.cancel();
        assert!(!waiting.await);
        wake.notify();
        assert_eq!(wake.wait(&shutdown, None).now_or_never(), Some(false));
    }
}
