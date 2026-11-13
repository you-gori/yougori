//! Stopping work: one token per turn, shared by the model stream, the tools and helpers.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone, Default)]
pub struct Cancel(Arc<Inner>);

#[derive(Default)]
struct Inner {
    flag: AtomicBool,
    notify: Notify,
    /// Why it was stopped, when it was not the person's Esc.
    why: Mutex<Option<String>>,
}

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.flag.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    /// Stops the work and says why (a helper's "Stop the turn" ends the whole turn this way).
    pub fn cancel_because(&self, why: &str) {
        {
            let mut kept = self.0.why.lock().unwrap_or_else(|e| e.into_inner());
            if kept.is_none() && !self.is_cancelled() {
                *kept = Some(why.to_owned());
            }
        }
        self.cancel();
    }

    /// Why it was stopped, when that was said.
    pub fn why(&self) -> Option<String> {
        self.0.why.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.flag.load(Ordering::SeqCst)
    }

    /// Resolves once the token is cancelled (at once when it already is).
    pub async fn cancelled(&self) {
        loop {
            // A `Notified` future sees `notify_waiters` from the moment it exists, so taking it
            // before the check cannot miss a cancel that lands in between.
            let notified = self.0.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Cancels the token when dropped: kept in the engine handle so the engine stops with it.
pub struct CancelOnDrop(pub Cancel);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_wakes_every_waiter_and_stays_cancelled() {
        let cancel = Cancel::new();
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let cancel = cancel.clone();
                tokio::spawn(async move { cancel.cancelled().await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        for waiter in waiters {
            tokio::time::timeout(Duration::from_secs(2), waiter).await.unwrap().unwrap();
        }
        tokio::time::timeout(Duration::from_millis(100), cancel.cancelled()).await.unwrap();
        assert!(cancel.is_cancelled());
        assert_eq!(cancel.why(), None, "an Esc says no reason");
        // A reason given after the stop does not rewrite it; the first one given stays.
        cancel.cancel_because("late");
        assert_eq!(cancel.why(), None);
        let stopped = Cancel::new();
        stopped.cancel_because("Stopped because the model kept making the same call.");
        stopped.cancel_because("another");
        assert!(stopped.is_cancelled());
        assert_eq!(stopped.why().as_deref(), Some("Stopped because the model kept making the same call."));
    }
}
