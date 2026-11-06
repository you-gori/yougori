//! Cooperative cancellation before a model environment is created. A blocking
//! result owns its cleanup until its caller takes it, including if that caller
//! disappears while the filesystem operation is still finishing.
use crate::model_memory::manifest::CancellationToken;

const CANCELLED: &str =
    "YOUGORI_OPERATION_CANCELLED: model preparation cancelled; no environment was created";

pub(super) fn check() -> Result<(), String> {
    if crate::automation::context::current()
        .is_some_and(|context| context.cancellation.is_cancelled())
    {
        Err(CANCELLED.into())
    } else {
        Ok(())
    }
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct Prepared<T> {
    value: Option<T>,
    cleanup: fn(&T),
}
impl<T> Drop for Prepared<T> {
    fn drop(&mut self) {
        if let Some(value) = &self.value {
            (self.cleanup)(value);
        }
    }
}

pub(super) async fn blocking<T: Send + 'static>(
    stage: &'static str,
    work: impl FnOnce(&CancellationToken) -> Result<T, String> + Send + 'static,
    cleanup: fn(&T),
) -> Result<T, String> {
    check()?;
    let context = crate::automation::context::current();
    let cancel = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop(cancel.clone());
    crate::automation::context::progress(serde_json::json!({
        "phase":"modelImport", "stage":stage, "cancellable":true
    }));
    let worker_cancel = cancel.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        work(&worker_cancel).map(|value| Prepared {
            value: Some(value),
            cleanup,
        })
    });
    let completed = if let Some(context) = context {
        tokio::select! {
            result = &mut worker => result,
            _ = context.cancellation.cancelled() => {
                cancel.cancel();
                // Do not report completion while a blocking copy still owns leases.
                worker.await
            }
        }
    } else {
        worker.await
    };
    crate::automation::context::progress(serde_json::json!({
        "phase":"modelImportFinished", "stage":stage, "cancellable":false
    }));
    let result = completed.map_err(|_| "Model preparation worker failed".to_string())?;
    // Both a successful raced result and a cancelled import are released before
    // returning. Published verified originals remain available for a later retry.
    if cancel.is_cancelled() || check().is_err() {
        drop(result);
        return Err(CANCELLED.into());
    }
    let mut prepared = result?;
    Ok(prepared.value.take().expect("prepared value is owned"))
}

pub(super) fn release_binding(binding: &super::catalog_binding::Binding) {
    if let super::catalog_binding::Binding::Catalog(bound) = binding {
        if let Err(error) = super::catalog_binding::release_bound_engine(bound) {
            eprintln!("Cancelled model preparation cleanup needs reconciliation: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn cleanup(value: &Arc<AtomicUsize>) {
        value.fetch_add(1, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cancellation_waits_for_worker_and_releases_a_raced_result() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let cleaned = Arc::new(AtomicUsize::new(0));
        let count = cleaned.clone();
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = observed.clone();
        let context = crate::automation::context::OperationContext {
            id: "import-cancel-test".into(),
            cancellation: cancellation.clone(),
            progress: Arc::new(|_| {}),
        };
        let task = tokio::spawn(crate::automation::context::scope(
            context,
            blocking(
                "catalog",
                move |token| {
                    started.store(true, Ordering::SeqCst);
                    while !token.is_cancelled() {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(count)
                },
                cleanup,
            ),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !observed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.starts_with("YOUGORI_OPERATION_CANCELLED"));
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_the_waiter_cancels_and_releases_the_blocking_result() {
        let cleaned = Arc::new(AtomicUsize::new(0));
        let count = cleaned.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(blocking(
            "catalog",
            move |token| {
                sender.send(()).unwrap();
                while !token.is_cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Ok(count)
            },
            cleanup,
        ));
        receiver.await.unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while cleaned.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
    }
}
