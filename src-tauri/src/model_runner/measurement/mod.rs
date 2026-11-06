//! Private runner measurement collection. Raw observations retain their exact
//! boundaries; conversion to CORE-08 never invents token clocks or completeness.

pub(crate) mod collector;
pub(crate) mod cursor;
pub(crate) mod report;
pub(crate) mod sink;
pub(crate) mod workflow;

use crate::AppHandle;
use collector::{Collection, Failure, Limits};
use cursor::CursorStore;
use report::{AttemptKind, ObservationIdentity, ReportContext};
use sink::DurableSink;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// An explicit measurement job supplies its trusted identities, metadata and
/// private storage. This does not enroll ordinary model traffic in a benchmark.
#[allow(dead_code)] // The CLI exposes raw sessions; trusted report-context enrollment remains open.
pub(crate) async fn collect_model<C>(
    app: &AppHandle,
    environment_id: &str,
    session_id: &str,
    cursor: &mut CursorStore,
    limits: Limits,
    shutdown: &CancellationToken,
    sink: &Arc<DurableSink>,
    context: &Arc<C>,
) -> Result<Collection, Failure>
where
    C: Fn(&ObservationIdentity, AttemptKind) -> Result<ReportContext, String>
        + Send
        + Sync
        + 'static,
{
    collector::collect(
        environment_id,
        session_id,
        cursor,
        limits,
        shutdown,
        &|id, path, body| async move { super::model_request(app, &id, &path, body).await },
        &|batch| {
            let sink = Arc::clone(sink);
            let context = Arc::clone(context);
            async move {
                // A blocked disk must not block the async collection deadline.
                // A write may finish after cancellation; no cursor is advanced
                // without its ACK and replay is idempotent at the sink.
                tokio::task::spawn_blocking(move || sink.persist(batch, context.as_ref()))
                    .await
                    .map_err(|_| "Measurement storage worker failed".to_owned())?
                    .map_err(|_| "Cannot persist measurement records".to_owned())
            }
        },
    )
    .await
}

#[cfg(test)]
mod protocol_integration;
