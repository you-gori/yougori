//! Bounded private journal replay. Fetch is not acknowledgement: persistence of
//! every raw event (including failures and starts) precedes the durable cursor.
use super::cursor::{opaque_id, Cursor, CursorStore, MAX_ACTIVE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

const MAX_SEQUENCE: u64 = (1 << 53) - 1;
const MAX_PAGE_BYTES: usize = 1_100_000;

#[derive(Clone, Debug)]
pub(crate) struct Limits {
    pub page_size: usize,
    pub max_pages: usize,
    pub deadline: Duration,
    pub seal: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            page_size: 64,
            max_pages: 16,
            deadline: Duration::from_secs(20),
            seal: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Invalid,
    Identity,
    Loss,
    Restart,
    Reordered,
    ResourceLimit,
    Cancelled,
    TimedOut,
    Transport,
    Persistence,
    Acknowledgement,
    Cursor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum End {
    Sealed,
    OpenHead,
    PageLimit,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Collection {
    pub after: u64,
    pub pages: usize,
    pub events: usize,
    pub inflight: usize,
    pub end: End,
}

/// Identity and exact event range to durably persist. Consumers must retain raw
/// events even when a CORE-08 conversion reports an unsupported metric/gap.
/// Replay after a crash is at-least-once, deduplicated by session + sequence.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidatedBatch {
    pub environment_id: String,
    pub session_id: String,
    pub after: u64,
    pub through: u64,
    pub records: Vec<Value>,
    pub sealed: bool,
    pub inflight: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct PersistAck {
    pub environment_id: String,
    pub session_id: String,
    pub through: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    journal: JournalPage,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalPage {
    version: u8,
    scope: String,
    clock: String,
    units: String,
    session_id: Option<String>,
    instance_id: String,
    status: String,
    first_sequence: u64,
    next_sequence: u64,
    after: u64,
    next_after: u64,
    has_more: bool,
    loss: bool,
    complete: bool,
    inflight: u64,
    interrupted: u64,
    records: Vec<Value>,
}

/// One journal event as the runner wrote it. Read with a strict tag (S06, `fd2612c`): a tag
/// that is not a string, or a key written twice, is refused instead of being read as a
/// variant index.
#[derive(Deserialize)]
#[serde(tag = "event", deny_unknown_fields)]
#[serde(remote = "Self")]
enum Event {
    #[serde(rename = "instance")]
    Instance {
        sequence: u64,
        #[serde(rename = "instanceId")]
        instance_id: String,
    },
    #[serde(rename = "start")]
    Start {
        sequence: u64,
        #[serde(rename = "instanceId")]
        instance_id: String,
        #[serde(rename = "attemptId")]
        attempt_id: u64,
        kind: String,
    },
    #[serde(rename = "finish")]
    Finish {
        sequence: u64,
        #[serde(rename = "instanceId")]
        instance_id: String,
        #[serde(rename = "attemptId")]
        attempt_id: u64,
        record: Value,
    },
    #[serde(rename = "seal")]
    Seal {
        sequence: u64,
        #[serde(rename = "instanceId")]
        instance_id: String,
    },
}

crate::foundation::strict_serde::strict_tag!(Event, "event", deserialize);

fn page(value: Value, cursor: &Cursor, limit: usize) -> Result<(JournalPage, Cursor), Failure> {
    if serde_json::to_vec(&value)
        .map_err(|_| Failure::Invalid)?
        .len()
        > MAX_PAGE_BYTES
    {
        return Err(Failure::ResourceLimit);
    }
    let Envelope { journal: page } = serde_json::from_value(value).map_err(|_| Failure::Invalid)?;
    if page.version != 1
        || page.scope != "session_window"
        || page.clock != "process_monotonic"
        || page.units != "milliseconds"
        || !opaque_id(&page.instance_id)
        || page.next_sequence == 0
        || page.next_sequence > MAX_SEQUENCE
        || page.next_after > MAX_SEQUENCE
        || page.first_sequence != 1
        || page.records.len() > limit
    {
        return Err(Failure::Invalid);
    }
    if page.session_id.as_deref() != Some(cursor.session_id.as_str()) {
        return Err(Failure::Identity);
    }
    if page.loss || page.interrupted != 0 || matches!(page.status.as_str(), "degraded" | "disabled")
    {
        return Err(Failure::Loss);
    }
    if !matches!(page.status.as_str(), "recording" | "sealed")
        || page.complete != (page.status == "sealed")
        || (page.complete && page.inflight != 0)
    {
        return Err(Failure::Invalid);
    }
    if page.next_sequence < cursor.observed_next
        || page.after != cursor.after
        || page.next_sequence <= cursor.after
        || page.next_after < cursor.after
        || page.next_after >= page.next_sequence
        || page.has_more != (page.next_after + 1 < page.next_sequence)
        || page.next_after - cursor.after != page.records.len() as u64
        || (page.has_more && page.records.is_empty())
    {
        return Err(Failure::Reordered);
    }
    if cursor
        .instance_id
        .as_ref()
        .is_some_and(|id| id != &page.instance_id)
    {
        return Err(Failure::Restart);
    }
    let mut next = cursor.clone();
    next.observed_next = page.next_sequence;
    for raw in &page.records {
        let event: Event = serde_json::from_value(raw.clone()).map_err(|_| Failure::Invalid)?;
        let (sequence, instance) = match &event {
            Event::Instance {
                sequence,
                instance_id,
            }
            | Event::Start {
                sequence,
                instance_id,
                ..
            }
            | Event::Finish {
                sequence,
                instance_id,
                ..
            }
            | Event::Seal {
                sequence,
                instance_id,
            } => (*sequence, instance_id),
        };
        if sequence != next.after + 1 || next.sealed {
            return Err(Failure::Reordered);
        }
        if instance != &page.instance_id || !opaque_id(instance) {
            return Err(Failure::Restart);
        }
        match event {
            Event::Instance { instance_id, .. } => {
                if next.after != 0 || next.instance_id.is_some() {
                    return Err(Failure::Restart);
                }
                next.instance_id = Some(instance_id);
            }
            Event::Start {
                attempt_id, kind, ..
            } => {
                if next.instance_id.is_none()
                    || attempt_id != next.last_started + 1
                    || !matches!(kind.as_str(), "load" | "request")
                {
                    return Err(Failure::Reordered);
                }
                if next.active.len() == MAX_ACTIVE {
                    return Err(Failure::ResourceLimit);
                }
                next.active.insert(attempt_id, kind);
                next.last_started = attempt_id;
            }
            Event::Finish {
                attempt_id, record, ..
            } => {
                super::report::parse_completed(&record).map_err(|_| Failure::Invalid)?;
                if record["id"].as_u64() != Some(attempt_id)
                    || record["completionSequence"].as_u64() != Some(next.completed + 1)
                    || next.active.get(&attempt_id).map(String::as_str) != record["kind"].as_str()
                {
                    return Err(Failure::Reordered);
                }
                next.active.remove(&attempt_id);
                next.completed += 1;
            }
            Event::Seal { .. } => {
                if next.instance_id.is_none() || !next.active.is_empty() || !page.complete {
                    return Err(Failure::Invalid);
                }
                next.sealed = true;
            }
        }
        next.after = sequence;
    }
    if !page.has_more && (next.active.len() as u64 != page.inflight || next.sealed != page.complete)
    {
        return Err(Failure::Invalid);
    }
    Ok((page, next))
}

async fn bounded<T, F: Future<Output = Result<T, Failure>>>(
    future: F,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<T, Failure> {
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(Failure::Cancelled),
        value = tokio::time::timeout_at(deadline, future) => value.map_err(|_| Failure::TimedOut)?,
    }
}

/// `send` must bind the engine's existing model + admin authenticated transport.
/// `persist` must acknowledge only after the complete raw batch is durable; an
/// error/cancellation may still have persisted it, so repeat delivery is normal.
pub(crate) async fn collect<S, SF, P, PF>(
    id: &str,
    session_id: &str,
    store: &mut CursorStore,
    limits: Limits,
    cancel: &CancellationToken,
    send: &S,
    persist: &P,
) -> Result<Collection, Failure>
where
    S: Fn(String, String, Option<Value>) -> SF,
    SF: Future<Output = Result<Value, String>>,
    P: Fn(ValidatedBatch) -> PF,
    PF: Future<Output = Result<PersistAck, String>>,
{
    if id != store.current().environment_id || session_id != store.current().session_id {
        return Err(Failure::Identity);
    }
    if limits.page_size == 0
        || limits.page_size > 128
        || limits.max_pages == 0
        || limits.max_pages > 64
        || limits.deadline.is_zero()
        || limits.deadline > Duration::from_secs(60)
    {
        return Err(Failure::ResourceLimit);
    }
    if cancel.is_cancelled() {
        return Err(Failure::Cancelled);
    }
    let deadline = tokio::time::Instant::now() + limits.deadline;
    let (mut pages, mut events, mut requested_seal) = (0, 0, false);
    let result = |cursor: &Cursor, pages, events, end| Collection {
        after: cursor.after,
        pages,
        events,
        inflight: cursor.active.len(),
        end,
    };
    if store.current().sealed {
        return Ok(result(store.current(), 0, 0, End::Sealed));
    }
    loop {
        let path = format!(
            "/v1/diagnostics/timings?journal=1&after={}&limit={}",
            store.current().after,
            limits.page_size
        );
        let value = bounded(
            async {
                send(id.into(), path, None)
                    .await
                    .map_err(|_| Failure::Transport)
            },
            deadline,
            cancel,
        )
        .await?;
        let (page, next) = page(value, store.current(), limits.page_size)?;
        pages += 1;
        if !page.records.is_empty() {
            let batch = ValidatedBatch {
                environment_id: id.into(),
                session_id: session_id.into(),
                after: store.current().after,
                through: next.after,
                records: page.records.clone(),
                sealed: next.sealed,
                inflight: next.active.len(),
            };
            let ack = bounded(
                async { persist(batch).await.map_err(|_| Failure::Persistence) },
                deadline,
                cancel,
            )
            .await?;
            if ack.environment_id != id || ack.session_id != session_id || ack.through != next.after
            {
                return Err(Failure::Acknowledgement);
            }
            // If cancelled after durable ACK but before checkpoint, replay is safe.
            if cancel.is_cancelled() {
                return Err(Failure::Cancelled);
            }
            store.commit(next).map_err(|_| Failure::Cursor)?;
            events += page.records.len();
        }
        if store.current().sealed {
            return Ok(result(store.current(), pages, events, End::Sealed));
        }
        if pages == limits.max_pages {
            return Ok(result(store.current(), pages, events, End::PageLimit));
        }
        if !page.has_more {
            if !limits.seal || requested_seal || page.inflight != 0 {
                return Ok(result(store.current(), pages, events, End::OpenHead));
            }
            bounded(
                async {
                    send(
                        id.into(),
                        "/v1/diagnostics/timings".into(),
                        Some(json!({"action":"seal", "sessionId":session_id})),
                    )
                    .await
                    .map_err(|_| Failure::Transport)
                },
                deadline,
                cancel,
            )
            .await?;
            requested_seal = true;
            // A successful HTTP response is not a seal proof. Replay and persist
            // the durable seal event before reporting the session complete.
        }
    }
}

#[cfg(test)]
mod tests;
