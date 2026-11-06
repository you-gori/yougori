//! Runner-origin hints through bounded private long polls, never admission authority.
use super::{control, Seen};
use futures_util::{
    future::{AbortHandle, Abortable, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    time::Duration,
};
use tokio::{sync::watch, time::Instant};
use tokio_util::sync::CancellationToken;

const MAX_MEMBERS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cursor {
    id: String,
    instance_id: String,
    sequence: u64,
}

pub(super) fn members(seen: &[Seen]) -> Vec<Cursor> {
    seen.iter()
        .filter_map(|row| {
            let health = row.health.as_ref()?;
            if health["optimizer"]["enabled"] != true {
                return None;
            }
            match control::observation(health).ok()? {
                control::Observation::V1 {
                    instance_id,
                    sequence,
                } => Some(Cursor {
                    id: row.id.clone(),
                    instance_id,
                    sequence,
                }),
                control::Observation::Legacy => None,
            }
        })
        .take(MAX_MEMBERS)
        .collect()
}

#[derive(Clone, Copy)]
struct Settings {
    concurrency: usize,
    wait_ms: u64,
    timeout: Duration,
    retry_base: Duration,
    retry_max: Duration,
    success_gap: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            concurrency: 4,
            wait_ms: 5000,
            timeout: Duration::from_secs(8),
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
            success_gap: Duration::from_millis(100),
        }
    }
}

impl Settings {
    fn retry_delay(self, failures: u32) -> Duration {
        self.retry_base
            .saturating_mul(1_u32 << failures.saturating_sub(1).min(31))
            .min(self.retry_max)
    }
}

struct Member {
    cursor: Cursor,
    next: Instant,
    failures: u32,
    running: Option<(u64, AbortHandle)>,
}

struct Completion {
    id: String,
    ticket: u64,
    asked: Cursor,
    answer: Option<Value>,
}

struct Members {
    rows: BTreeMap<String, Member>,
    order: VecDeque<String>,
    ticket: u64,
}

impl Members {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            order: VecDeque::new(),
            ticket: 0,
        }
    }

    fn reconcile(&mut self, desired: Vec<Cursor>, now: Instant) {
        let desired: BTreeMap<_, _> = desired
            .into_iter()
            .take(MAX_MEMBERS)
            .map(|cursor| (cursor.id.clone(), cursor))
            .collect();
        self.rows.retain(|id, member| {
            let keep = desired
                .get(id)
                .is_some_and(|cursor| cursor.instance_id == member.cursor.instance_id);
            if !keep {
                if let Some((_, handle)) = member.running.take() {
                    handle.abort();
                }
            }
            keep
        });
        self.order.retain(|id| self.rows.contains_key(id));
        for (id, cursor) in desired {
            if let Some(member) = self.rows.get_mut(&id) {
                // A newer health poll already observed this revision. A subsequent
                // watch reply at that revision must not trigger redundant work.
                member.cursor.sequence = member.cursor.sequence.max(cursor.sequence);
            } else {
                self.order.push_back(id.clone());
                self.rows.insert(
                    id,
                    Member {
                        cursor,
                        next: now,
                        failures: 0,
                        running: None,
                    },
                );
            }
        }
    }

    fn ready(
        &mut self,
        now: Instant,
    ) -> Option<(Cursor, u64, futures_util::future::AbortRegistration)> {
        for _ in 0..self.order.len() {
            let id = self.order.pop_front()?;
            self.order.push_back(id.clone());
            let member = self.rows.get_mut(&id)?;
            if member.running.is_some() || member.next > now {
                continue;
            }
            let (abort, registration) = AbortHandle::new_pair();
            self.ticket = self
                .ticket
                .checked_add(1)
                .expect("watch request counter exhausted");
            member.running = Some((self.ticket, abort));
            return Some((member.cursor.clone(), self.ticket, registration));
        }
        None
    }

    fn next_due(&self) -> Option<Instant> {
        self.rows
            .values()
            .filter(|member| member.running.is_none())
            .map(|member| member.next)
            .min()
    }

    fn complete(&mut self, completion: Completion, settings: Settings, now: Instant) -> bool {
        let Some(member) = self.rows.get_mut(&completion.id) else {
            return false;
        };
        if member.running.as_ref().map(|(ticket, _)| *ticket) != Some(completion.ticket) {
            return false;
        }
        member.running = None;
        let observation = completion
            .answer
            .as_ref()
            .and_then(|answer| control::observation(answer).ok());
        if let Some(control::Observation::V1 {
            instance_id,
            sequence,
        }) = observation
        {
            // Regressing revisions in the same incarnation are invalid, not new events.
            if instance_id != completion.asked.instance_id || sequence >= completion.asked.sequence
            {
                let changed =
                    member.cursor.instance_id != instance_id || sequence > member.cursor.sequence;
                if changed {
                    member.cursor.instance_id = instance_id;
                    member.cursor.sequence = sequence;
                }
                member.failures = 0;
                member.next = now + settings.success_gap;
                return changed;
            }
        }
        member.failures = member.failures.saturating_add(1);
        member.next = now + settings.retry_delay(member.failures);
        false
    }
}

pub(super) async fn run<F, Fut, N>(
    updates: watch::Receiver<Vec<Cursor>>,
    shutdown: &CancellationToken,
    notify: N,
    send: F,
) where
    F: Fn(String, Value) -> Fut + Sync,
    Fut: Future<Output = Result<Value, String>> + Send,
    N: Fn() + Sync,
{
    run_with(updates, shutdown, notify, send, Settings::default()).await;
}

async fn run_with<F, Fut, N>(
    mut updates: watch::Receiver<Vec<Cursor>>,
    shutdown: &CancellationToken,
    notify: N,
    send: F,
    settings: Settings,
) where
    F: Fn(String, Value) -> Fut + Sync,
    Fut: Future<Output = Result<Value, String>> + Send,
    N: Fn() + Sync,
{
    let mut members = Members::new();
    members.reconcile(updates.borrow_and_update().clone(), Instant::now());
    let mut pending = FuturesUnordered::<BoxFuture<'_, Completion>>::new();
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        // Membership is checked before filling newly free connection slots.
        if updates.has_changed().unwrap_or(false) {
            members.reconcile(updates.borrow_and_update().clone(), Instant::now());
        }
        while pending.len() < settings.concurrency {
            let Some((asked, ticket, registration)) = members.ready(Instant::now()) else {
                break;
            };
            let send = &send;
            pending.push(
                async move {
                    let body = json!({"action":"watch", "instanceId":asked.instance_id,
                                  "since":asked.sequence, "waitMs":settings.wait_ms});
                    let result = Abortable::new(
                        tokio::time::timeout(settings.timeout, async {
                            send(asked.id.clone(), body).await
                        }),
                        registration,
                    )
                    .await;
                    let answer = result.ok().and_then(Result::ok).and_then(Result::ok);
                    Completion {
                        id: asked.id.clone(),
                        ticket,
                        asked,
                        answer,
                    }
                }
                .boxed(),
            );
        }
        let deadline = if pending.len() < settings.concurrency {
            members.next_due()
        } else {
            None
        };
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            changed = updates.changed() => {
                if changed.is_err() { break; }
                members.reconcile(updates.borrow_and_update().clone(), Instant::now());
            },
            Some(completion) = pending.next(), if !pending.is_empty() => {
                if members.complete(completion, settings, Instant::now()) { notify(); }
            },
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => futures_util::future::pending::<()>().await,
                }
            } => {},
        }
    }
    // No request is spawned: dropping the set drops all transports immediately.
    drop(pending);
}

#[cfg(test)]
mod tests;
