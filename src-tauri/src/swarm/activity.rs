//! What each worker is doing, as numbered events the CLI console reads as they happen. The log
//! lives in memory only. Real bounty work records the agent's actions (tool, target, outcome),
//! never its text or tool output, which can hold other workers' shared observations.
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{LazyLock, Mutex},
};
use tokio_util::sync::CancellationToken;

/// Events kept per worker; a console that falls further behind skips to the oldest kept one.
const KEEP: usize = 5000;
/// Participant guidance waiting for the next practice attempt.
const INPUTS: usize = 32;

#[derive(Default)]
struct Log {
    events: VecDeque<Value>,
    next: u64,
    inputs: Vec<String>,
    practice: Option<CancellationToken>,
}

static LOGS: LazyLock<Mutex<BTreeMap<String, Log>>> = LazyLock::new(Default::default);

fn with<R>(worker: &str, f: impl FnOnce(&mut Log) -> R) -> R {
    let mut logs = LOGS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(logs.entry(worker.to_owned()).or_default())
}

/// Appends one event; `kind` names it and the rest of `event` describes it.
pub(crate) fn emit(worker: &str, kind: &str, mut event: Value) {
    with(worker, |log| {
        log.next += 1;
        if !event.is_object() {
            event = json!({});
        }
        event["seq"] = log.next.into();
        event["kind"] = kind.into();
        event["at"] = chrono::Utc::now().timestamp_millis().into();
        log.events.push_back(event);
        while log.events.len() > KEEP {
            log.events.pop_front();
        }
    })
}

/// Events after `after`, the cursor for the next read and whether a practice is running.
pub(crate) fn read(worker: &str, after: u64, limit: usize) -> Value {
    with(worker, |log| {
        let events = log
            .events
            .iter()
            .filter(|event| event["seq"].as_u64().is_some_and(|seq| seq > after))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next = events.last().and_then(|event| event["seq"].as_u64()).unwrap_or(after.min(log.next));
        json!({"events":events,"next":next,"latest":log.next,"practicing":log.practice.is_some()})
    })
}

/// Registers a practice session; false when one is already running.
pub(crate) fn begin_practice(worker: &str, cancel: CancellationToken) -> bool {
    with(worker, |log| {
        if log.practice.is_some() {
            return false;
        }
        log.inputs.clear();
        log.practice = Some(cancel);
        true
    })
}

pub(crate) fn end_practice(worker: &str) {
    with(worker, |log| {
        log.practice = None;
        log.inputs.clear();
    })
}

pub(crate) fn practicing(worker: &str) -> bool {
    with(worker, |log| log.practice.is_some())
}

/// Stops a running practice; its current attempt ends at once.
pub(crate) fn stop_practice(worker: &str) -> bool {
    with(worker, |log| log.practice.as_ref().map(CancellationToken::cancel).is_some())
}

/// Queues the participant's guidance for the next practice attempt.
pub(crate) fn add_input(worker: &str, text: &str) -> Result<(), String> {
    let accepted = with(worker, |log| {
        if log.practice.is_none() {
            return Err("No practice is running. Start one with /practice.".to_string());
        }
        if log.inputs.len() >= INPUTS {
            return Err("Your worker has not read your earlier messages yet; wait for its next attempt".to_string());
        }
        log.inputs.push(text.to_owned());
        Ok(())
    });
    if accepted.is_ok() {
        emit(worker, "input", json!({"text":text}));
    }
    accepted
}

pub(crate) fn take_inputs(worker: &str) -> Vec<String> {
    with(worker, |log| std::mem::take(&mut log.inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_follow_a_bounded_cursor_and_guidance_needs_a_running_practice() {
        let worker = "worker-activity-test";
        assert!(add_input(worker, "look at auth.js").is_err());
        for index in 0..(KEEP + 10) {
            emit(worker, "text", json!({"text":index.to_string()}));
        }
        let first = read(worker, 0, 100);
        assert_eq!(first["events"][0]["seq"], 11, "the oldest events were dropped");
        assert_eq!(first["next"], 110);
        let rest = read(worker, first["next"].as_u64().unwrap(), 100_000);
        assert_eq!(rest["events"].as_array().unwrap().len(), KEEP - 100);
        assert_eq!(read(worker, rest["next"].as_u64().unwrap(), 10)["events"], json!([]));
        let cancel = CancellationToken::new();
        assert!(begin_practice(worker, cancel.clone()));
        assert!(!begin_practice(worker, CancellationToken::new()), "one practice per worker");
        add_input(worker, "look at auth.js").unwrap();
        assert_eq!(take_inputs(worker), ["look at auth.js"]);
        assert!(take_inputs(worker).is_empty());
        assert!(stop_practice(worker) && cancel.is_cancelled());
        end_practice(worker);
        assert!(!practicing(worker) && !stop_practice(worker));
    }
}
