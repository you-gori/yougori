//! What each worker is doing, as numbered events the console reads as they happen. Every event is
//! also written to the worker's own file under the Swarm data folder, so the activity survives a
//! restart and the person who set up the bounty keeps the full record of reads, HTTP probes and
//! experiments rather than losing it when the app reopens. Real bounty work records the agent's
//! actions (tool, target, outcome), and its text and tool output only when raw trace is on; either
//! way, what is persisted here is exactly what is shown here, on this machine, and nothing is
//! uploaded or shared.
use serde_json::{json, Value};
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    io::Write,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex, OnceLock},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Events kept per worker; a console that falls further behind skips to the oldest kept one.
const KEEP: usize = 5000;
/// Participant guidance waiting for the next practice attempt.
const INPUTS: usize = 32;

/// Default for [`raw_trace`]. The activity log normally records only the agent's own actions
/// (tool, target, outcome); its text, reasoning, tool input/output and other workers' shared
/// observations are kept out, because the shared investigation context can hold data private to
/// other participants. Raw trace turns all of it on, raw, for local debugging on this machine only
/// — nothing extra is persisted, uploaded or shared; it is only shown here. Less private.
const RAW_TRACE_DEFAULT: bool = true;

/// The one switch for raw worker traces: `YOUGORI_SWARM_RAW_TRACE=0/1` overrides per run, else
/// [`RAW_TRACE_DEFAULT`]. Flipping either restores the redaction; the paths that build each event
/// are left intact.
pub(crate) fn raw_trace() -> bool {
    raw_trace_from(std::env::var("YOUGORI_SWARM_RAW_TRACE").ok().as_deref())
}

fn raw_trace_from(var: Option<&str>) -> bool {
    match var {
        Some("1") | Some("true") | Some("on") => true,
        Some("0") | Some("false") | Some("off") | Some("") => false,
        _ => RAW_TRACE_DEFAULT,
    }
}

#[derive(Default)]
struct Log {
    events: VecDeque<Value>,
    next: u64,
    /// Lines in this worker's on-disk file, so it can be compacted back towards the kept window
    /// instead of growing without bound over a long investigation.
    file_lines: usize,
    inputs: Vec<String>,
    practice: Option<CancellationToken>,
    /// The participant started typing: the practice waits for their message.
    held: bool,
    /// Ends the practice attempt that is streaming now.
    attempt: Option<Arc<Notify>>,
}

static LOGS: LazyLock<Mutex<BTreeMap<String, Log>>> = LazyLock::new(Default::default);

/// Where each worker's events are written. Set once when Swarm loads; until then — and in tests —
/// the log is memory-only and nothing touches the disk.
static DIR: OnceLock<PathBuf> = OnceLock::new();

/// Points the activity log at a folder on disk so it survives restarts. Idempotent; a folder that
/// cannot be created leaves the log memory-only rather than failing.
pub(crate) fn init(dir: PathBuf) {
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = DIR.set(dir);
    }
}

/// The file a worker's events live in, or None when persistence is off or the id is not a plain
/// identifier (so the id is always exactly its own file name, never a path).
fn file_for(worker: &str) -> Option<PathBuf> {
    if worker.is_empty()
        || !worker
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    DIR.get().map(|dir| dir.join(format!("{worker}.jsonl")))
}

fn with<R>(worker: &str, f: impl FnOnce(&mut Log) -> R) -> R {
    let mut logs = LOGS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let log = match logs.entry(worker.to_owned()) {
        Entry::Occupied(entry) => entry.into_mut(),
        // First touch after a restart reloads the worker's kept events from disk, so a console
        // reading from cursor 0 sees everything that happened before, not an empty feed.
        Entry::Vacant(entry) => entry.insert(load_persisted(worker)),
    };
    f(log)
}

fn load_persisted(worker: &str) -> Log {
    let mut log = Log::default();
    let Some(path) = file_for(worker) else {
        return log;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return log;
    };
    let lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()).collect();
    log.file_lines = lines.len();
    // Only the most recent KEEP events are brought back into memory for display; the whole tail of
    // the file stays on disk and is compacted towards that window as new events are appended.
    for line in lines.iter().rev().take(KEEP).rev() {
        if let Ok(event) = serde_json::from_slice::<Value>(line) {
            if let Some(seq) = event["seq"].as_u64() {
                log.next = log.next.max(seq);
            }
            push_event(&mut log, event);
        }
    }
    log
}

/// Appends one event to the worker's file, then compacts the file back to the kept window if it has
/// grown well past it. Best-effort: a disk that cannot be written leaves the in-memory log intact.
fn persist(worker: &str, line: Vec<u8>, log: &mut Log) {
    let Some(path) = file_for(worker) else {
        return;
    };
    let mut line = line;
    line.push(b'\n');
    if std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&line))
        .is_ok()
    {
        log.file_lines += 1;
    }
    if log.file_lines > KEEP * 2 {
        let mut body = Vec::new();
        for event in &log.events {
            if let Ok(mut encoded) = serde_json::to_vec(event) {
                encoded.push(b'\n');
                body.extend_from_slice(&encoded);
            }
        }
        let tmp = path.with_extension("jsonl.tmp");
        if std::fs::write(&tmp, &body).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            log.file_lines = log.events.len();
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Keep the newest full snapshot of each streamed part. Cursors remain strictly
/// increasing and a reconnect sees complete text, even if it missed early updates.
fn push_event(log: &mut Log, event: Value) {
    if let Some(stream) = event["streamId"].as_str() {
        log.events.retain(|old| old["streamId"].as_str() != Some(stream));
    }
    log.events.push_back(event);
    while log.events.len() > KEEP {
        log.events.pop_front();
    }
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
        let line = serde_json::to_vec(&event).ok();
        push_event(log, event);
        if let Some(line) = line {
            persist(worker, line, log);
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

/// Registers a practice session that starts with the participant's `first` message, if any;
/// false when one is already running.
pub(crate) fn begin_practice(worker: &str, cancel: CancellationToken, first: Option<&str>) -> bool {
    with(worker, |log| {
        if log.practice.is_some() {
            return false;
        }
        log.inputs = first.map(str::to_owned).into_iter().collect();
        log.practice = Some(cancel);
        log.held = false;
        log.attempt = None;
        true
    })
}

/// Drops a deleted worker's activity: its events, practice text and pending input do not stay
/// in memory until the engine restarts.
pub(crate) fn forget(worker: &str) {
    let mut logs = LOGS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(log) = logs.remove(worker) {
        if let Some(cancel) = log.practice {
            cancel.cancel();
        }
    }
    // A deleted worker's saved events go too, so the record does not outlive the worker on disk.
    if let Some(path) = file_for(worker) {
        let _ = std::fs::remove_file(path);
    }
}

/// Empties a kept worker's history: its events in memory and its file on disk. Numbering starts
/// again, so a console holding an older cursor sees `latest` fall behind it and starts over.
pub(crate) fn clear(worker: &str) -> Result<(), String> {
    with(worker, |log| {
        if let Some(path) = file_for(worker) {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("The saved history could not be removed. Nothing was cleared; try again.".into()),
            }
        }
        log.events.clear();
        log.next = 0;
        log.file_lines = 0;
        Ok(())
    })
}

pub(crate) fn end_practice(worker: &str) {
    with(worker, |log| {
        log.practice = None;
        log.inputs.clear();
        log.held = false;
        log.attempt = None;
    })
}

/// The practice attempt streaming now, which [`interrupt_practice`] ends; None once it ended.
pub(crate) fn set_attempt(worker: &str, attempt: Option<Arc<Notify>>) {
    with(worker, |log| log.attempt = attempt)
}

/// The participant started typing: the streaming attempt ends at once and the next one waits
/// for their message. False when no practice runs.
pub(crate) fn interrupt_practice(worker: &str) -> bool {
    with(worker, |log| {
        if log.practice.is_none() {
            return false;
        }
        log.held = true;
        if let Some(attempt) = &log.attempt {
            attempt.notify_one();
        }
        true
    })
}

/// The participant cleared what they were typing: the practice goes on without a message.
pub(crate) fn resume_practice(worker: &str) {
    with(worker, |log| log.held = false)
}

pub(crate) fn held(worker: &str) -> bool {
    with(worker, |log| log.held)
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
        log.held = false;
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
    fn streaming_snapshots_preserve_history_and_advance_the_cursor() {
        let worker = "worker-streaming-test";
        emit(worker, "turn", json!({"text":"Started"}));
        emit(worker, "text", json!({"streamId":"s:1","text":"Hello","streaming":true}));
        let cursor = read(worker, 0, 100)["next"].as_u64().unwrap();
        emit(worker, "text", json!({"streamId":"s:1","text":"Hello world","streaming":false}));
        let fresh = read(worker, cursor, 100);
        assert_eq!(fresh["events"].as_array().unwrap().len(), 1);
        assert_eq!(fresh["events"][0]["text"], "Hello world");
        assert_eq!(fresh["events"][0]["streaming"], false);
        let all = read(worker, 0, 100);
        assert_eq!(all["events"].as_array().unwrap().len(), 2);
        assert_eq!(all["events"][0]["kind"], "turn");
        assert!(all["next"].as_u64().unwrap() > cursor);
    }

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
        assert!(begin_practice(worker, cancel.clone(), None));
        assert!(!begin_practice(worker, CancellationToken::new(), None), "one practice per worker");
        let attempt = Arc::new(Notify::new());
        set_attempt(worker, Some(attempt.clone()));
        assert!(interrupt_practice(worker) && held(worker));
        assert!(futures_now(attempt.notified()), "typing ends the streaming attempt");
        add_input(worker, "look at auth.js").unwrap();
        assert!(!held(worker), "a sent message releases the practice");
        assert_eq!(take_inputs(worker), ["look at auth.js"]);
        assert!(take_inputs(worker).is_empty());
        assert!(stop_practice(worker) && cancel.is_cancelled());
        end_practice(worker);
        assert!(!practicing(worker) && !stop_practice(worker) && !interrupt_practice(worker));
        assert!(begin_practice(worker, CancellationToken::new(), Some("try auth.js")));
        assert_eq!(take_inputs(worker), ["try auth.js"], "a practice can start with a message");
        interrupt_practice(worker);
        resume_practice(worker);
        assert!(!held(worker));
        end_practice(worker);
    }

    #[test]
    fn raw_trace_switch_honours_the_override_and_default() {
        assert_eq!(raw_trace_from(None), RAW_TRACE_DEFAULT, "no override uses the default");
        assert!(raw_trace_from(Some("1")) && raw_trace_from(Some("true")), "1/true turn raw traces on");
        assert!(!raw_trace_from(Some("0")) && !raw_trace_from(Some("off")), "0/off force the redaction on");
        assert_eq!(raw_trace_from(Some("maybe")), RAW_TRACE_DEFAULT, "an unknown value falls back to the default");
    }

    /// Whether `future` is ready without waiting.
    fn futures_now(future: impl std::future::Future) -> bool {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        future.as_mut().poll(&mut std::task::Context::from_waker(waker)).is_ready()
    }
}
