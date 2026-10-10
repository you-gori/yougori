//! Append-before-acknowledge channel memory. Compaction of the model context does
//! not delete persisted observations or advance past unrecorded channel events.
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

const LIMIT: usize = 32 * 1024 * 1024;
pub(super) fn record(path: &Path, events: &Value, after: u64) -> Result<u64, String> {
    let rows = events.as_array().ok_or("Invalid channel event batch")?;
    let mut previous = if path.exists() {
        fs::read(path).map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };
    if previous.len() > LIMIT {
        return Err(
            "Worker coordination journal reached its storage limit; no events were discarded"
                .into(),
        );
    }
    if !previous.is_empty() && !previous.ends_with(b"\n") {
        let end = previous
            .iter()
            .rposition(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(0);
        previous.truncate(end);
        OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())?
            .set_len(end as u64)
            .map_err(|e| e.to_string())?;
    }
    let mut stored = 0;
    for line in previous
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = serde_json::from_slice(line)
            .map_err(|_| "Channel journal is unreadable; cursor was not advanced")?;
        stored = stored.max(
            value["sequence"]
                .as_u64()
                .ok_or("Invalid journal sequence")?,
        );
    }
    if stored < after {
        return Err("Channel journal is missing acknowledged events. Restore or replay its memory before continuing.".into());
    }
    let mut buffer = Vec::new();
    let mut cursor = stored;
    for event in rows {
        let sequence = event["sequence"]
            .as_u64()
            .ok_or("Missing channel event sequence")?;
        if sequence <= stored {
            continue;
        }
        if sequence <= cursor {
            return Err("Channel events are out of order; cursor was not advanced".into());
        }
        let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        if bytes.len() > 32 * 1024 {
            return Err("Channel event exceeds its memory limit".into());
        }
        buffer.extend_from_slice(&bytes);
        buffer.push(b'\n');
        cursor = sequence;
    }
    if previous.len() + buffer.len() > LIMIT {
        return Err(
            "Worker coordination journal reached its storage limit; no events were discarded"
                .into(),
        );
    }
    if !buffer.is_empty() {
        let parent = path.parent().ok_or("Invalid journal path")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| e.to_string())?;
        file.write_all(&buffer).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(cursor.max(after))
}
pub(super) fn projection(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(json!([]));
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() > LIMIT {
        return Err("Worker journal exceeds its bound".into());
    }
    let mut events = Vec::new();
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let value: Value = serde_json::from_slice(line).map_err(|_| "Invalid journal event")?;
        if matches!(
            value["type"].as_str(),
            Some("attempt_result" | "verification_result" | "policy_changed")
        ) {
            events.push(json!({"id":value["id"],"sequence":value["sequence"],"type":value["type"],"body":value["body"]}));
        }
    }
    Ok(json!(events))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_batch_is_durable_before_context_compaction() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("events.jsonl");
        let batch=json!((1..=100).map(|i|json!({"id":format!("event-{i}"),"sequence":i,"type":"attempt_result","body":{"observations":format!("Attempt {i}")}})).collect::<Vec<_>>());
        assert_eq!(record(&p, &batch, 0).unwrap(), 100);
        assert_eq!(projection(&p).unwrap().as_array().unwrap().len(), 100);
        assert_eq!(record(&p, &batch, 100).unwrap(), 100);
        assert_eq!(projection(&p).unwrap().as_array().unwrap().len(), 100);
    }
    #[test]
    fn interrupted_unacknowledged_tail_replays_without_losing_prior_records() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("events.jsonl");
        record(
            &p,
            &json!([{"id":"a","sequence":1,"type":"attempt_result","body":{}}]),
            0,
        )
        .unwrap();
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"id\":\"partial").unwrap();
        assert_eq!(
            record(
                &p,
                &json!([{"id":"b","sequence":2,"type":"attempt_result","body":{}}]),
                1
            )
            .unwrap(),
            2
        );
        assert_eq!(projection(&p).unwrap().as_array().unwrap().len(), 2);
    }
    #[test]
    fn missing_acknowledged_history_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        assert!(record(&d.path().join("absent"), &json!([]), 80).is_err());
    }
}
