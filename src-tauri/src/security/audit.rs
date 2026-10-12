//! Tamper-evident, append-only audit log owned by the engine on the host.
//!
//! Each line is one JSON record. `hash` is the SHA-256 of the line's own bytes up to
//! and including `prev`, and `prev` repeats the previous record's `hash`, so an edited,
//! removed or reordered record breaks the chain. `head.json` anchors the newest record,
//! which makes a truncated end detectable. Old segments leave only through rotation,
//! which appends an `audit.rotated` record naming the last removed record. Guests never
//! reach this folder; the same-user host stays trusted and could rewrite the whole chain.
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Segment size and how many segments are kept (16 × 1 MiB by default).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub segment_bytes: u64,
    pub segments: usize,
}
pub(crate) const LIMITS: Limits = Limits { segment_bytes: 1024 * 1024, segments: 16 };
const LINE_LIMIT: usize = 16 * 1024;
/// No legitimate segment grows past its limit plus one record.
const READ_LIMIT: u64 = 4 * 1024 * 1024;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// `,"hash":"` + 64 hex digits + `"}`.
const HASH_SUFFIX: usize = 75;

/// One security-relevant event. Field names are compile-time constants and every value
/// is cleaned, so a caller cannot write control characters, URLs with credentials or
/// token-like strings into the log. Never pass secrets, prompts, file contents or output.
#[derive(Debug, Clone)]
pub(crate) struct Event {
    kind: &'static str,
    environment: Option<String>,
    via: Option<&'static str>,
    outcome: Option<&'static str>,
    detail: Map<String, Value>,
    command: Option<String>,
}

impl Event {
    pub(crate) fn new(kind: &'static str) -> Self {
        Self { kind, environment: None, via: None, outcome: None, detail: Map::new(), command: None }
    }
    #[cfg(test)]
    pub(crate) fn kind(&self) -> &'static str { self.kind }
    #[cfg(test)]
    pub(crate) fn environment(&self) -> Option<&str> { self.environment.as_deref() }
    pub(crate) fn has_via(&self) -> bool { self.via.is_some() }
    pub(crate) fn env(mut self, id: &str) -> Self {
        let id: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')).take(96).collect();
        self.environment = (!id.is_empty()).then_some(id);
        self
    }
    pub(crate) fn via(mut self, via: &'static str) -> Self {
        self.via = Some(via);
        self
    }
    pub(crate) fn outcome<T, E>(mut self, result: &Result<T, E>) -> Self {
        self.outcome = Some(if result.is_ok() { "succeeded" } else { "failed" });
        self
    }
    pub(crate) fn succeeded(mut self, ok: bool) -> Self {
        self.outcome = Some(if ok { "succeeded" } else { "failed" });
        self
    }
    pub(crate) fn text(mut self, key: &'static str, value: &str) -> Self {
        self.detail.insert(key.into(), Value::String(clean(value, 200)));
        self
    }
    pub(crate) fn path(mut self, key: &'static str, value: &str) -> Self {
        self.detail.insert(key.into(), Value::String(clean(value, 1024)));
        self
    }
    /// At most eight cleaned paths; record the full count separately.
    pub(crate) fn paths<S: AsRef<str>>(mut self, key: &'static str, values: &[S]) -> Self {
        let list = values.iter().take(8).map(|value| Value::String(clean(value.as_ref(), 1024))).collect();
        self.detail.insert(key.into(), Value::Array(list));
        self
    }
    pub(crate) fn number(mut self, key: &'static str, value: u64) -> Self {
        self.detail.insert(key.into(), json!(value));
        self
    }
    pub(crate) fn signed(mut self, key: &'static str, value: i64) -> Self {
        self.detail.insert(key.into(), json!(value));
        self
    }
    pub(crate) fn decimal(mut self, key: &'static str, value: f64) -> Self {
        if value.is_finite() {
            self.detail.insert(key.into(), json!((value * 100.0).round() / 100.0));
        }
        self
    }
    pub(crate) fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.detail.insert(key.into(), json!(value));
        self
    }
    /// Small structured values built by the engine itself (counters, step lists).
    pub(crate) fn object(mut self, key: &'static str, value: Value) -> Self {
        self.detail.insert(key.into(), sanitize(value, 0));
        self
    }
    /// Records only the program name, length and a salted hash; never the command line.
    pub(crate) fn command(mut self, command: &str) -> Self {
        self.command = Some(command.to_owned());
        self
    }
}

/// The first word of a shell command after `NAME=value` assignments, as a file name.
pub(crate) fn program(command: &str) -> String {
    for word in command.split_whitespace() {
        let assignment = word.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.starts_with(|c: char| c.is_ascii_digit())
        });
        if assignment {
            continue;
        }
        let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let valid = !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
        return if valid { name.to_owned() } else { "(shell)".into() };
    }
    "(empty)".into()
}

fn command_summary(salt: &[u8], command: &str) -> Value {
    let mut digest = Sha256::new();
    digest.update(salt);
    digest.update([0]);
    digest.update(command.as_bytes());
    let hash = hex::encode(digest.finalize());
    json!({"program": program(command), "commandLength": command.chars().count(), "commandHash": &hash[..32]})
}

fn sanitize(value: Value, depth: usize) -> Value {
    match value {
        Value::String(text) => Value::String(clean(&text, 200)),
        Value::Array(items) if depth < 3 => Value::Array(items.into_iter().take(32).map(|item| sanitize(item, depth + 1)).collect()),
        Value::Object(fields) if depth < 3 => Value::Object(
            fields.into_iter().take(32).map(|(key, item)| (clean(&key, 64), sanitize(item, depth + 1))).collect(),
        ),
        Value::Array(_) | Value::Object(_) => Value::Null,
        other => other,
    }
}

/// Printable, bounded, credential-free text.
pub(crate) fn clean(text: &str, limit: usize) -> String {
    let printable: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let redacted = redact_tokens(&redact_assignments(&redact_urls(&printable)));
    let mut chars = redacted.chars();
    let mut bounded: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

/// `scheme://user:password@host/path?query#fragment` keeps only `scheme://host/path`.
fn redact_urls(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let token_end = rest[index..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '>' | ')')).map_or(rest.len(), |i| index + i);
        output.push_str(&rest[..index + 3]);
        let tail = &rest[index + 3..token_end];
        let authority_end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        output.push_str(host);
        let path = &tail[authority_end..];
        output.push_str(&path[..path.find(['?', '#']).unwrap_or(path.len())]);
        rest = &rest[token_end..];
    }
    output.push_str(rest);
    output
}

const MARKERS: &[&str] = &["password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "bearer", "access_key", "private_key", "credential"];

/// Replaces the value after `password=`, `token: `, `Bearer ` and similar markers.
fn redact_assignments(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut cut: Vec<(usize, usize)> = Vec::new();
    for marker in MARKERS {
        let mut from = 0;
        while let Some(found) = lower[from..].find(marker) {
            let mut index = from + found + marker.len();
            from = index;
            let mut separators = 0;
            while index < bytes.len() && matches!(bytes[index], b'=' | b':' | b' ' | b'"' | b'\'') && separators < 4 {
                index += 1;
                separators += 1;
            }
            if separators == 0 {
                continue;
            }
            let end = index + text[index..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '&' | ',' | ';')).unwrap_or(text.len() - index);
            if end > index {
                cut.push((index, end));
            }
        }
    }
    if cut.is_empty() {
        return text.to_owned();
    }
    cut.sort_unstable();
    let mut output = String::with_capacity(text.len());
    let mut position = 0;
    for (start, end) in cut {
        if start < position {
            position = position.max(end);
            continue;
        }
        output.push_str(&text[position..start]);
        output.push_str("[redacted]");
        position = end;
    }
    output.push_str(&text[position..]);
    output
}

fn uuid_like(mut run: &str) -> bool {
    while let Some(rest) = ["env-", "share-", "exec-", "job-", "term-", "host-", "pub-", "publication-"].iter().find_map(|prefix| run.strip_prefix(prefix)) {
        run = rest;
    }
    let hex = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_hexdigit());
    (run.len() == 32 && hex(run))
        || (run.len() == 36 && run.split('-').map(str::len).eq([8, 4, 4, 4, 12]) && run.split('-').all(hex))
}

/// Long runs of key-like characters (API keys, bearer tokens, private links).
fn redact_tokens(text: &str) -> String {
    let token = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | '-');
    let mut output = String::with_capacity(text.len());
    let mut start = None;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    for position in 0..=chars.len() {
        let current = chars.get(position).copied();
        match (current, start) {
            (Some((index, c)), None) if token(c) => start = Some(index),
            (Some((_, c)), Some(_)) if token(c) => {}
            (_, Some(begin)) => {
                let end = current.map_or(text.len(), |(index, _)| index);
                let run = &text[begin..end];
                let digest = text[..begin].ends_with("sha256:") && run.len() == 64 && run.bytes().all(|b| b.is_ascii_hexdigit());
                let mixed = run.bytes().any(|b| b.is_ascii_digit()) && run.bytes().any(|b| b.is_ascii_alphabetic());
                if run.len() >= 40 && mixed && !digest && !uuid_like(run) {
                    output.push_str("[redacted]");
                } else {
                    output.push_str(run);
                }
                start = None;
                if let Some((_, c)) = current {
                    output.push(c);
                }
            }
            (Some((_, c)), None) => output.push(c),
            (None, None) => {}
        }
    }
    output
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Query {
    pub environment: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: usize,
}

struct Writer {
    segment: u64,
    bytes: u64,
    file: Option<fs::File>,
    seq: u64,
    hash: String,
    salt: Vec<u8>,
    anchored: u64,
    anchor_written: Option<Instant>,
    /// A failed write may have left a partial line: continue in a new segment.
    broken: bool,
}

pub(crate) struct AuditLog {
    root: PathBuf,
    limits: Limits,
    inner: Mutex<Writer>,
}

fn segment_name(number: u64) -> String {
    format!("audit-{number:06}.jsonl")
}

fn segments(root: &Path) -> Result<Vec<u64>, String> {
    let mut numbers = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| format!("Read audit folder: {error}"))? {
        let entry = entry.map_err(|error| format!("Read audit folder: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(number) = name.strip_prefix("audit-").and_then(|rest| rest.strip_suffix(".jsonl")).and_then(|digits| digits.parse::<u64>().ok()) {
            if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                numbers.push(number);
            }
        }
    }
    numbers.sort_unstable();
    Ok(numbers)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(READ_LIMIT).read_to_end(&mut data))
        .map_err(|error| format!("Read {}: {error}", path.display()))?;
    Ok(data)
}

/// Splits a line into its hashed body and stated hash, or None when it is not a record.
fn split_record(line: &[u8]) -> Option<(Vec<u8>, &str)> {
    if line.len() <= HASH_SUFFIX || line.len() > LINE_LIMIT {
        return None;
    }
    let (body, suffix) = line.split_at(line.len() - HASH_SUFFIX);
    let suffix = std::str::from_utf8(suffix).ok()?;
    let hash = suffix.strip_prefix(",\"hash\":\"")?.strip_suffix("\"}")?;
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut body = body.to_vec();
    body.push(b'}');
    Some((body, hash))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The newest complete record (seq, hash) and whether the data ends with a partial line.
fn last_record(data: &[u8]) -> (Option<(u64, String)>, bool) {
    let partial = !data.is_empty() && !data.ends_with(b"\n");
    let complete = if partial { &data[..data.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1)] } else { data };
    for line in complete.split(|b| *b == b'\n').rev() {
        let Some((body, hash)) = split_record(line) else { continue };
        if let Some(seq) = serde_json::from_slice::<Value>(&body).ok().and_then(|value| value["seq"].as_u64()) {
            return (Some((seq, hash.to_owned())), partial);
        }
    }
    (None, partial)
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Audit folder missing")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())?;
    }
    file.write_all(contents).map_err(|error| error.to_string())?;
    file.as_file().sync_all().map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.error.to_string())?;
    Ok(())
}

impl AuditLog {
    pub(crate) fn open(root: &Path) -> Result<Self, String> {
        Self::open_with(root, LIMITS)
    }

    pub(crate) fn open_with(root: &Path, limits: Limits) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("Create audit folder: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
        }
        let salt_path = root.join("salt");
        let salt = match fs::read(&salt_path) {
            Ok(salt) if salt.len() == 32 => salt,
            _ => {
                let salt: Vec<u8> = uuid::Uuid::new_v4().as_bytes().iter().chain(uuid::Uuid::new_v4().as_bytes()).copied().collect();
                write_private(&salt_path, &salt)?;
                salt
            }
        };
        let numbers = segments(root)?;
        let mut writer = Writer { segment: 1, bytes: 0, file: None, seq: 0, hash: GENESIS.into(), salt, anchored: 0, anchor_written: None, broken: false };
        let mut recovered = None;
        if let Some(&newest) = numbers.last() {
            writer.segment = newest;
            for &number in numbers.iter().rev() {
                let data = read_bounded(&root.join(segment_name(number)))?;
                let (last, partial) = last_record(&data);
                if number == newest {
                    writer.bytes = data.len() as u64;
                    if partial {
                        recovered = Some(segment_name(number));
                    }
                }
                if let Some((seq, hash)) = last {
                    writer.seq = seq;
                    writer.hash = hash;
                    break;
                }
            }
            if recovered.is_some() {
                writer.segment += 1;
                writer.bytes = 0;
            }
        }
        // A log that ends before its anchor lost records outside Yougori. Record that in the
        // chain before the next write moves the anchor, so the evidence cannot be overwritten.
        let anchor = fs::read(root.join("head.json")).ok().and_then(|data| serde_json::from_slice::<Value>(&data).ok());
        let anchored_seq = anchor.as_ref().and_then(|anchor| anchor["seq"].as_u64()).unwrap_or(0);
        let anchored_hash = anchor.as_ref().and_then(|anchor| anchor["hash"].as_str().map(str::to_owned));
        let truncated = anchored_seq > writer.seq || (anchored_seq == writer.seq && anchored_seq > 0 && anchored_hash.as_deref() != Some(writer.hash.as_str()));
        let last_seq = writer.seq;
        writer.anchored = anchored_seq;
        let log = Self { root: root.to_owned(), limits, inner: Mutex::new(writer) };
        if last_seq == 0 {
            log.append(Event::new("audit.started").via("engine").number("format", 1))?;
        }
        if truncated {
            log.append(Event::new("audit.truncated").via("engine").number("anchoredSeq", anchored_seq).number("lastSeq", last_seq)
                .text("reason", "the log ended before the record anchored in head.json"))?;
        }
        if let Some(segment) = recovered {
            log.append(Event::new("audit.recovered").via("engine").text("segment", &segment).text("reason", "incomplete final line kept as evidence"))?;
        }
        Ok(log)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn append(&self, event: Event) -> Result<u64, String> {
        self.append_at(event, Utc::now())
    }

    pub(crate) fn append_at(&self, mut event: Event, time: DateTime<Utc>) -> Result<u64, String> {
        let mut writer = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(command) = event.command.take() {
            if let Value::Object(summary) = command_summary(&writer.salt, &command) {
                event.detail.extend(summary);
            }
        }
        if writer.broken {
            writer.broken = false;
            writer.segment += 1;
            writer.bytes = 0;
            writer.file = None;
            let notice = Event::new("audit.recovered").via("engine").text("reason", "a previous write failed; continuing in a new segment");
            self.write_event(&mut writer, &notice, time)?;
        }
        let line = encode(&writer, &event, time)?;
        if writer.bytes > 0 && writer.bytes + line.0.len() as u64 > self.limits.segment_bytes {
            self.rotate(&mut writer, time)?;
        }
        let seq = self.write_event(&mut writer, &event, time)?;
        self.anchor(&mut writer, false);
        Ok(seq)
    }

    fn write_event(&self, writer: &mut Writer, event: &Event, time: DateTime<Utc>) -> Result<u64, String> {
        let (line, seq, hash) = encode(writer, event, time)?;
        if writer.file.is_none() {
            let path = self.root.join(segment_name(writer.segment));
            let file = fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|error| format!("Open audit segment: {error}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
            writer.file = Some(file);
        }
        let file = writer.file.as_mut().expect("audit segment is open");
        if let Err(error) = file.write_all(&line).and_then(|_| file.sync_data()) {
            writer.broken = true;
            writer.file = None;
            return Err(format!("Write audit record: {error}"));
        }
        writer.bytes += line.len() as u64;
        writer.seq = seq;
        writer.hash = hash;
        Ok(seq)
    }

    /// Starts a new segment and removes the oldest beyond the retention limit, recording each removal.
    fn rotate(&self, writer: &mut Writer, time: DateTime<Utc>) -> Result<(), String> {
        writer.segment += 1;
        writer.bytes = 0;
        writer.file = None;
        let mut numbers = segments(&self.root)?;
        if !numbers.contains(&writer.segment) {
            numbers.push(writer.segment);
        }
        while numbers.len() > self.limits.segments {
            let oldest = numbers.remove(0);
            let path = self.root.join(segment_name(oldest));
            let (last, _) = last_record(&read_bounded(&path)?);
            if fs::remove_file(&path).is_err() {
                break;
            }
            let mut record = Event::new("audit.rotated").via("engine").text("removedSegment", &segment_name(oldest));
            if let Some((seq, hash)) = last {
                // A chain hash, not user text: stored verbatim so verification can match it.
                record.detail.insert("removedThroughSeq".into(), json!(seq));
                record.detail.insert("removedLastHash".into(), Value::String(hash));
            }
            self.write_event(writer, &record, time)?;
        }
        Ok(())
    }

    fn anchor(&self, writer: &mut Writer, force: bool) {
        if writer.anchored == writer.seq {
            return;
        }
        if !force && writer.anchor_written.is_some_and(|written| written.elapsed() < Duration::from_secs(1)) {
            return;
        }
        let head = json!({"seq": writer.seq, "hash": writer.hash, "segment": segment_name(writer.segment)});
        if write_private(&self.root.join("head.json"), head.to_string().as_bytes()).is_ok() {
            writer.anchored = writer.seq;
            writer.anchor_written = Some(Instant::now());
        }
    }

    /// Writes a pending anchor (monitor tick and shutdown).
    pub(crate) fn flush_anchor(&self) {
        let mut writer = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        self.anchor(&mut writer, true);
    }

    /// Newest matching records, returned oldest first, without their chain fields.
    pub(crate) fn query(&self, query: &Query) -> Result<Vec<Value>, String> {
        let limit = query.limit.clamp(1, 1000);
        let filter = query.environment.as_ref().map(|id| format!("\"env\":{}", Value::String(id.clone())));
        let mut found = Vec::new();
        'segments: for number in segments(&self.root)?.into_iter().rev() {
            let data = read_bounded(&self.root.join(segment_name(number)))?;
            for line in data.split(|b| *b == b'\n').rev() {
                if line.is_empty() || filter.as_ref().is_some_and(|filter| !line.windows(filter.len()).any(|window| window == filter.as_bytes())) {
                    continue;
                }
                let Some((body, hash)) = split_record(line) else { continue };
                let Ok(mut record) = serde_json::from_slice::<Value>(&body) else { continue };
                if let Some(since) = query.since {
                    let time = record["time"].as_str().and_then(|time| DateTime::parse_from_rfc3339(time).ok());
                    if time.is_none_or(|time| time < since) {
                        continue;
                    }
                }
                if let Some(fields) = record.as_object_mut() {
                    fields.remove("prev");
                    fields.insert("hash".into(), Value::String(hash.to_owned()));
                }
                found.push(record);
                if found.len() >= limit {
                    break 'segments;
                }
            }
        }
        found.reverse();
        Ok(found)
    }

    /// Checks every hash and link, sequence steps, rotation records and the head anchor.
    pub(crate) fn verify(&self) -> Value {
        let _writer = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        verify_folder(&self.root)
    }
}

fn encode(writer: &Writer, event: &Event, time: DateTime<Utc>) -> Result<(Vec<u8>, u64, String), String> {
    let seq = writer.seq + 1;
    let text = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), |value| Value::String(value.to_owned()).to_string());
    let mut body = format!(
        "{{\"seq\":{seq},\"time\":{},\"event\":{},\"env\":{},\"via\":{},\"outcome\":{},\"detail\":{},\"prev\":\"{}\"}}",
        Value::String(time.to_rfc3339_opts(SecondsFormat::Millis, true)),
        Value::String(event.kind.to_owned()),
        text(event.environment.as_deref()),
        text(Some(event.via.unwrap_or("app"))),
        text(event.outcome),
        Value::Object(event.detail.clone()),
        writer.hash,
    );
    if body.len() + HASH_SUFFIX > LINE_LIMIT {
        body = format!(
            "{{\"seq\":{seq},\"time\":{},\"event\":{},\"env\":{},\"via\":{},\"outcome\":{},\"detail\":{{\"truncated\":true}},\"prev\":\"{}\"}}",
            Value::String(time.to_rfc3339_opts(SecondsFormat::Millis, true)),
            Value::String(event.kind.to_owned()),
            text(event.environment.as_deref()),
            text(Some(event.via.unwrap_or("app"))),
            text(event.outcome),
            writer.hash,
        );
    }
    let hash = digest(body.as_bytes());
    body.pop();
    body.push_str(&format!(",\"hash\":\"{hash}\"}}\n"));
    Ok((body.into_bytes(), seq, hash))
}

pub(crate) fn verify_folder(root: &Path) -> Value {
    let mut problems: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();
    let numbers = match segments(root) {
        Ok(numbers) => numbers,
        Err(error) => return json!({"ok": false, "records": 0, "problems": [{"problem": error}], "warnings": []}),
    };
    let anchor = fs::read(root.join("head.json")).ok().and_then(|data| serde_json::from_slice::<Value>(&data).ok());
    let anchor_seq = anchor.as_ref().and_then(|anchor| anchor["seq"].as_u64());
    let anchor_hash = anchor.as_ref().and_then(|anchor| anchor["hash"].as_str().map(str::to_owned));
    let mut anchor_found = false;
    let (mut records, mut first, mut last_seq, mut last_hash) = (0u64, None::<(u64, String)>, None::<u64>, None::<String>);
    let mut rotations: Vec<(u64, String)> = Vec::new();
    // Earlier losses the engine noticed and recorded in the chain itself.
    let mut incidents: Vec<Value> = Vec::new();
    for (position, number) in numbers.iter().enumerate() {
        let name = segment_name(*number);
        let data = match read_bounded(&root.join(&name)) {
            Ok(data) => data,
            Err(error) => {
                problems.push(json!({"segment": name, "problem": error}));
                continue;
            }
        };
        if data.len() as u64 >= READ_LIMIT {
            problems.push(json!({"segment": name, "problem": "segment is larger than any rotation allows"}));
        }
        let partial = !data.is_empty() && !data.ends_with(b"\n");
        let lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
        let count = lines.len();
        for (index, line) in lines.into_iter().enumerate() {
            if line.is_empty() {
                continue;
            }
            if index + 1 == count && partial {
                warnings.push(json!({"segment": name, "warning": if position + 1 == numbers.len() { "incomplete final line (write in progress or interrupted)" } else { "incomplete final line kept from an interrupted write" }}));
                continue;
            }
            let Some((body, hash)) = split_record(line) else {
                problems.push(json!({"segment": name, "line": index + 1, "problem": "not a chained audit record"}));
                continue;
            };
            let computed = digest(&body);
            let Ok(record) = serde_json::from_slice::<Value>(&body) else {
                problems.push(json!({"segment": name, "line": index + 1, "problem": "record is not valid JSON"}));
                continue;
            };
            let seq = record["seq"].as_u64().unwrap_or(0);
            let prev = record["prev"].as_str().unwrap_or("").to_owned();
            if computed != hash {
                problems.push(json!({"seq": seq, "segment": name, "problem": "record was changed after it was written (hash mismatch)"}));
            }
            match (last_seq, &last_hash) {
                (Some(previous), Some(previous_hash)) => {
                    if seq != previous + 1 {
                        problems.push(json!({"seq": seq, "segment": name, "problem": format!("sequence jumps from {previous} to {seq} (records removed or reordered)")}));
                    }
                    if &prev != previous_hash {
                        problems.push(json!({"seq": seq, "segment": name, "problem": "chain link does not match the previous record"}));
                    }
                }
                _ => first = Some((seq, prev.clone())),
            }
            if matches!(record["event"].as_str(), Some("audit.truncated" | "audit.dropped")) {
                incidents.push(json!({"seq": seq, "time": record["time"], "event": record["event"], "detail": record["detail"]}));
            }
            if record["event"] == "audit.rotated" {
                if let (Some(through), Some(removed)) = (record["detail"]["removedThroughSeq"].as_u64(), record["detail"]["removedLastHash"].as_str()) {
                    rotations.push((through, removed.to_owned()));
                }
            }
            if anchor_seq == Some(seq) {
                anchor_found = true;
                if anchor_hash.as_deref() != Some(hash) {
                    problems.push(json!({"seq": seq, "problem": "anchored record differs from the anchor in head.json"}));
                }
            }
            records += 1;
            last_seq = Some(seq);
            last_hash = Some(hash.to_owned());
        }
    }
    match &first {
        Some((1, prev)) if prev != GENESIS => problems.push(json!({"seq": 1, "problem": "first record does not start the chain"})),
        Some((seq, prev)) if *seq > 1 && !rotations.iter().any(|(through, hash)| *through + 1 == *seq && hash == prev) => {
            problems.push(json!({"seq": seq, "problem": format!("records before {seq} are missing without a rotation record")}));
        }
        _ => {}
    }
    match (anchor_seq, last_seq) {
        (Some(anchored), Some(last)) if anchored > last => problems.push(json!({"problem": format!("log ends at record {last} but head.json anchors record {anchored} (truncated)")})),
        (Some(anchored), None) if anchored > 0 => problems.push(json!({"problem": format!("no records remain but head.json anchors record {anchored} (truncated)")})),
        (Some(anchored), Some(_)) if !anchor_found && first.as_ref().is_some_and(|(seq, _)| anchored >= *seq) => {
            problems.push(json!({"seq": anchored, "problem": "anchored record is missing"}));
        }
        (None, Some(_)) => warnings.push(json!({"warning": "head.json is missing; truncation of the newest records cannot be ruled out"})),
        _ => {}
    }
    json!({
        "ok": problems.is_empty(), "records": records, "segments": numbers.len(),
        "firstSeq": first.map(|(seq, _)| seq), "lastSeq": last_seq, "anchoredSeq": anchor_seq,
        "problems": problems, "warnings": warnings, "incidents": incidents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> (tempfile::TempDir, AuditLog) {
        let directory = tempfile::tempdir().unwrap();
        let log = AuditLog::open(&directory.path().join("audit")).unwrap();
        (directory, log)
    }

    fn segment(log: &AuditLog, number: u64) -> PathBuf {
        log.root().join(segment_name(number))
    }

    #[test]
    fn records_chain_from_genesis_and_verify() {
        let (_directory, log) = log();
        for index in 0..20 {
            log.append(Event::new("exec.run").env("env-00000000-0000-0000-0000-000000000001").via("cli").number("index", index)).unwrap();
        }
        log.flush_anchor();
        let report = log.verify();
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["records"], 21);
        assert_eq!(report["firstSeq"], 1);
        assert_eq!(report["anchoredSeq"], 21);
        let text = fs::read_to_string(segment(&log, 1)).unwrap();
        let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["event"], "audit.started");
        assert_eq!(first["prev"], GENESIS);
    }

    #[test]
    fn edits_removals_reordering_and_truncation_are_detected() {
        let tamper = |change: &dyn Fn(&mut Vec<String>)| {
            let (directory, log) = log();
            for index in 0..6 {
                log.append(Event::new("environment.started").env("env-a").number("index", index)).unwrap();
            }
            log.flush_anchor();
            let path = segment(&log, 1);
            let mut lines: Vec<String> = fs::read_to_string(&path).unwrap().lines().map(str::to_owned).collect();
            change(&mut lines);
            fs::write(&path, lines.iter().map(|line| format!("{line}\n")).collect::<String>()).unwrap();
            let report = verify_folder(log.root());
            drop(directory);
            report
        };
        let edited = tamper(&|lines| lines[3] = lines[3].replace("\"index\":2", "\"index\":9"));
        assert_eq!(edited["ok"], false);
        assert!(edited["problems"].to_string().contains("hash mismatch"), "{edited}");
        let removed = tamper(&|lines| { lines.remove(2); });
        assert_eq!(removed["ok"], false);
        assert!(removed["problems"].to_string().contains("sequence jumps"), "{removed}");
        let reordered = tamper(&|lines| lines.swap(2, 3));
        assert_eq!(reordered["ok"], false);
        let truncated = tamper(&|lines| { lines.truncate(4); });
        assert_eq!(truncated["ok"], false);
        assert!(truncated["problems"].to_string().contains("truncated"), "{truncated}");
        let rehashed_edit = tamper(&|lines| {
            // Recomputing one record's own hash still breaks the next link.
            let (body, _) = split_record(lines[3].replace("\"index\":2", "\"index\":7").as_bytes()).unwrap();
            let hash = digest(&body);
            let mut body = String::from_utf8(body).unwrap();
            body.pop();
            lines[3] = format!("{body},\"hash\":\"{hash}\"}}");
        });
        assert_eq!(rehashed_edit["ok"], false);
        assert!(rehashed_edit["problems"].to_string().contains("chain link"), "{rehashed_edit}");
    }

    #[test]
    fn rotation_is_bounded_recorded_and_verifiable() {
        let directory = tempfile::tempdir().unwrap();
        let limits = Limits { segment_bytes: 4096, segments: 4 };
        let log = AuditLog::open_with(&directory.path().join("audit"), limits).unwrap();
        let filler = "x".repeat(150);
        let mut appended = 0;
        while segments(log.root()).unwrap().last().copied().unwrap_or(0) < limits.segments as u64 + 3 {
            log.append(Event::new("transfer.in").env("env-a").path("destination", &format!("/data/{filler}/{appended}"))).unwrap();
            appended += 1;
        }
        log.flush_anchor();
        let numbers = segments(log.root()).unwrap();
        assert_eq!(numbers.len(), limits.segments);
        let total: u64 = numbers.iter().map(|n| fs::metadata(segment(&log, *n)).unwrap().len()).sum();
        assert!(total <= limits.segments as u64 * (limits.segment_bytes + LINE_LIMIT as u64));
        assert!(fs::read_to_string(segment(&log, *numbers.last().unwrap())).unwrap().contains("audit.rotated"));
        let report = log.verify();
        assert_eq!(report["ok"], true, "{report}");
        assert!(report["firstSeq"].as_u64().unwrap() > 1);
        // Deleting a retained segment outside rotation is detected.
        fs::remove_file(segment(&log, numbers[0])).unwrap();
        let report = verify_folder(log.root());
        assert_eq!(report["ok"], false);
        assert!(report["problems"].to_string().contains("missing without a rotation record"), "{report}");
    }

    #[test]
    fn interrupted_write_is_kept_as_evidence_and_the_chain_continues() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("audit");
        {
            let log = AuditLog::open(&root).unwrap();
            log.append(Event::new("environment.started").env("env-a")).unwrap();
            log.flush_anchor();
        }
        let path = root.join(segment_name(1));
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"seq\":3,\"time\":\"2026-").unwrap();
        drop(file);
        let log = AuditLog::open(&root).unwrap();
        log.append(Event::new("environment.stopped").env("env-a")).unwrap();
        log.flush_anchor();
        let report = log.verify();
        assert_eq!(report["ok"], true, "{report}");
        assert!(report["warnings"].to_string().contains("incomplete final line"), "{report}");
        assert_eq!(report["lastSeq"], 4);
        let newest = fs::read_to_string(root.join(segment_name(2))).unwrap();
        assert!(newest.contains("audit.recovered"));
    }

    #[test]
    fn truncation_noticed_at_startup_is_recorded_before_the_anchor_moves() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("audit");
        {
            let log = AuditLog::open(&root).unwrap();
            for index in 0..5 {
                log.append(Event::new("environment.started").env("env-a").number("index", index)).unwrap();
            }
            log.flush_anchor();
        }
        let path = root.join(segment_name(1));
        let kept: String = fs::read_to_string(&path).unwrap().lines().take(3).map(|line| format!("{line}\n")).collect();
        fs::write(&path, kept).unwrap();
        let log = AuditLog::open(&root).unwrap();
        log.append(Event::new("environment.stopped").env("env-a")).unwrap();
        log.flush_anchor();
        let report = log.verify();
        assert_eq!(report["ok"], true, "the chain itself continues: {report}");
        assert_eq!(report["incidents"][0]["event"], "audit.truncated", "{report}");
        assert_eq!(report["incidents"][0]["detail"]["anchoredSeq"], 6);
        assert_eq!(report["incidents"][0]["detail"]["lastSeq"], 3);
    }

    #[test]
    fn reopening_continues_the_same_chain() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("audit");
        AuditLog::open(&root).unwrap().append(Event::new("environment.created").env("env-a")).unwrap();
        let log = AuditLog::open(&root).unwrap();
        assert_eq!(log.append(Event::new("environment.deleted").env("env-a")).unwrap(), 3);
        log.flush_anchor();
        assert_eq!(log.verify()["ok"], true);
    }

    #[test]
    fn secrets_commands_and_links_never_reach_the_file() {
        let (_directory, log) = log();
        let token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
        log.append(Event::new("exec.run").env("env-a").command(&format!("API_KEY={token} curl -H 'Authorization: Bearer {token}' https://user:hunter2@example.com/x?sig=abc"))).unwrap();
        log.append(Event::new("share.remote").text("link", "https://example.com/share/share-1?token=supersecretvalue#frag")).unwrap();
        log.append(Event::new("transfer.in").path("destination", &format!("/home/dev/.config/{token}/file"))).unwrap();
        log.append(Event::new("settings").text("note", "password=correct-horse token: tok123 bearer zzz")).unwrap();
        log.append(Event::new("image").text("image", "ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55")).unwrap();
        let text = fs::read_to_string(segment(&log, 1)).unwrap();
        for secret in [token, "hunter2", "sig=abc", "supersecretvalue", "frag", "correct-horse", "tok123", "zzz", "curl -H"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(text.contains("\"program\":\"curl\""), "{text}");
        assert!(text.contains("\"commandHash\""));
        assert!(text.contains("\"link\":\"https://example.com/share/share-1\""), "{text}");
        assert!(text.contains("sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"), "{text}");
        assert_eq!(log.verify()["ok"], true);
    }

    #[test]
    fn program_names_skip_assignments_and_paths() {
        assert_eq!(program("npm test"), "npm");
        assert_eq!(program("FOO=bar BAZ=1 /usr/bin/python3 -c 'print(1)'"), "python3");
        assert_eq!(program("C:\\tools\\git.exe status"), "git.exe");
        assert_eq!(program("\"quoted\" arg"), "(shell)");
        assert_eq!(program("   "), "(empty)");
    }

    #[test]
    fn identifiers_and_text_are_bounded_and_printable() {
        let event = Event::new("x").env("env-1\u{1b}[31m;rm -rf").text("name", &"a\u{7}".repeat(500));
        assert_eq!(event.environment(), Some("env-131mrm-rf"));
        let text = event.detail["name"].as_str().unwrap();
        assert!(text.chars().count() <= 201 && !text.contains('\u{7}'));
    }

    #[test]
    fn queries_filter_by_environment_and_time_and_return_oldest_first() {
        let (_directory, log) = log();
        let base = DateTime::parse_from_rfc3339("2026-10-11T10:00:00Z").unwrap().with_timezone(&Utc);
        for minute in 0..10i64 {
            let env = if minute % 2 == 0 { "env-a" } else { "env-b" };
            log.append_at(Event::new("environment.started").env(env).number("minute", minute as u64), base + chrono::Duration::minutes(minute)).unwrap();
        }
        let records = log.query(&Query { environment: Some("env-a".into()), since: Some(base + chrono::Duration::minutes(3)), limit: 10 }).unwrap();
        let minutes: Vec<u64> = records.iter().map(|r| r["detail"]["minute"].as_u64().unwrap()).collect();
        assert_eq!(minutes, vec![4, 6, 8]);
        assert!(records[0].get("prev").is_none() && records[0]["hash"].is_string());
        let newest = log.query(&Query { environment: None, since: None, limit: 2 }).unwrap();
        assert_eq!(newest.iter().map(|r| r["detail"]["minute"].as_u64().unwrap()).collect::<Vec<_>>(), vec![8, 9]);
    }
}
