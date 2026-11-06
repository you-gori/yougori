//! Engine-owned durable measurement output. The cursor may advance only after
//! this sink acknowledges an atomic, synced snapshot. Replayed pages may overlap.
use super::{
    collector::{PersistAck, ValidatedBatch},
    cursor::opaque_id,
    report::{self, AttemptKind, ObservationIdentity, ReportContext},
};
use crate::foundation::{ids::OperationId, report as core};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 8192;
const MAX_BATCH: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SinkError {
    Identity,
    Busy,
    Storage,
    Invalid,
    Conflict,
    Context,
    ResourceLimit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredEvent {
    raw: Value,
    context: Option<Value>,
    operation: Option<OperationId>,
    report: Option<Value>,
    gaps: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    version: u8,
    environment_id: String,
    session_id: String,
    events: Vec<StoredEvent>,
    sealed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    checksum: String,
    snapshot: Snapshot,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    pub events: usize,
    pub started: usize,
    pub completed: usize,
    pub inflight: usize,
    pub converted: usize,
    pub with_gaps: usize,
    pub sealed: bool,
}

pub(crate) struct DurableSink {
    directory: PathBuf,
    _lock: File,
    state: Mutex<Snapshot>,
}

impl DurableSink {
    /// `directory` must be an engine-owned private directory, never a runner path.
    pub(crate) fn open(
        directory: &Path,
        environment_id: &str,
        session_id: &str,
    ) -> Result<Self, SinkError> {
        if !opaque_id(session_id)
            || environment_id.is_empty()
            || environment_id.len() > 128
            || !environment_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(SinkError::Identity);
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory).map_err(|_| SinkError::Storage)?;
        if !fs::symlink_metadata(directory)
            .map_err(|_| SinkError::Storage)?
            .file_type()
            .is_dir()
        {
            return Err(SinkError::Invalid);
        }
        regular(&directory.join("sink.lock"))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options
            .open(directory.join("sink.lock"))
            .map_err(|_| SinkError::Storage)?;
        lock.try_lock().map_err(|_| SinkError::Busy)?;
        let path = directory.join("measurement.json");
        regular(&path)?;
        let snapshot = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| SinkError::Storage)?;
                if bytes.len() > MAX_BYTES {
                    return Err(SinkError::ResourceLimit);
                }
                let envelope: Envelope =
                    serde_json::from_slice(&bytes).map_err(|_| SinkError::Invalid)?;
                if checksum(&envelope.snapshot)? != envelope.checksum {
                    return Err(SinkError::Invalid);
                }
                envelope.snapshot
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Snapshot {
                version: 1,
                environment_id: environment_id.into(),
                session_id: session_id.into(),
                events: Vec::new(),
                sealed: false,
            },
            Err(_) => return Err(SinkError::Storage),
        };
        if snapshot.environment_id != environment_id || snapshot.session_id != session_id {
            return Err(SinkError::Identity);
        }
        validate(&snapshot)?;
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
            state: Mutex::new(snapshot),
        })
    }

    /// Export validated raw evidence, explicitly retaining incomplete-window status.
    pub(crate) fn export(&self) -> Result<PathBuf, SinkError> {
        let state = self.state.lock().map_err(|_| SinkError::Storage)?;
        let summary = validate(&state)?;
        let destination = self.directory.join("observations.json");
        regular(&destination)?;
        let bytes = serde_json::to_vec(&json!({"version":1,"environmentId":state.environment_id,
            "sessionId":state.session_id,"complete":summary.sealed,"summary":summary,"evidence":"runner_observations",
            "benchmarkContext":"unavailable","events":state.events})).map_err(|_| SinkError::Invalid)?;
        if bytes.len() > MAX_BYTES {
            return Err(SinkError::ResourceLimit);
        }
        let mut file =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| SinkError::Storage)?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| SinkError::Storage)?;
        file.persist(&destination).map_err(|_| SinkError::Storage)?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| SinkError::Storage)?;
        Ok(destination)
    }

    pub(crate) fn summary(&self) -> Result<Summary, SinkError> {
        let state = self.state.lock().map_err(|_| SinkError::Storage)?;
        validate(&state)
    }

    pub(crate) fn persist<C>(
        &self,
        batch: ValidatedBatch,
        context: &C,
    ) -> Result<PersistAck, SinkError>
    where
        C: Fn(&ObservationIdentity, AttemptKind) -> Result<ReportContext, String>,
    {
        self.persist_optional(batch, &|identity, kind| context(identity, kind).map(Some))
    }

    pub(crate) fn persist_raw(&self, batch: ValidatedBatch) -> Result<PersistAck, SinkError> {
        self.persist_optional(batch, &|_, _| Ok(None))
    }

    fn persist_optional<C>(
        &self,
        batch: ValidatedBatch,
        context: &C,
    ) -> Result<PersistAck, SinkError>
    where
        C: Fn(&ObservationIdentity, AttemptKind) -> Result<Option<ReportContext>, String>,
    {
        let mut state = self.state.lock().map_err(|_| SinkError::Storage)?;
        if batch.environment_id != state.environment_id || batch.session_id != state.session_id {
            return Err(SinkError::Identity);
        }
        if batch.records.is_empty()
            || batch.records.len() > MAX_BATCH
            || batch.after > MAX_EVENTS as u64
            || batch.through
                != batch
                    .after
                    .checked_add(batch.records.len() as u64)
                    .ok_or(SinkError::ResourceLimit)?
            || batch.through > MAX_EVENTS as u64
            || batch.after > state.events.len() as u64
        {
            return Err(SinkError::Invalid);
        }
        let mut next = state.clone();
        for (index, raw) in batch.records.iter().enumerate() {
            let sequence = batch.after + index as u64 + 1;
            if raw["sequence"].as_u64() != Some(sequence) {
                return Err(SinkError::Invalid);
            }
            let event = prepare(raw, &state.session_id, context)?;
            let slot = sequence as usize - 1;
            if slot < next.events.len() {
                if next.events[slot] != event {
                    return Err(SinkError::Conflict);
                }
            } else {
                next.events.push(event);
            }
        }
        // Validate the incoming prefix too: a replay may stop before the current
        // sink head, so its flags cannot be compared only with today's head.
        let mut prefix = next.clone();
        prefix.events.truncate(batch.through as usize);
        prefix.sealed = prefix
            .events
            .last()
            .is_some_and(|e| e.raw["event"] == "seal");
        let accounting = validate(&prefix)?;
        if accounting.sealed != batch.sealed || accounting.inflight != batch.inflight {
            return Err(SinkError::Invalid);
        }
        next.sealed = next.events.last().is_some_and(|e| e.raw["event"] == "seal");
        validate(&next)?;
        // Even a duplicate ACK re-establishes durable output. An in-memory
        // match cannot prove the file still exists or has not been replaced.
        {
            let envelope = Envelope {
                checksum: checksum(&next)?,
                snapshot: next.clone(),
            };
            let bytes = serde_json::to_vec(&envelope).map_err(|_| SinkError::Invalid)?;
            if bytes.len() > MAX_BYTES {
                return Err(SinkError::ResourceLimit);
            }
            regular(&self.directory.join("measurement.json"))?;
            let mut file =
                tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| SinkError::Storage)?;
            file.write_all(&bytes)
                .and_then(|_| file.as_file().sync_all())
                .map_err(|_| SinkError::Storage)?;
            file.persist(self.directory.join("measurement.json"))
                .map_err(|_| SinkError::Storage)?;
            #[cfg(unix)]
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| SinkError::Storage)?;
            *state = next;
        }
        Ok(PersistAck {
            environment_id: state.environment_id.clone(),
            session_id: state.session_id.clone(),
            through: batch.through,
        })
    }
}

fn checksum(snapshot: &Snapshot) -> Result<String, SinkError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(snapshot).map_err(|_| SinkError::Invalid)?)
    ))
}
fn regular(path: &Path) -> Result<(), SinkError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(SinkError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SinkError::Storage),
    }
}
fn context_value(context: &ReportContext) -> Value {
    let m = &context.metadata;
    json!({"attempt":m.attempt,"substrate":m.substrate,"build":m.build,"executionCategory":m.execution_category,
        "model":m.model,"precision":m.precision,"engine":m.engine,"host":m.host,"workload":m.workload,
        "client":m.client,"load":m.load,"state":m.state,"launch":m.launch,"price":m.price})
}
fn prepare<C>(raw: &Value, session: &str, context: &C) -> Result<StoredEvent, SinkError>
where
    C: Fn(&ObservationIdentity, AttemptKind) -> Result<Option<ReportContext>, String>,
{
    let mut event = StoredEvent {
        raw: raw.clone(),
        context: None,
        operation: None,
        report: None,
        gaps: Vec::new(),
    };
    if raw["event"] == "finish" {
        let observation =
            report::parse_completed(&raw["record"]).map_err(|_| SinkError::Invalid)?;
        let identity = ObservationIdentity::new(
            session,
            raw["instanceId"].as_str().ok_or(SinkError::Identity)?,
            observation.id,
        )
        .map_err(|_| SinkError::Identity)?;
        let Some(context) = context(&identity, observation.kind).map_err(|_| SinkError::Context)?
        else {
            event.gaps.push("ReportContextUnavailable".into());
            return Ok(event);
        };
        let adapted =
            report::adapt(&observation, &identity, &context).map_err(|_| SinkError::Context)?;
        event.context = Some(context_value(&context));
        event.operation = Some(context.metadata.attempt.operation);
        event.report = adapted
            .record
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| SinkError::Context)?;
        event.gaps = adapted.gaps.iter().map(|gap| format!("{gap:?}")).collect();
    }
    Ok(event)
}

fn validate(snapshot: &Snapshot) -> Result<Summary, SinkError> {
    if snapshot.version != 1
        || snapshot.events.len() > MAX_EVENTS
        || !opaque_id(&snapshot.session_id)
    {
        return Err(SinkError::Invalid);
    }
    let mut instance = None;
    let mut active = BTreeMap::new();
    let mut operations = BTreeSet::new();
    let (mut started, mut completed, mut converted, mut gaps, mut sealed) = (0, 0, 0, 0, false);
    for (index, event) in snapshot.events.iter().enumerate() {
        let raw = event.raw.as_object().ok_or(SinkError::Invalid)?;
        if event.raw["sequence"].as_u64() != Some(index as u64 + 1) || sealed {
            return Err(SinkError::Invalid);
        }
        let observed = event.raw["instanceId"]
            .as_str()
            .filter(|id| opaque_id(id))
            .ok_or(SinkError::Identity)?;
        let kind = event.raw["event"].as_str().ok_or(SinkError::Invalid)?;
        let expected_fields = match kind {
            "instance" | "seal" => 3,
            "start" | "finish" => 5,
            _ => return Err(SinkError::Invalid),
        };
        if raw.len() != expected_fields
            || !raw.contains_key("sequence")
            || !raw.contains_key("instanceId")
            || !raw.contains_key("event")
        {
            return Err(SinkError::Invalid);
        }
        if kind == "instance" {
            if index != 0 || instance.is_some() {
                return Err(SinkError::Invalid);
            }
            instance = Some(observed.to_owned());
        } else if instance.as_deref() != Some(observed) {
            return Err(SinkError::Identity);
        }
        match kind {
            "start" => {
                let id = event.raw["attemptId"].as_u64().ok_or(SinkError::Invalid)?;
                let kind = event.raw["kind"]
                    .as_str()
                    .filter(|k| matches!(*k, "load" | "request"))
                    .ok_or(SinkError::Invalid)?;
                if id != started + 1 || active.len() == 4096 {
                    return Err(SinkError::Invalid);
                }
                active.insert(id, kind.to_owned());
                started += 1;
            }
            "finish" => {
                let observation = report::parse_completed(&event.raw["record"])
                    .map_err(|_| SinkError::Invalid)?;
                let id = event.raw["attemptId"].as_u64().ok_or(SinkError::Invalid)?;
                let expected = if observation.kind == AttemptKind::Load {
                    "load"
                } else {
                    "request"
                };
                if id != observation.id
                    || observation.completion_sequence != completed + 1
                    || active.remove(&id).as_deref() != Some(expected)
                {
                    return Err(SinkError::Invalid);
                }
                if event.context.is_none() {
                    if event.operation.is_some()
                        || event.report.is_some()
                        || event.gaps != ["ReportContextUnavailable"]
                    {
                        return Err(SinkError::Invalid);
                    }
                    completed += 1;
                    gaps += 1;
                    continue;
                }
                let operation = event.operation.as_ref().ok_or(SinkError::Invalid)?;
                if !operations.insert(operation.as_str().to_owned())
                    || event
                        .context
                        .as_ref()
                        .and_then(|c| c.get("attempt"))
                        .and_then(|c| c.get("operation"))
                        != Some(&json!(operation))
                {
                    return Err(SinkError::Conflict);
                }
                if let Some(value) = &event.report {
                    let report = core::RunRecord::from_json(&value.to_string())
                        .map_err(|_| SinkError::Invalid)?;
                    if report.attempt.operation != *operation {
                        return Err(SinkError::Conflict);
                    }
                    converted += 1;
                }
                if event.gaps.is_empty() {
                    return Err(SinkError::Invalid);
                }
                gaps += 1;
                completed += 1;
            }
            "seal" => {
                if !active.is_empty() {
                    return Err(SinkError::Invalid);
                }
                sealed = true;
            }
            _ => {}
        }
        if kind != "finish"
            && (event.context.is_some()
                || event.operation.is_some()
                || event.report.is_some()
                || !event.gaps.is_empty())
        {
            return Err(SinkError::Invalid);
        }
    }
    if snapshot.sealed != sealed {
        return Err(SinkError::Invalid);
    }
    Ok(Summary {
        events: snapshot.events.len(),
        started: started as usize,
        completed: completed as usize,
        inflight: active.len(),
        converted,
        with_gaps: gaps,
        sealed,
    })
}

#[cfg(test)]
pub(super) mod tests;
