//! Explicit owner measurement sessions. Raw evidence never asserts benchmark context.
use super::{
    collector::{self, Limits},
    cursor::{opaque_id, CursorStore},
    sink::DurableSink,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const PATH: &str = "/v1/diagnostics/timings";
const STORAGE: &str = "Measurement storage could not be opened or is invalid";
const BUSY: &str = "Another measurement operation is active for this model; retry shortly";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Current {
    version: u8,
    session_id: Option<String>,
}
struct Owner {
    directory: PathBuf,
    _lock: File,
    current: Option<String>,
}

fn regular(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(STORAGE.into()),
    }
}
fn directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => return Ok(()),
        Ok(_) => return Err(STORAGE.into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(STORAGE.into()),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| STORAGE.to_owned())
}
impl Owner {
    fn open(root: &Path, environment: &str) -> Result<Self, String> {
        if environment.is_empty()
            || environment.len() > 128
            || !environment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("Invalid measurement environment".into());
        }
        directory(root)?;
        let dir = root.join(environment);
        directory(&dir)?;
        let path = dir.join("owner.lock");
        regular(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options.open(path).map_err(|_| STORAGE)?;
        lock.try_lock().map_err(|_| BUSY)?;
        let path = dir.join("current.json");
        regular(&path)?;
        let current = match File::open(path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(1025)
                    .read_to_end(&mut bytes)
                    .map_err(|_| STORAGE)?;
                if bytes.len() > 1024 {
                    return Err(STORAGE.into());
                }
                let value: Current = serde_json::from_slice(&bytes).map_err(|_| STORAGE)?;
                if value.version != 1 || value.session_id.as_ref().is_some_and(|id| !opaque_id(id))
                {
                    return Err(STORAGE.into());
                }
                value.session_id
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(STORAGE.into()),
        };
        Ok(Self {
            directory: dir,
            _lock: lock,
            current,
        })
    }
    fn select(&mut self, session: Option<String>) -> Result<(), String> {
        let path = self.directory.join("current.json");
        regular(&path)?;
        let bytes = serde_json::to_vec(&Current {
            version: 1,
            session_id: session.clone(),
        })
        .map_err(|_| STORAGE)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| STORAGE)?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| STORAGE)?;
        file.persist(path).map_err(|_| STORAGE)?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| STORAGE)?;
        self.current = session;
        Ok(())
    }
    fn session(&self, id: &str, create: bool) -> Result<PathBuf, String> {
        if !opaque_id(id) {
            return Err("Session ID must be 32 lowercase hexadecimal characters".into());
        }
        let path = self.directory.join(id);
        if !path.exists() {
            if !create {
                return Err("Measurement session not found on this engine".into());
            }
            let mut count = 0;
            for (index, entry) in fs::read_dir(&self.directory)
                .map_err(|_| STORAGE)?
                .enumerate()
            {
                if index >= 128 {
                    return Err("Measurement directory entry limit reached".into());
                }
                let entry = entry.map_err(|_| STORAGE)?;
                if opaque_id(&entry.file_name().to_string_lossy()) {
                    count += 1;
                }
            }
            if count >= 8 {
                return Err("Eight measurement sessions are retained. Archive old session directories before starting another".into());
            }
        }
        directory(&path)?;
        Ok(path)
    }
}
fn open_session(
    path: &Path,
    environment: &str,
    session: &str,
) -> Result<(CursorStore, Arc<DurableSink>), String> {
    let mut cursor_path = path.to_owned();
    cursor_path.push("cursor");
    let mut sink_path = path.to_owned();
    sink_path.push("output");
    directory(&cursor_path)?;
    directory(&sink_path)?;
    let cursor = CursorStore::open(&cursor_path, environment, session).map_err(|_| STORAGE)?;
    let sink = Arc::new(DurableSink::open(&sink_path, environment, session).map_err(|_| STORAGE)?);
    Ok((cursor, sink))
}
async fn open_async(
    path: PathBuf,
    environment: &str,
    session: &str,
) -> Result<(CursorStore, Arc<DurableSink>), String> {
    let environment = environment.to_owned();
    let session = session.to_owned();
    tokio::task::spawn_blocking(move || open_session(&path, &environment, &session))
        .await
        .map_err(|_| STORAGE)?
}
async fn control<S, F>(send: &S, env: &str, action: &str, id: &str) -> Result<Value, String>
where
    S: Fn(String, String, Option<Value>) -> F,
    F: Future<Output = Result<Value, String>>,
{
    tokio::time::timeout(Duration::from_secs(15),send(env.into(),PATH.into(),Some(json!({"action":action,"sessionId":id}))))
        .await.map_err(|_|"Measurement control timed out".to_owned())?
        .map_err(|_|"Runner refused measurement control or is unavailable; update/restart an older runner, or retry after active requests finish".to_owned())
}
fn result(env: &str, id: &str, sink: &DurableSink, state: &str) -> Result<Value, String> {
    Ok(json!({"environmentId":env,"sessionId":id,"state":state,
        "summary":sink.summary().map_err(|_|STORAGE)?,"benchmarkContext":"unavailable"}))
}

pub(super) async fn execute<S, F>(
    root: PathBuf,
    environment: String,
    action: String,
    session: Option<String>,
    send: &S,
) -> Result<Value, String>
where
    S: Fn(String, String, Option<Value>) -> F,
    F: Future<Output = Result<Value, String>>,
{
    if !matches!(
        action.as_str(),
        "start" | "collect" | "seal" | "status" | "export" | "abandon"
    ) {
        return Err("Unknown measurement action".into());
    }
    if session.as_ref().is_some_and(|s| !opaque_id(s)) {
        return Err("Invalid measurement session ID".into());
    }
    let env = environment.clone();
    let mut owner = tokio::task::spawn_blocking(move || Owner::open(&root, &env))
        .await
        .map_err(|_| STORAGE)??;
    let old = owner.current.clone();
    let mut id = session.clone().or_else(|| old.clone());
    if action == "start" {
        if let Some(old_id) = &old {
            let path = owner.session(old_id, false)?;
            let (_, prior) = open_async(path, &environment, old_id).await?;
            let sealed = prior.summary().map_err(|_| STORAGE)?.sealed;
            if !sealed && session.as_ref().is_some_and(|id| id != old_id) {
                return Err("Collect/seal or explicitly abandon the current measurement before replacing it".into());
            }
            if sealed && session.as_ref() == Some(old_id) {
                return result(&environment, old_id, &prior, "sealed");
            }
            if sealed {
                let response = control(send, &environment, "release", old_id).await?;
                if response["journal"]["status"] != "disabled" {
                    return Err("Runner did not confirm release of the sealed session".into());
                }
                id = session.clone();
            }
        }
        if id.is_none() {
            id = Some(uuid::Uuid::new_v4().simple().to_string());
        }
    }
    let id = id.ok_or("No current measurement session; start one or supply --session ID")?;
    let path = owner.session(&id, action == "start")?;
    let (mut cursor, sink) = open_async(path, &environment, &id).await?;
    if action == "start" {
        if sink.summary().map_err(|_| STORAGE)?.sealed {
            return Err("A sealed session cannot be restarted; use a new session ID".into());
        }
        owner.select(Some(id.clone()))?; // Persist identity before any remote side effect.
        let response = control(send, &environment, "start", &id).await;
        let confirmed = response.as_ref().is_ok_and(|v| {
            v["journal"]["sessionId"] == id
                && v["journal"]["status"] == "recording"
                && v["journal"]["loss"] == false
        });
        let mut value = result(
            &environment,
            &id,
            &sink,
            if confirmed {
                "recording"
            } else {
                "startUnconfirmed"
            },
        )?;
        if !confirmed {
            value["issue"] = json!(response
                .err()
                .unwrap_or_else(|| "Runner did not confirm the requested session".into()));
            value["remedy"] =
                json!("Retry start with this session ID; no window has been certified complete");
        }
        return Ok(value);
    }
    if action == "status" {
        return result(
            &environment,
            &id,
            &sink,
            if sink.summary().map_err(|_| STORAGE)?.sealed {
                "sealed"
            } else {
                "open"
            },
        );
    }
    if action == "export" {
        let export = Arc::clone(&sink);
        let path = tokio::task::spawn_blocking(move || export.export())
            .await
            .map_err(|_| STORAGE)?
            .map_err(|_| STORAGE)?;
        let mut value = result(&environment, &id, &sink, "exported")?;
        value["path"] = json!(path);
        return Ok(value);
    }
    let persist = |batch| {
        let sink = Arc::clone(&sink);
        async move {
            tokio::task::spawn_blocking(move || sink.persist_raw(batch))
                .await
                .map_err(|_| STORAGE.to_owned())?
                .map_err(|_| STORAGE.to_owned())
        }
    };
    let collected = collector::collect(
        &environment,
        &id,
        &mut cursor,
        Limits {
            page_size: 64,
            max_pages: 64,
            deadline: Duration::from_secs(30),
            seal: action == "seal",
        },
        &CancellationToken::new(),
        send,
        &persist,
    )
    .await;
    if action == "abandon" {
        // Collection is best effort; incomplete raw evidence is never relabelled complete.
        let stopped = control(send, &environment, "abandon", &id)
            .await
            .is_ok_and(|v| v["journal"]["status"] == "disabled");
        if owner.current.as_ref() == Some(&id) {
            owner.select(None)?;
        }
        let mut value = result(&environment, &id, &sink, "abandoned")?;
        value["runnerStopped"] = json!(stopped);
        value["remedy"]=json!("Incomplete observations remain available with --session; an unreachable runner may still be recording");
        return Ok(value);
    }
    let mut value = result(&environment, &id, &sink, "open")?;
    match collected {
        Ok(collection) => {
            value["state"] = json!(if sink.summary().map_err(|_| STORAGE)?.sealed {
                "sealed"
            } else {
                "open"
            });
            value["after"] = json!(collection.after);
            value["end"] = json!(format!("{:?}", collection.end));
            if action == "seal" && value["state"] != "sealed" {
                value["remedy"] = json!("Run seal again to continue from the saved cursor");
            }
        }
        Err(error) => {
            value["state"] = json!("incomplete");
            value["issue"] = json!(format!("{error:?}"));
            value["remedy"]=json!("Retry collection; export preserves incomplete evidence. Abandon only to start a separate session");
        }
    }
    Ok(value)
}

pub(crate) async fn command(
    app: &crate::AppHandle,
    environment: String,
    action: String,
    session: Option<String>,
) -> Result<Value, String> {
    use tauri::Manager;
    let store = app.state::<crate::store::PlatformStore>();
    if !matches!(action.as_str(), "status" | "export") {
        store.environment(&environment)?;
    }
    let root = store.data_folder("model-measurements");
    execute(
        root,
        environment,
        action,
        session,
        &|env, path, body| async move { super::super::model_request(app, &env, &path, body).await },
    )
    .await
}

#[cfg(test)]
mod tests;
