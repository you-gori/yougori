//! SQLite record reconciliation. The same direction and priority apply as file sync.
use super::*;
use std::{collections::{BTreeMap, BTreeSet}, io::{BufRead, BufReader, Seek, SeekFrom, Write}, process::{Child, ChildStdin, ChildStdout, Command, Stdio}};

pub(super) struct Helper {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    _script: tempfile::NamedTempFile,
    diagnostics: tempfile::NamedTempFile,
    failed: bool,
}
impl Drop for Helper {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}
impl Helper {
    fn start(root: &Path) -> Result<Self, String> {
        let mut script = tempfile::Builder::new().suffix(".cjs").tempfile().map_err(|e| e.to_string())?;
        script.write_all(include_bytes!("../assets/sqlite.cjs")).map_err(|e| e.to_string())?;
        script.flush().map_err(|e| e.to_string())?;
        let diagnostics = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        let mut command = Command::new("node");
        command.arg("--no-warnings").arg(script.path()).arg(root).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::from(diagnostics.as_file().try_clone().map_err(|e| e.to_string())?));
        #[cfg(windows)] { use std::os::windows::process::CommandExt; command.creation_flags(0x08000000); }
        let mut child = command.spawn().map_err(|e| format!("SQLite sync needs Node.js 22.16 or newer on this computer: {e}"))?;
        let input = child.stdin.take().ok_or("Missing SQLite helper input")?;
        let output = BufReader::new(child.stdout.take().ok_or("Missing SQLite helper output")?);
        Ok(Self { child, input, output, _script: script, diagnostics, failed: false })
    }
    fn transport_error(&mut self, cause: &str) -> String {
        self.failed = true;
        let _ = self.child.kill();
        let status = self.child.wait().ok();
        let mut diagnostics = String::new();
        let file = self.diagnostics.as_file_mut();
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.take(8192).read_to_string(&mut diagnostics);
        let detail = if diagnostics.trim().is_empty() {
            format!("{cause}{}", status.map(|s| format!(" (exit {s})")).unwrap_or_default())
        } else { diagnostics.trim().to_owned() };
        format!("Local SQLite helper stopped: {detail}")
    }
    #[cfg(test)]
    fn request(&mut self, request: Value) -> Result<Value, String> {
        self.request_progress(request, None)
    }
    fn request_progress(&mut self, request: Value, progress: Option<&ui::Task>) -> Result<Value, String> {
        if self.failed { return Err("Local SQLite helper is stopped; the next sync will restart it".into()); }
        let mut data = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        data.push(b'\n');
        if let Err(error) = self.input.write_all(&data).and_then(|_| self.input.flush()) {
            return Err(self.transport_error(&error.to_string()));
        }
        loop {
            let mut line = String::new();
            match self.output.read_line(&mut line) {
                Ok(0) => return Err(self.transport_error("No response from helper")),
                Err(error) => return Err(self.transport_error(&error.to_string())),
                _ => {}
            }
            let reply: Value = match serde_json::from_str(&line) {
                Ok(reply) => reply,
                Err(_) => return Err(self.transport_error("Invalid helper response")),
            };
            if let Some(measurement) = reply.get("progress") {
                if let Some(progress) = progress { progress.database_progress(measurement, "local"); }
                continue;
            }
            if let Some(error) = reply["error"].as_str() { return Err(error.into()); }
            return Ok(reply["result"].clone());
        }
    }
}

#[cfg(test)]
fn local_request(helper: &mut Option<Helper>, root: &Path, request: Value) -> Result<Value, String> {
    local_request_progress(helper, root, request, None)
}

fn local_request_progress(helper: &mut Option<Helper>, root: &Path, request: Value, progress: Option<&ui::Task>) -> Result<Value, String> {
    if helper.as_ref().is_some_and(|helper| helper.failed) { helper.take(); }
    if helper.is_none() { *helper = Some(Helper::start(root)?); }
    helper.as_mut().unwrap().request_progress(request, progress)
}

#[derive(Debug, PartialEq)]
enum Action { Same, Push, Pull, Conflict, Ignore }

#[derive(PartialEq)]
pub(super) struct Revision {
    local: String,
    remote: String,
    two_way: bool,
    direction: sync::Direction,
    priority: sync::Priority,
}
fn action(base: Option<&str>, local: Option<&str>, remote: Option<&str>, two_way: bool, priority: sync::Priority) -> Action {
    if local == remote { return Action::Same; }
    if !two_way { return if local == base { Action::Ignore } else { Action::Push }; }
    if local == base { Action::Pull }
    else if remote == base { Action::Push }
    else { match priority { sync::Priority::Local => Action::Push, sync::Priority::Remote => Action::Pull, sync::Priority::KeepBoth => Action::Conflict } }
}

fn directed(action: Action, direction: sync::Direction) -> Action {
    match action {
        Action::Push if !direction.sends() => Action::Ignore,
        Action::Pull if !direction.receives() => Action::Ignore,
        other => other,
    }
}

impl Live {
    pub(super) fn discover_databases(&mut self, manifest: &sync::Manifest) {
        self.database_probes.retain(|path, _| manifest.contains_key(path));
        for (path, stamp) in manifest {
            if stamp.0 >= 16 && self.database_probes.get(path) != Some(stamp) {
                if sync::sqlite_file(&self.folder.join(path)) { self.database_files.insert(path.clone()); }
                self.database_probes.insert(path.clone(), *stamp);
            }
        }
    }
    async fn database_request(&mut self, remote: bool, request: Value, progress: Option<&ui::Task>) -> Result<Value, String> {
        if remote { self.receiver.rpc_progress(request, progress).await }
        else { local_request_progress(&mut self.database_helper, &self.folder, request, progress) }
    }
    async fn rows(&mut self, path: &str, remote: bool, progress: &ui::Task) -> Result<BTreeMap<String, String>, String> {
        let mut rows = BTreeMap::new();
        let mut offset = 0;
        loop {
            let reply = self.database_request(remote, json!({"op":"sqlite-scan","path":path,"offset":offset}), Some(progress)).await?;
            for entry in reply["entries"].as_array().ok_or("Missing SQLite row inventory")? {
                let key = entry[0].as_str().ok_or("Invalid SQLite row key")?;
                let hash = entry[1].as_str().ok_or("Invalid SQLite row checksum")?;
                rows.insert(key.into(), hash.into());
            }
            progress.progress(if remote { "Loading container record inventory" } else { "Loading local record inventory" }, rows.len() as u64, reply["total"].as_u64().unwrap_or(rows.len() as u64), "records");
            match reply["next"].as_u64() { Some(next) if next > offset => offset = next, Some(_) => return Err("Invalid SQLite page".into()), None => break }
        }
        Ok(rows)
    }
    async fn stage_row(&mut self, path: &str, key: &str, source_remote: bool, source: Option<&str>, expected: Option<&str>, progress: &ui::Task) -> Result<(), String> {
        let row = {
            let mut data = Vec::new();
            loop {
                let reply = self.database_request(source_remote, json!({"op":"sqlite-row","path":path,"key":key,"expected":source,"offset":data.len()}), None).await?;
                let chunk = B64.decode(reply["data"].as_str().ok_or("Missing SQLite record")?).map_err(|e| e.to_string())?;
                if chunk.is_empty() && reply["done"] != true { return Err("SQLite transfer made no progress".into()); }
                data.extend(chunk);
                let total = reply["total"].as_u64().unwrap_or(data.len() as u64);
                progress.progress("Reading large database record", data.len() as u64, total, "bytes");
                if reply["done"] == true { break; }
            }
            serde_json::from_slice::<Value>(&data).map_err(|e| e.to_string())?
        };
        let operation = serde_json::to_vec(&json!({"key":key,"row":row,"expected":expected})).map_err(|e| e.to_string())?;
        let chunks = operation.chunks(24 * 1024);
        let count = chunks.len();
        progress.progress("Staging large database record", 0, operation.len() as u64, "bytes");
        for (i, chunk) in chunks.enumerate() {
            self.database_request(!source_remote, json!({"op":"sqlite-stage","path":path,"data":B64.encode(chunk),"done":i+1 == count}), None).await?;
            progress.progress("Staging large database record", ((i + 1) * 24 * 1024).min(operation.len()) as u64, operation.len() as u64, "bytes");
        }
        Ok(())
    }
    async fn stage_rows(&mut self, path: &str, source_remote: bool, entries: &[Value], progress: &ui::Task, completed: &mut u64, total: u64) -> Result<(), String> {
        for batch in entries.chunks(64) {
            let mut offset = 0;
            while offset < batch.len() {
                let reply = self.database_request(source_remote, json!({"op":"sqlite-export","path":path,"entries":batch,"offset":offset}), None).await?;
                let operations = reply["operations"].as_array().ok_or("Missing SQLite export batch")?;
                if !operations.is_empty() {
                    self.database_request(!source_remote, json!({"op":"sqlite-stage-batch","path":path,"operations":operations}), None).await?;
                    *completed += operations.len() as u64;
                }
                let next = reply["next"].as_u64().ok_or("Invalid SQLite export position")? as usize;
                if next < offset || next > batch.len() || next - offset != operations.len() { return Err("Invalid SQLite export position".into()); }
                offset = next;
                if reply.get("large").is_some() {
                    let entry = batch.get(offset).ok_or("Invalid large SQLite record")?;
                    let key = entry[0].as_str().ok_or("Invalid large SQLite record key")?;
                    if reply["large"] != key { return Err("SQLite export returned the wrong record".into()); }
                    self.stage_row(path, key, source_remote, entry[1].as_str(), entry[2].as_str(), progress).await?;
                    offset += 1; *completed += 1;
                } else if operations.is_empty() { return Err("SQLite export made no progress".into()); }
                progress.progress("Transferring database changes", *completed, total, "records");
            }
        }
        Ok(())
    }

    async fn sync_database(&mut self, path: &str, two_way: bool, direction: sync::Direction, progress: &ui::Task) -> Result<usize, String> {
        progress.copy_status("Inspecting database schema");
        let mut local = self.database_request(false, json!({"op":"sqlite-info","path":path}), Some(progress)).await?;
        let mut remote = self.database_request(true, json!({"op":"sqlite-info","path":path}), Some(progress)).await?;
        if local["missing"] == true && remote["missing"] == true { return Ok(0); }
        // Whole-database disappearance may be temporary during an app migration.
        // Never turn it into a destructive recursive delete or recreate silently.
        if self.saved.databases.contains_key(path) && (local["missing"] == true || remote["missing"] == true) {
            return Err("A previously synced database is missing; restore it or resolve its deletion before record sync resumes".into());
        }
        if (local["missing"] == true && (!two_way || !direction.receives()))
            || (remote["missing"] == true && !direction.sends()) { return Ok(0); }
        if local["missing"] == true {
            if !two_way { return Ok(0); }
            local = self.database_request(false, json!({"op":"sqlite-create","path":path,"schema":remote["schema"]}), Some(progress)).await?;
        }
        if remote["missing"] == true {
            remote = self.database_request(true, json!({"op":"sqlite-create","path":path,"schema":local["schema"]}), Some(progress)).await?;
        }
        if local["signature"] != remote["signature"] { return Err("The database schemas differ; run the same app migration on both copies".into()); }
        let revision = local["revision"].as_str().zip(remote["revision"].as_str()).map(|(local, remote)| Revision {
            local: local.into(), remote: remote.into(), two_way, direction, priority: self.priority,
        });
        if revision.as_ref().is_some_and(|version| self.database_versions.get(path) == Some(version))
            && self.saved.databases.contains_key(path) { return Ok(0); }
        progress.copy_status("Reading local database records");
        let local = self.rows(path, false, progress).await?;
        progress.copy_status("Reading container database records");
        // A first bulk import has no app writer yet and its snapshot's checksums
        // are already known. Avoid indexing/transmitting that inventory again.
        let remote = if self.initial_databases.remove(path) {
            self.saved.databases.get(path).cloned().unwrap_or_default()
        } else { self.rows(path, true, progress).await? };
        let base = self.saved.databases.get(path).cloned().unwrap_or_default();
        let mut next = base.clone();
        let keys: BTreeSet<_> = base.keys().chain(local.keys()).chain(remote.keys()).cloned().collect();
        let mut conflicts = 0;
        let mut push = Vec::new();
        let mut pull = Vec::new();
        for key in keys {
            let l = local.get(&key).map(String::as_str);
            let r = remote.get(&key).map(String::as_str);
            let result = match directed(action(base.get(&key).map(String::as_str), l, r, two_way, self.priority), direction) {
                Action::Ignore => continue,
                Action::Conflict => { conflicts += 1; continue; }
                Action::Same => l,
                Action::Push => { push.push(json!([key, l, r])); l }
                Action::Pull => { pull.push(json!([key, r, l])); r }
            };
            if let Some(hash) = result { next.insert(key, hash.into()); } else { next.remove(&key); }
        }
        let total = (push.len() + pull.len()) as u64;
        let mut completed = 0;
        progress.progress("Transferring database changes", 0, total, "records");
        self.stage_rows(path, false, &push, progress, &mut completed, total).await?;
        if two_way { self.stage_rows(path, true, &pull, progress, &mut completed, total).await?; }
        // Each destination validates all expected rows under a write transaction.
        // A crash between destinations is safe to retry: already equal rows converge.
        let pushed = self.database_request(true, json!({"op":"sqlite-apply","path":path}), Some(progress)).await?["count"].as_u64().unwrap_or(0);
        let pulled = if two_way { self.database_request(false, json!({"op":"sqlite-apply","path":path}), Some(progress)).await?["count"].as_u64().unwrap_or(0) } else { 0 };
        if self.saved.databases.get(path) != Some(&next) {
            progress.copy_status("Saving database sync checkpoint");
            let previous = self.saved.databases.insert(path.into(), next);
            if let Err(error) = self.saved.save(&self.state_path) {
                // An unpersisted baseline must stay dirty so the next pass retries
                // the checkpoint, even when the destination already has the rows.
                if let Some(previous) = previous { self.saved.databases.insert(path.into(), previous); }
                else { self.saved.databases.remove(path); }
                return Err(error);
            }
        }
        if let Some(revision) = revision { self.database_versions.insert(path.into(), revision); }
        if conflicts > 0 { ui::warn(&format!("{}: {conflicts} record conflicts kept on both sides; change sync priority to choose a winner", clean(path))); }
        Ok((pushed + pulled) as usize)
    }
    pub(super) async fn sync_databases(&mut self, two_way: bool) -> Result<usize, String> {
        self.sync_databases_direction(two_way, if two_way { sync::Direction::Both } else { sync::Direction::ToContainer }).await
    }

    pub(super) async fn sync_databases_direction(&mut self, two_way: bool, direction: sync::Direction) -> Result<usize, String> {
        let filter = sync::Filter::load(&self.folder, self.env_files)?;
        let filter = if two_way { filter.two_way() } else { filter };
        self.database_files.retain(|p| !filter.excluded(p, false));
        let mut changed = 0;
        let mut errors = Vec::new();
        let paths = self.database_files.clone();
        if paths.is_empty() { return Ok(0); }
        let progress = ui::task("Syncing project databases");
        for (index, path) in paths.iter().enumerate() {
            if two_way {
                // Record writes on this computer follow the same name rules as files.
                if self.is_held(path) { continue; }
                if let Err(error) = two_way::host_target(&self.folder, path) {
                    self.warn_once(format!("Database sync skipped {}: {}", clean(path), clean(&error)));
                    continue;
                }
            }
            self.pump().await?;
            progress.detail(&format!("{} / {} · {}", index + 1, paths.len(), clean(path)));
            match self.sync_database(path, two_way, direction, &progress).await {
                Ok(count) => changed += count,
                Err(error) => {
                    let stopped = self.database_helper.as_ref().is_some_and(|helper| helper.failed);
                    if !stopped { let _ = self.database_request(false, json!({"op":"sqlite-abort"}), None).await; }
                    let _ = self.database_request(true, json!({"op":"sqlite-abort"}), None).await;
                    let message = format!("Database sync paused for {}: {}", clean(&path), clean(&error));
                    if self.conflicts.insert(message.clone()) { ui::warn(&message); }
                    errors.push(message);
                    // All later DBs share this process. Stop once and restart on the
                    // next sync pass, rather than flooding the terminal with pipe errors.
                    if stopped { break; }
                }
            }
        }
        progress.clear();
        if changed > 0 { ui::info(&format!("Synced {changed} database record changes")); }
        if errors.is_empty() { Ok(changed) } else { Err(errors.join("; ")) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_accepts_canonical_project_paths_and_restarts_after_a_crash() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("CRM with spaces");
        fs::create_dir(&root).unwrap();
        // Windows canonicalize returns \\?\ paths, exactly as run_in does.
        let root = root.canonicalize().unwrap();
        let mut helper = None;
        let request = json!({"op":"sqlite-detect","path":"missing.db"});
        assert_eq!(local_request(&mut helper, &root, request.clone()).unwrap()["database"], false);
        helper.as_mut().unwrap().child.kill().unwrap();
        helper.as_mut().unwrap().child.wait().unwrap();
        let error = local_request(&mut helper, &root, request.clone()).unwrap_err();
        assert!(error.contains("Local SQLite helper stopped"), "{error}");
        assert!(helper.as_ref().unwrap().failed);
        assert_eq!(local_request(&mut helper, &root, request).unwrap()["database"], false);
    }

    #[test]
    fn helper_reports_startup_stderr_instead_of_a_generic_pipe_error() {
        let root = tempfile::tempdir().unwrap();
        let mut helper = Helper::start(&root.path().join("missing-project")).unwrap();
        let error = helper.request(json!({"op":"sqlite-detect","path":"missing.db"})).unwrap_err();
        assert!(error.contains("ENOENT"), "{error}");
        assert!(error.contains("missing-project"), "{error}");
        assert!(helper.failed);
    }
    #[test]
    fn mode_and_priority_control_rows_including_deletions() {
        for priority in [sync::Priority::Local, sync::Priority::Remote, sync::Priority::KeepBoth] {
            assert_eq!(action(Some("base"),Some("base"),Some("remote"),false,priority),Action::Ignore);
            assert_eq!(action(Some("base"),Some("local"),Some("remote"),false,priority),Action::Push);
            assert_eq!(action(Some("base"),None,Some("remote"),false,priority),Action::Push);
        }
        assert_eq!(action(Some("base"),Some("local"),Some("remote"),true,sync::Priority::Local),Action::Push);
        assert_eq!(action(Some("base"),Some("local"),None,true,sync::Priority::Remote),Action::Pull);
        assert_eq!(action(None,Some("local"),Some("remote"),true,sync::Priority::KeepBoth),Action::Conflict);
    }

    #[test]
    fn handoffs_defer_the_other_direction_without_consuming_conflicts_or_deletions() {
        for (base, local, remote) in [(Some("base"), Some("local"), Some("base")), (Some("base"), None, Some("base")), (None, Some("new"), None)] {
            let result = action(base, local, remote, true, sync::Priority::Remote);
            assert_eq!(directed(result, sync::Direction::ToComputer), Action::Ignore);
        }
        for (base, local, remote) in [(Some("base"), Some("base"), Some("remote")), (Some("base"), Some("base"), None), (None, None, Some("new"))] {
            let result = action(base, local, remote, true, sync::Priority::Local);
            assert_eq!(directed(result, sync::Direction::ToContainer), Action::Ignore);
        }
        assert_eq!(directed(action(Some("base"),Some("local"),Some("remote"),true,sync::Priority::Remote),sync::Direction::ToContainer), Action::Ignore);
        assert_eq!(directed(action(Some("base"),Some("local"),Some("remote"),true,sync::Priority::Local),sync::Direction::ToComputer), Action::Ignore);
        assert_eq!(directed(Action::Conflict,sync::Direction::ToComputer),Action::Conflict);
        assert_eq!(directed(Action::Same,sync::Direction::ToComputer),Action::Same);
    }
}
