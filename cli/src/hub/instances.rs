//! Instances: one running copy of a template on this computer. Its files live in
//! `~/.yougori/hub/instances/INSTANCE/`, with `instance.json` there for the desktop app (state,
//! addresses, steps; never an answer or a secret). The CLI's own record, which keeps the answers
//! needed to continue or update a run, is `~/.yougori/hub/records/INSTANCE.json`.
use super::{client, scan::{self, Files}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex},
    time::Duration,
};

/// How far one part of a run got.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// pending, done, failed, or step (left for a person).
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Part {
    pub fn done() -> Part {
        Part { status: "done".into(), message: None }
    }
    pub fn pending() -> Part {
        Part { status: "pending".into(), message: None }
    }
    pub fn failed(message: impl Into<String>) -> Part {
        Part { status: "failed".into(), message: Some(message.into()) }
    }
    pub fn step(message: impl Into<String>) -> Part {
        Part { status: "step".into(), message: Some(message.into()) }
    }
    pub fn is(&self, status: &str) -> bool {
        self.status == status
    }
}

/// A public address an instance set up.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub environment: String,
    pub port: u16,
    /// quick, domain or none.
    pub access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub part: Part,
}

/// A step that needs a person, as shown at the end and in status.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// The version an update is moving to, kept apart from the instance's own until it finished.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub version: String,
    pub digest: String,
}

/// What Yougori remembers about an instance. Secret answers are never in it: only the names of
/// the deployment secrets that hold them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub instance: String,
    /// `hub` or `folder`.
    pub origin: String,
    /// `PUBLISHER/NAME` for Hub templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// The template folder for local runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub template: String,
    pub title: String,
    pub version: String,
    pub digest: String,
    pub verified: bool,
    /// The project file inside the instance folder.
    pub project: String,
    #[serde(default)]
    pub answers: BTreeMap<String, String>,
    /// Deployment secrets this instance stored, by name.
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub allow_pc_access: bool,
    #[serde(default)]
    pub without_gpu: bool,
    /// Environment name in the project to its ID.
    #[serde(default)]
    pub environments: BTreeMap<String, String>,
    #[serde(default)]
    pub create: Part,
    /// `ENVIRONMENT/TOOL` to how its installation went.
    #[serde(default)]
    pub tools: BTreeMap<String, Part>,
    #[serde(default)]
    pub public: Vec<Address>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub outputs: Vec<(String, String)>,
    /// Each file written into the instance folder and its SHA-256, to tell edits apart.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub review: Value,
    #[serde(default)]
    pub counted: bool,
    /// creating, ready, incomplete or stopped, as the desktop app shows it.
    #[serde(default)]
    pub phase: String,
    /// Each environment name to its sandbox's real name in the engine (a replaced sandbox gets a
    /// new one).
    #[serde(default)]
    pub names: BTreeMap<String, String>,
    /// Every environment name the instance ever had, so every sandbox it made can be found.
    #[serde(default)]
    pub keys: BTreeSet<String>,
    /// The engine's project keys its sandboxes were made under.
    #[serde(default)]
    pub project_keys: BTreeSet<String>,
    /// An update that has not finished yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updating: Option<Target>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

impl State {
    /// Whether every part finished.
    pub fn complete(&self) -> bool {
        self.create.is("done")
            && self.tools.values().all(|part| !part.is("failed") && !part.is("pending"))
            && self.public.iter().all(|address| !address.part.is("failed") && !address.part.is("pending"))
    }
    /// The first part that did not finish as the desktop app names it (environments, tools or
    /// public), and why.
    pub fn failed_part(&self) -> Option<(&'static str, String)> {
        let message = |part: &Part| part.message.clone().unwrap_or_else(|| "It did not finish.".into());
        if !self.create.is("done") {
            return Some(("environments", message(&self.create)));
        }
        if let Some(part) = self.tools.values().find(|part| part.is("failed") || part.is("pending")) {
            return Some(("tools", message(part)));
        }
        self.public.iter().find(|a| a.part.is("failed") || a.part.is("pending")).map(|a| ("public", message(&a.part)))
    }
    /// The first part that did not finish, and why.
    pub fn failed(&self) -> Option<(String, String)> {
        if !self.create.is("done") {
            return Some(("creating the sandboxes".into(), self.create.message.clone().unwrap_or_else(|| "It did not finish.".into())));
        }
        if let Some((key, part)) = self.tools.iter().find(|(_, part)| part.is("failed") || part.is("pending")) {
            let (environment, tool) = key.split_once('/').unwrap_or((key, ""));
            return Some((format!("installing {tool} in {}-{environment}", self.instance), part.message.clone().unwrap_or_else(|| "It did not finish.".into())));
        }
        self.public.iter().find(|a| a.part.is("failed") || a.part.is("pending"))
            .map(|a| (format!("public access for {}-{}", self.instance, a.environment), a.part.message.clone().unwrap_or_else(|| "It did not finish.".into())))
    }
    /// How the template is named in commands: `hub/PUBLISHER/NAME@VERSION` or the folder.
    pub fn source(&self) -> String {
        match (&self.item, &self.path) {
            (Some(item), _) => format!("hub/{item}@{}", self.version),
            (None, Some(path)) => quote(path),
            _ => self.template.clone(),
        }
    }
    /// The one command that continues or finishes this instance, whatever stopped it.
    pub fn continue_command(&self) -> String {
        format!("yougori template continue {}", self.instance)
    }
    /// ready, incomplete, creating or stopped.
    pub fn status_word(&self) -> &'static str {
        match self.phase.as_str() {
            "stopped" => "stopped",
            "creating" => "creating",
            _ if self.updating.is_none() && self.complete() => "ready",
            _ => "incomplete",
        }
    }
    pub fn remove_command(&self) -> String {
        format!("yougori template rm {} --yes", self.instance)
    }
}

/// A path in a command a person copies: as it is when nothing in it needs quoting, otherwise in
/// the quotes this computer's shell reads (double quotes on Windows).
pub fn quote(path: &str) -> String {
    let plain = !path.is_empty() && path.chars().all(|c| c.is_alphanumeric() || "-_./:\\".contains(c));
    if plain {
        path.to_owned()
    } else if cfg!(windows) {
        format!("\"{}\"", path.replace('"', ""))
    } else {
        shell_words::quote(path).into_owned()
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// An instance name: lowercase letters, digits, - or _, starting with a letter or digit, at most
/// 40 characters, as a project name allows.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub const NAME_RULE: &str = "lowercase letters, digits, - or _, starting with a letter or digit, at most 40 characters";

/// The longest instance name that keeps every `INSTANCE-ENVIRONMENT` within 80 characters.
fn longest(environments: &[String]) -> usize {
    let key = environments.iter().map(String::len).max().unwrap_or(0);
    40.min(79usize.saturating_sub(key)).max(1)
}

/// The first free name: `NAME`, then `NAME-2`, `NAME-3` … A name is free when no instance has
/// it and no environment called `NAME-ENVIRONMENT` exists yet (names compare without case).
pub fn available(base: &str, environments: &[String], instances: &BTreeSet<String>, taken: &BTreeSet<String>) -> String {
    let limit = longest(environments);
    let clean: String = base.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect::<String>().to_ascii_lowercase();
    let clean = clean.trim_start_matches(['-', '_']).to_owned();
    let clean = if clean.is_empty() { "template".to_owned() } else { clean };
    for n in 1u32.. {
        let suffix = if n == 1 { String::new() } else { format!("-{n}") };
        let stem: String = clean.chars().take(limit.saturating_sub(suffix.len()).max(1)).collect();
        let name = format!("{}{suffix}", stem.trim_end_matches(['-', '_']));
        let free = !instances.contains(&name)
            && environments.iter().all(|environment| !taken.contains(&format!("{name}-{environment}").to_lowercase()));
        if free && valid_name(&name) {
            return name;
        }
    }
    unreachable!("names are endless")
}

/// Why `name` cannot hold this template's environments, or nothing.
pub fn name_problem(name: &str, environments: &[String]) -> Option<String> {
    if !valid_name(name) {
        return Some(format!("{} is not an instance name: use {NAME_RULE}.", scan::shown(name)));
    }
    let limit = longest(environments);
    (name.len() > limit).then(|| format!("{name} is too long for this template's environment names; use at most {limit} characters."))
}

/// What the desktop app reads from `instance.json`: no secrets, and input values only where the
/// template's own steps and outputs show them. `next` always continues or finishes the instance.
pub fn app_view(state: &State) -> Value {
    let phase = state.status_word();
    let failed = (phase == "incomplete")
        .then(|| state.failed_part().or_else(|| state.updating.as_ref().map(|target| ("update", format!("The update to {} did not finish.", target.version)))))
        .flatten()
        .map(|(part, message)| serde_json::json!({"part": part, "message": message, "next": state.continue_command()}));
    let public: serde_json::Map<String, Value> = state.public.iter().filter_map(|a| a.url.clone().map(|url| (a.environment.clone(), Value::String(url)))).collect();
    serde_json::json!({
        "schema": 1,
        "name": state.instance,
        "ref": state.item,
        "source": if state.origin == "hub" { "hub" } else { "local" },
        "folder": if state.origin == "hub" { None } else { state.path.clone() },
        "kind": "template",
        "title": state.title,
        "version": state.version,
        "digest": state.digest,
        "verified": state.verified,
        "state": phase,
        "failed": failed,
        "createdAt": state.created_at,
        "updatedAt": state.updated_at,
        "environments": state.environments,
        "public": public,
        "steps": state.steps.iter().map(|s| serde_json::json!({"title": s.title, "detail": s.detail, "command": s.command})).collect::<Vec<_>>(),
        "outputs": state.outputs.iter().map(|(label, value)| serde_json::json!({"label": label, "value": value})).collect::<Vec<_>>(),
        "inputs": state.answers.keys().chain(state.secrets.iter().filter(|id| !id.starts_with("tool."))).collect::<Vec<_>>(),
        "next": state.continue_command(),
    })
}

/// The instance this command works on, as last saved: what Ctrl+C left behind, and what the
/// heartbeat keeps fresh.
static CURRENT: Mutex<Option<State>> = Mutex::new(None);
/// One writer of `instance.json` at a time: a save or the heartbeat.
static WRITING: Mutex<()> = Mutex::new(());

pub fn current() -> Option<State> {
    CURRENT.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

pub fn clear_current() {
    *CURRENT.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

fn write_view(folder: &Path, state: &State) -> Result<(), String> {
    let _writing = WRITING.lock().unwrap_or_else(|p| p.into_inner());
    write_atomically(&folder.join("instance.json"), &serde_json::to_vec_pretty(&app_view(state)).map_err(|e| e.to_string())?)
}

/// Holds an instance while a command changes it. Another command finds it held and waits for
/// nothing: it says so. While held, a heartbeat rewrites `instance.json`'s `updatedAt` every 30
/// seconds, so the app can tell a run that stopped (a stale `creating`) from one still working.
pub struct Lock {
    _file: std::fs::File,
    stop: Option<Arc<AtomicBool>>,
}

impl Lock {
    pub fn heartbeat(&mut self, folder: PathBuf) {
        if self.stop.is_some() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.stop = Some(stop.clone());
        std::thread::spawn(move || {
            let mut ticks = 0u32;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(1));
                ticks += 1;
                if !ticks.is_multiple_of(30) || stop.load(Ordering::Relaxed) {
                    continue;
                }
                if let Some(mut state) = current() {
                    state.updated_at = now();
                    let _ = write_view(&folder, &state);
                }
            }
        });
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Writes `bytes` to `path` through a temporary file in the same folder and a rename.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid record path")?;
    std::fs::create_dir_all(folder).map_err(|e| format!("Cannot save the instance record: {e}"))?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|e| format!("Cannot save the instance record: {e}"))?;
    std::io::Write::write_all(&mut file, bytes).map_err(|e| format!("Cannot save the instance record: {e}"))?;
    file.persist(path).map_err(|e| format!("Cannot save the instance record: {}", e.error))?;
    Ok(())
}

/// Where instances live.
#[derive(Clone, Debug)]
pub struct Instances {
    pub root: PathBuf,
}

impl Instances {
    pub fn standard() -> Result<Instances, String> {
        Ok(Instances { root: client::home()?.join("hub").join("instances") })
    }
    pub fn folder(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    /// The engine's key for an instance's project, worked out from where its project file is (or
    /// was), so it is known even after the instance's folder is gone. It is the only thing that
    /// ties a sandbox to this instance: a sandbox of another project with a matching name is never
    /// this instance's.
    pub fn project_key(&self, name: &str, project: &str) -> Option<String> {
        let mut file = self.folder(name);
        for part in (if project.is_empty() { "yougori.yaml" } else { project }).split('/') {
            file.push(part);
        }
        // The nearest folder that exists, canonical as the engine sees it, then the rest as named.
        let mut rest = Vec::new();
        let mut existing = file.as_path();
        let canonical = loop {
            if let Ok(path) = std::fs::canonicalize(existing) {
                break path;
            }
            rest.push(existing.file_name()?.to_owned());
            existing = existing.parent()?;
        };
        let full = rest.iter().rev().fold(canonical, |path, part| path.join(part));
        Some(scan::sha256_hex(full.to_string_lossy().as_bytes()))
    }
    fn records(&self) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).join("records")
    }
    fn record(&self, name: &str) -> PathBuf {
        self.records().join(format!("{name}.json"))
    }
    pub fn backups(&self, name: &str) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).join("backups").join(name)
    }
    fn lock_file(&self, name: &str) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).join("locks").join(format!("{name}.lock"))
    }
    /// Holds `name` for this command, or says another command is changing it right now.
    pub fn lock(&self, name: &str) -> Result<Lock, String> {
        let path = self.lock_file(name);
        std::fs::create_dir_all(path.parent().unwrap_or(&self.root)).map_err(|e| format!("Cannot hold {name}: {e}"))?;
        let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path).map_err(|e| format!("Cannot hold {name}: {e}"))?;
        match file.try_lock() {
            Ok(()) => Ok(Lock { _file: file, stop: None }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!("{name} is being changed by another yougori command right now. Wait for it to finish, then try again.")),
            Err(std::fs::TryLockError::Error(e)) => Err(format!("Cannot hold {name}: {e}")),
        }
    }
    /// Whether a command holds `name` right now.
    pub fn busy(&self, name: &str) -> bool {
        let Ok(file) = std::fs::OpenOptions::new().write(true).open(self.lock_file(name)) else { return false };
        match file.try_lock() {
            Ok(()) => {
                let _ = file.unlock();
                false
            }
            Err(std::fs::TryLockError::WouldBlock) => true,
            Err(_) => false,
        }
    }
    /// The record of `name`. A run that stopped without saying so (the window was closed) is
    /// still `creating` but nothing holds it: it reads, and is saved, as incomplete.
    pub fn load(&self, name: &str) -> Result<Option<State>, String> {
        if !valid_name(name) {
            return Ok(None);
        }
        let mut state: State = match std::fs::read(self.record(name)) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("The record of {name} cannot be read ({e}). Remove the instance with yougori template rm {name} --yes."))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("Cannot read the record of {name}: {e}")),
        };
        if state.project_keys.is_empty() {
            state.project_keys.extend(self.project_key(name, &state.project));
        }
        if state.phase == "creating" && !self.busy(name) {
            state.phase = "incomplete".into();
            let _ = self.save_quietly(&mut state);
        }
        Ok(Some(state))
    }
    /// Loads an instance that must exist.
    pub fn get(&self, name: &str) -> Result<State, String> {
        self.load(name)?.ok_or_else(|| {
            let known: Vec<String> = self.list().into_iter().map(|state| state.instance).collect();
            if known.is_empty() {
                format!("There is no instance named {}. Run a template with yougori run hub/PUBLISHER/NAME.", scan::shown(name))
            } else {
                format!("There is no instance named {}. Instances: {}.", scan::shown(name), known.join(", "))
            }
        })
    }
    /// Saves the record and the desktop app's `instance.json`, each atomically, and remembers it
    /// as the instance this command works on.
    pub fn save(&self, state: &mut State) -> Result<(), String> {
        self.save_quietly(state)?;
        *CURRENT.lock().unwrap_or_else(|p| p.into_inner()) = Some(state.clone());
        Ok(())
    }
    /// [`Instances::save`] without making it this command's instance.
    pub fn save_quietly(&self, state: &mut State) -> Result<(), String> {
        state.updated_at = now();
        if state.created_at == 0 {
            state.created_at = state.updated_at;
        }
        write_atomically(&self.record(&state.instance), &serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?)?;
        write_view(&self.folder(&state.instance), state)
    }
    /// The names of instances with a record, readable or not.
    pub fn recorded(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.records()).into_iter().flatten().flatten()
            .filter_map(|entry| entry.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_owned))
            .filter(|name| valid_name(name))
            .collect();
        names.sort();
        names
    }
    pub fn forget(&self, name: &str) -> Result<(), String> {
        match std::fs::remove_file(self.record(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Cannot remove the record of {name}: {e}")),
        }
    }
    pub fn list(&self) -> Vec<State> {
        self.recorded().into_iter().filter_map(|name| self.load(&name).ok().flatten()).collect()
    }
    /// Names in use, lowercase: records and folders alike.
    pub fn names(&self) -> BTreeSet<String> {
        let folders = std::fs::read_dir(&self.root).into_iter().flatten().flatten().filter_map(|entry| entry.file_name().to_str().map(str::to_ascii_lowercase));
        let records = std::fs::read_dir(self.records()).into_iter().flatten().flatten().filter_map(|entry| entry.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_ascii_lowercase));
        folders.chain(records).filter(|name| !name.starts_with('.')).collect()
    }
}

/// One of an instance's sandboxes as the engine has it now.
#[derive(Clone, Debug, PartialEq)]
pub struct Sandbox {
    /// The environment's name in the template.
    pub key: String,
    pub id: String,
    pub name: String,
    /// An update replaced it; the engine keeps it, stopped, with its data.
    pub replaced: bool,
}

/// The engine's key for a project file: the SHA-256 of its full path, as the engine writes it in
/// each sandbox's description (`Yougori project KEY / NAME`).
pub fn project_key(project_file: &Path) -> Option<String> {
    std::fs::canonicalize(project_file).ok().map(|path| scan::sha256_hex(path.to_string_lossy().as_bytes()))
}

/// Every sandbox the engine holds for this instance: the ones it runs, the ones an update
/// replaced (`INSTANCE-NAME-replaced-…`) and the ones a newer version no longer lists (stopped
/// and kept). The engine marks each sandbox with its project's key, and that mark alone decides:
/// a sandbox of another project is never taken for this instance's, whatever its name.
pub fn sandboxes(state: &State, live: &Value) -> Vec<Sandbox> {
    let mut found = Vec::new();
    for environment in live["environments"].as_array().into_iter().flatten() {
        let (Some(id), Some(name), Some(description)) = (environment["id"].as_str(), environment["name"].as_str(), environment["description"].as_str()) else { continue };
        let Some((project, owner)) = description.strip_prefix("Yougori project ").and_then(|rest| rest.split_once(" / ")) else { continue };
        if !state.project_keys.contains(project) {
            continue;
        }
        let (key, replaced) = match owner.strip_suffix(" (replaced)") {
            Some(key) => (key, true),
            None => (owner, false),
        };
        found.push(Sandbox { key: key.to_owned(), id: id.to_owned(), name: name.to_owned(), replaced });
    }
    found
}

/// A sandbox that changed (replaced or made again) has none of its tools or public access yet.
pub fn reset_environment(state: &mut State, key: &str) {
    let prefix = format!("{key}/");
    for (tool, part) in state.tools.iter_mut() {
        if tool.starts_with(&prefix) {
            *part = Part::pending();
        }
    }
    for address in state.public.iter_mut().filter(|a| a.environment == key) {
        address.part = Part::pending();
        address.url = None;
    }
}

/// Writes a version's files into an instance folder, then the generated project in place of the
/// template's own, and returns what each file hashes to.
pub fn write(folder: &Path, files: &Files, project_path: &str, project: &str) -> Result<BTreeMap<String, String>, String> {
    std::fs::create_dir_all(folder).map_err(|e| format!("Cannot create the instance folder {}: {e}", folder.display()))?;
    let mut all = files.clone();
    all.insert(project_path.to_owned(), project.as_bytes().to_vec());
    client::write_files(folder, &all)?;
    Ok(all.iter().map(|(path, bytes)| (path.clone(), scan::sha256_hex(bytes))).collect())
}

/// Files the person changed or removed since they were written, by comparing hashes.
pub fn changed(folder: &Path, written: &BTreeMap<String, String>) -> (Vec<String>, Vec<String>) {
    let (mut edited, mut removed) = (Vec::new(), Vec::new());
    for (path, sha) in written {
        match std::fs::read(folder.join(path)) {
            Ok(bytes) if &scan::sha256_hex(&bytes) != sha => edited.push(path.clone()),
            Ok(_) => {}
            Err(_) => removed.push(path.clone()),
        }
    }
    (edited, removed)
}

/// Copies changed files into `backup`, keeping their paths.
pub fn back_up(folder: &Path, paths: &[String], backup: &Path) -> Result<(), String> {
    for path in paths {
        let target = backup.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Cannot back up {path}: {e}"))?;
        }
        std::fs::copy(folder.join(path), &target).map_err(|e| format!("Cannot back up {path}: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_numbered_and_fit_the_environment_names() {
        let envs = vec!["web".to_owned(), "db".to_owned()];
        let none = BTreeSet::new();
        assert_eq!(available("my-api", &envs, &none, &none), "my-api");
        let instances: BTreeSet<String> = ["my-api".to_owned()].into();
        assert_eq!(available("my-api", &envs, &instances, &none), "my-api-2");
        let taken: BTreeSet<String> = ["my-api-2-web".to_owned()].into();
        assert_eq!(available("my-api", &envs, &instances, &taken), "my-api-3", "an environment of that name elsewhere takes the name too");
        let long = "a".repeat(64);
        let name = available(&long, &envs, &none, &none);
        assert_eq!(name.len(), 40);
        let wide = vec!["e".repeat(60)];
        let name = available(&long, &wide, &none, &none);
        assert_eq!(name.len(), 19);
        assert!(name.len() + 1 + 60 <= 80);
        let mut used = BTreeSet::new();
        used.insert(name.clone());
        let second = available(&long, &wide, &used, &none);
        assert_eq!(second, format!("{}-2", "a".repeat(17)));
        assert_eq!(available("My_Site!", &envs, &none, &none), "my_site");
        assert_eq!(available("--", &envs, &none, &none), "template");
    }

    #[test]
    fn name_problems_are_plain() {
        let envs = vec!["web".to_owned()];
        assert!(name_problem("shop", &envs).is_none());
        assert!(name_problem("Shop", &envs).unwrap().contains("not an instance name"));
        assert!(name_problem(&"a".repeat(41), &envs).unwrap().contains("not an instance name"));
        assert!(name_problem(&"a".repeat(30), &["e".repeat(60)]).unwrap().contains("at most 19 characters"));
    }

    #[test]
    fn records_round_trip_and_edits_are_found() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = State { instance: "shop".into(), origin: "hub".into(), item: Some("acme/shop".into()), version: "1.0.0".into(), project: "yougori.yaml".into(), ..Default::default() };
        state.create = Part::done();
        state.tools.insert("web/codex".into(), Part::failed("codex did not install"));
        instances.save(&mut state).unwrap();
        let loaded = instances.get("shop").unwrap();
        assert_eq!(loaded.item.as_deref(), Some("acme/shop"));
        assert!(!loaded.complete());
        assert_eq!(loaded.failed().unwrap().0, "installing codex in shop-web");
        assert_eq!(loaded.continue_command(), "yougori template continue shop");
        assert_eq!(loaded.source(), "hub/acme/shop@1.0.0");
        assert!(instances.get("nope").unwrap_err().contains("Instances: shop"));
        let files: Files = [("site/index.html".to_owned(), b"<h1>hi</h1>".to_vec()), ("yougori.yaml".to_owned(), b"raw".to_vec())].into();
        let folder = instances.folder("shop");
        let written = write(&folder, &files, "yougori.yaml", "project: shop\n").unwrap();
        assert_eq!(std::fs::read_to_string(folder.join("yougori.yaml")).unwrap(), "project: shop\n", "the generated project replaces the template's");
        assert_eq!(changed(&folder, &written), (vec![], vec![]));
        std::fs::write(folder.join("site/index.html"), "<h1>mine</h1>").unwrap();
        std::fs::remove_file(folder.join("yougori.yaml")).unwrap();
        let (edited, removed) = changed(&folder, &written);
        assert_eq!(edited, ["site/index.html"]);
        assert_eq!(removed, ["yougori.yaml"]);
        let backup = instances.backups("shop").join("1");
        back_up(&folder, &edited, &backup).unwrap();
        assert_eq!(std::fs::read_to_string(backup.join("site/index.html")).unwrap(), "<h1>mine</h1>");
        assert!(instances.names().contains("shop"));
        instances.forget("shop").unwrap();
        assert!(instances.load("shop").unwrap().is_none());
    }

    #[test]
    fn the_desktop_app_reads_instance_json_without_answers_or_secrets() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = State {
            instance: "shop".into(), origin: "folder".into(), path: Some("C:/templates/shop".into()), template: "shop".into(), title: "Shop".into(),
            version: "1.0.0".into(), digest: "a".repeat(64), project: "yougori.yaml".into(),
            answers: [("admin_email".to_owned(), "owner@example.com".to_owned())].into(), secrets: vec!["openai_key".into()],
            environments: [("web".to_owned(), "env-1".to_owned())].into(), create: Part::done(), phase: "incomplete".into(), ..Default::default()
        };
        state.public.push(Address { environment: "web".into(), port: 3000, access: "quick".into(), url: Some("https://a.trycloudflare.com".into()), part: Part::done(), domain: None });
        state.tools.insert("web/aider".into(), Part::failed("aider did not install in shop-web."));
        state.steps.push(Step { title: "Sign in".into(), detail: None, command: Some("yougori terminal shop-web".into()) });
        instances.save(&mut state).unwrap();
        let text = std::fs::read_to_string(instances.folder("shop").join("instance.json")).unwrap();
        assert!(!text.contains("owner@example.com"), "no input values");
        let view: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(view["schema"], 1);
        assert_eq!(view["name"], "shop");
        assert_eq!(view["ref"], Value::Null);
        assert_eq!(view["source"], "local");
        assert_eq!(view["folder"], "C:/templates/shop");
        assert_eq!(view["kind"], "template");
        assert_eq!(view["state"], "incomplete");
        assert_eq!(view["failed"]["part"], "tools");
        assert_eq!(view["failed"]["next"], "yougori template continue shop");
        assert_eq!(view["next"], "yougori template continue shop");
        assert_eq!(view["environments"], serde_json::json!({"web": "env-1"}));
        assert_eq!(view["public"], serde_json::json!({"web": "https://a.trycloudflare.com"}));
        assert_eq!(view["steps"], serde_json::json!([{"title": "Sign in", "detail": null, "command": "yougori terminal shop-web"}]));
        assert_eq!(view["inputs"], serde_json::json!(["admin_email", "openai_key"]));
        assert!(view["createdAt"].as_u64().unwrap() > 0 && view["updatedAt"].as_u64().unwrap() >= view["createdAt"].as_u64().unwrap());
        state.phase = "ready".into();
        state.tools.clear();
        assert_eq!(app_view(&state)["failed"], Value::Null);
        assert_eq!(app_view(&state)["next"], "yougori template continue shop", "next is there whatever the state");
        state.phase = "stopped".into();
        assert_eq!(app_view(&state)["state"], "stopped");
        state.phase = String::new();
        state.updating = Some(Target { version: "2.0.0".into(), digest: "b".repeat(64) });
        assert_eq!(app_view(&state)["state"], "incomplete", "an unfinished update is not ready");
        assert_eq!(app_view(&state)["failed"]["part"], "update");
    }

    #[test]
    fn a_run_that_stopped_without_saying_so_reads_as_incomplete_and_two_runs_never_overlap() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = State { instance: "shop".into(), origin: "hub".into(), create: Part::pending(), phase: "creating".into(), ..Default::default() };
        {
            let mut held = instances.lock("shop").unwrap();
            held.heartbeat(instances.folder("shop"));
            instances.save(&mut state).unwrap();
            assert!(instances.busy("shop"));
            assert!(instances.lock("shop").err().unwrap().contains("being changed by another yougori command"));
            assert_eq!(instances.load("shop").unwrap().unwrap().phase, "creating", "a held run is still creating");
        }
        assert!(!instances.busy("shop"));
        let stale = instances.load("shop").unwrap().unwrap();
        assert_eq!(stale.phase, "incomplete");
        let view: Value = serde_json::from_slice(&std::fs::read(instances.folder("shop").join("instance.json")).unwrap()).unwrap();
        assert_eq!(view["state"], "incomplete");
        assert_eq!(view["failed"]["next"], "yougori template continue shop");
        assert!(instances.lock("shop").is_ok());
    }

    #[test]
    fn every_sandbox_an_update_replaced_or_dropped_is_found() {
        let mut state = State { instance: "shop".into(), ..Default::default() };
        state.environments.insert("web".into(), "env-new".into());
        state.keys.insert("old".into());
        state.project_keys.insert("k1".into());
        let live = serde_json::json!({"environments": [
            {"id": "env-new", "name": "shop-web-1a2b3c", "description": "Yougori project k1 / web"},
            {"id": "env-was", "name": "shop-web-replaced-9f8e7d", "description": "Yougori project k1 / web (replaced)"},
            {"id": "env-old", "name": "shop-old", "description": "Yougori project k1 / old"},
            {"id": "env-other", "name": "shop-web", "description": "Yougori project k2 / web"},
            {"id": "env-hand", "name": "shop-web", "description": "Made by hand"},
        ]});
        let found = sandboxes(&state, &live);
        assert_eq!(found.iter().map(|s| (s.id.as_str(), s.key.as_str(), s.replaced)).collect::<Vec<_>>(), [("env-new", "web", false), ("env-was", "web", true), ("env-old", "old", false)]);
        state.project_keys.clear();
        assert!(sandboxes(&state, &live).is_empty(), "a name alone never makes a sandbox this instance's");
        state.tools.insert("web/aider".into(), Part::done());
        state.tools.insert("webapp/aider".into(), Part::done());
        state.public.push(Address { environment: "web".into(), port: 80, access: "quick".into(), url: Some("https://x".into()), part: Part::done(), domain: None });
        reset_environment(&mut state, "web");
        assert!(state.tools["web/aider"].is("pending") && state.tools["webapp/aider"].is("done"));
        assert!(state.public[0].part.is("pending") && state.public[0].url.is_none());
    }

    #[test]
    fn the_project_key_is_known_with_or_without_the_instance_folder() {
        let home = tempfile::tempdir().unwrap();
        let instances = Instances { root: home.path().join("hub").join("instances") };
        let before = instances.project_key("shop", "").unwrap();
        std::fs::create_dir_all(instances.folder("shop")).unwrap();
        std::fs::write(instances.folder("shop").join("yougori.yaml"), "project: shop\n").unwrap();
        assert_eq!(project_key(&instances.folder("shop").join("yougori.yaml")).unwrap(), before, "the engine's key for the file");
        assert_eq!(instances.project_key("shop", "yougori.yaml").unwrap(), before);
        std::fs::create_dir_all(instances.folder("shop").join("app")).unwrap();
        std::fs::write(instances.folder("shop").join("app").join("yougori.yaml"), "project: shop\n").unwrap();
        assert_eq!(instances.project_key("shop", "app/yougori.yaml"), project_key(&instances.folder("shop").join("app").join("yougori.yaml")));
        assert_ne!(instances.project_key("shop-2", "").unwrap(), before);
    }

    #[test]
    fn copied_commands_quote_paths_for_this_computers_shell() {
        assert_eq!(quote("C:\\Templates\\shop"), "C:\\Templates\\shop");
        let spaced = quote("C:\\My Templates\\shop");
        if cfg!(windows) {
            assert_eq!(spaced, "\"C:\\My Templates\\shop\"");
        } else {
            assert_eq!(spaced, "'C:\\My Templates\\shop'");
        }
    }
}
