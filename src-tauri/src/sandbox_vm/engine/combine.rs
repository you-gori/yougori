//! Combining two compatible VM sandboxes into one (the owner's requested feature: one real VM
//! holding both workloads and their data, not a group in a list; not a migration).
//!
//! - **preview** compares the two sandboxes as they run: the guest's own OS identity read inside
//!   each guest (`/etc/os-release`, `uname -m`, `uname -r`), their images, the CPU and memory
//!   they reserve, their workspaces file by file, the services, connection endpoints and routes
//!   they declared, and the host-file grants they hold. It shows the combined VM those make (the
//!   sum of both allocations, with GPU access preserved when requested), every conflict
//!   that needs the owner's decision, whether the host can admit the result once both originals
//!   release theirs, and what is not carried. It changes nothing, and names itself by a digest.
//! - **start** applies exactly the previewed combination (the digest must still match) with the
//!   owner's decisions: both guests lose their workspace (no more writes), each original's
//!   staged files are copied (and checked) into the combined workspace, both originals stop
//!   (their reservations end before the combined VM reserves, so nothing is charged twice), the
//!   combined VM boots with the merged settings, and its workspace is checked file by file
//!   inside the guest. The originals' workspaces and settings are kept: if the combined VM
//!   fails, it is stopped and each original is launched again from its own settings.
//! - **finish** removes the originals' workspaces only when the owner says so, after a healthy
//!   combine; one-time grants and pending requests never carry over, and a lasting grant reaches
//!   the combined VM only when the owner adopts it explicitly.
//!
//! VM sandboxes boot once (task VMs): processes, the image root in guest memory and files outside
//! the workspace are not carried, and the preview says so. Each operation is journaled under
//! `combine/<operation>/`; a start the engine's end cut short is reported at the next start with
//! the data it left and the settings that launch each original again.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::{
    blocking, connection_endpoints, launch_from, published_ports, string, Production,
    GUEST_WORKSPACE, LEAST_LAUNCH_MEMORY_BYTES, MAX_LAUNCH_MEMORY_BYTES,
};
use crate::foundation::events::write_atomic;
use crate::foundation::ids::ExecutionId;
use crate::foundation::coordination::SandboxState;
use crate::sandbox::vm_service::{ExecRequest, SandboxId};
use crate::AppHandle;

/// The launch settings kept beside each running VM (`record_launch`).
pub(super) const LAUNCHES_DIRECTORY: &str = "launches";
const COMBINE_DIRECTORY: &str = "combine";
const JOURNAL: &str = "journal.json";
/// What one source workspace may hold, as the workspace store bounds it.
const MAX_FILES: usize = crate::sandbox_vm::workspace::MAX_FILES;
const MAX_TOTAL_BYTES: u64 = crate::sandbox_vm::workspace::MAX_TOTAL_BYTES;
const GIB: f64 = (1u64 << 30) as f64;

fn data_dir(production: &Production) -> Result<PathBuf, String> {
    production
        .state_file
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "The sandbox data folder is unknown.".to_owned())
}

fn live(production: &Production) -> BTreeSet<String> {
    production
        .service
        .status()
        .into_iter()
        .filter(|row| row.state.is_some_and(SandboxState::holds_authority))
        .map(|row| row.sandbox.execution().as_str().to_owned())
        .collect()
}

/// Launch settings are kept only while their VM runs (a combine journals what it needs).
pub(super) fn prune_launches(production: &Production) {
    let Ok(data) = data_dir(production) else { return };
    let Ok(entries) = fs::read_dir(data.join(LAUNCHES_DIRECTORY)) else { return };
    let running = live(production);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_suffix(".json") {
            if !running.contains(id) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

pub(super) fn launch_params(production: &Production, id: &SandboxId) -> Result<Value, String> {
    let path = data_dir(production)?
        .join(LAUNCHES_DIRECTORY)
        .join(format!("{}.json", id.execution().as_str()));
    let bytes = fs::read(&path).map_err(|_| {
        format!("{id} has no launch settings kept: only sandboxes launched directly (not by a template or a remote bootstrap) since this version can be combined")
    })?;
    let record: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok(record["params"].clone())
}

/// The guest's own OS identity, read inside it (an image VM's terminal runs in its image root).
fn guest_identity(production: &Production, id: &SandboxId) -> Result<BTreeMap<String, String>, String> {
    let script = "cat /etc/os-release 2>/dev/null; echo \"machine=$(uname -m)\"; echo \"kernel=$(uname -r)\"";
    let outcome = production
        .service
        .exec(id, ExecRequest::new(script.as_bytes().to_vec(), 16 << 10, std::time::Duration::from_secs(20)))
        .map_err(|e| format!("The OS of {id} could not be read inside it: {e}"))?;
    let text = String::from_utf8_lossy(outcome.output.as_bytes()).into_owned();
    let mut identity = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if matches!(key, "ID" | "VERSION_ID" | "PRETTY_NAME" | "machine" | "kernel") {
                identity.insert(key.to_owned(), value.trim().trim_matches('"').to_owned());
            }
        }
    }
    if !identity.contains_key("machine") || !identity.contains_key("ID") {
        return Err(format!("The OS of {id} did not identify itself (no os-release or uname)."));
    }
    Ok(identity)
}

/// Every regular file under `root` with its SHA-256 and size, bounded as a workspace is.
fn files_of(root: &Path) -> Result<BTreeMap<String, (String, u64)>, String> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = pending.pop() {
        for entry in fs::read_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if kind.is_dir() {
                pending.push((entry.path(), relative));
            } else if kind.is_file() {
                let mut file = fs::File::open(entry.path()).map_err(|e| e.to_string())?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0u8; 1 << 20];
                let mut size = 0u64;
                loop {
                    let read = file.read(&mut buffer).map_err(|e| e.to_string())?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                    size += read as u64;
                }
                total += size;
                files.insert(relative, (hex::encode(hasher.finalize()), size));
                if files.len() > MAX_FILES || total > MAX_TOTAL_BYTES {
                    return Err(format!("{} holds more than a workspace may.", root.display()));
                }
            }
        }
    }
    Ok(files)
}

fn copy_tree(files: &BTreeMap<String, (String, u64)>, from: &Path, to: &Path, prefix: &str) -> Result<(), String> {
    for (name, (hash, _)) in files {
        let target = if prefix.is_empty() { to.join(name) } else { to.join(prefix).join(name) };
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(from.join(name), &target).map_err(|e| format!("{name}: {e}"))?;
        let copied = hex::encode(Sha256::digest(fs::read(&target).map_err(|e| e.to_string())?));
        if &copied != hash {
            return Err(format!("{name} changed while it was copied; the combine stopped before any original did."));
        }
    }
    Ok(())
}

/// One source as the preview reads it.
struct Source {
    id: SandboxId,
    params: Value,
    os: BTreeMap<String, String>,
    memory_bytes: u64,
    cpus: u64,
    staging: Option<PathBuf>,
    folder: Option<String>,
    files: BTreeMap<String, (String, u64)>,
    grants: Vec<Value>,
    one_time: usize,
    pending: usize,
}

fn source(production: &Production, id: &SandboxId) -> Result<Source, String> {
    let status = production
        .service
        .status()
        .into_iter()
        .find(|row| row.sandbox == *id)
        .ok_or_else(|| format!("VM sandbox {id} not found."))?;
    if !status.state.is_some_and(SandboxState::holds_authority) {
        return Err(format!("{id} is not running; only running sandboxes are combined (a stopped one cannot boot again)."));
    }
    if status.remote_control.is_some() {
        return Err(format!("{id} runs on a remote host; a combined VM cannot span hosts."));
    }
    let params = launch_params(production, id)?;
    let memory_gb = params.get("memoryGb").and_then(Value::as_f64).unwrap_or(1.0);
    let cpus = params.get("cpu").and_then(Value::as_u64).unwrap_or(1);
    let os = guest_identity(production, id)?;
    let (staging, folder, files) = match production.workspaces().open(id.execution())? {
        Some(workspace) => {
            let staging = workspace.staging();
            let files = files_of(&staging)?;
            (Some(staging), Some(workspace.record.source.display().to_string()), files)
        }
        None => (None, None, BTreeMap::new()),
    };
    let access = production
        .host_access
        .lock()
        .map_err(|_| "Host-access settings are unavailable")?
        .view(id.execution().as_str());
    let grants = access["grants"].as_array().cloned().unwrap_or_default();
    Ok(Source {
        id: id.clone(),
        os,
        memory_bytes: (memory_gb * GIB) as u64,
        cpus,
        staging,
        folder,
        files,
        one_time: grants.iter().filter(|grant| grant["duration"] == "once").count(),
        grants: grants.into_iter().filter(|grant| grant["duration"] == "always").collect(),
        pending: access["requests"].as_array().map_or(0, |requests| requests.iter().filter(|r| r["state"] == "pending").count()),
        params,
    })
}

/// A source's folder name in a separate layout: its workspace folder's name, made distinct.
fn parts(a: &Source, b: &Source) -> (String, String) {
    let name = |source: &Source, fallback: &str| {
        source
            .folder
            .as_deref()
            .and_then(|folder| Path::new(folder).file_name())
            .map(|name| name.to_string_lossy().chars().filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')).collect::<String>())
            .filter(|name| !name.is_empty() && !name.starts_with('.'))
            .unwrap_or_else(|| fallback.to_owned())
    };
    let (first, second) = (name(a, "first"), name(b, "second"));
    if first.eq_ignore_ascii_case(&second) {
        (format!("{first}-1"), format!("{second}-2"))
    } else {
        (first, second)
    }
}

/// A conflict: the same key declared differently by both sources.
fn union<T: Clone + PartialEq + serde::Serialize>(
    kind: &str,
    a: &[T],
    b: &[T],
    key: impl Fn(&T) -> Vec<String>,
    conflicts: &mut Vec<Value>,
    decisions: &Value,
) -> Vec<T> {
    let mut merged = a.to_vec();
    for item in b {
        let clashes: Vec<usize> = merged
            .iter()
            .enumerate()
            .filter(|(_, other)| *other != item && key(other).iter().any(|k| key(item).contains(k)))
            .map(|(index, _)| index)
            .collect();
        if merged.contains(item) {
            continue;
        }
        if clashes.is_empty() {
            merged.push(item.clone());
            continue;
        }
        let name = format!("{kind}:{}", key(item)[0]);
        let decided = decisions["keep"][&name].as_str();
        conflicts.push(json!({"kind": kind, "key": name, "first": clashes.iter().map(|i| &merged[*i]).collect::<Vec<_>>(),
                               "second": item, "decision": decided}));
        if decided == Some("second") {
            for index in clashes.into_iter().rev() {
                merged.remove(index);
            }
            merged.push(item.clone());
        }
    }
    merged
}

/// The preview of combining `a` and `b` under `decisions` (module docs).
fn preview(production: &Production, a: &SandboxId, b: &SandboxId, decisions: &Value, available: Option<u64>) -> Result<Value, String> {
    if a == b {
        return Err("Choose two different sandboxes.".into());
    }
    let first = source(production, a)?;
    let second = source(production, b)?;
    let mut reasons = Vec::new();
    for key in ["ID", "VERSION_ID", "machine", "kernel"] {
        if first.os.get(key) != second.os.get(key) {
            reasons.push(format!("{key} differs: {:?} and {:?}", first.os.get(key), second.os.get(key)));
        }
    }
    let image = (first.params.get("image").cloned(), second.params.get("image").cloned());
    if image.0 != image.1 {
        reasons.push("They run different images; one VM holds one image root.".to_owned());
    }
    // The combined VM is a new launch: trust roots that refuse the guest refuse it (M18).
    if let Err(refusal) = super::guest_publisher() {
        reasons.push(refusal);
    }
    let mut conflicts = Vec::new();
    let publish = union(
        "publish",
        &published_ports(first.params.get("publish"))?,
        &published_ports(second.params.get("publish"))?,
        |p| vec![p.service.clone(), format!("port {}", p.port)],
        &mut conflicts,
        decisions,
    );
    let connect = union(
        "connect",
        &connection_endpoints(first.params.get("connect"))?,
        &connection_endpoints(second.params.get("connect"))?,
        |c| vec![c.name.clone(), format!("port {}", c.port)],
        &mut conflicts,
        decisions,
    );
    let routes_of = |source: &Source| source.params.get("routes").and_then(Value::as_array).cloned().unwrap_or_default();
    let routes = union(
        "route",
        &routes_of(&first),
        &routes_of(&second),
        |route: &Value| vec![route["name"].as_str().unwrap_or_default().to_owned()],
        &mut conflicts,
        decisions,
    );
    // Workspaces: each source in its own folder (separate), or merged at the root, where the
    // same path with different bytes is a conflict the owner decides file by file.
    let layout = decisions["layout"].as_str().unwrap_or("separate");
    let (first_part, second_part) = parts(&first, &second);
    let mut workspace = BTreeMap::new();
    match layout {
        "separate" => {
            for (name, entry) in &first.files {
                workspace.insert(format!("{first_part}/{name}"), (entry.clone(), "first"));
            }
            for (name, entry) in &second.files {
                workspace.insert(format!("{second_part}/{name}"), (entry.clone(), "second"));
            }
        }
        "merged" => {
            for (name, entry) in &first.files {
                workspace.insert(name.clone(), (entry.clone(), "first"));
            }
            for (name, entry) in &second.files {
                match workspace.get(name) {
                    Some((existing, _)) if existing.0 == entry.0 => {}
                    Some(_) => {
                        let decided = decisions["files"][name].as_str();
                        conflicts.push(json!({"kind": "file", "key": format!("file:{name}"), "decision": decided,
                                              "first": {"sha256": first.files[name].0, "bytes": first.files[name].1},
                                              "second": {"sha256": entry.0, "bytes": entry.1}}));
                        if decided == Some("second") {
                            workspace.insert(name.clone(), (entry.clone(), "second"));
                        }
                    }
                    None => {
                        workspace.insert(name.clone(), (entry.clone(), "second"));
                    }
                }
            }
        }
        other => return Err(format!("Unknown workspace layout '{other}'; use separate or merged.")),
    }
    if image.0.is_some() && decisions["imageProcess"].as_str() != Some("once") {
        conflicts.push(json!({"kind": "image-process", "key": "image-process", "decision": decisions["imageProcess"],
                               "detail": "Both sources run the same image's own process; the combined VM runs it once. Decide imageProcess: once."}));
    }
    let undecided = conflicts.iter().filter(|c| c["decision"].as_str().is_none_or(|d| !matches!(d, "first" | "second" | "once"))).count();
    let memory_bytes = first.memory_bytes + second.memory_bytes;
    let cpus = first.cpus + second.cpus;
    if !(LEAST_LAUNCH_MEMORY_BYTES..=MAX_LAUNCH_MEMORY_BYTES).contains(&memory_bytes) {
        reasons.push(format!("The combined memory ({:.2} GiB) is outside what one VM may reserve (64 GiB at most).", memory_bytes as f64 / GIB));
    }
    if cpus > 255 {
        reasons.push(format!("The combined {cpus} vCPUs exceed one VM's 255."));
    }
    let freed = first.memory_bytes + second.memory_bytes;
    let fits = available.map(|available| available.saturating_add(freed) >= memory_bytes);
    let minimum = |key: &str| [first.params.get(key), second.params.get(key)].into_iter().flatten().filter_map(Value::as_u64).min();
    let adoptable = first.grants.iter().chain(second.grants.iter()).map(|grant| json!({
        "grant": grant["id"], "path": grant["path"], "mode": grant["mode"], "folder": grant["folder"],
        "adopt": decisions["adopt"].as_array().is_some_and(|ids| ids.contains(&grant["id"])),
    })).collect::<Vec<_>>();
    let combined_params = {
        let mut params = json!({
            "memoryGb": memory_bytes as f64 / GIB,
            "cpu": cpus,
            "publish": publish,
            "connect": connect,
        });
        if first.params["gpu"] == true || second.params["gpu"] == true { params["gpu"] = json!(true); }
        if first.params["internet"] == true || second.params["internet"] == true { params["internet"] = json!(true); }
        let grids: std::collections::BTreeSet<_> = [&first.params, &second.params].into_iter()
            .filter_map(|p|p["gridHosting"].as_array()).flatten().filter_map(Value::as_str).collect();
        if !grids.is_empty() { params["gridHosting"] = json!(grids); }
        if !routes.is_empty() { params["routes"] = json!(routes); }
        if let Some(image) = &image.0 { params["image"] = image.clone(); }
        if let Some(seconds) = minimum("idleSeconds") { params["idleSeconds"] = json!(seconds); }
        if let Some(seconds) = minimum("lifetimeSeconds") { params["lifetimeSeconds"] = json!(seconds); }
        params
    };
    if let Err(reason) = super::network::launch_internet(&combined_params) {
        reasons.push(reason);
    }
    let describe = |source: &Source| json!({
        "sandbox": source.id, "os": source.os, "image": source.params.get("image"),
        "memoryBytes": source.memory_bytes, "cpu": source.cpus,
        "workspace": source.folder.as_ref().map(|folder| json!({"folder": folder, "files": source.files.len(),
            "bytes": source.files.values().map(|(_, size)| size).sum::<u64>()})),
        "publish": source.params.get("publish"), "connect": source.params.get("connect"), "routes": source.params.get("routes"),
        "grants": {"lasting": source.grants.len(), "oneTime": source.one_time, "pendingRequests": source.pending},
    });
    let mut value = json!({
        "compatible": reasons.is_empty(),
        "reasons": reasons,
        "sources": [describe(&first), describe(&second)],
        "combined": {
            "params": combined_params,
            "layout": layout,
            "parts": if layout == "separate" { json!({"first": first_part, "second": second_part}) } else { Value::Null },
            "workspace": workspace.iter().map(|(name, ((hash, size), from))| json!({"path": name, "sha256": hash, "bytes": size, "from": from})).collect::<Vec<_>>(),
        },
        "conflicts": conflicts,
        "undecidedConflicts": undecided,
        "capacity": {"hostMemoryAvailableBytes": available, "releasedByOriginalsBytes": freed, "requiredBytes": memory_bytes, "fits": fits,
                     "gpu": "GPU acceleration is preserved; its memory reservation is reacquired after the originals stop"},
        "permissions": {"lastingGrants": adoptable, "notCarried": "one-time grants, pending requests and the tree/ask switches start empty"},
        "notCarried": ["running processes and anything in guest memory (the VMs boot once)", "files outside the workspace, including an image root's changes",
                       "one-time grants and pending host-file requests"],
        "transition": "Both guests lose their workspace, each staged copy is copied and checked, both sandboxes stop (their workspaces and settings are kept), then one VM boots with the sum of their CPU and memory and both workspaces, and its files are checked inside it. If it fails, it is stopped and each original is launched again from its own settings.",
        "trust": "Both workloads will share one guest kernel and one workspace; anything either could reach, the other can.",
        "promotion": "Changes made in the combined VM are reviewed and promoted into its combined folder; each original's own unpromoted changes stay reviewable in its kept workspace.",
    });
    value["digest"] = json!(preview_digest(&first.id, &second.id, &value, decisions)?);
    Ok(value)
}

/// What a start must find unchanged: both sources, the combined VM, its files, conflicts,
/// permissions and the owner's decisions. Not the host's capacity: its free memory moves between
/// the preview and the start, which checks capacity again itself.
fn preview_digest(first: &SandboxId, second: &SandboxId, value: &Value, decisions: &Value) -> Result<String, String> {
    let mut reviewed = value.clone();
    if let Some(fields) = reviewed.as_object_mut() {
        fields.remove("capacity");
        fields.remove("digest");
    }
    let canonical = serde_json::to_vec(&json!({"sources": [first, second], "value": reviewed, "decisions": decisions}))
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn journal_path(data: &Path, operation: &str) -> PathBuf {
    data.join(COMBINE_DIRECTORY).join(operation).join(JOURNAL)
}

fn save(data: &Path, journal: &Value) -> Result<(), String> {
    let operation = journal["operation"].as_str().ok_or("journal without operation")?;
    let path = journal_path(data, operation);
    fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    write_atomic(&path, &serde_json::to_vec_pretty(journal).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn journals(data: &Path) -> Vec<Value> {
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(data.join(COMBINE_DIRECTORY)) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path().join(JOURNAL)) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    found.push(value);
                }
            }
        }
    }
    found.sort_by(|a, b| a["operation"].as_str().cmp(&b["operation"].as_str()));
    found
}

/// At the engine's start: a combine its end cut short is marked interrupted, with what it left.
pub(super) fn recover(data: &Path) -> Value {
    let mut interrupted = Vec::new();
    for mut journal in journals(data) {
        if matches!(journal["state"].as_str(), Some("finished" | "healthy" | "rolled-back" | "failed" | "interrupted")) {
            continue;
        }
        let was = journal["state"].clone();
        journal["state"] = json!("interrupted");
        journal["interruptedAt"] = was;
        journal["recovery"] = json!("The engine ended during this combine. Every VM ended with it; the originals' workspaces are kept and each can be launched again from originals[].params (workspace: its own folder).");
        let _ = save(data, &journal);
        interrupted.push(journal["operation"].clone());
    }
    json!({"interrupted": interrupted})
}

fn sandbox_of(params: &Value, key: &str) -> Result<SandboxId, String> {
    let text = string(params, key).ok_or_else(|| format!("{key} is required (a sandbox id)."))?;
    ExecutionId::new(text).map(SandboxId::new).map_err(|error| format!("Invalid sandbox id: {error}"))
}

fn ledger_available(ledger: &crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>) -> Option<u64> {
    use crate::foundation::ledger::{HostResource, ResourceKey};
    ledger.lock().ok()?.available(ResourceKey::Host(HostResource::Ram))
}

/// The files a guest sees in its workspace, by SHA-256, read inside the guest.
fn guest_files(production: &Production, id: &SandboxId) -> Result<BTreeMap<String, String>, String> {
    let script = format!("cd {GUEST_WORKSPACE} && find . -type f -exec sha256sum {{}} +");
    let outcome = production
        .service
        .exec(id, ExecRequest::new(script.into_bytes(), 4 << 20, std::time::Duration::from_secs(120)))
        .map_err(|e| format!("The combined workspace could not be checked inside the VM: {e}"))?;
    let text = String::from_utf8_lossy(outcome.output.as_bytes()).into_owned();
    Ok(text
        .lines()
        .filter_map(|line| line.split_once("  "))
        .map(|(hash, path)| (path.trim_start_matches("./").to_owned(), hash.to_owned()))
        .collect())
}

/// `sandbox_vm combine` (module docs): preview, start, status or finish.
pub(super) async fn dispatch(app: &AppHandle, production: &Arc<Production>, params: Value) -> Result<Value, String> {
    let operation = string(&params, "operation").unwrap_or_else(|| "preview".to_owned());
    let data = data_dir(production)?;
    match operation.as_str() {
        "status" => Ok(json!({"operations": journals(&data)})),
        "preview" => {
            let ledger = crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(app)).await?;
            let available = ledger_available(&ledger);
            let (a, b) = (sandbox_of(&params, "sandbox")?, sandbox_of(&params, "with")?);
            let decisions = params.get("decisions").cloned().unwrap_or(Value::Null);
            blocking(Arc::clone(production), move |production| preview(production, &a, &b, &decisions, available)).await
        }
        "finish" => {
            let id = string(&params, "id").ok_or("id is required (the combine operation).")?;
            let path = journal_path(&data, &id);
            let mut journal: Value = serde_json::from_slice(&fs::read(&path).map_err(|_| "No such combine operation.")?).map_err(|e| e.to_string())?;
            if journal["state"] != "healthy" {
                return Err(format!("This combine is {}; only a healthy one is finished.", journal["state"]));
            }
            let originals = string(&params, "originals").ok_or("originals is required: keep or remove.")?;
            let removed = match originals.as_str() {
                "keep" => Vec::new(),
                "remove" => {
                    let ids = journal["originals"].as_array().cloned().unwrap_or_default();
                    let production = Arc::clone(production);
                    blocking(production, move |production| {
                        let mut removed = Vec::new();
                        for original in &ids {
                            let execution = ExecutionId::new(original["sandbox"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
                            if production.workspaces().discard(&execution)? {
                                removed.push(original["sandbox"].clone());
                            }
                        }
                        Ok(removed)
                    }).await?
                }
                other => return Err(format!("originals must be keep or remove, not '{other}'.")),
            };
            journal["state"] = json!("finished");
            journal["originalsKept"] = json!(originals == "keep");
            journal["originalWorkspacesRemoved"] = json!(removed);
            save(&data, &journal)?;
            Ok(journal)
        }
        "start" => {
            let ledger = crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(app)).await?;
            let available = ledger_available(&ledger);
            let (a, b) = (sandbox_of(&params, "sandbox")?, sandbox_of(&params, "with")?);
            let decisions = params.get("decisions").cloned().unwrap_or(Value::Null);
            let digest = string(&params, "preview").ok_or("preview is required: the digest of the preview being applied.")?;
            let key = string(&params, "requestKey").filter(|key| key.len() <= 128 && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
            if let Some(key) = &key {
                if let Some(earlier) = journals(&data).into_iter().find(|journal| journal["requestKey"] == key.as_str()) {
                    return Ok(earlier);
                }
            }
            let operation = format!("combine-{}", uuid::Uuid::new_v4().simple());
            let folder = data.join(COMBINE_DIRECTORY).join(&operation).join("workspace");
            let prepared = {
                let (a, b, decisions, folder, operation, data) = (a.clone(), b.clone(), decisions.clone(), folder.clone(), operation.clone(), data.clone());
                blocking(Arc::clone(production), move |production| {
                    let shown = preview(production, &a, &b, &decisions, available)?;
                    if shown["digest"] != digest.as_str() {
                        return Err("The sandboxes changed since this preview (or other decisions were given); preview again.".into());
                    }
                    if shown["compatible"] != true {
                        return Err(format!("These sandboxes cannot be combined: {}", shown["reasons"]));
                    }
                    if shown["undecidedConflicts"].as_u64().unwrap_or(0) > 0 {
                        return Err("Every conflict needs a decision (decisions.keep, decisions.files, decisions.imageProcess); preview again with them.".into());
                    }
                    if shown["capacity"]["fits"] == false {
                        return Err("The host cannot admit the combined VM even once both originals release theirs.".into());
                    }
                    let first = source(production, &a)?;
                    let second = source(production, &b)?;
                    let mut journal = json!({
                        "operation": operation, "requestKey": key, "state": "copying", "preview": shown["digest"],
                        "decisions": decisions, "folder": folder.display().to_string(),
                        "originals": [{"sandbox": a, "params": first.params}, {"sandbox": b, "params": second.params}],
                    });
                    save(&data, &journal)?;
                    // Copied and checked against the previewed bytes while both still run: a copy
                    // that fails, or finds a file changed since the preview, changes nothing.
                    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
                    let layout = shown["combined"]["layout"].as_str().unwrap_or("separate");
                    for (source, side) in [(&first, "first"), (&second, "second")] {
                        let Some(staging) = &source.staging else { continue };
                        let chosen: BTreeMap<String, (String, u64)> = if layout == "separate" {
                            source.files.clone()
                        } else {
                            source.files.iter().filter(|(name, _)| shown["combined"]["workspace"].as_array().is_some_and(|rows|
                                rows.iter().any(|row| row["path"] == name.as_str() && row["from"] == side))).map(|(n, e)| (n.clone(), e.clone())).collect()
                        };
                        let prefix = if layout == "separate" { shown["combined"]["parts"][side].as_str().unwrap_or(side).to_owned() } else { String::new() };
                        if let Err(error) = copy_tree(&chosen, staging, &folder, &prefix) {
                            journal["state"] = json!("failed");
                            journal["failure"] = json!(error);
                            let _ = fs::remove_dir_all(&folder);
                            save(&data, &journal)?;
                            return Err(error);
                        }
                    }
                    // Trust roots reloaded while the files were copied would refuse the combined
                    // VM and each original's relaunch alike: stop here, both still running.
                    if let Err(refusal) = super::guest_publisher() {
                        journal["state"] = json!("failed");
                        journal["failure"] = json!(refusal);
                        let _ = fs::remove_dir_all(&folder);
                        save(&data, &journal)?;
                        return Err(refusal);
                    }
                    // No more writes from either guest. A write that landed between the copy and
                    // now is not in the combined VM; it stays in its original's kept workspace.
                    production.service.detach_workspace(&a);
                    production.service.detach_workspace(&b);
                    let mut late = Vec::new();
                    for source in [&first, &second] {
                        if let Some(staging) = &source.staging {
                            let now = files_of(staging)?;
                            late.extend(now.iter().filter(|(name, entry)| source.files.get(*name) != Some(*entry))
                                .map(|(name, _)| json!({"sandbox": source.id, "path": name})));
                        }
                    }
                    journal["lateWrites"] = json!(late);
                    journal["state"] = json!("stopping-originals");
                    save(&data, &journal)?;
                    let mut params = shown["combined"]["params"].clone();
                    params["workspace"] = json!(folder.display().to_string());
                    Ok((journal, params, shown))
                }).await
            };
            let (mut journal, launch, shown) = prepared?;
            // Both originals stop: their reservations end before the combined VM reserves.
            let stops = {
                let (a, b) = (a.clone(), b.clone());
                blocking(Arc::clone(production), move |production| {
                    Ok([&a, &b].map(|id| production.stop_sandbox(id).err()))
                }).await?
            };
            if let Some(error) = stops.iter().flatten().next() {
                return roll_back(app, production, &data, journal, format!("an original did not stop: {error}")).await;
            }
            journal["state"] = json!("launching");
            save(&data, &journal)?;
            let adopt = decisions["adopt"].as_array().cloned().unwrap_or_default();
            let launched = launch_from(app, production, launch).await;
            let combined = match launched.as_ref().ok().and_then(|value| value["sandbox"].as_str().map(str::to_owned)) {
                Some(id) => id,
                None => return roll_back(app, production, &data, journal, launched.err().unwrap_or_default()).await,
            };
            journal["combined"] = json!(combined);
            journal["state"] = json!("checking");
            save(&data, &journal)?;
            let expected: BTreeMap<String, String> = shown["combined"]["workspace"].as_array().into_iter().flatten()
                .filter_map(|row| Some((row["path"].as_str()?.to_owned(), row["sha256"].as_str()?.to_owned()))).collect();
            let combined_id = sandbox_of(&json!({"sandbox": combined}), "sandbox")?;
            let check = {
                let (combined_id, expected, adopt, shown) = (combined_id.clone(), expected.clone(), adopt.clone(), shown.clone());
                blocking(Arc::clone(production), move |production| {
                    let seen = guest_files(production, &combined_id)?;
                    let missing: Vec<&String> = expected.iter().filter(|(name, hash)| seen.get(*name) != Some(*hash)).map(|(name, _)| name).collect();
                    if !missing.is_empty() || seen.len() != expected.len() {
                        return Err(format!("The combined workspace does not match the reviewed result ({} differ, {} seen, {} expected).", missing.len(), seen.len(), expected.len()));
                    }
                    let declared = production.service.publications(&combined_id).declared;
                    let wanted = published_ports(shown["combined"]["params"].get("publish"))?;
                    if declared.len() != wanted.len() || !wanted.iter().all(|port| declared.contains(port)) {
                        return Err("The combined VM did not declare exactly the merged services.".into());
                    }
                    let mut adopted = Vec::new();
                    let lasting = shown["permissions"]["lastingGrants"].as_array().cloned().unwrap_or_default();
                    for grant in lasting.iter().filter(|grant| adopt.contains(&grant["grant"])) {
                        let mut access = production.host_access.lock().map_err(|_| "Host-access settings are unavailable")?;
                        let made = access.adopt(combined_id.execution().as_str(), grant["path"].as_str().unwrap_or_default(), &grant["mode"])?;
                        adopted.push(json!({"from": grant["grant"], "grant": made}));
                    }
                    Ok(json!({"files": seen.len(), "services": declared, "adopted": adopted}))
                }).await
            };
            match check {
                Ok(health) => {
                    journal["state"] = json!("healthy");
                    journal["health"] = health;
                    save(&data, &journal)?;
                    Ok(journal)
                }
                Err(error) => {
                    let stopped = blocking(Arc::clone(production), move |production| production.stop_sandbox(&combined_id)).await;
                    journal["combinedStopped"] = json!(stopped.is_ok());
                    roll_back(app, production, &data, journal, error).await
                }
            }
        }
        other => Err(format!("Unknown combine operation '{other}'; use preview, start, status or finish.")),
    }
}

/// After a failed combine: each original this combine stopped is launched again from its own
/// settings (its workspace from its own folder; its old workspace, with any unpromoted changes,
/// is kept). One still running is left as it is.
async fn roll_back(app: &AppHandle, production: &Arc<Production>, data: &Path, mut journal: Value, error: String) -> Result<Value, String> {
    journal["failure"] = json!(error);
    let running = live(production);
    let mut relaunched = Vec::new();
    for original in journal["originals"].as_array().cloned().unwrap_or_default() {
        if original["sandbox"].as_str().is_some_and(|id| running.contains(id)) {
            relaunched.push(json!({"from": original["sandbox"], "sandbox": original["sandbox"], "kept": "still running"}));
            continue;
        }
        let outcome = launch_from(app, production, original["params"].clone()).await;
        relaunched.push(match outcome {
            Ok(value) => json!({"from": original["sandbox"], "sandbox": value["sandbox"]}),
            Err(error) => json!({"from": original["sandbox"], "error": error}),
        });
    }
    journal["state"] = json!(if relaunched.iter().all(|row| row.get("sandbox").is_some()) { "rolled-back" } else { "failed" });
    journal["relaunched"] = json!(relaunched);
    save(data, &journal)?;
    Err(format!("The combine failed and was rolled back: {error} (operation {}; originals: {})", journal["operation"], journal["relaunched"]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::vm_service::PublishedPort;

    fn port(service: &str, port: u16) -> PublishedPort {
        PublishedPort { service: service.into(), port }
    }

    #[test]
    fn the_preview_digest_ignores_free_memory_and_follows_what_the_owner_reviews() {
        let (a, b) = (SandboxId::new(ExecutionId::new("vm-a").unwrap()), SandboxId::new(ExecutionId::new("vm-b").unwrap()));
        let shown = |available: u64, file: &str| json!({"combined": {"workspace": [{"path": file}]},
            "capacity": {"hostMemoryAvailableBytes": available, "fits": true}});
        let decisions = json!({"keep": {}});
        let digest = |value: &Value, decisions: &Value| preview_digest(&a, &b, value, decisions).unwrap();
        assert_eq!(digest(&shown(1 << 30, "a.txt"), &decisions), digest(&shown(3 << 30, "a.txt"), &decisions));
        assert_ne!(digest(&shown(1 << 30, "a.txt"), &decisions), digest(&shown(1 << 30, "b.txt"), &decisions));
        assert_ne!(digest(&shown(1 << 30, "a.txt"), &decisions), digest(&shown(1 << 30, "a.txt"), &json!({"keep": {"publish:web": "first"}})));
    }

    #[test]
    fn a_service_declared_differently_by_both_is_a_conflict_the_owner_decides() {
        let key = |p: &PublishedPort| vec![p.service.clone(), format!("port {}", p.port)];
        let a = vec![port("web", 8080)];
        let b = vec![port("web", 8081), port("api", 9000)];
        let mut conflicts = Vec::new();
        assert_eq!(union("publish", &a, &b, key, &mut conflicts, &Value::Null), vec![port("web", 8080), port("api", 9000)]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0]["key"], "publish:web");
        assert!(conflicts[0]["decision"].is_null());
        let mut conflicts = Vec::new();
        let decided = json!({"keep": {"publish:web": "second"}});
        assert_eq!(union("publish", &a, &b, key, &mut conflicts, &decided), vec![port("web", 8081), port("api", 9000)]);
        assert_eq!(conflicts[0]["decision"], "second");
        // The same port under two names clashes too; identical declarations do not.
        let mut conflicts = Vec::new();
        union("publish", &a, &[port("other", 8080)], key, &mut conflicts, &Value::Null);
        assert_eq!(conflicts.len(), 1);
        let mut conflicts = Vec::new();
        assert_eq!(union("publish", &a, &a, key, &mut conflicts, &Value::Null), a);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn copies_are_checked_against_the_previewed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("from");
        fs::create_dir_all(from.join("sub")).unwrap();
        fs::write(from.join("a.txt"), b"one").unwrap();
        fs::write(from.join("sub/b.txt"), b"two").unwrap();
        let files = files_of(&from).unwrap();
        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), vec!["a.txt".to_owned(), "sub/b.txt".to_owned()]);
        let to = dir.path().join("to");
        copy_tree(&files, &from, &to, "part").unwrap();
        assert_eq!(fs::read(to.join("part/sub/b.txt")).unwrap(), b"two");
        // A file changed after the preview is refused, so no original is stopped for it.
        fs::write(from.join("a.txt"), b"changed").unwrap();
        assert!(copy_tree(&files, &from, &dir.path().join("again"), "").is_err());
    }
}
