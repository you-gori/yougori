//! Explicit owner grants for host paths. Guests get a separate, VM-bound endpoint;
//! no owner/approval method is exposed there. Tree permission discloses names only.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::foundation::events::write_atomic;
use crate::sandbox_contract::files::{
    GrantedRoot, GuestName, ResolveIntent, Resolved, RootIdentity,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(super) mod transport;
pub(super) const ENDPOINT: &str = "yougori-host-files";
pub(super) const HOST: &str = "host.yougori";
pub(super) const MAX_FILE_BYTES: usize = 8 << 20;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Policy {
    pub tree_visible: bool,
    pub ask_for_access: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Read,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Duration {
    Once,
    Always,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    id: String,
    sandbox: String,
    path: String,
    mode: Mode,
    state: String,
    grant: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    id: String,
    sandbox: String,
    path: String,
    folder: bool,
    mode: Mode,
    duration: Duration,
    root_identity: RootIdentity,
    /// The identity of the approved folder (a file's own folder for a file grant), opened as
    /// itself at approval: a folder replaced at the same path is not the one approved.
    #[serde(default)]
    folder_identity: Option<RootIdentity>,
}

/// The folder a grant is pinned to: the approved folder itself, or the folder of an approved
/// file (the file may be replaced in place by an editor's save; its folder may not).
fn anchor(path: &str, folder: bool) -> Option<PathBuf> {
    if folder {
        Some(PathBuf::from(path))
    } else {
        Path::new(path).parent().map(Path::to_path_buf)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    policies: BTreeMap<String, Policy>,
    requests: BTreeMap<String, Request>,
    grants: BTreeMap<String, Grant>,
}

pub(super) struct Access {
    file: PathBuf,
    roots: Vec<PathBuf>,
    saved: Saved,
    generations: BTreeMap<String, u64>,
}

pub(super) type Shared = Arc<Mutex<Access>>;

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{key} is required"))
}

fn normalized(path: &str) -> Result<String, String> {
    if path.len() > 4096 || path.chars().any(char::is_control) {
        return Err("Give a normal absolute host path.".into());
    }
    let path = path.replace('\\', "/");
    if path.starts_with("//") || path.split('/').any(|p| p == ".." || p == ".") {
        return Err("Network/device paths and traversal are not allowed.".into());
    }
    #[cfg(windows)]
    let path = {
        let bytes = path.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || &bytes[1..3] != b":/"
            || path[3..].contains(':')
        {
            return Err("Use an absolute local drive path, such as C:/Projects.".into());
        }
        format!("{}{}", path[..1].to_ascii_uppercase(), &path[1..])
    };
    #[cfg(not(windows))]
    if !path.starts_with('/') {
        return Err("Use an absolute host path.".into());
    }
    let path = path.trim_end_matches('/');
    Ok(if path.is_empty() {
        "/".into()
    } else if path.ends_with(':') {
        format!("{path}/")
    } else {
        path.into()
    })
}

fn computer_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        (b'A'..=b'Z')
            .filter_map(|letter| {
                let name = format!("{}:/", letter as char);
                let wide: Vec<u16> = name
                    .replace('/', "\\")
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                // Local/removable/RAM/optical drives only; never walk a mapped network drive.
                let kind = unsafe {
                    windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(wide.as_ptr())
                };
                matches!(kind, 2 | 3 | 5 | 6).then(|| PathBuf::from(name))
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

impl Access {
    pub(super) fn open(file: PathBuf) -> Result<Shared, String> {
        let saved = match std::fs::read(&file) {
            Ok(bytes) if bytes.len() <= 4 << 20 => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Read host-access settings: {e}"))?,
            Ok(_) => return Err("Host-access settings exceed their bound.".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::default(),
            Err(e) => return Err(format!("Read host-access settings: {e}")),
        };
        Ok(Arc::new(Mutex::new(Self {
            file,
            roots: computer_roots(),
            saved,
            generations: BTreeMap::new(),
        })))
    }

    fn commit(&mut self, saved: Saved) -> Result<(), String> {
        let bytes = serde_json::to_vec(&saved).map_err(|e| e.to_string())?;
        if bytes.len() > 4 << 20 {
            return Err(
                "Host-access settings are full; revoke old grants or dismiss old requests.".into(),
            );
        }
        write_atomic(&self.file, &bytes).map_err(|e| e.to_string())?;
        self.saved = saved;
        Ok(())
    }

    pub(super) fn generation(&self, sandbox: &str) -> u64 {
        self.generations.get(sandbox).copied().unwrap_or(0)
    }

    pub(super) fn retain_running(
        &mut self,
        live: &std::collections::BTreeSet<String>,
    ) -> Result<(), String> {
        let ended: std::collections::BTreeSet<_> = self
            .saved
            .policies
            .keys()
            .chain(self.saved.requests.values().map(|r| &r.sandbox))
            .chain(self.saved.grants.values().map(|g| &g.sandbox))
            .filter(|id| !live.contains(*id))
            .cloned()
            .collect();
        if ended.is_empty() {
            return Ok(());
        }
        let mut saved = self.saved.clone();
        saved.policies.retain(|id, _| live.contains(id));
        saved.requests.retain(|_, r| live.contains(&r.sandbox));
        saved.grants.retain(|_, g| live.contains(&g.sandbox));
        self.commit(saved)?;
        for id in ended {
            *self.generations.entry(id).or_default() += 1;
        }
        Ok(())
    }

    pub(super) fn view(&self, sandbox: &str) -> Value {
        json!({"policy": self.saved.policies.get(sandbox).copied().unwrap_or_default(),
            "requests": self.saved.requests.values().filter(|r| r.sandbox == sandbox).collect::<Vec<_>>(),
            "grants": self.saved.grants.values().filter(|r| r.sandbox == sandbox).collect::<Vec<_>>(),
            "endpoint": format!("http://{HOST}/"), "maxFileBytes": MAX_FILE_BYTES})
    }

    fn locate(&self, path: &str) -> Result<(GrantedRoot, Option<GuestName>, String), String> {
        let path = normalized(path)?;
        let root = self
            .roots
            .iter()
            .filter(|r| Path::new(&path).starts_with(r))
            .max_by_key(|r| r.components().count())
            .ok_or("This path is not on an available local drive.")?;
        let relative = Path::new(&path)
            .strip_prefix(root)
            .map_err(|e| e.to_string())?;
        let name = if relative.as_os_str().is_empty() {
            None
        } else {
            Some(
                GuestName::parse(&relative.to_string_lossy().replace('\\', "/"))
                    .map_err(|e| e.to_string())?,
            )
        };
        Ok((
            GrantedRoot::open(root).map_err(|e| e.to_string())?,
            name,
            path,
        ))
    }

    /// Owner-only actions, called through the authenticated engine API.
    pub(super) fn owner(&mut self, sandbox: &str, params: &Value) -> Result<Value, String> {
        let mut saved = self.saved.clone();
        match text(params, "operation")? {
            "status" => return Ok(self.view(sandbox)),
            "policy" => {
                let policy: Policy = serde_json::from_value(
                    params.get("policy").cloned().ok_or("policy is required")?,
                )
                .map_err(|e| e.to_string())?;
                if !policy.ask_for_access {
                    for request in saved
                        .requests
                        .values_mut()
                        .filter(|r| r.sandbox == sandbox && r.state == "pending")
                    {
                        request.state = "cancelled".into();
                    }
                }
                saved.policies.insert(sandbox.to_owned(), policy);
            }
            "approve" | "deny" => {
                let id = text(params, "request")?;
                let request = saved
                    .requests
                    .get(id)
                    .filter(|r| r.sandbox == sandbox && r.state == "pending")
                    .cloned()
                    .ok_or("This pending request is no longer available.")?;
                if params["operation"] == "deny" {
                    saved.requests.get_mut(id).unwrap().state = "denied".into();
                } else {
                    if !saved
                        .policies
                        .get(sandbox)
                        .is_some_and(|p| p.ask_for_access)
                    {
                        return Err("File-access requests are disabled.".into());
                    }
                    let mode: Mode = serde_json::from_value(params["mode"].clone())
                        .map_err(|e| e.to_string())?;
                    if request.mode == Mode::Read && mode == Mode::ReadWrite {
                        return Err("The request only asked to read.".into());
                    }
                    let duration: Duration = serde_json::from_value(params["duration"].clone())
                        .map_err(|e| e.to_string())?;
                    let (root, name, path) = self.locate(&request.path)?;
                    let folder = match name.as_ref() {
                        None => true,
                        Some(name) => match root
                            .resolve(name, ResolveIntent::Open)
                            .map_err(|e| e.to_string())?
                        {
                            Resolved::Directory => true,
                            Resolved::File { .. } => false,
                            Resolved::Absent => {
                                return Err("The requested path does not exist.".into())
                            }
                        },
                    };
                    let folder_identity = anchor(&path, folder)
                        .map(|anchor| GrantedRoot::open(&anchor).map(|opened| opened.identity()))
                        .transpose()
                        .map_err(|e| format!("The approved folder cannot be opened: {e}"))?;
                    let grant = uuid::Uuid::new_v4().to_string();
                    saved.grants.insert(
                        grant.clone(),
                        Grant {
                            id: grant.clone(),
                            sandbox: sandbox.into(),
                            path,
                            folder,
                            mode,
                            duration,
                            root_identity: root.identity(),
                            folder_identity,
                        },
                    );
                    let request = saved.requests.get_mut(id).unwrap();
                    request.state = "approved".into();
                    request.grant = Some(grant);
                }
            }
            "revoke" => {
                let id = text(params, "grant")?;
                if !saved.grants.get(id).is_some_and(|g| g.sandbox == sandbox) {
                    return Err("Grant not found.".into());
                }
                saved.grants.remove(id);
            }
            "dismiss" => {
                saved
                    .requests
                    .retain(|_, r| r.sandbox != sandbox || r.state == "pending");
            }
            _ => return Err("Use status, policy, approve, deny, revoke or dismiss.".into()),
        }
        self.commit(saved)?;
        // Only an owner change that may remove authority invalidates queued bytes.
        // Requests and one-time consumption must not truncate unrelated in-flight reads.
        if matches!(params["operation"].as_str(), Some("policy" | "revoke")) {
            *self.generations.entry(sandbox.to_owned()).or_default() += 1;
        }
        Ok(self.view(sandbox))
    }

    /// The owner's explicit adoption of a lasting grant for another VM (a combine): `path` is
    /// resolved again now, for `sandbox` only; nothing is inherited implicitly.
    pub(super) fn adopt(&mut self, sandbox: &str, path: &str, mode: &Value) -> Result<String, String> {
        let mode: Mode = serde_json::from_value(mode.clone()).map_err(|e| e.to_string())?;
        let (root, name, path) = self.locate(path)?;
        let folder = match name.as_ref() {
            None => true,
            Some(name) => match root.resolve(name, ResolveIntent::Open).map_err(|e| e.to_string())? {
                Resolved::Directory => true,
                Resolved::File { .. } => false,
                Resolved::Absent => return Err("The adopted path no longer exists.".into()),
            },
        };
        let folder_identity = anchor(&path, folder)
            .map(|anchor| GrantedRoot::open(&anchor).map(|opened| opened.identity()))
            .transpose()
            .map_err(|e| format!("The adopted folder cannot be opened: {e}"))?;
        let mut saved = self.saved.clone();
        let id = uuid::Uuid::new_v4().to_string();
        saved.grants.insert(id.clone(), Grant {
            id: id.clone(),
            sandbox: sandbox.into(),
            path,
            folder,
            mode,
            duration: Duration::Always,
            root_identity: root.identity(),
            folder_identity,
        });
        self.commit(saved)?;
        Ok(id)
    }

    /// Guest-only actions. The sandbox identity comes from its authenticated VM link,
    /// never from a field in the request. The owner API is deliberately absent.
    pub(super) fn guest(
        &mut self,
        sandbox: &str,
        live: &AtomicBool,
        params: &Value,
    ) -> Result<Value, String> {
        if !live.load(Ordering::Acquire) {
            return Err("The VM access channel ended.".into());
        }
        let policy = self
            .saved
            .policies
            .get(sandbox)
            .copied()
            .unwrap_or_default();
        match text(params, "operation")? {
            "tree" => {
                if !policy.tree_visible {
                    return Err("Computer tree visibility is disabled.".into());
                }
                let Some(path) = params
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|p| !p.is_empty())
                else {
                    return Ok(
                        json!({"roots": self.roots.iter().map(|p| p.to_string_lossy().replace('\\', "/")).collect::<Vec<_>>() }),
                    );
                };
                let (root, name, path) = self.locate(path)?;
                let mut page =
                    root.tree_page(name.as_ref(), params.get("after").and_then(Value::as_str))?;
                page["path"] = json!(path);
                Ok(page)
            }
            "request" => {
                if !policy.ask_for_access {
                    return Err("Asking for host-file access is disabled.".into());
                }
                let path = normalized(text(params, "path")?)?;
                let mode: Mode =
                    serde_json::from_value(params["mode"].clone()).map_err(|e| e.to_string())?;
                if let Some(r) = self.saved.requests.values().find(|r| {
                    r.sandbox == sandbox && r.path == path && r.mode == mode
                        && matches!(r.state.as_str(), "pending" | "denied")
                }) {
                    return Ok(json!(r));
                }
                if self.saved.requests.len() >= 256
                    || self
                        .saved
                        .requests
                        .values()
                        .filter(|r| r.sandbox == sandbox && r.state == "pending")
                        .count()
                        >= 16
                {
                    return Err("Too many requests; wait for or dismiss existing requests.".into());
                }
                let request = Request {
                    id: uuid::Uuid::new_v4().to_string(),
                    sandbox: sandbox.into(),
                    path,
                    mode,
                    state: "pending".into(),
                    grant: None,
                };
                let mut saved = self.saved.clone();
                saved.requests.insert(request.id.clone(), request.clone());
                self.commit(saved)?;
                Ok(json!(request))
            }
            "request_status" => {
                let request = self
                    .saved
                    .requests
                    .get(text(params, "request")?)
                    .filter(|r| r.sandbox == sandbox)
                    .ok_or("Request not found.")?;
                Ok(json!(request))
            }
            operation @ ("read" | "write" | "list") => {
                let grant = self
                    .saved
                    .grants
                    .get(text(params, "grant")?)
                    .filter(|g| g.sandbox == sandbox)
                    .cloned()
                    .ok_or("No active permission covers this request.")?;
                let path = normalized(text(params, "path")?)?;
                let covered = path == grant.path
                    || (grant.folder && Path::new(&path).starts_with(&grant.path));
                if !covered || (operation == "write" && grant.mode != Mode::ReadWrite) {
                    return Err(
                        "This operation is outside the approved path or permissions.".into(),
                    );
                }
                let content = if operation == "write" {
                    let encoded = params
                        .get("contentBase64")
                        .and_then(Value::as_str)
                        .ok_or("contentBase64 is required")?;
                    if encoded.len() > MAX_FILE_BYTES.div_ceil(3) * 4 {
                        return Err("Host-file writes are limited to 8 MiB per file.".into());
                    }
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|e| e.to_string())?;
                    if bytes.len() > MAX_FILE_BYTES {
                        return Err("Write exceeds 8 MiB.".into());
                    }
                    Some(bytes)
                } else {
                    None
                };
                let (root, name, _) = self.locate(&path)?;
                if root.identity() != grant.root_identity {
                    return Err(
                        "The approved drive/root was replaced; request access again.".into(),
                    );
                }
                if let Some(expected) = grant.folder_identity {
                    let current = anchor(&grant.path, grant.folder)
                        .and_then(|anchor| GrantedRoot::open(&anchor).ok())
                        .map(|opened| opened.identity());
                    if current != Some(expected) {
                        return Err(
                            "The approved folder was replaced or removed; request access again."
                                .into(),
                        );
                    }
                }
                // Consume durably before I/O. Failure cannot make a one-time grant
                // replayable, including after a crash or a concurrent second request.
                if grant.duration == Duration::Once {
                    let mut saved = self.saved.clone();
                    saved.grants.remove(&grant.id);
                    self.commit(saved)?;
                }
                if !live.load(Ordering::Acquire) {
                    return Err("The VM access channel ended.".into());
                }
                match operation {
                    "list" => {
                        root.tree_page(name.as_ref(), params.get("after").and_then(Value::as_str))
                    }
                    "read" => {
                        let bytes = root.read_whole(
                            name.as_ref().ok_or("Choose a file to read.")?,
                            MAX_FILE_BYTES as u64,
                        )?;
                        Ok(
                            json!({"contentBase64": base64::engine::general_purpose::STANDARD.encode(bytes)}),
                        )
                    }
                    _ => {
                        root.write_authorized(
                            name.as_ref().ok_or("Choose a file to write.")?,
                            content.as_deref().unwrap_or_default(),
                        )?;
                        Ok(json!({"written": content.as_ref().map_or(0, Vec::len)}))
                    }
                }
            }
            _ => Err(
                "Use tree, request, request_status, list, read or write. Approval is owner-only."
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests;
