//! Connection-owned folders. No guest disks or arbitrary host folders are exposed.
#[cfg(test)]
mod tests;
use super::RuntimeManager;
use crate::{
    host_files::{FileForward, HostFolderServer},
    models::{ConnectionDirection, Environment, EnvironmentKind, PermissionKind, SelectedConnectionFolder},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub const GUEST_URL: &str = "http://10.192.0.1:7444";

pub(crate) fn validate_selected_folder_path(path: &str) -> Result<(), &'static str> {
    if path.trim_matches('/').is_empty() {
        return Err("Choose a folder inside the environment, not its entire filesystem (/)");
    }
    if !path.starts_with('/') || path.len() > 4096 || path.contains(['\0', '\\', ':'])
        || path.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..") {
        return Err("Choose a specific absolute folder inside the environment");
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct SharedFiles(Arc<Mutex<HashMap<String, Arc<Share>>>>);
struct Share {
    environments: [Environment; 2],
    source: String,
    target: String,
    label: String,
    both: bool,
    storage: bool,
    commands: bool,
    command_clients: [Option<FolderClient>; 2],
    source_server: HostFolderServer,
    target_server: HostFolderServer,
    selected: Vec<SelectedAccess>,
    selected_mounts: Vec<(usize, usize, HostFolderServer)>,
}
#[derive(Clone)]
struct SelectedAccess {
    owner_id: String,
    path: String,
    client: FolderClient,
}
#[derive(Clone)]
enum FolderClient {
    Agent { endpoint: String, token: String, runtime_id: String, exec_path: &'static str, micro_workload: bool },
    Cloud(super::cloud::Session),
}
impl SelectedAccess {
    async fn request(&self, body: Value, read_only: bool) -> Result<(u16, Vec<u8>), String> {
        if body["operation"] == "read" && body["length"].as_u64().unwrap_or(0) > 65536 {
            let mut output = Vec::new();
            let total = body["length"].as_u64().unwrap_or(0).min(256 * 1024);
            let offset = body["offset"].as_u64().unwrap_or(0);
            while output.len() < total as usize {
                let mut part = body.clone();
                let wanted = (total as usize - output.len()).min(65536);
                part["offset"] = json!(offset + output.len() as u64);
                part["length"] = json!(wanted);
                let (status, reply) = self.request_once(part, read_only).await?;
                if status != 200 { return Ok((status, reply)); }
                let value: Value = serde_json::from_slice(&reply).map_err(|_| "Invalid guest file response")?;
                let bytes = STANDARD.decode(value["data"].as_str().ok_or("Missing guest file data")?)
                    .map_err(|_| "Invalid guest file data")?;
                let count = bytes.len();
                output.extend(bytes);
                if count < wanted { break; }
            }
            return Ok((200, serde_json::to_vec(&json!({"data":STANDARD.encode(output)})).unwrap()));
        }
        if body["operation"] == "write" {
            if let Some(data) = body["data"].as_str() {
                let decoded = STANDARD.decode(data).map_err(|_| "Invalid file data")?;
                if decoded.len() > 256 * 1024 { return Err("Write chunk is too large".into()); }
                if decoded.len() > 65536 {
                    let offset = body["offset"].as_u64().unwrap_or(0);
                    for (index, part) in decoded.chunks(65536).enumerate() {
                        let mut request = body.clone();
                        request["offset"] = json!(offset + (index * 65536) as u64);
                        request["data"] = json!(STANDARD.encode(part));
                        let (status, reply) = self.request_once(request, read_only).await?;
                        if status != 200 { return Ok((status, reply)); }
                    }
                    return Ok((200, serde_json::to_vec(&json!({"count":decoded.len()})).unwrap()));
                }
            }
        }
        self.request_once(body, read_only).await
    }
    async fn request_once(&self, mut body: Value, read_only: bool) -> Result<(u16, Vec<u8>), String> {
        body["root"] = json!(self.path);
        body["readOnly"] = json!(read_only);
        match &self.client {
            FolderClient::Agent { endpoint, token, runtime_id, .. } => {
                body["id"] = json!(runtime_id);
                let response = loopback_client().post(format!("{endpoint}/v1/remote/files"))
                    .bearer_auth(token).json(&body)
                    .timeout(std::time::Duration::from_secs(25)).send().await
                    .map_err(|_| "The selected guest folder is unavailable")?;
                let status = response.status().as_u16();
                let bytes = response.bytes().await.map_err(|_| "The guest file response was interrupted")?;
                if bytes.len() > 1024 * 1024 { return Err("Guest file response exceeded the limit".into()); }
                Ok((status, bytes.to_vec()))
            }
            FolderClient::Cloud(session) => {
                let result = session.request("/v1/remote/files", body).await?;
                Ok((200, serde_json::to_vec(&result).map_err(|_| "Invalid cloud file response")?))
            }
        }
    }
}
impl FolderClient {
    fn same_endpoint(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Cloud(a), Self::Cloud(b)) => a.tx.same_channel(&b.tx),
            (Self::Agent { endpoint: a, token: at, runtime_id: ai, exec_path: ap, micro_workload: am }, Self::Agent { endpoint: b, token: bt, runtime_id: bi, exec_path: bp, micro_workload: bm }) => a == b && at == bt && ai == bi && ap == bp && am == bm,
            _ => false,
        }
    }
    async fn execute(&self, command: &str) -> Result<Value, String> {
        match self {
            Self::Agent { endpoint, token, runtime_id, exec_path, micro_workload } => {
                let command = if *micro_workload {
                    format!("nerdctl --namespace yougori-workload exec app /bin/sh -lc '{}'", command.replace('\'', "'\"'\"'"))
                } else { command.to_owned() };
                let response = loopback_client().post(format!("{endpoint}{exec_path}"))
                    .bearer_auth(token).json(&json!({"id":runtime_id,"command":command}))
                    .timeout(std::time::Duration::from_secs(25)).send().await
                    .map_err(|_| "The target guest command service is unavailable")?;
                if !response.status().is_success() { return Err("The target guest refused the command".into()); }
                response.json().await.map_err(|_| "Invalid guest command result".into())
            }
            Self::Cloud(session) => session.request("exec", json!({"command":command})).await,
        }
    }
}
fn storage_permission(permissions: &[PermissionKind]) -> bool {
    permissions.iter().any(|p| {
        matches!(
            p,
            PermissionKind::Files | PermissionKind::Volumes | PermissionKind::Data
        )
    })
}
/// Guest agents and host folder servers listen on loopback; a configured
/// proxy must never receive their bearer tokens.
fn loopback_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| reqwest::Client::builder().no_proxy().build().unwrap_or_default())
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
impl SharedFiles {
    pub async fn desktop_request(&self, environment: &str, body: Value) -> Result<Value, String> {
        let encoded = serde_json::to_vec(&body).map_err(|_| "Invalid shared file request")?;
        if encoded.len() > 256 * 1024 { return Err("Shared file request is too large".into()); }
        let mut request = format!("POST /api HTTP/1.1\r\nHost: 10.192.0.1:7444\r\nX-Yougori-Files: 1\r\nContent-Length: {}\r\n\r\n", encoded.len()).into_bytes();
        request.extend(encoded);
        let (status, _, reply) = self.handle(environment, &request).await?;
        let value: Value = serde_json::from_slice(&reply).map_err(|_| "Invalid shared file response")?;
        if status != 200 { return Err(value["error"].as_str().unwrap_or("Shared file operation failed").to_owned()); }
        Ok(value)
    }
    pub fn has(&self, id: &str) -> bool {
        self.0.lock().unwrap().contains_key(id)
    }
    pub fn remove(&self, id: &str) {
        if let Some(share) = self.0.lock().unwrap().remove(id) {
            share.source_server.stop();
            share.target_server.stop();
            for (_, _, server) in &share.selected_mounts { server.stop(); }
        }
    }
    pub fn remove_environment(&self, id: &str) {
        self.0.lock().unwrap().retain(|_, s| {
            if s.source == id || s.target == id {
                s.source_server.stop();
                s.target_server.stop();
                for (_, _, server) in &s.selected_mounts { server.stop(); }
                false
            } else {
                true
            }
        });
    }
    pub fn available(&self, environment: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .values()
            .any(|s| s.source == environment || s.target == environment)
    }
    pub async fn http(&self, environment: &str, request: &[u8]) -> Vec<u8> {
        let result = self.handle(environment, request).await;
        let (status, kind, body) = match result {
            Ok(v) => v,
            Err(error) => (
                403,
                "application/json",
                serde_json::to_vec(&json!({"error":error})).unwrap(),
            ),
        };
        let csp = format!("default-src 'none'; script-src 'sha256-{}'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", script_hash());
        let mut response = format!("HTTP/1.1 {status} Response\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {csp}\r\n\r\n", body.len()).into_bytes();
        response.extend(body);
        response
    }
    async fn handle(
        &self,
        environment: &str,
        request: &[u8],
    ) -> Result<(u16, &'static str, Vec<u8>), String> {
        let split = request
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("Invalid request")?;
        let header = std::str::from_utf8(&request[..split]).map_err(|_| "Invalid headers")?;
        let mut first = header.lines().next().unwrap_or_default().split_whitespace();
        let method = first.next().unwrap_or_default();
        let uri = first.next().unwrap_or_default();
        // Reject DNS rebinding and cross-origin form/fetch attacks. No CORS headers.
        if !header.lines().any(|l| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.eq_ignore_ascii_case("host") && v.trim() == "10.192.0.1:7444"
            })
        }) {
            return Err("Invalid file service host".into());
        }
        if header.lines().any(|l| {
            l.split_once(':')
                .is_some_and(|(k, v)| k.eq_ignore_ascii_case("origin") && v.trim() != GUEST_URL)
        }) {
            return Err("Cross-origin file access is blocked".into());
        }
        if method == "GET" && uri == "/" {
            return Ok((
                200,
                "text/html; charset=utf-8",
                include_bytes!("connection_files.html").to_vec(),
            ));
        }
        if method == "GET" && uri == "/connections" {
            let shares = self.0.lock().unwrap();
            let entries: Vec<_> = shares.iter().filter(|(_,s)| s.storage && (s.source == environment || s.target == environment)).map(|(id,s)| json!({"id":id,"label":s.label,"writable":s.source == environment || s.both})).collect();
            return Ok((
                200,
                "application/json",
                serde_json::to_vec(&entries).unwrap(),
            ));
        }
        if method != "POST"
            || !matches!(uri, "/api" | "/exec")
            || !header.lines().any(|l| {
                l.split_once(':').is_some_and(|(k, v)| {
                    (k.eq_ignore_ascii_case("x-yougori-files")
                        || k.eq_ignore_ascii_case(yougori_cli::legacy_names::FILES_HEADER)) && v.trim() == "1"
                })
            })
        {
            return Err("Use the private connection API with X-Yougori-Files: 1".into());
        }
        let mut body: Value =
            serde_json::from_slice(&request[split + 4..]).map_err(|_| "Invalid file request")?;
        let id = body
            .get("connectionId")
            .and_then(Value::as_str)
            .ok_or("Choose a connection")?
            .to_owned();
        let share = self
            .0
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or("This connection is disconnected")?;
        if uri == "/exec" {
            if !share.commands { return Err("This connection does not allow commands".into()); }
            let target_index = if share.source == environment { 1 }
                else if share.target == environment && share.both { 0 }
                else { return Err("Commands are not allowed in this direction".into()); };
            let command = body["command"].as_str().ok_or("Enter a command")?;
            if command.trim().is_empty() || command.len() > 32768 { return Err("Command must be between 1 and 32768 characters".into()); }
            let client = share.command_clients[target_index].as_ref()
                .ok_or("This target VM needs a verified guest SSH server. Use yougori connection exec with request.ssh on this computer.")?;
            let result = client.execute(command).await?;
            if !self.0.lock().unwrap().get(&id).is_some_and(|current| Arc::ptr_eq(current, &share)) {
                return Err("This connection was disconnected".into());
            }
            return Ok((200, "application/json", serde_json::to_vec(&result).map_err(|_| "Invalid command result")?));
        }
        if !share.storage { return Err("This connection does not share data".into()); }
        let server = if share.source == environment {
            &share.source_server
        } else if share.target == environment {
            &share.target_server
        } else {
            return Err("This environment cannot access that connection".into());
        };
        body.as_object_mut()
            .ok_or("Invalid file request")?
            .remove("connectionId");
        let requested_path = body["path"].as_str().unwrap_or("").trim_matches('/').to_owned();
        if !share.selected.is_empty() && requested_path == "_selected" {
            if body["operation"] != "list" { return Err("Choose one selected folder".into()); }
            let entries: Vec<_> = share.selected.iter().enumerate().map(|(index, folder)| {
                json!({"name":index.to_string(),"directory":true,"size":0,"ownerId":folder.owner_id,"guestPath":folder.path})
            }).collect();
            return Ok((200, "application/json", serde_json::to_vec(&json!({"entries":entries})).unwrap()));
        }
        if let Some(rest) = requested_path.strip_prefix("_selected/") {
            let (number, relative) = rest.split_once('/').unwrap_or((rest, ""));
            let index = number.parse::<usize>().map_err(|_| "Unknown selected folder")?;
            let folder = share.selected.get(index).ok_or("Unknown selected folder")?;
            body["path"] = json!(relative);
            let (status, bytes) = folder.request(body, share.source != environment && !share.both).await?;
            if !self.0.lock().unwrap().get(&id).is_some_and(|current| Arc::ptr_eq(current, &share)) {
                return Err("This connection was disconnected".into());
            }
            return Ok((status, "application/json", bytes));
        }
        if requested_path.is_empty() && body["operation"] == "list" && !share.selected.is_empty() {
            let reply = loopback_client().post(format!("http://127.0.0.1:{}/files", server.port))
                .bearer_auth(&server.token).json(&body).timeout(std::time::Duration::from_secs(20))
                .send().await.map_err(|_| "Shared folder is unavailable")?;
            let mut value: Value = reply.json().await.map_err(|_| "Invalid shared folder listing")?;
            let entries = value["entries"].as_array_mut().ok_or("Invalid shared folder listing")?;
            entries.push(json!({"name":"_selected","directory":true,"size":0}));
            return Ok((200, "application/json", serde_json::to_vec(&value).unwrap()));
        }
        // Reuse the authenticated, path-confined and read-only-enforcing file API.
        let reply = loopback_client()
            .post(format!("http://127.0.0.1:{}/files", server.port))
            .bearer_auth(&server.token)
            .json(&body)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
            .map_err(|_| "Shared folder is unavailable")?;
        let status = reply.status().as_u16();
        let bytes = reply
            .bytes()
            .await
            .map_err(|_| "File operation failed")?
            .to_vec();
        if !self
            .0
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &share))
        {
            return Err("This connection was disconnected".into());
        }
        Ok((status, "application/json", bytes))
    }
}
fn script_hash() -> String {
    html_script_hash(include_str!("connection_files.html"))
}
fn html_script_hash(html: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    // HTML parsing normalizes CRLF and bare CR before CSP hashes the script.
    // Match that even if the source was checked out or edited on Windows.
    let html = html.replace("\r\n", "\n").replace('\r', "\n");
    let script = html
        .split_once("<script>")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()))
}

impl RuntimeManager {
    pub async fn remove_shared_files(&self, id: &str) {
        let (mounts, cloud_mounts) = self
            .shared_files
            .0
            .lock()
            .unwrap()
            .get(id)
            .map(|s| {
                let mut mounts = Vec::new();
                let mut cloud_mounts = Vec::new();
                for (side, env) in s.environments.iter().enumerate() {
                    if env.kind == EnvironmentKind::Cloud {
                        for (index, access) in s.selected.iter().enumerate() {
                            if access.owner_id != env.id { cloud_mounts.push((env.id.clone(), index)); }
                        }
                    }
                    if matches!(env.kind, EnvironmentKind::FullVm | EnvironmentKind::Cloud) { continue; }
                    mounts.push((env.clone(), id.to_owned()));
                    for (mount_side, index, _) in &s.selected_mounts {
                        if *mount_side == side { mounts.push((env.clone(), format!("{id}-selected-{index}"))); }
                    }
                }
                (mounts, cloud_mounts)
            }).unwrap_or_default();
        self.shared_files.remove(id);
        for (env, share_id) in mounts {
            let endpoint_id = env.runtime_id.as_deref().unwrap_or(&env.id);
            let _ = self.workspace_request(&env, "/v1/shares/detach", json!({
                "id":endpoint_id,"shareId":share_id
            })).await;
        }
        for (environment_id, index) in cloud_mounts {
            if let Ok(session) = self.cloud.session(&environment_id).await {
                let _ = session.request("share/detach", json!({"connectionId":id,"index":index})).await;
            }
        }
    }
    pub async fn apply_shared_files(
        &self,
        id: &str,
        source: &Environment,
        target: &Environment,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        selected_folders: &[SelectedConnectionFolder],
        commands: bool,
    ) -> Result<(), String> {
        let storage = storage_permission(permissions);
        if !storage && !commands {
            self.remove_shared_files(id).await;
            return Ok(());
        }
        if !safe_id(id) {
            return Err("Invalid connection identifier".into());
        }
        let source_id = source.runtime_id.as_deref().unwrap_or(&source.id);
        let target_id = target.runtime_id.as_deref().unwrap_or(&target.id);
        let both = *direction == ConnectionDirection::Bidirectional;
        let mut command_clients = [None, None];
        if commands {
            for (index, environment) in [source, target].into_iter().enumerate() {
                command_clients[index] = if environment.kind == EnvironmentKind::Cloud {
                    Some(FolderClient::Cloud(self.cloud.session(&environment.id).await?))
                } else if matches!(environment.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm) {
                    let (endpoint, token) = self.workspace_endpoint(environment).await
                        .map_err(|error| format!("{} cannot receive connected commands: {error}", environment.name))?;
                    Some(FolderClient::Agent {
                        endpoint, token,
                        runtime_id: environment.runtime_id.as_deref().unwrap_or(&environment.id).to_owned(),
                        exec_path: if environment.kind == EnvironmentKind::Container { "/v1/containers/exec" } else { "/v1/system/exec" },
                        micro_workload: environment.kind == EnvironmentKind::MicroVm && self.is_micro_workload(environment.runtime_id.as_deref().unwrap_or(&environment.id))?,
                    })
                } else { None };
            }
        }
        let mut selected = Vec::with_capacity(selected_folders.len());
        for folder in selected_folders {
            validate_selected_folder_path(&folder.path)?;
            let environment = if folder.environment_id == source.id { source }
                else if folder.environment_id == target.id { target }
                else { return Err("A selected folder does not belong to this connection".into()) };
            let client = if environment.kind == EnvironmentKind::Cloud {
                FolderClient::Cloud(self.cloud.session(&environment.id).await?)
            } else {
                let (endpoint, token) = self.workspace_endpoint(environment).await
                    .map_err(|_| "This environment cannot expose a selected folder. A running Yougori guest agent is required.")?;
                FolderClient::Agent { endpoint, token, runtime_id: environment.runtime_id.as_deref().unwrap_or(&environment.id).to_owned(), exec_path: if environment.kind == EnvironmentKind::Container { "/v1/containers/exec" } else { "/v1/system/exec" }, micro_workload: false }
            };
            // This read-only call verifies that the chosen directory exists and
            // that the guest agent's confinement rules accept it.
            let access = SelectedAccess { owner_id: environment.id.clone(), path: folder.path.clone(), client };
            let (status, value) = access.request(json!({"operation":"list","path":""}), true).await?;
            if status != 200 || serde_json::from_slice::<Value>(&value).ok().and_then(|v| v["entries"].as_array().cloned()).is_none() {
                return Err(format!("Selected folder {} is unavailable or cannot be shared", folder.path));
            }
            selected.push(access);
        }
        let existing = self.shared_files.0.lock().unwrap().get(id).cloned();
        let share = match existing
            .filter(|s| s.source == source_id && s.target == target_id && s.both == both && s.storage == storage && s.commands == commands
                && s.selected.len() == selected.len()
                && s.selected.iter().zip(&selected).all(|(a,b)| a.owner_id == b.owner_id && a.path == b.path && a.client.same_endpoint(&b.client))
                && s.command_clients.iter().zip(&command_clients).all(|(a,b)| match (a,b) { (None,None) => true, (Some(a),Some(b)) => a.same_endpoint(b), _ => false }))
        {
            Some(s) => s,
            None => {
                let parent = self.data_root.join("connection-files");
                std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
                let parent = parent.canonicalize().map_err(|e| e.to_string())?;
                let root = parent.join(id);
                if !root.exists() {
                    std::fs::create_dir(&root).map_err(|e| e.to_string())?;
                }
                let meta = std::fs::symlink_metadata(&root).map_err(|e| e.to_string())?;
                if !meta.is_dir()
                    || meta.file_type().is_symlink()
                    || root.canonicalize().map_err(|e| e.to_string())? != root
                {
                    return Err("Unsafe connection folder".into());
                }
                let mut selected_mounts = Vec::new();
                for (folder_index, access) in selected.iter().enumerate() {
                    for (side, environment) in [source, target].into_iter().enumerate() {
                        if access.owner_id == environment.id || !matches!(environment.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm) {
                            continue;
                        }
                        let access = access.clone();
                        let read_only = side == 1 && !both;
                        let forward: FileForward = Arc::new(move |body| {
                            let access = access.clone();
                            Box::pin(async move { access.request(body, read_only).await })
                        });
                        selected_mounts.push((side, folder_index, HostFolderServer::start_forward(forward).await?));
                    }
                }
                self.remove_shared_files(id).await;
                Arc::new(Share {
                    environments: [source.clone(), target.clone()],
                    source: source_id.into(),
                    target: target_id.into(),
                    label: format!("{} ↔ {}", source.name, target.name),
                    both,
                    storage,
                    commands,
                    command_clients,
                    source_server: HostFolderServer::start(root.clone(), false).await?,
                    target_server: HostFolderServer::start(root, !both).await?,
                    selected,
                    selected_mounts,
                })
            }
        };
        // Publish first so mounted clients can reach their endpoint; rollback on error.
        self.shared_files
            .0
            .lock()
            .unwrap()
            .insert(id.into(), share.clone());
        for (env, server, read_only) in [
            (source, &share.source_server, false),
            (target, &share.target_server, !both),
        ] {
            if !storage { continue; }
            if matches!(env.kind, EnvironmentKind::FullVm | EnvironmentKind::Cloud) {
                continue;
            }
            // Custom MicroVMs without our agent can still use the browser/API.
            if env.kind == EnvironmentKind::MicroVm && self.workspace_endpoint(env).await.is_err() {
                continue;
            }
            let endpoint_id = env.runtime_id.as_deref().unwrap_or(&env.id);
            let endpoint = match self.host_folder_endpoint(env, server).await {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    self.remove_shared_files(id).await;
                    return Err(format!("Shared files: {error}"));
                }
            };
            let result = self.workspace_request(env,"/v1/shares/attach",json!({"id":endpoint_id,"shareId":id,"endpoint":endpoint,"token":server.token,"readOnly":read_only,"connection":true})).await;
            if let Err(error) = result {
                self.remove_shared_files(id).await;
                return Err(format!("Shared files: {error}. Restart older containers/MicroVMs to load the updated agent, then retry the connection."));
            }
        }
        for (side, folder_index, server) in &share.selected_mounts {
            let env = if *side == 0 { source } else { target };
            if env.kind == EnvironmentKind::MicroVm && self.workspace_endpoint(env).await.is_err() { continue; }
            let endpoint = match self.host_folder_endpoint(env, server).await {
                Ok(endpoint) => endpoint,
                Err(error) => { self.remove_shared_files(id).await; return Err(format!("Selected folder: {error}")); }
            };
            let mount_id = format!("{id}-selected-{folder_index}");
            let result = self.workspace_request(env, "/v1/shares/attach", json!({
                "id":env.runtime_id.as_deref().unwrap_or(&env.id), "shareId":mount_id,
                "endpoint":endpoint,"token":server.token,"readOnly":*side == 1 && !both,"connection":true
            })).await;
            if let Err(error) = result {
                self.remove_shared_files(id).await;
                return Err(format!("Could not mount the selected folder in {}: {error}", env.name));
            }
        }
        for (side, env) in [source, target].into_iter().enumerate() {
            if env.kind != EnvironmentKind::Cloud { continue; }
            for (index, access) in share.selected.iter().enumerate() {
                if access.owner_id == env.id { continue; }
                let owner = if source.id == access.owner_id { source } else { target };
                let result = async {
                    let session = self.cloud.session(&env.id).await?;
                    session.ensure_share_helper().await?;
                    session.request("share/attach", json!({
                        "connectionId":id,"index":index,"label":owner.name,
                        "readOnly":side == 1 && !both
                    })).await?;
                    Ok::<(), String>(())
                }.await;
                if let Err(error) = result {
                    self.remove_shared_files(id).await;
                    return Err(format!("Could not mount {}'s folder in cloud environment {}: {error}", owner.name, env.name));
                }
            }
        }
        Ok(())
    }
}
