//! Existing servers only: pinned SSH, an ephemeral unprivileged connector, no
//! cloud account API, power operations, host/LAN routing or public listeners.
mod bridge;
pub(crate) mod file_copy;
mod import_files;
mod service;
use super::{connection_files::SharedFiles, fabric::Fabric};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::{mpsc, oneshot},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub vendor: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub identity_file: String,
    pub host_key: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKey {
    pub key: String,
    pub fingerprint: String,
}
/// Environment console = file browser; control = SOCKS proxy. Neither is a
/// host listener: these loopback addresses belong to the connected server.
pub fn endpoints(info: &Value) -> Result<(Option<String>, Option<String>), String> {
    let port = |field: &str| {
        info[field]
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| "Cloud connector returned an invalid endpoint".to_string())
    };
    if info["platform"] != "linux" {
        return Err("Cloud connections require a Linux SSH server with Python 3".into());
    }
    Ok((
        Some(format!("http://127.0.0.1:{}", port("filesPort")?)),
        Some(format!("socks5h://127.0.0.1:{}", port("socksPort")?)),
    ))
}
pub fn validate(profile: &Profile, key_required: bool) -> Result<(), String> {
    if !(2..=80).contains(&profile.name.trim().len()) {
        return Err("Use a name between 2 and 80 characters".into());
    }
    if !["aws", "google", "azure", "other"].contains(&profile.vendor.as_str()) {
        return Err("Choose a cloud provider".into());
    }
    validate_host(&profile.host, profile.port)?;
    if profile.username.is_empty()
        || profile.username.len() > 64
        || profile.username.starts_with('-')
        || !profile
            .username
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err("Enter a valid SSH username".into());
    }
    if public_identity(&profile.identity_file)?.is_none() {
        let key = Path::new(&profile.identity_file);
        if profile.identity_file.contains(['\n', '\r', '\0']) || !key.is_absolute() || !key.is_file() {
            return Err("Choose an existing private key file, or paste a public key whose private key is loaded in this PC's SSH agent.".into());
        }
    }
    if key_required {
        parse_key(&profile.host_key)?;
    }
    Ok(())
}

const AGENT_KEY_HELP: &str = "This is a public SSH key. Load its matching private key into this PC's SSH agent, or use Browse to select the private key file. A public key alone cannot sign in.";

pub(crate) fn public_identity(value: &str) -> Result<Option<String>, String> {
    let mut parts = value.split_whitespace();
    let kind = parts.next().unwrap_or("");
    if !matches!(kind, "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521") {
        return Ok(None);
    }
    let invalid = || "Invalid SSH public key. Paste the complete single-line public key, including its key type and base64 data.".to_string();
    if value.len() > 16384 || value.contains('\0') || value.trim().lines().count() != 1 {
        return Err(invalid());
    }
    let encoded = parts.next().ok_or_else(invalid)?;
    let bytes = B64.decode(encoded).map_err(|_| invalid())?;
    // The first SSH wire string must agree with the displayed algorithm.
    if bytes.len() < 4 { return Err(invalid()); }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length != kind.len() || bytes.get(4..4 + length) != Some(kind.as_bytes()) || bytes.len() <= 4 + length {
        return Err(invalid());
    }
    Ok(Some(format!("{kind} {encoded}")))
}

pub(super) fn identity_path(value: &str, directory: &Path) -> Result<PathBuf, String> {
    if let Some(key) = public_identity(value)? {
        let path = directory.join("identity.pub");
        std::fs::write(&path, format!("{key}\n")).map_err(|e| format!("Prepare public SSH identity: {e}"))?;
        Ok(path)
    } else {
        Ok(PathBuf::from(value))
    }
}

fn agent_has_identity(key: &str, output: &[u8]) -> bool {
    String::from_utf8_lossy(output).lines().any(|line| public_identity(line).ok().flatten().as_deref() == Some(key))
}

async fn check_identity_agent(value: &str) -> Result<(), String> {
    let Some(key) = public_identity(value)? else { return Ok(()) };
    let mut child = command("ssh-add").arg("-L")
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .spawn().map_err(|_| AGENT_KEY_HELP.to_string())?;
    let mut stdout = child.stdout.take().unwrap().take(262145);
    let mut output = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(stdout.read_to_end(&mut output), child.wait())
    }).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    match result {
        Ok(Ok((_, status))) if status.success() && output.len() <= 262144 && agent_has_identity(&key, &output) => Ok(()),
        _ => Err(AGENT_KEY_HELP.into()),
    }
}
fn validate_host(host: &str, port: u16) -> Result<(), String> {
    if port == 0
        || host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
        || host.starts_with(['-', '.'])
    {
        return Err("Enter a hostname or IP address and an SSH port from 1 to 65535".into());
    }
    Ok(())
}
fn parse_key(key: &str) -> Result<HostKey, String> {
    let parts: Vec<_> = key.split(' ').collect();
    if parts.len() != 2
        || !["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"].contains(&parts[0])
        || parts[1].len() > 8192
    {
        return Err("Invalid SSH host key".into());
    }
    let bytes = B64
        .decode(parts[1])
        .map_err(|_| "Invalid SSH host key encoding")?;
    if bytes.len() < 16 {
        return Err("Invalid SSH host key".into());
    }
    Ok(HostKey {
        key: key.into(),
        fingerprint: format!(
            "SHA256:{}",
            B64.encode(Sha256::digest(bytes)).trim_end_matches('=')
        ),
    })
}
pub(crate) fn command(name: &str) -> Command {
    #[cfg(target_os = "windows")]
    let binary = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|p| p.join("System32/OpenSSH").join(format!("{name}.exe")))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| name.into());
    #[cfg(not(target_os = "windows"))]
    let binary = PathBuf::from(name);
    let mut cmd = Command::new(binary);
    cmd.kill_on_drop(true);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(0x08000000);
    cmd
}
pub async fn scan(host: String, port: u16) -> Result<Vec<HostKey>, String> {
    validate_host(&host, port)?;
    let mut child = command("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-p",
            &port.to_string(),
            "-t",
            "ed25519,ecdsa,rsa",
            &host,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("OpenSSH client is required: {e}"))?;
    let mut output = vec![];
    tokio::time::timeout(
        Duration::from_secs(12),
        child
            .stdout
            .take()
            .unwrap()
            .take(32769)
            .read_to_end(&mut output),
    )
    .await
    .map_err(|_| "Server identity check timed out")?
    .map_err(|e| e.to_string())?;
    let _ = child.kill().await;
    let _ = child.wait().await;
    if output.len() > 32768 {
        return Err("Server identity response was too large. No key was trusted.".into());
    }
    let keys = scanned_keys(&output);
    // Windows OpenSSH 9.x keyscan can advertise a KEX it cannot implement.
    // ssh.exe negotiates supported algorithms correctly. Discovery remains TOFU;
    // the subsequent authenticated connection still requires the exact pinned key.
    #[cfg(windows)]
    let keys = if keys.is_empty() { scan_with_ssh(&host, port).await? } else { keys };
    if keys.is_empty() {
        return Err("Cannot reach the SSH server. Check its address, SSH port, firewall and VPN. No server was trusted.".into());
    }
    Ok(keys)
}

fn scanned_keys(output: &[u8]) -> Vec<HostKey> {
    let mut keys = vec![];
    for line in String::from_utf8_lossy(&output).lines().take(20) {
        if line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() == 3 {
            if let Ok(key) = parse_key(&format!("{} {}", parts[1], parts[2])) {
                if !keys.iter().any(|k: &HostKey| k.key == key.key) {
                    keys.push(key);
                }
            }
        }
    }
    keys
}

#[cfg(windows)]
fn discovery_command(host: &str, port: u16, known: &Path) -> Command {
    let mut cmd = command("ssh");
    cmd.args(["-F", "NUL", "-N", "-p", &port.to_string()]);
    for option in ["BatchMode=yes", "ConnectTimeout=10", "ConnectionAttempts=1",
        "StrictHostKeyChecking=accept-new", "GlobalKnownHostsFile=NUL", "HashKnownHosts=no",
        "UpdateHostKeys=no", "VerifyHostKeyDNS=no", "PreferredAuthentications=none",
        "PubkeyAuthentication=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
        "HostbasedAuthentication=no", "GSSAPIAuthentication=no", "IdentityAgent=none",
        "ClearAllForwardings=yes", "ForwardAgent=no", "PermitLocalCommand=no",
        "ProxyCommand=none", "HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"] {
        cmd.args(["-o", option]);
    }
    cmd.arg("-o").arg(format!("UserKnownHostsFile=\"{}\"", known.display()));
    cmd.arg(format!("root@{host}"));
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd
}

#[cfg(windows)]
async fn scan_with_ssh(host: &str, port: u16) -> Result<Vec<HostKey>, String> {
    // A fresh private file is used only for collecting the public host key. No
    // credentials are offered, no command is run, and user SSH config is ignored.
    let directory = tempfile::Builder::new().prefix("yougori-host-scan-").tempdir()
        .map_err(|e| format!("Prepare server identity check: {e}"))?;
    let known = directory.path().join("known_hosts");
    let mut child = discovery_command(host, port, &known).spawn()
        .map_err(|e| format!("OpenSSH client is required: {e}"))?;
    let _ = tokio::time::timeout(Duration::from_secs(12), child.wait()).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    let output = std::fs::read(&known).unwrap_or_default();
    if output.len() > 32768 { return Err("Server identity response was too large. No key was trusted.".into()); }
    Ok(scanned_keys(&output))
}
fn ssh_command(profile: &Profile, known: &Path) -> Result<Command, String> {
    ssh_service_command(profile, known, None)
}
fn ssh_service_command(profile: &Profile, known: &Path, port: Option<u16>) -> Result<Command, String> {
    let identity = identity_path(&profile.identity_file, known.parent().ok_or("Missing SSH metadata directory")?)?;
    let mut cmd = command("ssh");
    cmd.args([
        "-F",
        "none",
        "-T",
        "-a",
        "-x",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
    ]);
    cmd.arg(format!("UserKnownHostsFile=\"{}\"", known.display()))
        .arg("-i")
        .arg(identity)
        .arg("-p")
        .arg(profile.port.to_string())
        .arg("-l")
        .arg(&profile.username);
    if let Some(port) = port {
        cmd.arg("-W").arg(format!("127.0.0.1:{port}"));
    }
    cmd.arg(&profile.host);
    Ok(cmd)
}

/// Test authentication and the connector prerequisites without creating a node
/// or leaving a remote service running. First contact pins the scanned key;
/// subsequent attempts use the supplied pin with strict SSH verification.
pub async fn test_connection(mut profile: Profile) -> Result<Profile, String> {
    validate(&profile, false)?;
    check_identity_agent(&profile.identity_file).await?;
    if profile.host_key.is_empty() {
        let keys = scan(profile.host.clone(), profile.port).await?;
        profile.host_key = keys.iter().find(|key| key.key.starts_with("ssh-ed25519 "))
            .unwrap_or(&keys[0]).key.clone();
    }
    let temp = tempfile::Builder::new().prefix("yougori-cloud-check-").tempdir()
        .map_err(|e| format!("Prepare SSH connection: {e}"))?;
    let cloud = Cloud::new(temp.path().to_owned());
    cloud.save("env-check", &profile)?;
    let known = cloud.directory("env-check")?.join("known_hosts");
    let mut cmd = ssh_command(&profile, &known)?;
    // These are the system modules required by the ephemeral Linux connector.
    let script = "import base64,concurrent.futures,fcntl,http.server,ipaddress,json,os,pty,select,signal,socket,struct,subprocess,sys,termios,threading,time,uuid;assert sys.platform == 'linux', 'A Linux server is required';print('yougori-cloud-ready')";
    cmd.arg(format!("python3 -c \"import base64;exec(base64.b64decode('{}'))\"", B64.encode(script)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("OpenSSH client is required: {e}"))?;
    let mut stdout = child.stdout.take().unwrap().take(16385);
    let mut stderr = child.stderr.take().unwrap().take(16385);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors),
            child.wait(),
        )
    }).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    let (_, _, status) = result.map_err(|_| "SSH connection timed out. Check the server address, port and VPN.")?
        .map_err(|e| format!("Test SSH connection: {e}"))?;
    validate_connection_output(status.success(), &output, &errors)?;
    Ok(profile)
}

fn validate_connection_output(success: bool, output: &[u8], errors: &[u8]) -> Result<(), String> {
    if !success || output.len() > 16384 || errors.len() > 16384
        || !String::from_utf8_lossy(output).lines().any(|line| line == "yougori-cloud-ready") {
        let detail = String::from_utf8_lossy(errors).trim().to_owned();
        return Err(if detail.is_empty() {
            "Could not connect. Requires key-based SSH and a Linux server with Python 3.".into()
        } else { format!("Could not connect over SSH: {detail}{}", ssh_hint(&detail)) });
    }
    Ok(())
}

/// Next steps for the failures people hit most when connecting an EC2 instance with a .pem key.
fn ssh_hint(detail: &str) -> &'static str {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("unprotected private key") || lower.contains("bad permissions") {
        "\n\nOpenSSH refused the key because other accounts can read it. Restrict the file to your user, for example in PowerShell: icacls KEY.pem /inheritance:r /grant:r \"$($env:USERNAME):(R)\""
    } else if lower.contains("permission denied (publickey") {
        "\n\nThe server rejected this user or key. Amazon Linux, RHEL and SUSE use ec2-user; Ubuntu uses ubuntu; Debian uses admin. Use the .pem file of the instance's key pair."
    } else if lower.contains("timed out") || lower.contains("connection refused") || lower.contains("no route to host") {
        "\n\nCheck that the instance is running, that you used its public IPv4 address or public DNS, and that its security group allows inbound TCP 22 from your IP."
    } else if lower.contains("could not resolve hostname") {
        "\n\nCheck the server address. For EC2, copy the Public IPv4 DNS or Public IPv4 address from the instance page."
    } else { "" }
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>>;
#[derive(Clone)]
pub(crate) struct Session {
    pub tx: mpsc::Sender<Value>,
    pending: Pending,
    stop: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pub bridge: mpsc::Sender<Value>,
    pub info: Value,
    share_helper_ready: Arc<tokio::sync::Mutex<bool>>,
    termination: Arc<Mutex<Option<Result<(), String>>>>,
}
impl Session {
    pub async fn request(&self, path: &str, body: Value) -> Result<Value, String> {
        rpc(&self.tx, &self.pending, path, body).await
    }
    pub async fn ensure_share_helper(&self) -> Result<(), String> {
        let mut ready = self.share_helper_ready.lock().await;
        if *ready { return Ok(()); }
        let binary: &[u8] = match self.info["architecture"].as_str() {
            Some("x86_64") => include_bytes!("../../../resources/runtime/cloud/yougori-share-linux-amd64"),
            Some("aarch64") => include_bytes!("../../../resources/runtime/cloud/yougori-share-linux-arm64"),
            _ => return Err("Cloud folder mounts require a Linux x64 or ARM64 server".into()),
        };
        let checksum = hex::encode(Sha256::digest(binary));
        self.request("share/helper", json!({"action":"begin","checksum":checksum})).await?;
        for bytes in binary.chunks(65536) {
            self.request("share/helper", json!({"action":"chunk","data":B64.encode(bytes)})).await?;
        }
        self.request("share/helper", json!({"action":"finish"})).await?;
        *ready = true;
        Ok(())
    }
    fn close(&self) {
        if let Some(stop) = self.stop.lock().unwrap().take() {
            let _ = stop.send(());
        }
    }
}
async fn rpc(
    tx: &mpsc::Sender<Value>,
    pending: &Pending,
    path: &str,
    body: Value,
) -> Result<Value, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let (send, receive) = oneshot::channel();
    {
        let mut pending = pending.lock().unwrap();
        if pending.len() >= 64 {
            return Err("Cloud connection is busy".into());
        }
        pending.insert(id.clone(), send);
    }
    let result = tokio::time::timeout(Duration::from_secs(25), async {
        tx.send(json!({"requestId":id,"path":path,"body":body}))
            .await
            .map_err(|_| "Cloud connection is closed")?;
        receive
            .await
            .map_err(|_| "Cloud connection was interrupted")?
    })
    .await
    .map_err(|_| "Cloud operation timed out".to_string())
    .and_then(|v| v);
    pending.lock().unwrap().remove(&id);
    result
}
pub struct Cloud {
    root: PathBuf,
    sessions: tokio::sync::Mutex<HashMap<String, Session>>,
}
impl Cloud {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            sessions: Default::default(),
        }
    }
    fn directory(&self, id: &str) -> Result<PathBuf, String> {
        if !id.starts_with("env-")
            || id.len() > 80
            || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err("Invalid cloud node ID".into());
        }
        Ok(self.root.join(id))
    }
    pub fn save(&self, id: &str, profile: &Profile) -> Result<(), String> {
        validate(profile, true)?;
        let dir = self.directory(id)?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let host = if profile.port == 22 {
            profile.host.clone()
        } else {
            format!("[{}]:{}", profile.host, profile.port)
        };
        // Only public keys and paths are persisted. Private key material never
        // enters platform state or logs.
        std::fs::write(
            dir.join("known_hosts"),
            format!("{host} {}\n", profile.host_key),
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join("profile.json"),
            serde_json::to_vec(profile).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
    pub fn profile(&self, id: &str) -> Result<Profile, String> {
        let bytes = std::fs::read(self.directory(id)?.join("profile.json"))
            .map_err(|e| format!("Read cloud connection settings: {e}"))?;
        if bytes.len() > 16384 {
            return Err("Cloud profile is too large".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid cloud profile: {e}"))
    }
    pub fn forget(&self, id: &str) -> Result<(), String> {
        let dir = self.directory(id)?;
        if !dir.exists() {
            return Ok(());
        }
        let resolved = dir.canonicalize().map_err(|e| e.to_string())?;
        let root = self.root.canonicalize().map_err(|e| e.to_string())?;
        if resolved.parent() != Some(root.as_path()) {
            return Err("Cloud metadata path is outside its storage folder".into());
        }
        // Only Yougori's own metadata, never the user's selected identity file
        // or connection-owned shared data. No recursive deletion.
        for name in ["profile.json", "known_hosts", "identity.pub"] {
            match std::fs::remove_file(dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        let _ = std::fs::remove_dir(dir);
        Ok(())
    }
    pub async fn session(&self, id: &str) -> Result<Session, String> {
        self.sessions.lock().await.get(id).filter(|s|!s.tx.is_closed()).cloned().ok_or_else(||"Cloud server is disconnected. Choose Connect; Yougori will not start or stop the server.".into())
    }
    pub async fn connected(&self, id: &str) -> bool {
        self.session(id).await.is_ok()
    }
    pub async fn disconnect(&self, id: &str) {
        if let Some(session) = self.sessions.lock().await.remove(id) {
            session.close();
        }
    }
    pub async fn shutdown_report(&self) -> Vec<Value> {
        let sessions: Vec<_> = self.sessions.lock().await.drain().collect();
        for (_, session) in &sessions { session.close(); }
        futures_util::future::join_all(sessions.into_iter().map(|(id, session)| async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let result = loop {
                if let Some(result) = session.termination.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone() { break result; }
                if tokio::time::Instant::now() >= deadline { break Err("Owned SSH process did not confirm disconnection before its deadline".to_string()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            json!({"provider":"cloudSsh","environmentId":id,"scope":"ownedRuntimes","status":if result.is_ok(){"disconnected"}else{"failed"},"postconditionVerified":result.is_ok(),"ownershipReleased":result.is_ok(),"error":result.err().map(|error|crate::lifecycle::safe_diagnostic(&error)),"remotePowerChanged":false})
        })).await
    }
    pub async fn connect(
        &self,
        id: &str,
        fabric: Fabric,
        files: SharedFiles,
    ) -> Result<Value, String> {
        if let Ok(session) = self.session(id).await {
            return Ok(session.info);
        }
        let profile = self.profile(id)?;
        validate(&profile, true)?;
        check_identity_agent(&profile.identity_file).await?;
        let known = self.directory(id)?.join("known_hosts");
        let mut cmd = ssh_command(&profile, &known)?;
        // Keep the SSH command short on Windows. The connector source is sent
        // over the authenticated stdin stream before JSON RPC begins; it is
        // held in memory rather than installed on the server.
        let source = format!("import types, base64\nyougori_models = types.ModuleType('yougori_models')\nexec(base64.b64decode('{}'), yougori_models.__dict__)\n{}", B64.encode(include_bytes!("model.py")), include_str!("agent.py"));
        let source = source.as_bytes();
        cmd.arg("python3 -u -c 'import sys;code=sys.stdin.buffer.read(int(sys.stdin.buffer.readline()));exec(compile(code,\"yougori-agent\",\"exec\"))'");
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("OpenSSH client is required: {e}"))?;
        let mut stdin = child.stdin.take().unwrap();
        if let Err(error) = async {
            stdin.write_all(format!("{}\n", source.len()).as_bytes()).await?;
            stdin.write_all(source).await
        }.await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!("Send cloud connector over SSH: {error}"));
        }
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, mut rx) = mpsc::channel::<Value>(128);
        let (bridge_tx, bridge_rx) = mpsc::channel(128);
        let pending: Pending = Default::default();
        let (stop, stopped) = oneshot::channel();
        let session = Session {
            tx: tx.clone(),
            pending: pending.clone(),
            stop: Arc::new(Mutex::new(Some(stop))),
            bridge: bridge_tx.clone(),
            info: Value::Null,
            share_helper_ready: Arc::new(tokio::sync::Mutex::new(false)),
            termination: Default::default(),
        };
        let own = id.to_owned();
        let task_session = session.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            let errors = Arc::new(Mutex::new(Vec::new()));
            let error_copy = errors.clone();
            tasks.spawn(async move {
                let mut bytes = vec![];
                let _ = stderr.take(16384).read_to_end(&mut bytes).await;
                *error_copy.lock().unwrap() = bytes;
            });
            let io = async {
                let writer = async {
                    while let Some(frame) = rx.recv().await {
                        let mut bytes = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
                        bytes.push(b'\n');
                        stdin.write_all(&bytes).await.map_err(|e| e.to_string())?;
                    }
                    Ok::<(), String>(())
                };
                let reader = async {
                    let mut reader = BufReader::new(stdout);
                    loop {
                        let mut bytes = Vec::new();
                        let n = (&mut reader)
                            .take(2 * 1024 * 1024 + 1)
                            .read_until(b'\n', &mut bytes)
                            .await
                            .map_err(|e| e.to_string())?;
                        if n == 0 || n > 2 * 1024 * 1024 {
                            return Err("Cloud connector ended or sent an invalid frame".into());
                        }
                        let frame: Value = serde_json::from_slice(&bytes)
                            .map_err(|_| "Cloud connector returned invalid data")?;
                        if let Some(event) = frame["event"].as_str() {
                            if event == "files" {
                                if tasks.len() > 32 {
                                    return Err("Too many cloud file requests".into());
                                }
                                let tx = tx.clone();
                                let files = files.clone();
                                let own = own.clone();
                                tasks.spawn(async move {
                                    let response=match B64.decode(frame["data"].as_str().unwrap_or("")) { Ok(data) if data.len()<=1024*1024+32768=>json!({"requestId":frame["requestId"],"result":B64.encode(files.http(&own,&data).await)}), _=>json!({"requestId":frame["requestId"],"error":"Invalid file request"}) };
                                    let _=tx.send(response).await;
                                });
                            } else {
                                bridge_tx
                                    .send(frame)
                                    .await
                                    .map_err(|_| "Private cloud bridge closed")?;
                            }
                        } else if let Some(key) = frame["requestId"].as_str() {
                            if let Some(send) = pending.lock().unwrap().remove(key) {
                                let _ = send.send(if let Some(error) = frame["error"].as_str() {
                                    Err(error.into())
                                } else {
                                    Ok(frame["result"].clone())
                                });
                            }
                        }
                        while tasks.try_join_next().is_some() {}
                    }
                };
                tokio::select! { result=writer=>result, result=reader=>result }
            };
            tokio::select! { _=stopped=>{}, _=io=>{} }
            let _ = child.kill().await;
            let terminated = child.wait().await.map(|_| ()).map_err(|error| error.to_string());
            *task_session.termination.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(terminated);
            // Let stderr finish before surfacing useful authentication/setup errors.
            let _ = tokio::time::timeout(Duration::from_millis(100), async {
                while tasks.join_next().await.is_some() {}
            })
            .await;
            let detail = String::from_utf8_lossy(&errors.lock().unwrap())
                .trim()
                .to_owned();
            let message = if detail.is_empty() {
                "Cloud connection closed. Check SSH connectivity and retry Connect.".into()
            } else {
                format!("Could not connect over SSH: {detail}\nRequires a Linux server with Python 3 and key-based SSH. For an encrypted key, unlock it in your SSH agent first. The server was not powered off.")
            };
            for (_, send) in task_session.pending.lock().unwrap().drain() {
                let _ = send.send(Err(message.clone()));
            }
            tasks.abort_all();
            let _ = task_session.bridge.send(json!({"event":"shutdown"})).await;
        });
        let info = match session.request("health", json!({})).await {
            Ok(info) => info,
            Err(error) => {
                session.close();
                return Err(error);
            }
        };
        if let Err(error) = endpoints(&info) {
            session.close();
            return Err(error);
        }
        if let Err(error) = bridge::start(id, fabric, session.clone(), bridge_rx).await {
            session.close();
            return Err(error);
        }
        let session = Session {
            info: info.clone(),
            ..session
        };
        self.sessions.lock().await.insert(id.into(), session);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn fallback_host_discovery_cannot_authenticate_or_use_user_config() {
        let command = discovery_command("example.test", 2222, Path::new("C:/private temp/known_hosts"));
        let args: Vec<_> = command.as_std().get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        for option in ["NUL", "-N", "PreferredAuthentications=none", "PubkeyAuthentication=no",
            "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentityAgent=none",
            "ClearAllForwardings=yes", "PermitLocalCommand=no", "GlobalKnownHostsFile=NUL",
            "UserKnownHostsFile=\"C:/private temp/known_hosts\""] {
            assert!(args.iter().any(|a| a == option), "Missing {option}");
        }
        assert_eq!(args.last().unwrap(), "root@example.test");
    }
    fn public_key_fixture(kind: &str, value: u8) -> String {
        let mut bytes = Vec::from((kind.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind.as_bytes());
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&[value; 32]);
        format!("{kind} {}", B64.encode(bytes))
    }

    #[test]
    fn pasted_public_identity_preserves_input_and_matches_agent_without_comments() {
        let key = public_key_fixture("ecdsa-sha2-nistp256", 1);
        let pasted = format!("  {key} google-ssh  ");
        assert_eq!(public_identity(&pasted).unwrap(), Some(key.clone()));
        assert!(agent_has_identity(&key, format!("{key} a different comment\n").as_bytes()));
        assert!(!agent_has_identity(&key, format!("{} google-ssh\n", public_key_fixture("ecdsa-sha2-nistp256", 2)).as_bytes()));
        assert!(!agent_has_identity(&key, b"The agent has no identities."));
        assert!(public_identity(&format!("{key}\n{key}")).is_err());
        assert!(public_identity("ecdsa-sha2-nistp256 invalid-base64 google-ssh").is_err());
        assert!(public_identity(&key.replacen("ecdsa-sha2-nistp256", "ssh-ed25519", 1)).is_err());
        assert_eq!(public_identity("C:/My Keys/key.pem").unwrap(), None);
    }

    #[test]
    fn pasted_public_identity_survives_save_reopen_and_uses_managed_file() {
        let root = tempfile::tempdir().unwrap();
        let cloud = Cloud::new(root.path().to_owned());
        let key = public_key_fixture("ssh-ed25519", 1);
        let profile = Profile {
            name: "Public key server".into(), vendor: "google".into(), host: "server.example.test".into(),
            port: 22, username: "ubuntu".into(), identity_file: format!(" {key} google-ssh "), host_key: key.clone(),
        };
        cloud.save("env-test", &profile).unwrap();
        let restored = cloud.profile("env-test").unwrap();
        assert_eq!(restored.identity_file, profile.identity_file);
        let directory = root.path().join("env-test");
        let cmd = ssh_command(&restored, &directory.join("known_hosts")).unwrap();
        let args: Vec<_> = cmd.as_std().get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        assert!(args.windows(2).any(|args| args[0] == "-i" && args[1] == directory.join("identity.pub").to_string_lossy()));
        assert_eq!(std::fs::read_to_string(directory.join("identity.pub")).unwrap(), format!("{key}\n"));
        assert!(!args.iter().any(|arg| arg.contains("google-ssh")));
        cloud.forget("env-test").unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn connection_check_requires_success_and_python_response() {
        assert!(validate_connection_output(true, b"yougori-cloud-ready\n", b"").is_ok());
        assert!(validate_connection_output(true, b"Welcome\r\nyougori-cloud-ready\r\n", b"").is_ok());
        assert!(validate_connection_output(false, b"yougori-cloud-ready\n", b"Permission denied").unwrap_err().contains("Permission denied"));
        assert!(validate_connection_output(true, b"Welcome to SSH\n", b"").is_err());
        assert!(validate_connection_output(false, b"", b"python3: command not found").unwrap_err().contains("python3"));
        assert!(validate_connection_output(false, b"", b"ec2-user@1.2.3.4: Permission denied (publickey).").unwrap_err().contains("Ubuntu uses ubuntu"));
        assert!(validate_connection_output(false, b"", b"WARNING: UNPROTECTED PRIVATE KEY FILE!").unwrap_err().contains("icacls"));
        assert!(validate_connection_output(false, b"", b"ssh: connect to host 1.2.3.4 port 22: Connection timed out").unwrap_err().contains("security group"));
        assert!(validate_connection_output(true, &vec![b'x'; 16385], b"").is_err());
    }

    #[test]
    fn connection_check_and_sessions_use_pinned_batch_ssh() {
        let profile = Profile {
            name: "Cloud server".into(), vendor: "other".into(), host: "cloud.example.test".into(),
            port: 2222, username: "ubuntu".into(), identity_file: "key with spaces.pem".into(), host_key: String::new(),
        };
        let cmd = ssh_command(&profile, Path::new("known hosts")).unwrap();
        let args: Vec<_> = cmd.as_std().get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        for required in ["StrictHostKeyChecking=yes", "UpdateHostKeys=no", "BatchMode=yes", "ClearAllForwardings=yes", "IdentitiesOnly=yes", "PermitLocalCommand=no"] {
            assert!(args.iter().any(|arg| arg == required));
        }
        assert!(args.windows(2).any(|args| args == ["-i", "key with spaces.pem"]));
        assert!(args.windows(2).any(|args| args == ["-p", "2222"]));
        let tunnel = ssh_service_command(&profile, Path::new("known hosts"), Some(8000)).unwrap();
        let tunnel: Vec<_> = tunnel.as_std().get_args().map(|v| v.to_string_lossy().into_owned()).collect();
        assert!(tunnel.windows(2).any(|args| args == ["-W", "127.0.0.1:8000"]));
        assert!(tunnel.iter().any(|arg| arg == "StrictHostKeyChecking=yes"));
        assert_eq!(tunnel.last().unwrap(), "cloud.example.test");
        assert_eq!(args.last().unwrap(), "cloud.example.test");
    }

    #[tokio::test]
    async fn connection_check_validates_unmodified_identifiers_before_network_access() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let mut profile = Profile {
            name: "  ".into(), vendor: "other".into(), host: "localhost".into(), port: 22,
            username: " ubuntu ".into(), identity_file: format!(" {} ", key.path().display()), host_key: String::new(),
        };
        assert_eq!(test_connection(profile.clone()).await.err().unwrap(), "Use a name between 2 and 80 characters");
        profile.name = " Test server ".into();
        profile.username = "  ".into();
        assert_eq!(test_connection(profile).await.err().unwrap(), "Enter a valid SSH username");
    }

    #[test]
    fn cloud_endpoints_keep_browser_and_proxy_in_the_correct_fields() {
        assert_eq!(
            endpoints(&json!({"platform":"linux","socksPort":1234,"filesPort":5678})).unwrap(),
            (
                Some("http://127.0.0.1:5678".into()),
                Some("socks5h://127.0.0.1:1234".into())
            )
        );
        for info in [
            json!({"platform":"win32","socksPort":1234,"filesPort":5678}),
            json!({"platform":"linux","socksPort":0,"filesPort":5678}),
            json!({"platform":"linux","socksPort":1234,"filesPort":65536}),
        ] {
            assert!(endpoints(&info).is_err());
        }
    }
    #[test]
    fn rejects_option_and_shell_injection() {
        for h in [
            "-oProxyCommand=calc",
            "x;touch",
            "user@host",
            "host\nfoo",
            "host/path",
            "",
        ] {
            assert!(validate_host(h, 22).is_err());
        }
        assert!(validate_host("ec2.example.com", 22).is_ok());
        assert!(validate_host("2001:db8::1", 22).is_ok());
        assert!(validate_host("host", 0).is_err());
        assert!(parse_key("ssh-ed25519 bad\ninjected key").is_err());
    }
    #[test]
    fn profile_paths_cannot_escape_root() {
        let cloud = Cloud::new("root".into());
        for id in ["../x", "env-../x", "env-a/b", "env-C:\\x"] {
            assert!(cloud.directory(id).is_err());
        }
    }
    #[test]
    fn removing_cloud_metadata_preserves_selected_key_and_unrelated_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cloud");
        let dir = root.join("env-test");
        std::fs::create_dir_all(&dir).unwrap();
        let key = temp.path().join("private-key.pem");
        std::fs::write(&key, "fixture-only").unwrap();
        std::fs::write(dir.join("profile.json"), "{}").unwrap();
        std::fs::write(dir.join("known_hosts"), "public key").unwrap();
        std::fs::write(dir.join("keep.txt"), "keep").unwrap();
        Cloud::new(root).forget("env-test").unwrap();
        assert!(key.is_file());
        assert!(dir.join("keep.txt").is_file());
        assert!(!dir.join("profile.json").exists());
        assert!(!dir.join("known_hosts").exists());
    }
}
