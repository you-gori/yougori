//! Optional Windows CUDA container backend. No dependency on Tauri or QEMU.
//! The application owns one instance and must await shutdown before exit.
#[cfg(windows)]
mod storage;
mod compatibility;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Mutex,
};

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub base_url: String,
    pub token: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    pub update_available: bool,
    pub detail: String,
    pub checks: Vec<compatibility::Check>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Installed {
    version: u32,
    distribution: String,
    identity: String,
    payload_checksum: Option<String>,
}

struct Process {
    child: Child,
    endpoint: Endpoint,
    // Windows releases this exclusive handle even if the app crashes. Other
    // live Yougori instances cannot recover, update or start this runtime.
    _ownership: std::fs::File,
    cleanup_only: bool,
}

pub struct CudaRuntime {
    directory: PathBuf,
    process: Mutex<Option<Process>>,
    client: reqwest::Client,
}

fn identity(directory: &Path) -> Result<(String, String), String> {
    if !directory.is_absolute() || directory.parent().is_none() {
        return Err("CUDA storage must be a dedicated absolute directory".into());
    }
    let absolute = std::path::absolute(directory).map_err(|e| e.to_string())?;
    let normalized = absolute
        .to_string_lossy()
        .trim_start_matches("\\\\?\\")
        .trim_end_matches(['\\', '/'])
        .to_lowercase();
    #[cfg(windows)]
    let normalized = normalized.replace('/', "\\");
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    Ok((format!("OpenDock-CUDA-{}", &digest[..12]), digest))
}

fn hidden(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn setup_failure(log_path: &Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    // Setup output can be large. Read only its tail and the explicit error
    // marker; prerequisite failures have already been reported before setup.
    let detail = (|| {
        let mut file = std::fs::File::open(log_path).ok()?;
        let start = file.metadata().ok()?.len().saturating_sub(16 * 1024);
        file.seek(SeekFrom::Start(start)).ok()?;
        let mut bytes = Vec::new();
        file.take(16 * 1024).read_to_end(&mut bytes).ok()?;
        // WSL status output may leave UTF-16 NULs next to PowerShell's text.
        let output = String::from_utf8_lossy(&bytes).replace('\0', "");
        output.lines().rev().find_map(|line| {
            line.strip_prefix("YOUGORI_CUDA_SETUP_ERROR: ")
                .filter(|message| !message.trim().is_empty())
                .map(|message| message.chars().take(1000).collect::<String>())
        })
    })();
    format!("CUDA setup failed{}. Existing container disks were kept. Setup log: {}",
        detail.map(|message| format!(": {message}")).unwrap_or_default(), log_path.display())
}

fn startup_failure(log: &str, log_path: &Path, cleanup: bool) -> String {
    if let Some(detail) = log.lines().rev().find_map(|line| line.split_once("Yougori storage preparation failed: ").map(|(_, detail)| detail)) {
        return format!("CUDA storage could not be prepared: {}. Existing container data was kept. See {}", detail.chars().take(1000).collect::<String>(), log_path.display());
    }
    format!("{} exited before becoming ready. See {}", if cleanup { "CUDA cleanup helper" } else { "CUDA runtime" }, log_path.display())
}

impl CudaRuntime {
    pub fn has_owned_installation(directory: &Path) -> bool {
        Self::new(directory.to_owned()).and_then(|runtime| runtime.installation()).is_ok()
    }

    /// The desktop identifier changed after some users had installed CUDA. The
    /// app data folder was renamed, but WSL still owns the disk at its original
    /// path. Restore only that exact moved installation; never rewrite a CUDA
    /// identity or register an unverified disk under another distribution.
    pub fn restore_relocated_installation(current: &Path, original: &Path) -> Result<bool, String> {
        let manifest = current.join("installed.json");
        if !manifest.is_file() || original.exists() { return Ok(false); }
        let bytes = fs::read(&manifest).map_err(|e| format!("Read moved CUDA installation: {e}"))?;
        if bytes.len() > 4096 { return Ok(false); }
        let installed: Installed = match serde_json::from_slice(&bytes) { Ok(value) => value, Err(_) => return Ok(false) };
        let (original_name, original_digest) = identity(original)?;
        if installed.version != 1 || installed.distribution != original_name || installed.identity != original_digest {
            return Ok(false);
        }
        for path in [current, &current.join("distribution"), &current.join("distribution/ext4.vhdx")] {
            let metadata = fs::symlink_metadata(path).map_err(|e| format!("Inspect moved CUDA storage: {e}"))?;
            if metadata.file_type().is_symlink() { return Err("Moved CUDA storage is redirected; its disk was left in place".into()); }
        }
        if !current.join("distribution/ext4.vhdx").is_file() {
            return Ok(false);
        }
        let parent = original.parent().ok_or("Invalid original CUDA storage path")?;
        fs::create_dir_all(parent).map_err(|e| format!("Prepare original CUDA storage directory: {e}"))?;
        for path in [parent, parent.parent().ok_or("Invalid original CUDA storage parent")?] {
            if fs::symlink_metadata(path).map_err(|e| e.to_string())?.file_type().is_symlink() {
                return Err("Original CUDA storage parent is redirected; its disk was left in place".into());
            }
        }
        fs::rename(current, original).map_err(|e| format!("Restore CUDA disk to its WSL-registered directory: {e}"))?;
        let verify = (|| {
            CudaRuntime::new(original.to_owned())?.installation()?;
            let bootstrap = original.join("bootstrap");
            fs::create_dir_all(&bootstrap).map_err(|e| e.to_string())?;
            fs::write(bootstrap.join("verify-owned.ps1"), include_str!("../../verify-owned.ps1")).map_err(|e| e.to_string())?;
            fs::write(bootstrap.join("paths.ps1"), include_str!("../../paths.ps1")).map_err(|e| e.to_string())?;
            let mut command = std::process::Command::new("powershell.exe");
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let status = command.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(bootstrap.join("verify-owned.ps1"))
                .arg("-DataDirectory").arg(original)
                .arg("-Distribution").arg(&installed.distribution)
                .arg("-RequireStopped")
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status().map_err(|e| format!("Verify original CUDA registration: {e}"))?;
            if !status.success() { return Err("WSL did not verify the original stopped CUDA distribution".into()); }
            Ok::<(), String>(())
        })();
        if let Err(error) = verify {
            fs::rename(original, current).map_err(|rollback| format!("{error}; CUDA storage could not be returned to its prior location: {rollback}"))?;
            return Ok(false);
        }
        Ok(true)
    }

    fn ownership(&self) -> Result<std::fs::File, String> {
        std::fs::create_dir_all(&self.directory).map_err(|e| e.to_string())?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        options.open(self.directory.join("runtime-owner.lock")).map_err(|error| {
            if error.raw_os_error() == Some(32) || error.raw_os_error() == Some(33) {
                "[OPENDOCK_RUNTIME_BUSY] Another live Yougori instance owns this CUDA runtime. Close that instance normally; its containers were not interrupted.".into()
            } else { format!("Lock CUDA runtime: {error}") }
        })
    }

    async fn verify_owned(&self, installation: &Installed, terminate: bool, require_stopped: bool) -> Result<(), String> {
        let assets = self.directory.join("bootstrap");
        tokio::fs::create_dir_all(&assets)
            .await
            .map_err(|e| e.to_string())?;
        let script = assets.join("verify-owned.ps1");
        tokio::fs::write(&script, include_str!("../../verify-owned.ps1"))
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::write(assets.join("paths.ps1"), include_str!("../../paths.ps1"))
            .await.map_err(|e| e.to_string())?;
        let mut command = hidden("powershell.exe");
        command.kill_on_drop(true);
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .arg("-DataDirectory")
            .arg(&self.directory)
            .arg("-Distribution")
            .arg(&installation.distribution);
        if terminate {
            command.arg("-Terminate");
        }
        if require_stopped {
            command.arg("-RequireStopped");
        }
        let status = tokio::time::timeout(Duration::from_secs(45), command.status())
            .await
            .map_err(|_| "CUDA ownership check timed out; no other runtime was targeted")?
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(if require_stopped {
                "The CUDA disk could not be verified as owned and stopped. Close its containers and WSL sessions normally, then retry Reclaim space. No distribution was stopped or changed."
            } else {
                "The CUDA distribution could not be verified against its owned storage. No other WSL distribution was touched."
            }.into());
        }
        Ok(())
    }

    /// Recover only a verified abandoned runtime, including native startup.
    /// The exclusive ownership handle protects other live app instances.
    pub async fn recover_abandoned(&self) -> Result<(), String> {
        if !cfg!(windows) {
            return Err("CUDA runtime recovery requires Windows".into());
        }
        let mut guard = self.process.lock().await;
        if let Some(process) = guard.as_mut() {
            if process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Err("The current app owns this CUDA runtime. Stop its containers normally; running workloads were not force-stopped.".into());
            }
        }
        *guard = None;
        let _ownership = self.ownership()?;
        let installation = self.installation()?;
        self.verify_owned(&installation, true, false).await?;
        // Termination acknowledgement is not recovery: prove the registered
        // distribution is stopped while our exclusive ownership is still held.
        self.verify_owned(&installation, false, true).await
    }
    pub fn new(directory: PathBuf) -> Result<Self, String> {
        identity(&directory)?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            directory,
            process: Mutex::new(None),
            client,
        })
    }

    fn installation(&self) -> Result<Installed, String> {
        let path = self.directory.join("installed.json");
        let metadata = std::fs::metadata(&path)
            .map_err(|_| "Install the optional WSL 2 CUDA backend first")?;
        if metadata.len() > 4096 {
            return Err("Invalid CUDA installation manifest".into());
        }
        let installation: Installed =
            serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Read CUDA installation: {e}"))?;
        let (name, digest) = identity(&self.directory)?;
        if installation.version != 1
            || installation.distribution != name
            || installation.identity != digest
        {
            return Err(
                "CUDA installation belongs to a different storage directory; it was not started"
                    .into(),
            );
        }
        Ok(installation)
    }

    pub fn installed_payload_checksum(&self) -> Option<String> {
        self.installation().ok()?.payload_checksum
    }

    pub fn storage_path(&self) -> PathBuf {
        self.directory.join("distribution/ext4.vhdx")
    }

    pub fn storage_sizes(&self) -> Result<(u64, u64), String> {
        #[cfg(windows)]
        {
            storage::sizes(&self.storage_path())
        }
        #[cfg(not(windows))]
        {
            Err("CUDA storage requires Windows and WSL 2".into())
        }
    }

    pub async fn status(&self) -> Status {
        let mut guard = self.process.lock().await;
        let running = guard
            .as_mut()
            .is_some_and(|p| p.child.try_wait().is_ok_and(|s| s.is_none()));
        let result = self.installation();
        drop(guard);
        let checks = compatibility::checks().await;
        let supported = checks.iter().all(|c| c.passed);
        let blocked = checks.iter().filter(|c| !c.passed).map(|c| c.detail.as_str()).collect::<Vec<_>>().join(" ");
        Status {
            supported,
            installed: result.is_ok(),
            running,
            update_available: false,
            checks,
            detail: if !supported {
                blocked
            } else if running {
                "CUDA runtime running. Use Test CUDA in the environment settings to verify a real GPU calculation.".into()
            } else {
                result
                    .map(|_| "CUDA runtime installed; starts only when needed.".into())
                    .unwrap_or_else(|e| e)
            },
        }
    }

    pub async fn install(&self, agent: &Path) -> Result<(), String> {
        let checks = compatibility::checks().await;
        if checks.iter().any(|c| !c.passed) {
            return Err(checks.iter().filter(|c| !c.passed).map(|c| c.detail.as_str()).collect::<Vec<_>>().join(" "));
        }
        let mut guard = self.process.lock().await;
        if guard
            .as_mut()
            .is_some_and(|p| !p.child.try_wait().is_ok_and(|s| s.is_some()))
        {
            return Err(
                "Stop CUDA containers and shut down their runtime before updating it".into(),
            );
        }
        *guard = None;
        let _ownership = self.ownership()?;
        let assets = self.directory.join("bootstrap");
        tokio::fs::create_dir_all(&assets)
            .await
            .map_err(|e| e.to_string())?;
        for (name, contents) in [
            ("install.ps1", include_str!("../../install.ps1")),
            ("paths.ps1", include_str!("../../paths.ps1")),
            ("setup.sh", include_str!("../../setup.sh")),
            ("install-oci.py", include_str!("../../install-oci.py")),
            ("start.sh", include_str!("../../start.sh")),
            ("wsl.conf", include_str!("../../wsl.conf")),
        ] {
            tokio::fs::write(assets.join(name), contents)
                .await
                .map_err(|e| e.to_string())?;
        }
        let log =
            std::fs::File::create(self.directory.join("setup.log")).map_err(|e| e.to_string())?;
        let mut command = hidden("powershell.exe");
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(assets.join("install.ps1"))
            .arg("-DataDirectory")
            .arg(&self.directory)
            .arg("-AgentPath")
            .arg(agent)
            .arg("-AssetsDirectory")
            .arg(&assets)
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        // Installation is deliberately not cancelled halfway through WSL import.
        // A failure leaves its owned disk intact and can be retried explicitly.
        let status = command
            .status()
            .await
            .map_err(|e| format!("Start CUDA setup: {e}"))?;
        if !status.success() {
            return Err(setup_failure(&self.directory.join("setup.log")));
        }
        self.installation()?;
        *guard = None;
        Ok(())
    }

    pub async fn current_endpoint(&self) -> Result<Endpoint, String> {
        let mut guard = self.process.lock().await;
        let process = guard.as_mut().ok_or("The CUDA runtime is stopped")?;
        if process.cleanup_only { return Err("CUDA cleanup is in progress; retry when deletion finishes".into()); }
        if process
            .child
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err(
                "The CUDA runtime exited; stop and start the container to reconnect".into(),
            );
        }
        Ok(process.endpoint.clone())
    }

    pub async fn ensure_started(&self) -> Result<Endpoint, String> {
        let mut guard = self.process.lock().await;
        self.start_locked(&mut guard, None).await
    }

    /// Delete through the owned live runtime, or a temporary current helper.
    /// Holding the process lock prevents workload operations during maintenance.
    pub async fn cleanup_request(&self, agent: &[u8], path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        if !matches!(path, "/v1/containers/delete" | "/v1/snapshots/delete") {
            return Err("Unsupported CUDA cleanup operation".into());
        }
        let mut guard = self.process.lock().await;
        let endpoint = match self.start_locked(&mut guard, Some(agent)).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                if guard.as_ref().is_some_and(|p| p.cleanup_only) {
                    if let Err(shutdown) = self.shutdown_locked(&mut guard).await {
                        return Err(format!("{error}. Cleanup shutdown also needs attention: {shutdown}"));
                    }
                }
                return Err(error);
            }
        };
        let result = async {
            let response = self.client.post(format!("{}{path}", endpoint.base_url))
                .bearer_auth(&endpoint.token).json(body).timeout(Duration::from_secs(150))
                .send().await.map_err(|e| format!("CUDA cleanup request failed: {e}"))?;
            let status = response.status();
            let value: serde_json::Value = response.json().await.map_err(|e| format!("Read CUDA cleanup response: {e}"))?;
            if !status.is_success() {
                return Err(format!("CUDA cleanup failed: {}", value["error"].as_str().unwrap_or(status.canonical_reason().unwrap_or("runtime operation failed"))));
            }
            Ok(value)
        }.await;
        if guard.as_ref().is_some_and(|p| p.cleanup_only) {
            self.shutdown_locked(&mut guard).await.map_err(|e| format!("CUDA cleanup shutdown did not finish; retry deletion. {e}"))?;
        }
        result
    }

    async fn start_locked(&self, guard: &mut Option<Process>, cleanup_agent: Option<&[u8]>) -> Result<Endpoint, String> {
        if !cfg!(windows) {
            return Err("WSL CUDA containers require Windows".into());
        }
        if let Some(process) = guard.as_mut() {
            if process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                if process.cleanup_only && cleanup_agent.is_none() {
                    return Err("CUDA cleanup is in progress; retry deletion before starting workloads".into());
                }
                if self.health(&process.endpoint).await {
                    return Ok(process.endpoint.clone());
                }
                return Err(
                    "CUDA runtime is not responding. No live workload was restarted.".into(),
                );
            }
        }
        *guard = None;
        let installation = self.installation()?;
        let ownership = self.ownership()?;
        self.verify_owned(&installation, false, cleanup_agent.is_some()).await?;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        drop(listener);
        let endpoint = Endpoint {
            base_url: format!("http://127.0.0.1:{port}"),
            token: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        };
        let log =
            std::fs::File::create(self.directory.join("runtime.log")).map_err(|e| e.to_string())?;
        let mut command = hidden("wsl.exe");
        command
            .args([
                "-d",
                &installation.distribution,
                "-u",
                "root",
                "--exec",
                "/bin/bash",
            ]);
        if cleanup_agent.is_some() {
            command.arg("-c").arg(include_str!("../../cleanup.sh").replace("\r\n", "\n")).arg("yougori-cleanup");
        } else {
            command.arg("/usr/local/sbin/opendock-cuda-start");
        }
        command.stdin(Stdio::piped())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        let mut child = command
            .spawn()
            .map_err(|e| format!("Start WSL CUDA runtime: {e}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or("CUDA launcher has no input pipe")?;
        // Retain ownership even if payload transfer or health checking fails.
        *guard = Some(Process {
            child,
            endpoint: endpoint.clone(),
            _ownership: ownership,
            cleanup_only: cleanup_agent.is_some(),
        });
        stdin.write_all(format!("{}\n{port}\n", endpoint.token).as_bytes()).await.map_err(|e| e.to_string())?;
        if let Some(agent) = cleanup_agent {
            stdin.write_all(format!("{}\n", agent.len()).as_bytes()).await.map_err(|e| e.to_string())?;
            stdin.write_all(agent).await.map_err(|e| e.to_string())?;
        }
        drop(stdin);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if guard
                .as_mut()
                .unwrap()
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                let log =
                    std::fs::read_to_string(self.directory.join("runtime.log")).unwrap_or_default();
                if log.contains("already owned by another Yougori process")
                    || log.contains("already owned by another OpenDock process") {
                    return Err("[OPENDOCK_RUNTIME_BUSY] An abandoned Yougori CUDA runtime is still running. Press Stop to recover it. A runtime owned by another live app will not be stopped.".into());
                }
                return Err(startup_failure(&log, &self.directory.join("runtime.log"), cleanup_agent.is_some()));
            }
            if self.health(&endpoint).await {
                return Ok(endpoint);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("CUDA runtime did not become ready. It was not force-restarted; inspect its runtime log.".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn health(&self, endpoint: &Endpoint) -> bool {
        self.client
            .get(format!("{}/v1/health", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let mut guard = self.process.lock().await;
        self.shutdown_locked(&mut guard).await
    }

    pub async fn owns_runtime(&self) -> bool { self.process.lock().await.is_some() }

    async fn shutdown_locked(&self, guard: &mut Option<Process>) -> Result<(), String> {
        let Some(process) = guard.as_mut() else {
            return Ok(());
        };
        if process
            .child
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_none()
        {
            let response = self
                .client
                .post(format!("{}/v1/system/shutdown", process.endpoint.base_url))
                .bearer_auth(&process.endpoint.token)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err("CUDA runtime refused shutdown".into());
            }
            tokio::time::timeout(Duration::from_secs(45), process.child.wait())
                .await
                .map_err(|_| {
                    "CUDA runtime is still shutting down; its disk was not force-detached"
                })?
                .map_err(|e| e.to_string())?;
        }
        let installation = self.installation()?;
        self.verify_owned(&installation, true, false).await?;
        self.verify_owned(&installation, false, true).await?;
        *guard = None;
        Ok(())
    }

    /// Caller holds the runtime-wide operation writer lock and has verified
    /// there are no running/paused containers in the agent, not just the UI.
    pub async fn compact_idle_storage(&self) -> Result<(), String> {
        #[cfg(windows)] {
            let mut guard = self.process.lock().await;
            if guard.is_none() { return Err("CUDA runtime ownership is missing; storage was not changed.".into()); }
            self.shutdown_locked(&mut guard).await?;
            let ownership = self.ownership()?;
            self.compact_verified_storage(ownership).await
        }
        #[cfg(not(windows))] { Err("CUDA compaction requires Windows".into()) }
    }

    /// Compact an already stopped disk without booting an obsolete guest,
    /// downloading an update, or requiring a working GPU driver.
    pub async fn compact_stopped_storage(&self) -> Result<(), String> {
        #[cfg(windows)] {
            let mut guard = self.process.lock().await;
            if let Some(process) = guard.as_mut() {
                if process.child.try_wait().map_err(|e| e.to_string())?.is_none() {
                    return Err("CUDA is still running; offline disk compaction was skipped.".into());
                }
            }
            *guard = None;
            let ownership = self.ownership()?;
            self.compact_verified_storage(ownership).await
        }
        #[cfg(not(windows))] { Err("CUDA compaction requires Windows".into()) }
    }

    #[cfg(windows)]
    async fn compact_verified_storage(&self, ownership: std::fs::File) -> Result<(), String> {
        self.verify_owned(&self.installation()?, false, true).await?;
        let path = self.storage_path();
        // Keep ownership in the blocking task even if its caller is cancelled.
        tokio::task::spawn_blocking(move || {
            let _ownership = ownership;
            storage::compact(&path)
        }).await.map_err(|e| format!("CUDA compaction task: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "compacts only the explicitly prepared idle integration-runtime VHDX"]
    async fn compact_pretrimmed_test_disk() -> Result<(), String> {
        let path = PathBuf::from(std::env::var("OPENDOCK_CUDA_TEST_ROOT").map_err(|_| "test root required")?);
        let expected = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../build/cuda/integration-runtime").canonicalize().map_err(|e| e.to_string())?;
        if path.canonicalize().map_err(|e| e.to_string())? != expected { return Err("Refusing user CUDA disk".into()); }
        let runtime = CudaRuntime::new(path)?;
        let _owner = runtime.ownership()?;
        runtime.verify_owned(&runtime.installation()?, false, true).await?;
        let before = runtime.storage_sizes()?.1;
        storage::compact(&runtime.storage_path())?;
        eprintln!("Native VHDX compaction: {before} -> {}", runtime.storage_sizes()?.1);
        Ok(())
    }
    #[tokio::test]
    async fn cleanup_rejects_workload_operations_before_starting_any_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = CudaRuntime::new(directory.path().to_owned()).unwrap();
        for path in ["/v1/containers/action", "/v1/containers/provision", "/v1/containers/exec", "/v1/snapshots/restore"] {
            let error = runtime.cleanup_request(b"unused", path, &serde_json::json!({"id":"test"})).await.unwrap_err();
            assert_eq!(error, "Unsupported CUDA cleanup operation");
        }
        assert!(runtime.process.lock().await.is_none());
        assert!(!directory.path().join("runtime-owner.lock").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cleanup_reuses_a_live_runtime_and_keeps_it_running() {
        use tokio::io::AsyncReadExt;
        let directory = tempfile::tempdir().unwrap();
        let runtime = CudaRuntime::new(directory.path().to_owned()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint { base_url: format!("http://{}", listener.local_addr().unwrap()), token: "test-token".into() };
        let requests = tokio::spawn(async move {
            for expected in ["GET /v1/health ", "POST /v1/containers/delete ", "GET /v1/health ", "POST /v1/snapshots/delete "] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                        let length: usize = header.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap_or("0").parse().unwrap();
                        if bytes.len() >= end + 4 + length { break; }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.starts_with(expected), "{request}");
                assert!(request.to_lowercase().contains("authorization: bearer test-token"));
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            }
        });
        let child = hidden("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"]).kill_on_drop(true).spawn().unwrap();
        *runtime.process.lock().await = Some(Process { child, endpoint, _ownership: runtime.ownership().unwrap(), cleanup_only: false });
        for path in ["/v1/containers/delete", "/v1/snapshots/delete"] {
            assert_eq!(runtime.cleanup_request(b"unused for live runtime", path, &serde_json::json!({"id":"test"})).await.unwrap(), serde_json::json!({}));
        }
        requests.await.unwrap();
        // A maintenance-only helper can never become the workload runtime.
        runtime.process.lock().await.as_mut().unwrap().cleanup_only = true;
        assert!(runtime.current_endpoint().await.unwrap_err().contains("cleanup"));
        assert!(runtime.ensure_started().await.unwrap_err().contains("cleanup"));
        let mut process = runtime.process.lock().await.take().unwrap();
        assert!(process.child.try_wait().unwrap().is_none());
        process.child.kill().await.unwrap();
        process.child.wait().await.unwrap();
    }

    #[test]
    fn startup_errors_identify_storage_failures_without_blaming_the_driver() {
        let message = startup_failure("2026/09/21 Yougori storage preparation failed: unexpected files at /var/lib/nerdctl; preserved\n", Path::new("runtime.log"), true);
        assert!(message.contains("unexpected files at /var/lib/nerdctl"));
        assert!(message.contains("Existing container data was kept"));
        assert!(!message.contains("driver"));
        assert!(startup_failure("", Path::new("runtime.log"), true).starts_with("CUDA cleanup helper"));
    }

    #[test]
    fn setup_errors_report_the_actual_failure_without_blaming_prerequisites() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("setup.log");
        std::fs::write(&log, format!("{}\n\0YOUGORI_CUDA_SETUP_ERROR: CUDA setup file is missing: C:\\Example\\opendock-mount-helper\nPowerShell diagnostic details\n", "download progress\n".repeat(2000))).unwrap();
        let message = setup_failure(&log);
        assert!(message.contains("CUDA setup file is missing: C:\\Example\\opendock-mount-helper"));
        assert!(message.contains("Existing container disks were kept"));
        assert!(!message.contains("driver"));
        assert!(!message.contains("download progress"));
        assert!(setup_failure(&directory.path().join("missing.log")).contains("Setup log:"));
    }
    #[test]
    fn names_are_stable_scoped_and_never_shell_arguments() {
        let directory = std::env::temp_dir().join("Yougori CUDA test");
        let (name, digest) = identity(&directory).unwrap();
        assert!(name.starts_with("OpenDock-CUDA-"));
        assert_eq!(name.len(), 26);
        assert_eq!(digest.len(), 64);
        assert_ne!(identity(&directory.join("other")).unwrap().0, name);
        assert!(identity(Path::new("relative")).is_err());
        #[cfg(windows)]
        {
            assert_eq!(
                identity(Path::new("C:/Users/Test/CUDA/")).unwrap(),
                identity(Path::new("c:\\users\\test\\cuda")).unwrap()
            );
            assert_eq!(
                identity(Path::new("\\\\?\\C:\\Users\\Test\\CUDA")).unwrap(),
                identity(Path::new("c:\\users\\test\\cuda")).unwrap()
            );
        }
    }
    #[test]
    #[cfg(windows)]
    fn live_owner_prevents_recovery_or_installation() {
        let directory = tempfile::tempdir().unwrap();
        let first = CudaRuntime::new(directory.path().to_owned()).unwrap();
        let second = CudaRuntime::new(directory.path().to_owned()).unwrap();
        let ownership = first.ownership().unwrap();
        assert!(second
            .ownership()
            .unwrap_err()
            .contains("Another live Yougori"));
        drop(ownership);
        assert!(second.ownership().is_ok());
    }
    #[test]
    fn copied_or_malformed_installation_is_not_adopted() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = CudaRuntime::new(directory.path().to_owned()).unwrap();
        assert!(runtime.installation().is_err());
        let (name, digest) = identity(directory.path()).unwrap();
        std::fs::write(
            directory.path().join("installed.json"),
            serde_json::json!({"version":1,"distribution":name,"identity":digest}).to_string(),
        )
        .unwrap();
        assert!(runtime.installation().is_ok());
        std::fs::write(
            directory.path().join("installed.json"),
            serde_json::json!({"version":1,"distribution":"Ubuntu-22.04","identity":digest})
                .to_string(),
        )
        .unwrap();
        assert!(runtime.installation().is_err());
    }

    #[test]
    fn moved_cuda_disk_is_preserved_when_wsl_cannot_verify_its_original_location() {
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join("new/runtime/cuda");
        let original = root.path().join("old/runtime/cuda");
        fs::create_dir_all(current.join("distribution")).unwrap();
        fs::write(current.join("distribution/ext4.vhdx"), b"test disk").unwrap();
        let (name, digest) = identity(&original).unwrap();
        fs::write(current.join("installed.json"), serde_json::json!({
            "version": 1, "distribution": name, "identity": digest
        }).to_string()).unwrap();
        assert!(!CudaRuntime::restore_relocated_installation(&current, &original).unwrap());
        assert_eq!(fs::read(current.join("distribution/ext4.vhdx")).unwrap(), b"test disk");
        assert!(!original.exists());
    }

    #[cfg(windows)]
    fn isolated_d_recovery_root() -> Result<PathBuf, String> {
        let root = PathBuf::from(std::env::var_os("YOUGORI_CUDA_RECOVERY_TEST_ROOT").ok_or("Set YOUGORI_CUDA_RECOVERY_TEST_ROOT to a fresh dedicated D: recovery fixture")?);
        let base = Path::new("D:/Yougori-Releases/reliability-review-20261002").canonicalize().map_err(|error| error.to_string())?;
        if !root.is_absolute() || root.parent().and_then(|parent| parent.canonicalize().ok()).as_ref() != Some(&base) {
            return Err("CUDA crash recovery tests only accept the dedicated D: reliability review directory".into());
        }
        let name = root.file_name().and_then(|name| name.to_str()).ok_or("Invalid fixture directory")?;
        let suffix = name.strip_prefix("cuda-recovery-").ok_or("Fixture directory needs a unique cuda-recovery-UUID name")?;
        uuid::Uuid::parse_str(suffix).map_err(|_| "Fixture directory UUID is invalid")?;
        Ok(base.join(name))
    }

    #[cfg(windows)]
    async fn recovery_test_post(runtime: &CudaRuntime, endpoint: &Endpoint, path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
        let response = runtime.client.post(format!("{}{path}", endpoint.base_url)).bearer_auth(&endpoint.token)
            .timeout(Duration::from_secs(180)).json(&body).send().await.map_err(|error| error.to_string())?;
        let success = response.status().is_success();
        let value: serde_json::Value = response.json().await.map_err(|error| error.to_string())?;
        if !success { return Err(format!("Disposable CUDA fixture request failed: {}", value["error"].as_str().unwrap_or("guest operation failed"))); }
        Ok(value)
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "internal process owner for the explicitly isolated D: CUDA crash recovery test"]
    async fn cuda_recovery_fixture_owner() -> Result<(), String> {
        let root = isolated_d_recovery_root()?;
        let fixture_id = root.file_name().unwrap().to_string_lossy().to_string();
        if fs::read_to_string(root.join("yougori-recovery-fixture.txt")).map_err(|error| error.to_string())? != fixture_id {
            return Err("The disposable CUDA fixture ownership marker is missing; no runtime was started".into());
        }
        let runtime = CudaRuntime::new(root.clone())?;
        let endpoint = runtime.ensure_started().await?;
        recovery_test_post(&runtime, &endpoint, "/v1/containers/action", serde_json::json!({"id":fixture_id,"action":"start","networkAccess":false})).await?;
        fs::write(root.join("crash-owner-ready.json"), serde_json::json!({"pid":std::process::id()}).to_string()).map_err(|error| error.to_string())?;
        // This subprocess deliberately models an engine killed without cleanup.
        // Its parent owns the exact child handle and the only fixture storage.
        tokio::time::sleep(Duration::from_secs(600)).await;
        runtime.shutdown().await
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "installs a fresh owned CUDA distribution on D: and tests live ownership, engine crash recovery, GPU execution and preserved files"]
    async fn isolated_d_cuda_engine_crash_recovers_only_after_live_owner_exits() -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        let root = isolated_d_recovery_root()?;
        // Fresh-only: this test never adopts a user's existing distribution.
        fs::create_dir(&root).map_err(|error| format!("Recovery fixture must be a new directory: {error}"))?;
        let fixture_id = root.file_name().unwrap().to_string_lossy().to_string();
        fs::write(root.join("yougori-recovery-fixture.txt"), &fixture_id).map_err(|error| error.to_string())?;
        let payload = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src-tauri/resources/runtime/cuda/opendock-agent").canonicalize().map_err(|error| error.to_string())?;
        let runtime = CudaRuntime::new(root.clone())?;
        runtime.install(&payload).await?;
        let result = async {
            let endpoint = runtime.ensure_started().await?;
            let separate = CudaRuntime::new(root.clone())?;
            assert!(separate.recover_abandoned().await.unwrap_err().contains("Another live Yougori"));
            recovery_test_post(&runtime, &endpoint, "/v1/containers/provision", serde_json::json!({"id":fixture_id,"image":"docker.io/library/python:3.12-slim","command":"sleep 2147483647","cpus":1,"memoryBytes":536870912,"networkAccess":false,"gpuAccess":true})).await?;
            recovery_test_post(&runtime, &endpoint, "/v1/containers/action", serde_json::json!({"id":fixture_id,"action":"start","networkAccess":false})).await?;
            let probe = format!("printf '{}' > /root/yougori-recovery-marker\npython3 - <<'YOUGORI_CUDA_PROBE'\n{}\nYOUGORI_CUDA_PROBE", fixture_id, include_str!("../../kernel-probe.py"));
            let initial = recovery_test_post(&runtime, &endpoint, "/v1/containers/exec", serde_json::json!({"id":fixture_id,"command":probe})).await?;
            if initial["exitCode"] != 0 || !initial["stdout"].as_str().unwrap_or_default().contains("CUDA KERNEL PASS") { return Err("Fresh D: fixture CUDA kernel probe failed".into()); }
            runtime.shutdown().await?;
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
            let mut owner = OwnedChild(std::process::Command::new(std::env::current_exe().map_err(|error| error.to_string())?)
                .creation_flags(0x08000000).args(["--ignored","--exact","tests::cuda_recovery_fixture_owner","--nocapture"])
                .env("YOUGORI_CUDA_RECOVERY_TEST_ROOT", &root).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().map_err(|error| error.to_string())?);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
            while !root.join("crash-owner-ready.json").exists() {
                if owner.0.try_wait().map_err(|error| error.to_string())?.is_some() { return Err("Disposable engine owner exited before its readiness marker".into()); }
                if tokio::time::Instant::now() > deadline { return Err("Disposable engine owner did not become ready".into()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(separate.recover_abandoned().await.unwrap_err().contains("Another live Yougori"));
            owner.0.kill().map_err(|error| error.to_string())?;
            owner.0.wait().map_err(|error| error.to_string())?;
            separate.recover_abandoned().await?;
            let installation = separate.installation()?;
            separate.verify_owned(&installation, false, true).await?;
            assert_eq!(separate.storage_path(), root.join("distribution/ext4.vhdx"));
            let endpoint = separate.ensure_started().await?;
            recovery_test_post(&separate, &endpoint, "/v1/containers/action", serde_json::json!({"id":fixture_id,"action":"start","networkAccess":false})).await?;
            let preserved = recovery_test_post(&separate, &endpoint, "/v1/containers/exec", serde_json::json!({"id":fixture_id,"command":"cat /root/yougori-recovery-marker; test -e /dev/dxg"})).await?;
            if preserved["exitCode"] != 0 || preserved["stdout"].as_str() != Some(fixture_id.as_str()) { return Err("D: runtime crash recovery lost persistent guest data or GPU access".into()); }
            recovery_test_post(&separate, &endpoint, "/v1/containers/delete", serde_json::json!({"id":fixture_id})).await?;
            separate.shutdown().await?;
            eprintln!("Verified isolated D: CUDA GPU execution, live-owner protection, crash recovery, stopped postcondition and preserved guest files.");
            Ok::<(), String>(())
        }.await;
        // Preserve fixture evidence. Only this newly installed registration may
        // be removed, and only after exclusive ownership plus stopped verification.
        runtime.shutdown().await?;
        let cleanup = CudaRuntime::new(root.clone())?;
        cleanup.recover_abandoned().await?;
        let _ownership = cleanup.ownership()?;
        let installation = cleanup.installation()?;
        cleanup.verify_owned(&installation, false, true).await?;
        let status = hidden("wsl.exe").args(["--unregister", &installation.distribution]).status().await.map_err(|error| error.to_string())?;
        if !status.success() { return Err("Disposable D: CUDA registration cleanup needs attention; user registrations were untouched".into()); }
        result
    }

    #[tokio::test]
    #[ignore = "requires the explicitly installed build/cuda/integration-runtime test distribution"]
    async fn native_lifecycle_runs_cuda_and_preserves_data_on_shutdown() -> Result<(), String> {
        let root = PathBuf::from(
            std::env::var("OPENDOCK_CUDA_TEST_ROOT")
                .map_err(|_| "Set OPENDOCK_CUDA_TEST_ROOT to the dedicated test runtime")?,
        );
        let expected = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../build/cuda/integration-runtime")
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if root.canonicalize().map_err(|e| e.to_string())? != expected {
            return Err("This test cannot run against user CUDA storage".into());
        }
        let runtime = CudaRuntime::new(root)?;
        if runtime.current_endpoint().await.is_ok() {
            return Err("Fresh manager unexpectedly has an endpoint".into());
        }
        let endpoint = runtime.ensure_started().await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| e.to_string())?;
        let id = format!("cuda-native-test-{}", uuid::Uuid::new_v4().simple());
        async fn post(
            client: &reqwest::Client,
            endpoint: &Endpoint,
            path: &str,
            body: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            let response = client
                .post(format!("{}{path}", endpoint.base_url))
                .bearer_auth(&endpoint.token)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let success = response.status().is_success();
            let value: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            if !success {
                return Err(value.to_string());
            }
            Ok(value)
        }
        let result = async {
            post(&client, &endpoint, "/v1/containers/provision", serde_json::json!({"id":id,"image":"docker.io/library/python:3.12-slim","command":"sleep 2147483647","cpus":1,"memoryBytes":536870912,"networkAccess":false,"gpuAccess":true})).await?;
            post(&client, &endpoint, "/v1/containers/action", serde_json::json!({"id":id,"action":"start","networkAccess":false})).await?;
            let command = format!("printf survived > /root/opendock-shutdown-test\npython3 - <<'OPENDOCK_CUDA_PROBE'\n{}\nOPENDOCK_CUDA_PROBE", include_str!("../../kernel-probe.py"));
            let reply = post(&client, &endpoint, "/v1/containers/exec", serde_json::json!({"id":id,"command":command})).await?;
            if reply["exitCode"] != 0 || !reply["stdout"].as_str().unwrap_or_default().contains("CUDA KERNEL PASS") { return Err(reply.to_string()); }
            runtime.shutdown().await?;
            if runtime.status().await.running { return Err("Runtime remained running after shutdown".into()); }
            let endpoint = runtime.ensure_started().await?;
            post(&client, &endpoint, "/v1/containers/action", serde_json::json!({"id":id,"action":"start","networkAccess":false})).await?;
            let reply = post(&client, &endpoint, "/v1/containers/exec", serde_json::json!({"id":id,"command":"test -f /root/opendock-shutdown-test && test -e /dev/dxg"})).await?;
            if reply["exitCode"] != 0 { return Err("CUDA container did not survive full runtime shutdown".into()); }
            Ok(())
        }.await;
        if let Ok(endpoint) = runtime.current_endpoint().await {
            let cleanup = post(
                &client,
                &endpoint,
                "/v1/containers/delete",
                serde_json::json!({"id":id,"action":"delete","networkAccess":false}),
            )
            .await;
            if let Err(error) = cleanup {
                eprintln!("CUDA test cleanup: {error}");
            }
        }
        let shutdown = runtime.shutdown().await;
        result.and(shutdown)
    }
}
