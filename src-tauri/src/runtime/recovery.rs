use super::RuntimeManager;
use crate::models::{Environment, RuntimeProviderKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub environment_id: String,
    pub provider: RuntimeProviderKind,
    pub storage_root: String,
    pub disk_path: String,
    pub status: String,
    pub actions: Vec<String>,
    pub ownership_released: bool,
    pub ready_to_start: bool,
    pub error: Option<String>,
    pub recovery_action: Option<String>,
}

pub(crate) const MISSING_OCI_STORAGE:&str = "[YOUGORI_DURABLE_STORAGE_MISSING]";
fn saved_oci_storage_required(environment:&Environment) -> bool {
    crate::commands::provider(environment) == RuntimeProviderKind::YougoriOci &&
    (environment.last_opened_at.is_some() ||
     matches!(environment.status,crate::models::EnvironmentStatus::Stopped | crate::models::EnvironmentStatus::Running | crate::models::EnvironmentStatus::Paused) ||
     environment.last_error.as_ref().is_some_and(|error|error.contains(MISSING_OCI_STORAGE)))
}

fn require_original_oci_disk(disk:&std::path::Path) -> Result<(),String> {
    if !std::fs::symlink_metadata(disk).is_ok_and(|metadata|metadata.is_file() && !metadata.file_type().is_symlink()) {
        return Err(format!("{MISSING_OCI_STORAGE} The saved container disk is unavailable, missing or redirected on its original storage root. Restore that durable disk before retrying; no empty replacement was created."));
    }
    Ok(())
}

impl RuntimeManager {
    pub(crate) fn ensure_saved_oci_storage(&self,environment:&Environment) -> Result<(),String> {
        if !saved_oci_storage_required(environment) {return Ok(());}
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let selected = self.storage_runtime(id).map_err(|error|format!("{MISSING_OCI_STORAGE} Could not verify this finalized container's original durable storage: {}",crate::lifecycle::safe_diagnostic(&error)))?;
        let runtime = selected.as_deref().unwrap_or(self);
        require_original_oci_disk(&runtime.data_root.join("appliance/system.qcow2"))
    }
    /// Resolve the persisted drive and provider before doing any recovery. A
    /// missing/changed drive never redirects recovery to the default runtime.
    pub async fn recover_environment_report(&self, environment: &Environment) -> Result<RecoveryReport, String> {
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let selected = self.storage_runtime(id)?;
        let runtime = selected.as_deref().unwrap_or(self);
        let provider = crate::commands::provider(environment);
        let disk = match provider {
            RuntimeProviderKind::YougoriCuda => runtime.cuda.storage_path(),
            RuntimeProviderKind::YougoriOci => runtime.data_root.join("appliance/system.qcow2"),
            RuntimeProviderKind::Qemu => runtime.data_root.join("environments").join(id).join("system.qcow2"),
            _ => return Err("This provider does not support abandoned-runtime recovery".into()),
        };
        let mut report = RecoveryReport {
            environment_id: environment.id.clone(), provider: provider.clone(),
            storage_root: if provider == RuntimeProviderKind::YougoriCuda {
                disk.parent().and_then(std::path::Path::parent).and_then(std::path::Path::parent).unwrap_or(&runtime.data_root).display().to_string()
            } else { runtime.data_root.display().to_string() }, disk_path: disk.display().to_string(),
            status: "blocked".into(), actions: vec!["Verified saved provider and original storage route".into()],
            ownership_released: false, ready_to_start: false, error: None, recovery_action: None,
        };
        let recovered = async {
            if provider == RuntimeProviderKind::Qemu && !std::fs::symlink_metadata(&disk).is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink()) {
                return Err("The saved VM disk is missing or redirected; reconnect the original storage before recovery".into());
            }
            if provider.is_container() {
                let routed_provider = runtime.container_provider(id)?;
                if routed_provider != provider { return Err("Saved environment provider and durable runtime route differ; no runtime was stopped".into()); }
                if provider == RuntimeProviderKind::YougoriOci {require_original_oci_disk(&disk)?;}
                runtime.recover_container_provider(&provider).await?;
                if provider == RuntimeProviderKind::YougoriOci { runtime.verify_external_appliance_idle().await?; }
                // CUDA recover_abandoned verifies the original WSL registration
                // and a stopped distribution while retaining exclusive ownership.
            } else {
                runtime.recover_orphaned_vm(id).await?;
                runtime.verify_external_vm_idle(id).await?;
            }
            Ok::<(), String>(())
        }.await;
        match recovered {
            Ok(()) => {
                report.status = "ready".into();
                report.actions.push("Recovered only verified abandoned processes, or verified runtime already idle".into());
                report.actions.push("Verified ownership release and start prerequisites without starting workloads".into());
                report.ownership_released = true;
                report.ready_to_start = true;
                if provider == RuntimeProviderKind::YougoriCuda {
                    // Disk ownership recovery and provider readiness are separate
                    // outcomes. An old payload or missing driver is still blocked.
                    if let Err(error) = runtime.require_cuda_installation().await {
                        report.status = "recoveredNeedsSetup".into();
                        report.ready_to_start = false;
                        report.error = Some(crate::lifecycle::safe_diagnostic(&error));
                        report.recovery_action = Some("Set up or update CUDA on this original storage drive, then retry Start".into());
                    }
                }
            }
            Err(error) => {
                report.error = Some(crate::lifecycle::safe_diagnostic(&error));
                report.recovery_action = Some("Close any live owner normally; reconnect the original storage drive or repair the verified provider, then retry recovery".into());
            }
        }
        Ok(report)
    }

    async fn verify_external_vm_idle(&self, id: &str) -> Result<(), String> {
        let disk = self.data_root.join("environments").join(id).join("system.qcow2");
        #[cfg(windows)] {
            let executables = vec![self.layout.qemu_system.clone(), self.layout.root.join("qemu-secure/qemu-system-x86_64.exe")];
            let name = format!("Yougori {id}");
            tokio::task::spawn_blocking(move || windows::check_idle_named(&disk, &executables, &name)).await.map_err(|e| e.to_string())?
        }
        #[cfg(target_os = "linux")] { linux_disk_idle(&disk) }
        #[cfg(target_os = "macos")] { macos_disk_idle(&disk).await }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] { let _ = disk; Err("Runtime ownership verification is unavailable".into()) }
    }

    async fn verify_external_appliance_idle(&self) -> Result<(), String> {
        let disk = self.data_root.join("appliance/system.qcow2");
        #[cfg(windows)] {
            let mut executables = vec![self.layout.qemu_system.clone()];
            if let Ok(exe) = std::env::current_exe() { if let Some(parent) = exe.parent() { executables.push(parent.join("runtime/qemu/qemu-system-x86_64.exe")); } }
            tokio::task::spawn_blocking(move || windows::check_idle_named(&disk, &executables, "Yougori Internal OCI Runtime")).await.map_err(|e| e.to_string())?
        }
        #[cfg(target_os = "linux")] { linux_disk_idle(&disk) }
        #[cfg(target_os = "macos")] { macos_disk_idle(&disk).await }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] { let _ = disk; Err("Runtime ownership verification is unavailable".into()) }
    }
    pub async fn recover_orphaned_vm(&self, id: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.recover_orphaned_vm(id)).await; }

        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        if self.vm_is_running(id).await? {
            return Err("This VM is owned by the current app. Use normal Shut down.".into());
        }
        self.check_external_vm(id, true).await
    }

    pub(super) async fn check_external_vm(&self, id: &str, recover: bool) -> Result<(), String> {
        super::vm::validate_runtime_identifier("virtual machine", id)?;
        #[cfg(target_os = "windows")]
        {
            let disk = self.data_root.join("environments").join(id).join("system.qcow2");
            let executables = vec![self.layout.qemu_system.clone(), self.layout.root.join("qemu-secure/qemu-system-x86_64.exe")];
            let name = format!("Yougori {id}");
            tokio::task::spawn_blocking(move || windows::check_named(&disk, &executables, recover, &name))
                .await.map_err(|error| format!("inspect VM runtime: {error}"))?
        }
        #[cfg(target_os = "linux")]
        { let _ = recover; linux_disk_idle(&self.data_root.join("environments").join(id).join("system.qcow2")) }
        #[cfg(target_os = "macos")]
        { let _ = recover; macos_disk_idle(&self.data_root.join("environments").join(id).join("system.qcow2")).await }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        { let _ = recover; Ok(()) }
    }
    /// Only explicitly confirmed recovery may terminate an abandoned runtime.
    /// A live runtime owned by this instance is left alone; normal deletion uses its agent.
    pub async fn recover_orphaned_container_runtime(&self) -> Result<(), String> {
        let mut owned = self.appliance.lock().await;
        if let Some(process) = owned.as_mut() {
            if process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Ok(());
            }
        }
        self.check_external_appliance(true).await
    }

    pub(super) async fn check_external_appliance(&self, recover: bool) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let disk = self.data_root.join("appliance/system.qcow2");
            let mut executables = vec![self.layout.qemu_system.clone()];
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    executables.push(parent.join("runtime/qemu/qemu-system-x86_64.exe"));
                }
            }
            tokio::task::spawn_blocking(move || windows::check(&disk, &executables, recover))
                .await
                .map_err(|error| format!("inspect container runtime: {error}"))?
        }
        #[cfg(target_os = "linux")]
        { let _ = recover; linux_disk_idle(&self.data_root.join("appliance/system.qcow2")) }
        #[cfg(target_os = "macos")]
        { let _ = recover; macos_disk_idle(&self.data_root.join("appliance/system.qcow2")).await }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = recover;
            Ok(())
        }
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[tokio::test]
    async fn missing_saved_oci_disk_blocks_recovery_and_repeated_start_without_replacement() {
        let data = tempfile::tempdir().unwrap();
        let resources = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(resources,data.path()).unwrap();
        let mut environment:Environment = serde_json::from_value(serde_json::json!({
            "id":"env-missing-oci","runtimeId":"env-missing-oci","name":"Missing storage fixture","kind":"container","provider":"yougoriOci","status":"stopped","runtime":"docker.io/library/alpine:latest","description":"Disposable","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":true}
        })).unwrap();
        manager.register_container_provider(&environment.id,&RuntimeProviderKind::YougoriOci).unwrap();
        let disk = manager.data_root.join("appliance/system.qcow2");
        let sentinel = manager.data_root.join("environments/preserved-metadata");
        std::fs::write(&sentinel,b"preserve this").unwrap();
        let recovery = manager.recover_environment_report(&environment).await.unwrap();
        assert_eq!(recovery.provider,RuntimeProviderKind::YougoriOci);
        assert_eq!(recovery.disk_path,disk.display().to_string());
        assert!(!recovery.ready_to_start);
        assert!(!recovery.ownership_released);
        assert!(recovery.error.unwrap().contains(MISSING_OCI_STORAGE));
        let error = manager.ensure_saved_oci_storage(&environment).unwrap_err();
        environment.status = crate::models::EnvironmentStatus::Error;
        environment.last_error = Some(error);
        assert!(manager.ensure_saved_oci_storage(&environment).unwrap_err().contains(MISSING_OCI_STORAGE));
        assert!(!disk.exists());
        assert_eq!(std::fs::read(sentinel).unwrap(),b"preserve this");
        // A record interrupted before its first successful provision remains
        // eligible for explicit provisioning retry, even though it has an ID.
        environment.status = crate::models::EnvironmentStatus::Error;
        environment.last_error = Some("Environment creation failed before provisioning".into());
        assert!(manager.ensure_saved_oci_storage(&environment).is_ok());
        environment.last_opened_at = Some("2026-10-02T00:00:00Z".into());
        assert!(manager.ensure_saved_oci_storage(&environment).is_err());
    }
}

#[cfg(target_os = "macos")]
async fn macos_disk_idle(disk: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(disk) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Inspect VM disk: {e}")),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err("Runtime disk is not a regular file; nothing was deleted.".into()),
        Ok(_) => {}
    }
    // macOS permits unlinking an open disk. Never interpret an unknown lock
    // owner as safe, and never kill an arbitrary QEMU just because of its name.
    let mut command = tokio::process::Command::new("/usr/sbin/lsof");
    command.args(["-nP", "-F", "p", "--"]).arg(disk);
    super::configure_background_process(&mut command);
    let output = tokio::time::timeout(std::time::Duration::from_secs(8), command.output())
        .await.map_err(|_| "Disk ownership check timed out; no disk was deleted or replaced")?
        .map_err(|e| format!("Cannot inspect disk ownership with macOS lsof: {e}"))?;
    macos_disk_check_result(output.status.code(), &output.stdout, &output.stderr)
}

#[cfg(any(target_os = "macos", test))]
fn macos_disk_check_result(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
    if stdout.split(|b| *b == b'\n').any(|line| line.first() == Some(&b'p') && line[1..].iter().any(u8::is_ascii_digit)) {
        return Err("[YOUGORI_RUNTIME_BUSY] Another process still holds this disk. Close the other Yougori instance normally. If it crashed, use macOS Activity Monitor to quit only its QEMU process, then retry. This preview does not force-stop unverified processes; your disk was preserved.".into());
    }
    if code == Some(1) && stdout.is_empty() && stderr.is_empty() { return Ok(()); }
    Err("Could not verify that the runtime disk is unused. No disk was deleted or replaced. Close other Yougori instances and retry.".into())
}

#[cfg(test)]
mod macos_tests {
    use super::*;
    #[test]
    fn lsof_only_accepts_an_unambiguous_unused_disk() {
        assert!(macos_disk_check_result(Some(1), b"", b"").is_ok());
        assert!(macos_disk_check_result(Some(0), b"p123\n", b"").unwrap_err().contains("YOUGORI_RUNTIME_BUSY"));
        for code in [None, Some(0), Some(2)] {
            assert!(macos_disk_check_result(code, b"", b"").is_err());
        }
        assert!(macos_disk_check_result(Some(1), b"", b"permission denied").is_err());
        assert!(macos_disk_check_result(Some(1), b"unexpected", b"").is_err());
    }
}

#[cfg(target_os = "linux")]
fn linux_disk_idle(disk: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::metadata(disk) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Inspect runtime disk: {e}")),
    };
    for process in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
        let process = process.map_err(|e| e.to_string())?;
        let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else { continue };
        if pid == std::process::id() { continue; }
        let Ok(files) = std::fs::read_dir(process.path().join("fd")) else { continue };
        for fd in files.flatten() {
            if std::fs::metadata(fd.path()).is_ok_and(|m| m.dev() == meta.dev() && m.ino() == meta.ino()) {
                return Err("[YOUGORI_RUNTIME_BUSY] Another process still holds this environment's disk. Close the other Yougori instance normally, wait for its runtime to exit, then retry. No disk was deleted or replaced.".into());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
mod windows {
    use std::{
        ffi::OsString,
        path::{Path, PathBuf},
    };
    use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        },
    };

    fn same_file(a: &Path, b: &Path) -> bool {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a
                .to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy()),
            _ => false,
        }
    }

    #[cfg(test)]
    fn appliance_args(args: &[OsString], disk: &Path) -> bool {
        runtime_args(args, disk, "Yougori Internal OCI Runtime")
    }

    fn runtime_args(args: &[OsString], disk: &Path, name: &str) -> bool {
        use yougori_cli::legacy_names;
        let previous = legacy_names::vm_name(name);
        let legacy_prefix = format!("{} ", legacy_names::PRODUCT);
        let legacy_runtime = format!("{} Internal OCI Runtime", legacy_names::PRODUCT);
        let microvm = name.strip_prefix("Yougori ").or_else(|| name.strip_prefix(legacy_prefix.as_str()))
            .filter(|_| name != "Yougori Internal OCI Runtime" && name != legacy_runtime)
            .map(|id| [format!("Yougori microVM {id}"), format!("{} microVM {id}", legacy_names::PRODUCT)]);
        let named = args.windows(2).any(|pair| {
            pair[0] == "-name" && (pair[1] == name
                || previous.as_ref().is_some_and(|value| pair[1] == value.as_str())
                || microvm.as_ref().is_some_and(|names| names.iter().any(|value| pair[1] == value.as_str())))
        });
        named
            && args.windows(2).any(|pair| {
                if pair[0] != "-blockdev" {
                    return false;
                }
                let Ok(value) =
                    serde_json::from_str::<serde_json::Value>(&pair[1].to_string_lossy())
                else {
                    return false;
                };
                value["driver"] == "file"
                    && value["filename"]
                        .as_str()
                        .is_some_and(|file| same_file(Path::new(file), disk))
            })
    }

    fn matches(process: &Process, disk: &Path, executables: &[PathBuf], name: &str) -> bool {
        process
            .exe()
            .is_some_and(|exe| executables.iter().any(|allowed| same_file(exe, allowed)))
            && runtime_args(process.cmd(), disk, name)
    }

    fn refresh(system: &mut System) {
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::Always)
                .with_cmd(UpdateKind::Always),
        );
    }

    pub(super) fn check_idle_named(disk: &Path, executables: &[PathBuf], name: &str) -> Result<(), String> {
        let mut system = System::new();
        refresh(&mut system);
        if system.processes().values().any(|process| matches(process, disk, executables, name)) {
            return Err("[YOUGORI_RECOVERY_NOT_READY] The verified runtime still holds this storage; recovery did not make it ready to start".into());
        }
        // A process with an unrecognized executable must never be force-stopped,
        // but it can still hold this disk. Verify exclusive access separately.
        match std::fs::symlink_metadata(disk) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("Cannot inspect recovered runtime disk: {error}")),
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => return Err("Runtime disk is not a regular owned file".into()),
            Ok(_) => {}
        }
        use std::os::windows::fs::OpenOptionsExt;
        let _exclusive = std::fs::OpenOptions::new().read(true).write(true).share_mode(0).open(disk)
            .map_err(|_| "[YOUGORI_RECOVERY_NOT_READY] Runtime storage is still held or is not writable; ownership release was not verified")?;
        Ok(())
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(super) fn check(disk: &Path, executables: &[PathBuf], recover: bool) -> Result<(), String> {
        check_named(disk, executables, recover, "Yougori Internal OCI Runtime")
    }

    // Use only a QMP endpoint read from the verified process arguments: the
    // private socket, or loopback TCP from a runtime an older version started.
    fn request_power(args: &[OsString], command: &str) -> Result<(), String> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;
        let endpoint = args.windows(2).find(|p| p[0] == "-qmp").and_then(|p| p[1].to_str()).ok_or("No verified QMP endpoint")?;
        if let Some(socket) = super::super::qmp_socket::path_from_argument(endpoint) {
            return super::super::qmp_socket::request_blocking(&socket, command, None, Duration::from_secs(2)).map(drop);
        }
        let address = endpoint.strip_prefix("tcp:127.0.0.1:")
            .and_then(|s| s.split(',').next()).and_then(|s| s.parse::<u16>().ok())
            .ok_or("No verified QMP endpoint")?;
        let mut stream = TcpStream::connect_timeout(&SocketAddr::from(([127,0,0,1],address)), Duration::from_secs(2)).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        for (id, command) in [("hello", "qmp_capabilities"), ("power", command)] {
            writeln!(stream, "{}", serde_json::json!({"execute":command,"id":id})).map_err(|e| e.to_string())?;
            let mut matched = false;
            for _ in 0..32 {
                line.clear();
                if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 { break; }
                let reply: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                if reply["id"] == id {
                    if reply.get("error").is_some() { return Err("QMP power request failed".into()); }
                    matched = true;
                    break;
                }
            }
            if !matched { return Err("QMP did not acknowledge the power request".into()); }
        }
        Ok(())
    }

    /// True when no live process owns this runtime, so stopping it cannot
    /// interrupt another running Yougori instance.
    fn abandoned(system: &mut System, pid: Pid) -> bool {
        refresh(system);
        match system.process(pid).and_then(|process| process.parent()) {
            Some(parent) => system.process(parent).is_none(),
            None => false,
        }
    }

    pub(super) fn check_named(disk: &Path, executables: &[PathBuf], recover: bool, name: &str) -> Result<(), String> {
        let mut system = System::new();
        refresh(&mut system);
        let candidates: Vec<Pid> = system
            .processes()
            .iter()
            .filter(|(_, process)| matches(process, disk, executables, name))
            .map(|(pid, _)| *pid)
            .collect();
        for pid in candidates {
            if !recover {
                // A runtime whose owning Yougori is gone is nobody's: reclaim it
                // here instead of asking the user to recover it by hand. Only a
                // runtime still owned by a live instance is reported as busy.
                if abandoned(&mut system, pid) {
                    eprintln!("Reclaiming an abandoned {name} runtime left by a previous Yougori instance.");
                } else if name != "Yougori Internal OCI Runtime" {
                    return Err("[YOUGORI_VM_RUNTIME_BUSY] This VM is still running in a previous Yougori runtime. Press Stop (Shut down) on this VM to recover it without deleting its disk. Close any other Yougori instance normally first.".into());
                } else {
                    return Err("[YOUGORI_RUNTIME_BUSY] An older Yougori runtime still holds the container disk. Press Stop (Shut down) on this environment and confirm stopping the abandoned runtime, then retry Start. This does not delete your containers. Close any other Yougori instance normally first.".into());
                }
            }
            // Pin the process before rechecking its identity. Never use taskkill by PID:
            // a recycled PID must not cause an unrelated process to be terminated.
            let handle = Handle(unsafe {
                OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid.as_u32(),
                )
            });
            if handle.0.is_null() {
                return Err("Cannot access the old container runtime. Close its owning Yougori instance, then retry recovery.".into());
            }
            if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_OBJECT_0 {
                continue;
            }
            refresh(&mut system);
            let Some(process) = system.process(pid) else {
                continue;
            };
            if !matches(process, disk, executables, name) {
                return Err("Runtime identity changed during recovery; no process was stopped. Retry recovery.".into());
            }
            let Some(parent) = process.parent() else {
                return Err(
                    "Cannot verify the old runtime's owner; no process was stopped.".into(),
                );
            };
            if system.process(parent).is_some() {
                return Err("Another live process owns this runtime. Close its Yougori instance normally before recovery; recovery will not stop it.".into());
            }
            let shutdown_wait_ms = if name == "Yougori Internal OCI Runtime" { 10000 } else { 30000 };
            if request_power(process.cmd(), "system_powerdown").is_ok()
                && unsafe { WaitForSingleObject(handle.0, shutdown_wait_ms) } == WAIT_OBJECT_0 { continue; }
            // Even when the guest cannot respond, QMP quit lets QEMU close its
            // QCOW2 metadata before the last-resort process termination.
            if request_power(process.cmd(), "quit").is_ok()
                && unsafe { WaitForSingleObject(handle.0, 5000) } == WAIT_OBJECT_0 { continue; }
            if unsafe { TerminateProcess(handle.0, 1) } == 0 {
                return Err(
                    "Windows could not stop the orphaned runtime. No environment data was removed."
                        .into(),
                );
            }
            if unsafe { WaitForSingleObject(handle.0, 5000) } != WAIT_OBJECT_0 {
                return Err("The orphaned runtime is still shutting down. Wait a moment, then retry recovery.".into());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixture_command(exe: &Path, disk: &Path) -> std::process::Command {
            fixture_command_named(exe, disk, "Yougori Internal OCI Runtime")
        }

        fn fixture_command_named(exe: &Path, disk: &Path, name: &str) -> std::process::Command {
            use std::os::windows::process::CommandExt;
            let mut command = std::process::Command::new(exe);
            command
                .creation_flags(0x0800_0000)
                .args([
                    "-machine",
                    "none",
                    "-m",
                    "32M",
                    "-S",
                    "-nodefaults",
                    "-no-user-config",
                    "-display",
                    "none",
                    "-monitor",
                    "none",
                    "-serial",
                    "none",
                    "-name",
                    name,
                    "-blockdev",
                ])
                .arg(
                    serde_json::json!({"driver":"file", "filename":disk,"node-name":"test-disk"})
                        .to_string(),
                )
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            command
        }

        #[test]
        #[ignore = "internal subprocess helper for the isolated orphan recovery test"]
        fn recovery_fixture_parent() {
            let Some(directory) = std::env::var_os("YOUGORI_RECOVERY_FIXTURE_DIR") else {
                return;
            };
            let directory = PathBuf::from(directory);
            let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources/runtime/qemu/qemu-system-x86_64.exe");
            let name = std::env::var("YOUGORI_RECOVERY_FIXTURE_NAME").unwrap_or_else(|_| "Yougori Internal OCI Runtime".into());
            let child = fixture_command_named(&exe, &directory.join("system.qcow2"), &name)
                .spawn()
                .unwrap();
            std::fs::write(directory.join("pid"), child.id().to_string()).unwrap();
            // std::process::Child deliberately survives this short-lived parent.
        }

        #[test]
        #[ignore = "launches isolated disk-only QEMU processes to verify orphan recovery safety"]
        fn recovery_stops_only_an_orphan_with_the_exact_disk() {
            use std::os::windows::process::CommandExt;
            let temp = tempfile::tempdir().unwrap();
            let disk = temp.path().join("system.qcow2");
            std::fs::write(&disk, vec![0u8; 4096]).unwrap();
            let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources/runtime/qemu/qemu-system-x86_64.exe");
            let allowed = vec![exe.clone()];
            let mut owned = fixture_command(&exe, &disk).spawn().unwrap();
            // Check both the startup guard and refusal to kill a live owner's runtime.
            let busy = check(&disk, &allowed, false);
            let refusal = check(&disk, &allowed, true);
            let postcondition = check_idle_named(&disk, &allowed, "Yougori Internal OCI Runtime");
            let still_running = owned.try_wait().unwrap().is_none();
            let _ = owned.kill();
            let _ = owned.wait();
            assert!(busy.unwrap_err().contains("YOUGORI_RUNTIME_BUSY"));
            assert!(refusal.unwrap_err().contains("Another live process"));
            assert!(still_running);
            assert!(postcondition.unwrap_err().contains("RECOVERY_NOT_READY"));

            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .creation_flags(0x0800_0000)
                .args([
                    "--exact",
                    "runtime::recovery::windows::tests::recovery_fixture_parent",
                    "--ignored",
                ])
                .env("YOUGORI_RECOVERY_FIXTURE_DIR", temp.path())
                .status()
                .unwrap();
            assert!(status.success());
            let pid: u32 = std::fs::read_to_string(temp.path().join("pid"))
                .unwrap()
                .parse()
                .unwrap();
            let handle =
                Handle(unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) });
            assert!(!handle.0.is_null());
            // Always clean up this test-owned process, including when an assertion fails.
            struct FixtureGuard(Handle);
            impl Drop for FixtureGuard {
                fn drop(&mut self) {
                    unsafe {
                        TerminateProcess(self.0 .0, 1);
                        WaitForSingleObject(self.0 .0, 5000);
                    }
                }
            }
            let guard = FixtureGuard(handle);
            let other_disk = temp.path().join("unrelated.qcow2");
            std::fs::write(&other_disk, b"keep me").unwrap();
            check(&other_disk, &allowed, true).unwrap();
            assert_ne!(unsafe { WaitForSingleObject(guard.0 .0, 0) }, WAIT_OBJECT_0);
            // An abandoned runtime is reclaimed by an ordinary start, without
            // asking the user to recover it first.
            check(&disk, &allowed, false).unwrap();
            assert_eq!(unsafe { WaitForSingleObject(guard.0 .0, 0) }, WAIT_OBJECT_0);
            check(&disk, &allowed, true).unwrap(); // Repeat recovery is harmless.
            check_idle_named(&disk, &allowed, "Yougori Internal OCI Runtime").unwrap();
            assert_eq!(std::fs::read(&disk).unwrap(), vec![0u8; 4096]);
            assert_eq!(std::fs::read(&other_disk).unwrap(), b"keep me");
        }

        #[test]
        #[ignore = "launches isolated disk-only QEMU processes to verify orphan recovery safety"]
        fn vm_recovery_stops_only_an_orphan_with_the_exact_disk() {
            use std::os::windows::process::CommandExt;
            let temp = tempfile::tempdir().unwrap();
            let disk = temp.path().join("system.qcow2");
            std::fs::write(&disk, vec![0u8; 4096]).unwrap();
            let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources/runtime/qemu/qemu-system-x86_64.exe");
            let allowed = vec![exe.clone()];
            let name = "Yougori env-test-vm";
            let mut owned = fixture_command_named(&exe, &disk, name).spawn().unwrap();
            // Check both the startup guard and refusal to kill a live owner's runtime.
            let busy = check_named(&disk, &allowed, false, name);
            let refusal = check_named(&disk, &allowed, true, name);
            let still_running = owned.try_wait().unwrap().is_none();
            let _ = owned.kill();
            let _ = owned.wait();
            assert!(busy.unwrap_err().contains("YOUGORI_VM_RUNTIME_BUSY"));
            assert!(refusal.unwrap_err().contains("Another live process"));
            assert!(still_running);

            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .creation_flags(0x0800_0000)
                .args([
                    "--exact",
                    "runtime::recovery::windows::tests::recovery_fixture_parent",
                    "--ignored",
                ])
                .env("YOUGORI_RECOVERY_FIXTURE_DIR", temp.path())
                .env("YOUGORI_RECOVERY_FIXTURE_NAME", name)
                .status()
                .unwrap();
            assert!(status.success());
            let pid: u32 = std::fs::read_to_string(temp.path().join("pid"))
                .unwrap()
                .parse()
                .unwrap();
            let handle =
                Handle(unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) });
            assert!(!handle.0.is_null());
            // Always clean up this test-owned process, including when an assertion fails.
            struct FixtureGuard(Handle);
            impl Drop for FixtureGuard {
                fn drop(&mut self) {
                    unsafe {
                        TerminateProcess(self.0 .0, 1);
                        WaitForSingleObject(self.0 .0, 5000);
                    }
                }
            }
            let guard = FixtureGuard(handle);
            let other_disk = temp.path().join("unrelated.qcow2");
            std::fs::write(&other_disk, b"keep me").unwrap();
            check_named(&other_disk, &allowed, true, name).unwrap();
            assert_ne!(unsafe { WaitForSingleObject(guard.0 .0, 0) }, WAIT_OBJECT_0);
            check_named(&disk, &allowed, true, "Yougori env-unrelated").unwrap();
            assert_ne!(unsafe { WaitForSingleObject(guard.0 .0, 0) }, WAIT_OBJECT_0);
            // An abandoned runtime is reclaimed by an ordinary start, without
            // asking the user to recover it first.
            check_named(&disk, &allowed, false, name).unwrap();
            assert_eq!(unsafe { WaitForSingleObject(guard.0 .0, 0) }, WAIT_OBJECT_0);
            check_named(&disk, &allowed, true, name).unwrap(); // Repeat recovery is harmless.
            assert_eq!(std::fs::read(&disk).unwrap(), vec![0u8; 4096]);
            assert_eq!(std::fs::read(&other_disk).unwrap(), b"keep me");
        }

        #[test]
        fn recovery_requires_exact_appliance_name_and_managed_disk() {
            let temp = tempfile::tempdir().unwrap();
            let disk = temp.path().join("system.qcow2");
            std::fs::write(&disk, b"fixture").unwrap();
            let block = serde_json::json!({"driver":"file", "filename":disk}).to_string();
            let mut args: Vec<OsString> = [
                "qemu",
                "-name",
                "Yougori Internal OCI Runtime",
                "-blockdev",
                &block,
            ]
            .into_iter()
            .map(Into::into)
            .collect();
            assert!(appliance_args(&args, &disk));
            assert!(!appliance_args(&args, &temp.path().join("other.qcow2")));
            args[2] = "User VM".into();
            assert!(!appliance_args(&args, &disk));
            args[2] = "Yougori Internal OCI Runtime".into();
            args[4] = "not JSON".into();
            assert!(!appliance_args(&args, &disk));
        }

        #[test]
        fn recovery_recognizes_only_the_target_vm_or_microvm() {
            let temp = tempfile::tempdir().unwrap();
            let disk = temp.path().join("system.qcow2");
            std::fs::write(&disk, b"fixture").unwrap();
            let block = serde_json::json!({"driver":"file", "filename":disk}).to_string();
            for name in ["Yougori env-target", "Yougori microVM env-target"] {
                let args: Vec<OsString> = ["qemu", "-name", name, "-blockdev", &block].into_iter().map(Into::into).collect();
                assert!(runtime_args(&args, &disk, "Yougori env-target"));
                assert!(!runtime_args(&args, &disk, "Yougori env-other"));
                assert!(!runtime_args(&args, &temp.path().join("other.qcow2"), "Yougori env-target"));
                assert!(!appliance_args(&args, &disk));
            }
        }
    }
}
