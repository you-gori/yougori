use super::{command_output, RuntimeManager};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tauri::State;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GpuAdapter {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub luid: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub sub_sys_id: u32,
    pub revision: u32,
    pub memory_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveGpu {
    runtime_id: String,
    adapter: Option<GpuAdapter>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuSettings {
    adapters: Vec<GpuAdapter>,
    selected_id: Option<String>,
    active: Vec<ActiveGpu>,
    blocked_reason: Option<String>,
}

pub(super) struct GpuLaunch {
    selected: Option<GpuAdapter>,
    report_path: PathBuf,
}

#[derive(Deserialize)]
struct GpuReport {
    pid: u32,
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(flatten)]
    adapter: Option<GpuAdapter>,
}

fn identify_adapters(adapters: &mut [GpuAdapter]) {
    for adapter in adapters.iter_mut() {
        adapter.id = format!(
            "pci-{:04x}-{:04x}-{:08x}-{:02x}",
            adapter.vendor_id, adapter.device_id, adapter.sub_sys_id, adapter.revision
        );
    }
    let ids: Vec<_> = adapters.iter().map(|a| a.id.clone()).collect();
    for adapter in adapters {
        if ids.iter().filter(|id| *id == &adapter.id).count() > 1 {
            // Identical boards cannot be resolved by hardware identity alone.
            // A stale session LUID requires explicit re-selection, never fallback.
            adapter.id.push_str(&format!("-{}", adapter.luid));
        }
    }
}

impl RuntimeManager {
    fn gpu_selection(&self) -> Result<Option<String>, String> {
        let path = self.settings_root.join("shared-gpu.json");
        match fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Read GPU selection: {e}")),
            Ok(meta) if meta.len() > 4096 => Err("GPU selection file is invalid".into()),
            Ok(_) => serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Read GPU selection: {e}")),
        }
    }

    async fn gpu_adapters(&self) -> Result<Vec<GpuAdapter>, String> {
        if !cfg!(target_os = "windows") {
            return Err("Physical GPU selection is currently supported on Windows only".into());
        }
        let output = tokio::time::timeout(
            Duration::from_secs(8),
            command_output(
                &self.layout.root.join("qemu/yougori-gpu-probe.exe"),
                &[],
                "Enumerate graphics adapters",
            ),
        )
        .await
        .map_err(|_| "Graphics adapter discovery timed out")??;
        if output.stdout.len() > 65536 {
            return Err("Invalid graphics adapter response".into());
        }
        let mut adapters: Vec<GpuAdapter> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Read graphics adapters: {e}"))?;
        identify_adapters(&mut adapters);
        Ok(adapters)
    }

    pub(super) async fn prepare_gpu_launch(&self, directory: &Path) -> Result<GpuLaunch, String> {
        let selected = match self.gpu_selection()? {
            Some(id) => Some(self.gpu_adapters().await?.into_iter().find(|a| a.id == id)
                .ok_or("The selected GPU is unavailable. Choose an available GPU or Automatic in Shared GPU settings; no fallback was started.")?),
            None => None,
        };
        Ok(GpuLaunch {
            selected,
            report_path: directory.join("gpu-report.json"),
        })
    }

    pub async fn shared_gpu_settings(&self) -> Result<GpuSettings, String> {
        let adapters = self.gpu_adapters().await?;
        let mut active = Vec::new();
        let mut busy = false;
        match self.appliance_peek().await {
            Some(mut guard) => if let Some(process) = guard.as_mut() {
                if process
                    .child
                    .try_wait()
                    .map_err(|e| e.to_string())?
                    .is_none()
                {
                    busy |= !process.active_containers.is_empty();
                    active.push(ActiveGpu {
                        runtime_id: "containers".into(),
                        adapter: process.gpu.clone(),
                    });
                }
            },
            // Starting or resizing; changing the GPU must wait until it settles.
            None => busy = true,
        }
        for (id, process) in self.vms.lock().await.iter_mut() {
            if process.gpu_enabled
                && process
                    .child
                    .try_wait()
                    .map_err(|e| e.to_string())?
                    .is_none()
            {
                busy = true;
                active.push(ActiveGpu {
                    runtime_id: id.clone(),
                    adapter: process.gpu.clone(),
                });
            }
        }
        for engine in self.loaded_storage_runtimes() {
            let settings = Box::pin(engine.shared_gpu_settings()).await?;
            busy |= settings.blocked_reason.is_some();
            active.extend(settings.active);
        }
        Ok(GpuSettings { adapters, selected_id: self.gpu_selection()?, active,
            blocked_reason: busy.then(|| "Stop all running or paused containers and GPU-enabled full VMs before changing the shared GPU.".into()) })
    }

    pub async fn select_shared_gpu(
        &self,
        selected_id: Option<String>,
    ) -> Result<GpuSettings, String> {
        let engines = self.loaded_storage_runtimes();
        let mut leases = Vec::new();
        for engine in &engines { leases.push(engine.appliance_operations.write().await); }
        let _appliance_lease = self.appliance_operations.write().await;
        let _gpu_lease = self.gpu_launches.write().await;
        let adapters = self.gpu_adapters().await?;
        if selected_id
            .as_ref()
            .is_some_and(|id| !adapters.iter().any(|a| &a.id == id))
        {
            return Err(
                "The selected GPU is unavailable. Refresh the adapter list and try again.".into(),
            );
        }
        if self.gpu_selection()? != selected_id {
            for engine in &engines {
                if engine.shared_gpu_settings().await?.blocked_reason.is_some() { return Err("Stop environments on all storage drives before changing the shared GPU.".into()); }
            }
            for process in self.vms.lock().await.values_mut() {
                if process.gpu_enabled
                    && process
                        .child
                        .try_wait()
                        .map_err(|e| e.to_string())?
                        .is_none()
                {
                    return Err("Stop GPU-enabled full VMs before changing the shared GPU.".into());
                }
            }
            let mut guard = self.appliance.lock().await;
            if let Some(process) = guard.as_mut() {
                if process
                    .child
                    .try_wait()
                    .map_err(|e| e.to_string())?
                    .is_none()
                {
                    if !process.active_containers.is_empty() {
                        return Err(
                            "Stop all running or paused containers before changing the shared GPU."
                                .into(),
                        );
                    }
                    let response = self
                        .client
                        .post(format!("{}/v1/system/shutdown", process.endpoint.base_url))
                        .bearer_auth(&process.endpoint.token)
                        .timeout(Duration::from_secs(3))
                        .send()
                        .await
                        .map_err(|e| format!("Could not stop the idle graphics runtime: {e}"))?;
                    if !response.status().is_success() {
                        return Err("The idle runtime refused a clean shutdown; GPU selection was not changed.".into());
                    }
                    let status = tokio::time::timeout(Duration::from_secs(15), process.child.wait()).await
                        .map_err(|_| "The idle runtime is still stopping. Retry shortly; no forced restart was attempted.")?
                        .map_err(|e| e.to_string())?;
                    if !status.success() {
                        return Err(
                            "The idle runtime did not exit cleanly. GPU selection was not changed."
                                .into(),
                        );
                    }
                    self.record_appliance_overlay_state()?;
                }
                guard.take();
            }
            super::vm::write_durable_file(
                self.settings_root.join("shared-gpu.json"),
                serde_json::to_vec(&selected_id).map_err(|e| e.to_string())?,
            )
            .await?;
        }
        drop(_gpu_lease);
        drop(_appliance_lease);
        self.shared_gpu_settings().await
    }
}

impl GpuLaunch {
    pub(super) fn explicit(&self) -> bool {
        self.selected.is_some()
    }
    pub(super) fn configure(&self, command: &mut tokio::process::Command) -> Result<(), String> {
        if !cfg!(target_os = "windows") {
            return Err("GPU sharing is not available in this macOS/Linux preview. Disable shared GPU for this environment and retry; no GPU/CUDA acceleration was enabled.".into());
        }
        // Remove stale reports before every accelerator attempt. Environment
        // variables are child-only and cannot affect other Windows applications.
        match fs::remove_file(&self.report_path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("Reset GPU verification report: {e}")),
        }
        command
            .env("YOUGORI_GPU_REPORT", &self.report_path)
            .env_remove("YOUGORI_GPU_LUID");
        if let Some(adapter) = &self.selected {
            command.env("YOUGORI_GPU_LUID", &adapter.luid);
        }
        Ok(())
    }
    pub(super) fn verify(&self, pid: u32) -> Result<Option<GpuAdapter>, String> {
        let result = (|| {
            if fs::metadata(&self.report_path)
                .map_err(|e| e.to_string())?
                .len()
                > 16384
            {
                return Err("Oversized GPU verification report".into());
            }
            let report: GpuReport =
                serde_json::from_slice(&fs::read(&self.report_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if report.pid != pid {
                return Err("GPU verification belongs to a different process".into());
            }
            if !report.ok {
                return Err(report.error);
            }
            let mut actual = report
                .adapter
                .ok_or("GPU verification did not identify the adapter")?;
            if let Some(selected) = &self.selected {
                if selected.luid != actual.luid
                    || selected.vendor_id != actual.vendor_id
                    || selected.device_id != actual.device_id
                {
                    return Err(
                        "The graphics runtime used a different GPU. No fallback is allowed.".into(),
                    );
                }
                actual.id = selected.id.clone();
            } else {
                identify_adapters(std::slice::from_mut(&mut actual));
            }
            Ok(actual)
        })();
        match result {
            Ok(adapter) => Ok(Some(adapter)),
            Err(error) if self.explicit() => Err(format!(
                "Selected GPU could not be verified: {error}. No fallback was started."
            )),
            Err(_) => Ok(None),
        }
    }
}

#[tauri::command]
pub async fn get_shared_gpu_settings(
    runtime: State<'_, RuntimeManager>,
) -> Result<GpuSettings, String> {
    runtime.shared_gpu_settings().await
}
#[tauri::command]
pub async fn set_shared_gpu_selection(
    selected_id: Option<String>,
    runtime: State<'_, RuntimeManager>,
) -> Result<GpuSettings, String> {
    runtime.select_shared_gpu(selected_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    fn adapter(luid: &str) -> GpuAdapter {
        GpuAdapter {
            id: "fixture".into(),
            name: "Test GPU".into(),
            luid: luid.into(),
            vendor_id: 1,
            device_id: 2,
            sub_sys_id: 3,
            revision: 4,
            memory_bytes: 1024,
        }
    }

    #[test]
    fn gpu_identity_survives_reboot_but_duplicate_boards_are_disambiguated() {
        let mut first = vec![adapter("00000000:00000001")];
        identify_adapters(&mut first);
        let mut rebooted = vec![adapter("00000000:00000002")];
        identify_adapters(&mut rebooted);
        assert_eq!(first[0].id, rebooted[0].id);
        let mut duplicate = vec![first[0].clone(), rebooted[0].clone()];
        identify_adapters(&mut duplicate);
        assert_ne!(duplicate[0].id, duplicate[1].id);
    }

    #[test]
    fn explicit_gpu_reports_reject_missing_stale_and_wrong_adapters() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gpu.json");
        let selected = adapter("00000000:00000001");
        let launch = GpuLaunch {
            selected: Some(selected.clone()),
            report_path: path.clone(),
        };
        assert!(launch.verify(123).is_err());
        let mut report = serde_json::to_value(&selected).unwrap();
        report["pid"] = 999.into();
        report["ok"] = true.into();
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(launch.verify(123).is_err());
        report["pid"] = 123.into();
        report["luid"] = "00000000:00000002".into();
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(launch.verify(123).is_err());
        report["luid"] = selected.luid.into();
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(launch.verify(123).unwrap().is_some());
    }

    #[tokio::test]
    #[ignore = "boots an isolated GPU-enabled container and checks switching, persistence and data preservation"]
    async fn shared_gpu_switch_preserves_container_data() -> Result<(), String> {
        use crate::models::{Priority, ResourcePolicy, ResourceRange};
        let temp = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let adapters = runtime.gpu_adapters().await?;
        if adapters.len() < 2 {
            return Err("This hardware test requires two physical GPUs".into());
        }
        let result: Result<(), String> = async {
            runtime
                .select_shared_gpu(Some(adapters[0].id.clone()))
                .await?;
            let policy = ResourcePolicy {
                cpu: ResourceRange {
                    min: 0.1,
                    preferred: 0.5,
                    max: 1.0,
                    current: 0.0,
                },
                memory_gb: ResourceRange {
                    min: 0.125,
                    preferred: 0.25,
                    max: 0.5,
                    current: 0.0,
                },
                priority: Priority::Normal,
                dynamic: false,
            };
            runtime
                .provision_container(
                    "env-gpu-switch",
                    "quay.io/libpod/alpine:latest",
                    "sleep 2147483647",
                    &policy,
                    false,
                    true,
                )
                .await?;
            runtime
                .container_action("env-gpu-switch", "start", false)
                .await?;
            assert_eq!(
                runtime
                    .execute_container_command(
                        "env-gpu-switch",
                        "echo preserved > /root/gpu-marker"
                    )
                    .await?
                    .exit_code,
                0
            );
            assert!(runtime
                .select_shared_gpu(Some(adapters[1].id.clone()))
                .await
                .unwrap_err()
                .contains("Stop all"));
            runtime
                .container_action("env-gpu-switch", "pause", false)
                .await?;
            assert!(runtime
                .select_shared_gpu(Some(adapters[1].id.clone()))
                .await
                .unwrap_err()
                .contains("Stop all"));
            assert_eq!(runtime.gpu_selection()?, Some(adapters[0].id.clone()));
            runtime
                .container_action("env-gpu-switch", "stop", false)
                .await?;
            runtime
                .select_shared_gpu(Some(adapters[1].id.clone()))
                .await?;
            runtime
                .container_action("env-gpu-switch", "start", false)
                .await?;
            assert_eq!(
                runtime
                    .appliance
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .gpu
                    .as_ref()
                    .unwrap()
                    .luid,
                adapters[1].luid
            );
            let output = runtime
                .execute_container_command(
                    "env-gpu-switch",
                    "cat /root/gpu-marker; test -c /dev/dri/renderD128",
                )
                .await?;
            assert_eq!(output.exit_code, 0);
            assert!(output.stdout.contains("preserved"));
            eprintln!(
                "GPU switched from {} to {}; container files preserved",
                adapters[0].name, adapters[1].name
            );
            Ok(())
        }
        .await;
        runtime.shutdown_all().await;
        result?;
        let reopened = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        assert_eq!(reopened.gpu_selection()?, Some(adapters[1].id.clone()));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "starts diskless hidden QEMU processes to verify real Windows GPU selection"]
    async fn shared_gpu_selects_each_physical_adapter_and_rejects_fallback() -> Result<(), String> {
        verify_gpu_runtime(false).await
    }

    #[tokio::test]
    #[ignore = "boots a disposable appliance and runs a real non-root Mesa GPU workload; no user environments"]
    async fn container_gpu_runs_a_non_root_hardware_workload() -> Result<(), String> {
        verify_container_gpu_workload(false).await
    }

    #[tokio::test]
    #[ignore = "boots a disposable Ubuntu container and runs a real non-root Mesa GPU workload; no user environments"]
    async fn ubuntu_container_gpu_runs_a_non_root_hardware_workload() -> Result<(), String> {
        verify_container_gpu_workload(true).await
    }

    async fn verify_container_gpu_workload(ubuntu: bool) -> Result<(), String> {
        use crate::models::{Priority, ResourcePolicy, ResourceRange};
        let temp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let result: Result<(), String> = async {
            let policy = ResourcePolicy {
                cpu: ResourceRange { min: 0.5, preferred: 2.0, max: 2.0, current: 0.0 },
                memory_gb: ResourceRange { min: 0.5, preferred: 1.0, max: 1.0, current: 0.0 },
                priority: Priority::Normal, dynamic: true,
            };
            let id = "env-non-root-gpu-probe";
            // Alpine 3.24's distro Mesa deliberately omits the VirGL driver;
            // 3.23 still ships it. Do not treat a render node as proof that an
            // arbitrary OCI image includes a compatible userspace driver.
            let image = if ubuntu { "docker.io/library/ubuntu:24.04" } else { "docker.io/library/alpine:3.23" };
            runtime.provision_container(id, image, "sleep 2147483647", &policy, true, true).await?;
            runtime.container_action(id, "start", true).await?;
            if runtime.appliance.lock().await.as_ref().and_then(|p| p.gpu.as_ref()).is_none() {
                return Err("The host hardware adapter was not verified".into());
            }
            let source = include_str!("../../../appliance/agent/testdata/gpu-render-probe.c");
            let packages = if ubuntu {
                "apt-get update -qq\nDEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev libegl-dev libgles-dev libgbm-dev libegl-mesa0 libgl1-mesa-dri"
            } else {
                "apk add --no-cache gcc musl-dev mesa-dev mesa-egl mesa-gbm mesa-gles mesa-dri-gallium"
            };
            let user = if ubuntu {
                "useradd -M -u 10001 gpu-test\ngroupadd -g 65532 yougori-render\nusermod -aG yougori-render gpu-test"
            } else {
                "adduser -D -H -u 10001 gpu-test\naddgroup -g 65532 yougori-render\naddgroup gpu-test yougori-render"
            };
            let command = format!("set -eu\nawk '/^Groups:/ {{ for (i=2;i<=NF;i++) if ($i==65532) found=1 }} END {{ exit !found }}' /proc/1/status\n{packages}\ncc -x c - -o /tmp/gpu-render-probe -lEGL -lGLESv2 -lgbm <<'YOUGORI_GPU_PROBE'\n{source}\nYOUGORI_GPU_PROBE\n{user}\nsu -s /bin/sh -c /tmp/gpu-render-probe gpu-test");
            let output = runtime.execute_container_command(id, &command).await?;
            if output.exit_code != 0 || !output.stdout.contains("non-root GPU workload completed") {
                return Err(format!("GPU workload failed ({}): {}\n{}", output.exit_code, output.stdout, output.stderr));
            }
            for line in output.stdout.lines().filter(|s| s.starts_with("uid=") || s.contains("workload completed")) { eprintln!("{image}: {line}"); }
            if !ubuntu {
                let current_luid = runtime.appliance.lock().await.as_ref().and_then(|p| p.gpu.as_ref()).map(|a| a.luid.clone());
                if let Some(adapter) = runtime.gpu_adapters().await?.into_iter().find(|a| Some(&a.luid) != current_luid.as_ref()) {
                    runtime.container_action(id, "stop", true).await?;
                    runtime.select_shared_gpu(Some(adapter.id)).await?;
                    runtime.container_action(id, "start", true).await?;
                    let switched = runtime.execute_container_command(id, "su -s /bin/sh -c /tmp/gpu-render-probe gpu-test").await?;
                    if switched.exit_code != 0 || !switched.stdout.contains("non-root GPU workload completed") { return Err(format!("GPU switch workload failed: {} {}", switched.stdout, switched.stderr)); }
                    eprintln!("Switched to {}: {}", adapter.name, switched.stdout);
                }
            }
            // An otherwise identical disconnected container must not receive a
            // GPU device or the render group through this configuration path.
            runtime.provision_container("env-no-gpu-probe", image, "sleep 2147483647", &policy, false, false).await?;
            runtime.container_action("env-no-gpu-probe", "start", false).await?;
            let denied = runtime.execute_container_command("env-no-gpu-probe", "test ! -e /dev/dri/renderD128").await?;
            if denied.exit_code != 0 { return Err("A disconnected container received a GPU device".into()); }
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "starts diskless hidden secure QEMU processes to verify physical GPU selection; no user VMs"]
    async fn secure_qemu_preserves_physical_gpu_selection() -> Result<(), String> {
        verify_gpu_runtime(true).await
    }

    async fn verify_gpu_runtime(secure: bool) -> Result<(), String> {
        let temp = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let qemu_root = runtime.layout.root.join(if secure { "qemu-secure" } else { "qemu" });
        let executable = qemu_root.join("qemu-system-x86_64.exe");
        let adapters = runtime.gpu_adapters().await?;
        assert!(!adapters.is_empty());
        for selected in adapters
            .iter()
            .map(|a| Some(a.clone()))
            .chain(std::iter::once(None))
        {
            let launch = GpuLaunch {
                selected,
                report_path: temp.path().join("gpu.json"),
            };
            let mut command = tokio::process::Command::new(&executable);
            command
                .current_dir(&qemu_root)
                .args([
                    "-L",
                    runtime.layout.root.join("qemu/share").to_str().unwrap(),
                    "-machine",
                    "q35",
                    "-accel",
                    "tcg,thread=multi",
                    "-m",
                    "128",
                    "-nodefaults",
                    "-S",
                    "-qmp",
                    "stdio",
                ])
                .args(if secure { super::super::vm::full_vm_graphics_arguments(true) }
                    else { vec!["-device", "virtio-gpu-gl-pci,max_outputs=1", "-display", "egl-headless"] })
                .stdin(Stdio::piped())
                .kill_on_drop(true)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            super::super::configure_background_process(&mut command);
            launch.configure(&mut command)?;
            let mut child = command.spawn().map_err(|e| e.to_string())?;
            let pid = child.id().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut greeting = String::new();
            tokio::time::timeout(Duration::from_secs(15), output.read_line(&mut greeting))
                .await
                .map_err(|_| "GPU boot timed out")?
                .map_err(|e| e.to_string())?;
            if greeting.is_empty() {
                let result = child.wait_with_output().await.map_err(|e| e.to_string())?;
                return Err(format!(
                    "GPU launch failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                ));
            }
            let actual = launch.verify(pid)?;
            eprintln!(
                "Requested {:?}; verified {:?}",
                launch.selected.as_ref().map(|a| &a.name),
                actual.as_ref().map(|a| (&a.name, &a.luid))
            );
            assert!(
                actual.is_some(),
                "Automatic should identify the actual adapter too"
            );
            if let Some(selected) = &launch.selected {
                assert_eq!(actual.unwrap().luid, selected.luid);
            }
            // This fixture has no disks or guest workload to shut down.
            child.kill().await.map_err(|e| e.to_string())?;
            child.wait().await.map_err(|e| e.to_string())?;
        }
        let mut missing = adapters[0].clone();
        missing.luid = "7fffffff:ffffffff".into();
        let launch = GpuLaunch {
            selected: Some(missing),
            report_path: temp.path().join("invalid-gpu.json"),
        };
        let mut command = tokio::process::Command::new(&executable);
        command
            .current_dir(&qemu_root)
            .args([
                "-L",
                runtime.layout.root.join("qemu/share").to_str().unwrap(),
                "-machine",
                "q35",
                "-accel",
                "tcg,thread=multi",
                "-m",
                "128",
                "-nodefaults",
                "-S",
                "-device",
                "virtio-gpu-gl-pci,max_outputs=1",
                "-display",
                "egl-headless",
            ])
            .stdin(Stdio::null());
        super::super::configure_background_process(&mut command);
        launch.configure(&mut command)?;
        let output = tokio::time::timeout(Duration::from_secs(15), command.output())
            .await
            .map_err(|_| "Invalid GPU did not fail closed")?
            .map_err(|e| e.to_string())?;
        assert!(!output.status.success());
        let report: GpuReport =
            serde_json::from_slice(&fs::read(&launch.report_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        assert!(!report.ok);
        eprintln!("Missing GPU refused: {}", report.error);
        Ok(())
    }
}
