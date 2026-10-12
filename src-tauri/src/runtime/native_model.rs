//! Managed macOS inference. The Linux frontend owns public API policy; this
//! private service accepts only a per-model credential and dies with its owner.
use super::*;
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

fn metal_device(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        let (name, _) = line.trim().split_once(':')?;
        let index = name
            .strip_prefix("MTL")
            .or_else(|| name.strip_prefix("Metal"))?;
        (!index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())).then_some(name)
    })
}

pub(super) struct NativeModel {
    child: Child,
    access: Arc<AtomicBool>,
    memory_gb: f64,
}
impl Drop for NativeModel {
    fn drop(&mut self) {
        self.access.store(false, Ordering::Release);
    }
}

impl RuntimeManager {
    pub(crate) async fn native_model_capabilities(&self) -> Value {
        let mut result = serde_json::json!({"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "available":false,"metalSupported":false,"backend":"cpu","native":true,
            "unifiedMemory":cfg!(target_arch="aarch64"),"memoryGb":System::new_all().total_memory() as f64 / 1_073_741_824.});
        let root = match self.native_model_runtime() {
            Ok(root) => root,
            Err(error) => {
                result["detail"] = error.into();
                return result;
            }
        };
        let probe = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new(root.join("llama-server"))
                .arg("--list-devices")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .kill_on_drop(true)
                .output(),
        )
        .await;
        match probe {
            Ok(Ok(output)) if output.status.success() => {
                let listing = String::from_utf8_lossy(&output.stdout);
                let device = cfg!(target_arch = "aarch64")
                    .then(|| metal_device(&listing))
                    .flatten();
                let metal = device.is_some();
                result["available"] = true.into();
                result["metalSupported"] = metal.into();
                result["metalDevice"] = serde_json::json!(device);
                result["backend"] = if metal { "metal" } else { "cpu" }.into();
                result["detail"] = if metal {
                    "Native Apple Metal inference"
                } else {
                    "Native CPU inference; no Metal device exposed"
                }
                .into();
            }
            _ => {
                result["detail"] = "Native model runtime could not enumerate compute devices".into()
            }
        }
        result
    }
    pub(crate) fn native_model_runtime(&self) -> Result<PathBuf, String> {
        if !cfg!(target_os = "macos") {
            return Err("Native Mac models require macOS".into());
        }
        let root = std::env::var_os("YOUGORI_MACOS_MODEL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.layout.root.join("llama"));
        // The signed bundle's manifest covers the executable and supervisor.
        let record =
            verify_checksum_manifest(&root, &root.join("SHA256SUMS"), "native-model", None)?;
        for required in ["llama-server", "yougori-supervise"] {
            if !record.files.iter().any(|f| f.relative_path == required) {
                return Err(format!("Native model runtime is missing verified {required}; rebuild or reinstall Yougori"));
            }
        }
        Ok(root)
    }

    pub(super) async fn prepare_native_model(&self, id: &str) -> Result<(), String> {
        let options = self.workload_options(id)?;
        let Some(backend) = options.environment.get("YOUGORI_NATIVE_BACKEND") else {
            return Ok(());
        };
        if !matches!(backend.as_str(), "metal" | "cpu") {
            return Err("Invalid native model backend".into());
        }
        let root = self.native_model_runtime()?;
        let mut models = self.native_models.lock().await;
        if let Some(model) = models.get_mut(id) {
            if model.child.try_wait().map_err(|e| e.to_string())?.is_none() {
                return Ok(());
            }
        }
        models.remove(id);
        models.retain(|_, model| model.child.try_wait().is_ok_and(|status| status.is_none()));
        let number = |name: &str| {
            options
                .environment
                .get(name)
                .and_then(|s| s.parse::<f64>().ok())
                .filter(|n| n.is_finite() && *n > 0.)
                .ok_or_else(|| format!("Missing native model {name}"))
        };
        let memory = number("YOUGORI_NATIVE_MEMORY_GB")?;
        let threads = number("YOUGORI_MODEL_CPU_THREADS")?.floor().clamp(1., 64.) as u64;
        let port = options
            .environment
            .get("YOUGORI_NATIVE_PORT")
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p > 0)
            .ok_or("Missing native model port")?;
        let token = crate::projects::secrets::variable(&options, "YOUGORI_NATIVE_TOKEN")?;
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid native model credential".into());
        }
        let bind = options
            .binds
            .iter()
            .find(|b| b.target == "/yougori-model" && b.read_only)
            .ok_or("Native inference requires verified read-only weights")?;
        let folder = PathBuf::from(&bind.source)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let files: Value = serde_json::from_str(
            options
                .environment
                .get("YOUGORI_MODEL_FILES")
                .ok_or("Missing native weights")?,
        )
        .map_err(|e| e.to_string())?;
        let files = files
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or("Missing native weights")?;
        let bytes = files
            .iter()
            .try_fold(0u64, |total, f| {
                total.checked_add(f["size"].as_u64().unwrap_or(0))
            })
            .ok_or("Model size overflow")?;
        if bytes == 0 || bytes as f64 / 1_073_741_824. * 1.15 + 1.5 > memory {
            return Err("The model plus context exceeds its native memory budget. Select a smaller GGUF or increase model memory.".into());
        }
        let system = System::new_all();
        let total = system.total_memory() as f64 / 1_073_741_824.;
        let reserved = models.values().map(|m| m.memory_gb).sum::<f64>();
        if memory + reserved > (total - 4.).max(total * 0.5) {
            return Err("Native models must leave memory available for macOS and sandboxes; stop another model or reduce the allocation".into());
        }
        let mut weights = Vec::new();
        for file in files {
            let path = folder
                .join(crate::model_runner::macos::relative_weight(
                    file["name"].as_str().ok_or("Missing weight name")?,
                )?)
                .canonicalize()
                .map_err(|e| e.to_string())?;
            if !path.starts_with(&folder) {
                return Err("Native weight escapes the approved model folder".into());
            }
            crate::model_runner::macos::verify(
                path.clone(),
                file["size"].as_u64().ok_or("Missing size")?,
                file["sha256"].as_str().ok_or("Missing checksum")?.into(),
            )
            .await?;
            weights.push(path);
        }
        let binary = root.join("llama-server");
        let device = if backend == "metal" {
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::process::Command::new(&binary)
                    .arg("--list-devices")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .map_err(|_| "Metal device probe timed out")?
            .map_err(|e| e.to_string())?;
            let listing = String::from_utf8_lossy(&output.stdout);
            let device = metal_device(&listing);
            if !output.status.success() || device.is_none() {
                return Err("No Metal device is available to this Mac runtime. Select the cpu backend; hosted macOS VMs may not expose a GPU.".into());
            }
            device.unwrap().to_owned()
        } else {
            "none".into()
        };
        // Keys never enter arguments, logs or the subprocess inherited environment.
        let mut command = tokio::process::Command::new(root.join("yougori-supervise"));
        command
            .arg(&binary)
            .arg("-m")
            .arg(&weights[0])
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--no-webui",
                "-np",
                "1",
                "-c",
                "32768",
                "--jinja",
                "--reasoning-format",
                "none",
                "--threads",
                &threads.to_string(),
                "--threads-batch",
                &threads.to_string(),
                "--poll",
                "0",
                "--poll-batch",
                "0",
                "--device",
                &device,
                "-ngl",
                if backend == "metal" { "all" } else { "0" },
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LLAMA_API_KEY", token)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .map_err(|e| format!("Start native model: {e}"))?;
        let access = Arc::new(AtomicBool::new(true));
        self.grant_qemu_host_service(id, port, Arc::downgrade(&access), true)
            .await?;
        models.insert(
            id.into(),
            NativeModel {
                child,
                access,
                memory_gb: memory,
            },
        );
        Ok(())
    }

    pub(super) async fn stop_native_model(&self, id: &str) -> Result<(), String> {
        let mut models = self.native_models.lock().await;
        if let Some(model) = models.get_mut(id) {
            model.access.store(false, Ordering::Release);
            // EOF tells the watchdog to terminate the model, including on engine death.
            model.child.stdin.take();
            match tokio::time::timeout(std::time::Duration::from_secs(5), model.child.wait()).await
            {
                Ok(result) => {
                    result.map_err(|e| e.to_string())?;
                }
                Err(_) => {
                    model.child.kill().await.map_err(|e| e.to_string())?;
                }
            }
        }
        models.remove(id);
        Ok(())
    }
    pub(super) async fn shutdown_native_models(&self) -> Result<(), String> {
        let ids: Vec<String> = self.native_models.lock().await.keys().cloned().collect();
        for id in ids {
            self.stop_native_model(&id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::metal_device;

    #[test]
    fn detects_the_device_identifier_reported_by_llama_cpp() {
        assert_eq!(metal_device("Available devices:\n  MTL0: Apple Paravirtual device (4778 MiB)\n  BLAS: Accelerate (0 MiB)"), Some("MTL0"));
        assert_eq!(metal_device("  Metal1: Apple M1"), Some("Metal1"));
        assert_eq!(
            metal_device("  BLAS: Accelerate\n  CPU: Intel\nMetal initialization failed"),
            None
        );
        assert_eq!(metal_device("MTL: invalid\nMTL0 --host: invalid"), None);
    }
}
