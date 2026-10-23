use super::RuntimeManager;
use crate::scheduler::APPLIANCE_OVERHEAD_GB;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ApplianceCapacity {
    pub cpus: usize,
    pub memory_mib: usize,
}

impl Default for ApplianceCapacity {
    fn default() -> Self {
        Self {
            cpus: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .min(2),
            memory_mib: 1024,
        }
    }
}

impl ApplianceCapacity {
    pub fn for_workloads(cpu: f64, memory_gb: f64) -> Result<Self, String> {
        if !cpu.is_finite()
            || !memory_gb.is_finite()
            || cpu <= 0.0
            || memory_gb <= 0.0
            || cpu > 255.0
            || memory_gb > 1024.0
        {
            return Err("Invalid shared container runtime capacity".into());
        }
        Ok(Self {
            cpus: cpu.ceil() as usize,
            memory_mib: (((memory_gb + APPLIANCE_OVERHEAD_GB) * 8.0).ceil() as usize * 128)
                .max(1024),
        })
    }
    pub fn contains(self, requested: Self) -> bool {
        self.cpus >= requested.cpus && self.memory_mib >= requested.memory_mib
    }
}

impl RuntimeManager {
    /// Serialize runtime growth against provision/start/backup. Add RAM to a
    /// running appliance instead of restarting the containers already using it.
    pub async fn ensure_container_capacity(&self, cpu: f64, memory_gb: f64) -> Result<(), String> {
        let requested = ApplianceCapacity::for_workloads(cpu, memory_gb)?;
        let _exclusive = self.appliance_operations.write().await;
        let mut guard = self.appliance.lock().await;
        if let Some(process) = guard.as_mut() {
            if process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                if process.capacity.contains(requested) { return Ok(()); }
                return self.grow_live_appliance(process, requested).await;
            }
            guard.take();
        }
        // Never boot a large VM merely because a slider's ceiling is high if the
        // host cannot currently back that reservation. Fail before touching disks.
        let mut system = sysinfo::System::new();
        system.refresh_memory();
        let host_cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        if requested.cpus > host_cpus {
            return Err(format!(
                "The container runtime needs {} CPUs, but this computer has {host_cpus}",
                requested.cpus
            ));
        }
        let available_mib = system.available_memory() / 1_048_576;
        if requested.memory_mib as u64 + 512 > available_mib {
            return Err(format!("Not enough free host RAM to reserve {:.3} GB for the container runtime. Lower the resource maximum or close other workloads, then retry.", requested.memory_mib as f64 / 1024.0));
        }
        *self
            .appliance_capacity
            .lock()
            .map_err(|_| "Container capacity lock poisoned")? = requested;
        drop(guard);
        self.appliance_endpoint().await?;
        Ok(())
    }

    async fn grow_live_appliance(&self, process: &mut super::ApplianceProcess, requested: ApplianceCapacity) -> Result<(), String> {
        use serde_json::json;
        if requested.cpus > process.capacity.cpus || requested.memory_mib > process.max_memory_mib {
            return Err("The requested CPU or RAM allocation exceeds this computer's container capacity. Lower that allocation.".into());
        }
        // Check the guest API before attaching a device. An older guest agent
        // must never make an unverified memory increase look successful.
        let online = |ranges: &serde_json::Value| self.client.post(format!("{}/v1/system/capacity", process.endpoint.base_url))
            .bearer_auth(&process.endpoint.token).timeout(Duration::from_secs(5)).json(&json!({"memoryRanges": ranges})).send();
        let check: serde_json::Value = super::appliance::successful_response(online(&json!([])).await.map_err(|e| e.to_string())?).await?
            .json().await.map_err(|e| e.to_string())?;
        if check["memoryRangesOnline"].as_bool().is_none() {
            return Err("The container runtime needs its updated memory helper. Close Yougori normally and reopen the updated app, then retry. Container files were kept.".into());
        }
        let summary = super::vm::qmp_request(&process.qmp, "query-memory-size-summary", None).await?;
        let base_mib = summary["base-memory"].as_u64().ok_or("Runtime base RAM size is missing")? / 1_048_576;
        let reserved = base_mib + summary["plugged-memory"].as_u64().unwrap_or(0) / 1_048_576;
        // Round small changes into enough-sized DIMMs that repeated slider
        // edits cannot exhaust the 64 hotplug slots before reaching host RAM.
        let target_mib = memory_growth_target(base_mib, reserved, requested.memory_mib as u64, process.max_memory_mib as u64);
        let added_mib = target_mib.saturating_sub(reserved);
        if added_mib > 0 {
            let mut host = sysinfo::System::new();
            host.refresh_memory();
            if added_mib.saturating_add(512) > host.available_memory() / 1_048_576 {
                return Err(format!("Not enough free RAM to add {:.3} GB to the container runtime. Lower the memory allocation or close another workload.", added_mib as f64 / 1024.0));
            }
            let id = format!("yougori-memory-{}", uuid::Uuid::new_v4().simple());
            super::vm::qmp_execute(&process.qmp, "object-add", Some(json!({
                "qom-type": "memory-backend-ram", "id": id, "size": added_mib * 1_048_576
            }))).await?;
            if let Err(error) = super::vm::qmp_execute(&process.qmp, "device_add", Some(json!({
                "driver": "pc-dimm", "id": format!("dimm-{id}"), "memdev": id
            }))).await {
                // object-del refuses a backend referenced by an attached DIMM.
                // A retry queries actual RAM first, avoiding duplicate growth
                // if the device_add response was lost after QEMU accepted it.
                let _ = super::vm::qmp_execute(&process.qmp, "object-del", Some(json!({"id": id}))).await;
                return Err(format!("Could not add runtime RAM while containers were running: {error}"));
            }
        }
        let devices = super::vm::qmp_request(&process.qmp, "query-memory-devices", None).await?;
        let ranges = hotplug_memory_ranges(&devices, target_mib.saturating_sub(base_mib) * 1_048_576)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let response = super::appliance::successful_response(online(&ranges).await.map_err(|e| e.to_string())?).await?;
            let capacity: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            // The guest must have every attached DIMM block online. MemTotal
            // excludes kernel reservations and is not a hotplug readiness test.
            if capacity["memoryRangesOnline"].as_bool() == Some(true) {
                process.capacity.memory_mib = target_mib as usize;
                *self.appliance_capacity.lock().map_err(|_| "Container capacity lock poisoned")? = process.capacity;
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("The runtime is still bringing additional RAM online. Retry in a moment; no environments were restarted.".into());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

fn hotplug_memory_ranges(devices: &serde_json::Value, expected_bytes: u64) -> Result<serde_json::Value, String> {
    let mut total = 0u64;
    let mut ranges = Vec::new();
    for device in devices.as_array().ok_or("Invalid runtime memory device list")? {
        if device["type"] != "dimm" { return Err("Unexpected runtime memory device".into()); }
        let start = device["data"]["addr"].as_u64().ok_or("Missing runtime DIMM address")?;
        let size = device["data"]["size"].as_u64().filter(|size| *size > 0).ok_or("Missing runtime DIMM size")?;
        start.checked_add(size).ok_or("Invalid runtime DIMM address range")?;
        total = total.checked_add(size).ok_or("Invalid runtime DIMM total")?;
        ranges.push(serde_json::json!({"start": start, "size": size}));
    }
    if total != expected_bytes { return Err("Runtime RAM devices do not match the attached capacity; retry shortly.".into()); }
    Ok(serde_json::Value::Array(ranges))
}

fn memory_growth_target(base: u64, current: u64, requested: u64, maximum: u64) -> u64 {
    let chunk = maximum.saturating_sub(base).div_ceil(64 * 128).max(1) * 128;
    (current + requested.saturating_sub(current).div_ceil(chunk) * chunk).min(maximum)
}

/// QEMU's `-m` value for the runtime. Hotplug slots need room above the boot size, and QEMU
/// refuses slots whose maximum equals it, which is where growth stops at the host's limit.
pub(super) fn memory_argument(memory_mib: usize, max_memory_mib: usize) -> String {
    if max_memory_mib > memory_mib {
        format!("{memory_mib},slots=64,maxmem={max_memory_mib}M")
    } else {
        memory_mib.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_runtime_grown_to_the_host_limit_boots_without_hotplug_slots() {
        assert_eq!(memory_argument(4096, 16384), "4096,slots=64,maxmem=16384M");
        // Growth is capped at the maximum, so the next boot can start exactly there.
        let grown = memory_growth_target(4096, 15360, 16384, 16384) as usize;
        assert_eq!(memory_argument(grown, 16384), "16384");
        assert_eq!(memory_argument(16512, 16384), "16512");
    }
    #[test]
    fn hotplug_verification_covers_all_attached_dimm_ranges() {
        let devices = serde_json::json!([
            {"type":"dimm","data":{"addr":4294967296u64,"size":2147483648u64}},
            {"type":"dimm","data":{"addr":8589934592u64,"size":1073741824u64}}
        ]);
        let ranges = hotplug_memory_ranges(&devices, 3221225472).unwrap();
        assert_eq!(ranges, serde_json::json!([
            {"start":4294967296u64,"size":2147483648u64},
            {"start":8589934592u64,"size":1073741824u64}
        ]));
        assert!(hotplug_memory_ranges(&devices, 4294967296).is_err());
        assert!(hotplug_memory_ranges(&serde_json::json!([{"type":"dimm","data":{"size":1}}]), 1).is_err());
        assert!(hotplug_memory_ranges(&serde_json::json!([{"type":"virtio-mem"}]), 0).is_err());
    }
    #[test]
    fn capacity_adds_control_plane_memory_without_a_tiny_fixed_ceiling() {
        let large = ApplianceCapacity::for_workloads(8.0, 8.0).unwrap();
        assert_eq!(
            large,
            ApplianceCapacity {
                cpus: 8,
                memory_mib: 8576
            }
        );
        assert!(!ApplianceCapacity::default().contains(large));
        assert!(large.contains(ApplianceCapacity::for_workloads(4.0, 4.0).unwrap()));
        assert_eq!(
            ApplianceCapacity::for_workloads(0.5, 0.5)
                .unwrap()
                .memory_mib,
            1024
        );
    }
    #[test]
    fn invalid_capacity_is_rejected() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(ApplianceCapacity::for_workloads(bad, 1.0).is_err());
            assert!(ApplianceCapacity::for_workloads(1.0, bad).is_err());
        }
    }

    #[test]
    fn small_resource_edits_do_not_exhaust_memory_slots() {
        for maximum in [8192, 16384, 65024, 1048576] {
            let base = 1024;
            let mut current = base;
            let mut slots = 0;
            for requested in (base..=maximum).step_by(128) {
                let next = memory_growth_target(base, current, requested, maximum);
                assert!(next >= requested && next <= maximum);
                if next > current { slots += 1; }
                current = next;
            }
            assert_eq!(current, maximum);
            assert!(slots <= 64, "{slots} slots needed for {maximum} MiB");
        }
    }
}
