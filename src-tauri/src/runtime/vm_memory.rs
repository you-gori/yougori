//! VM launch memory diagnostics.

const GB: f64 = 1_073_741_824.0;
const STARTUP_HEADROOM: u64 = 256 * 1024 * 1024;
const BUILTIN_MICROVM_BOOT_GB: f64 = 0.5;

/// Match the actual QEMU -m conversion, including the existing runtime bounds.
pub fn startup_bytes(memory_gb: f64, full_vm: bool) -> u64 {
    let minimum_mib = if full_vm { 256.0 } else { 128.0 };
    ((memory_gb * 1024.0).round().clamp(minimum_mib, 1_048_576.0) as u64) * 1024 * 1024
}

/// The trusted built-in initramfs carries offline upgrades for existing disks.
/// Its unpacking needs 512 MiB; custom boot media keeps its existing conversion.
/// Return the actual whole-MiB QEMU allocation without changing saved preferences.
pub fn microvm_startup_gb(preferred_gb: f64, maximum_gb: f64, builtin: bool) -> Result<f64, String> {
    if !builtin {
        return Ok(startup_bytes(preferred_gb, false) as f64 / GB);
    }
    if !preferred_gb.is_finite() || !maximum_gb.is_finite() || preferred_gb <= 0.0 || preferred_gb > maximum_gb {
        return Err("Invalid built-in microVM memory policy".into());
    }
    if maximum_gb < BUILTIN_MICROVM_BOOT_GB {
        return Err("The built-in Alpine microVM needs at least 0.50 GB (512 MiB) of RAM to boot its trusted security update payload. Increase its maximum RAM to at least 0.50 GB, then retry Start. Your saved disk and resource preferences were preserved.".into());
    }
    let requested_mib = startup_bytes(preferred_gb.max(BUILTIN_MICROVM_BOOT_GB), false) / (1024 * 1024);
    let maximum_mib = (maximum_gb * 1024.0).floor().min(1_048_576.0) as u64;
    Ok(requested_mib.min(maximum_mib) as f64 / 1024.0)
}

/// Windows commits guest RAM up front; free physical RAM alone is not the limit.
#[cfg(target_os = "windows")]
pub fn available_commit_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: status is initialized and dwLength matches the writable structure.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return None;
    }
    Some(status.ullAvailPageFile)
}

#[cfg(not(target_os = "windows"))]
pub fn available_commit_bytes() -> Option<u64> {
    // Do not apply Windows commit rules to hosts with different allocation rules.
    None
}

fn setting_hint(full_vm: bool) -> &'static str {
    if full_vm {
        "This VM reserves its maximum RAM at startup, even with dynamic allocation. Choose Adjust memory to lower its maximum RAM, or use Stop on another VM to release memory. Stop can recover a leftover VM even if its node says Stopped. Then retry Start."
    } else {
        "This microVM reserves its boot RAM at startup; built-in Alpine needs at least 0.50 GB (512 MiB). Lower its preferred RAM if it exceeds the boot minimum, close other apps, or shut down another environment, then retry."
    }
}

pub fn check_available(required: u64, available: Option<u64>, full_vm: bool) -> Result<(), String> {
    if let Some(available) = available {
        if required.saturating_add(STARTUP_HEADROOM) > available {
            return Err(format!(
                "Not enough memory to start this environment. It needs {:.2} GB of RAM plus 0.25 GB of startup headroom, but Windows can currently allocate only {:.2} GB. {}",
                required as f64 / GB, available as f64 / GB, setting_hint(full_vm)
            ));
        }
    }
    Ok(())
}

/// Handle races after preflight without mistaking every 'Invalid argument' for RAM exhaustion.
pub fn allocation_failure(
    error: &str,
    required: u64,
    available: Option<u64>,
    full_vm: bool,
) -> Option<String> {
    let normalized = error.to_ascii_lowercase();
    if !normalized.contains("cannot set up guest memory 'pc.ram'") {
        return None;
    }
    let explanation = check_available(required, available, full_vm).err().unwrap_or_else(|| {
        format!(
            "Could not allocate {:.2} GB of RAM for this environment. Available memory may have changed during startup, or the runtime rejected the allocation. {}",
            required as f64 / GB, setting_hint(full_vm)
        )
    });
    Some(format!("{explanation} Technical details: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_actual_maximum_and_available_gb() {
        let error = check_available(startup_bytes(18.125, true), Some((12.9 * GB) as u64), true)
            .unwrap_err();
        assert!(error.contains("18.12 GB") || error.contains("18.13 GB"));
        assert!(error.contains("12.90 GB"));
        assert!(error.contains("maximum RAM"));
        assert!(!error.contains("MiB"));
    }

    #[test]
    fn respects_headroom_boundary() {
        let required = startup_bytes(8.0, true);
        assert!(check_available(required, Some(required + STARTUP_HEADROOM), true).is_ok());
        assert!(check_available(required, Some(required + STARTUP_HEADROOM - 1), true).is_err());
    }

    #[test]
    fn missing_measurement_does_not_block_launch() {
        assert!(check_available(startup_bytes(8.0, true), None, true).is_ok());
    }

    #[test]
    fn microvm_message_uses_preferred_not_maximum() {
        let error = check_available(startup_bytes(4.0, false), Some(0), false).unwrap_err();
        assert!(error.contains("preferred RAM"));
        assert!(!error.contains("maximum"));
    }

    #[test]
    fn allocation_race_preserves_diagnostics() {
        let original =
            "virtual machine exited: cannot set up guest memory 'pc.ram': Invalid argument";
        let message = allocation_failure(original, startup_bytes(8.0, true), None, true).unwrap();
        assert!(message.contains("Could not allocate 8.00 GB"));
        assert!(message.ends_with(original));
        assert!(!message.contains("Not enough memory"));
        assert!(
            allocation_failure(original, startup_bytes(8.0, true), Some(0), true)
                .unwrap()
                .contains("Not enough memory")
        );
    }

    #[test]
    fn unrelated_errors_are_not_relabelled() {
        for error in [
            "Invalid argument",
            "failed to initialize EGL",
            "cannot open disk: Permission denied",
        ] {
            assert!(allocation_failure(error, 0, Some(0), true).is_none());
        }
    }

    #[test]
    fn startup_conversion_matches_qemu_bounds() {
        assert_eq!(startup_bytes(18.125, true), 18560 * 1024 * 1024);
        assert_eq!(startup_bytes(0.0, true), 256 * 1024 * 1024);
        assert_eq!(startup_bytes(0.0, false), 128 * 1024 * 1024);
    }

    #[test]
    fn builtin_boot_floor_uses_available_policy_headroom() {
        assert_eq!(microvm_startup_gb(0.25, 0.5, true).unwrap(), 0.5);
        assert_eq!(microvm_startup_gb(0.125, 2.0, true).unwrap(), 0.5);
        assert_eq!(microvm_startup_gb(1.0, 2.0, true).unwrap(), 1.0);
    }

    #[test]
    fn builtin_boot_refuses_to_exceed_the_saved_maximum() {
        for maximum in [0.125, 0.25, 0.499999] {
            let error = microvm_startup_gb(0.125, maximum, true).unwrap_err();
            assert!(error.contains("512 MiB"));
            assert!(error.contains("maximum RAM"));
        }
        // A preference can round down to fit a fractional ceiling safely.
        assert_eq!(microvm_startup_gb(0.5005, 0.5005, true).unwrap(), 0.5);
        assert_eq!(microvm_startup_gb(0.7, 0.7, true).unwrap(), 716.0 / 1024.0);
    }

    #[test]
    fn custom_media_keeps_its_previous_small_boot_allocation() {
        assert_eq!(microvm_startup_gb(0.125, 0.25, false).unwrap(), 0.125);
        assert_eq!(microvm_startup_gb(0.25, 0.25, false).unwrap(), 0.25);
        assert_eq!(microvm_startup_gb(0.0, 0.125, false).unwrap(), 0.125);
    }

    #[test]
    fn builtin_boot_rejects_invalid_bounds_before_allocation() {
        for (preferred, maximum) in [(f64::NAN, 1.0), (0.5, f64::INFINITY), (1.0, 0.5), (0.0, 1.0)] {
            assert!(microvm_startup_gb(preferred, maximum, true).is_err());
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn reads_live_windows_commit_capacity() {
        assert!(available_commit_bytes().is_some_and(|bytes| bytes > 0));
    }
}
