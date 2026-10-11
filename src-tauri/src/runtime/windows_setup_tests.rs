//! Opt-in end-to-end Windows installer check, with no screenshots or install.
//! A tiny test-only guest observer reports visible window titles to its own
//! disposable FAT disk. QMP "running" and ISO reads alone are not sufficient.
use super::{command_output, path_string, vm::qmp_request, RuntimeManager};
use serde_json::json;
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

// Read only the bounded FAT12 test fixture, never a user's VM filesystem.
fn probe_log(disk: &[u8]) -> Option<String> {
    if disk.len() != 1_474_560 || disk[510..512] != [0x55, 0xaa] {
        return None;
    }
    let word = |at| u16::from_le_bytes([disk[at], disk[at + 1]]) as usize;
    let sector = word(11);
    if sector != 512 || disk[13] != 1 {
        return None;
    }
    let fat_start = word(14) * sector;
    let fat_size = word(22) * sector;
    let root = fat_start.checked_add(fat_size.checked_mul(disk[16] as usize)?)?;
    let root_size = word(17).checked_mul(32)?;
    let data = root.checked_add(root_size.div_ceil(sector) * sector)?;
    let entry = disk
        .get(root..root.checked_add(root_size)?)?
        .chunks_exact(32)
        .find(|entry| &entry[..11] == b"PROBE   LOG" && entry[11] & 0x18 == 0)?;
    let size = u32::from_le_bytes(entry[28..32].try_into().ok()?) as usize;
    if size > 65536 {
        return None;
    }
    let mut cluster = u16::from_le_bytes([entry[26], entry[27]]) as usize;
    let mut bytes = Vec::with_capacity(size);
    for _ in 0..128 {
        if bytes.len() >= size {
            break;
        }
        if !(2..0xff0).contains(&cluster) {
            return None;
        }
        let start = data.checked_add((cluster - 2).checked_mul(sector)?)?;
        bytes.extend_from_slice(
            disk.get(start..start.checked_add((size - bytes.len()).min(sector))?)?,
        );
        let at = cluster + cluster / 2;
        if at + 1 >= fat_size {
            return None;
        }
        let value =
            u16::from_le_bytes([*disk.get(fat_start + at)?, *disk.get(fat_start + at + 1)?]);
        cluster = if cluster & 1 == 0 {
            value & 0xfff
        } else {
            value >> 4
        } as usize;
    }
    (bytes.len() == size).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

async fn keys(port: u16, codes: &[&str]) -> Result<(), String> {
    let keys: Vec<_> = codes
        .iter()
        .map(|code| json!({"type":"qcode","data":code}))
        .collect();
    qmp_request(port, "send-key", Some(json!({"keys":keys,"hold-time":40}))).await?;
    tokio::time::sleep(Duration::from_millis(80)).await;
    Ok(())
}

async fn start_observer(port: u16) -> Result<(), String> {
    keys(port, &["shift", "f10"]).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    // A previous attempt may have arrived before WinPE finished initializing
    // its USB keyboard. Clear any partial line before retrying our observer.
    keys(port, &["ctrl", "c"]).await?;
    keys(port, &["esc"]).await?;
    // Only starts our read-only UI observer from the test disk. No installation,
    // diskpart, licensing acceptance, setup choices, or hardware bypasses.
    for character in
        "for %d in (c d e f g h i j) do @if exist %d:\\probe.exe start \"\" %d:\\probe.exe".chars()
    {
        let letter = character.to_string();
        let codes: Vec<&str> = match character {
            ' ' => vec!["spc"],
            '%' => vec!["shift", "5"],
            '(' => vec!["shift", "9"],
            ')' => vec!["shift", "0"],
            '@' => vec!["shift", "2"],
            ':' => vec!["shift", "semicolon"],
            '\\' => vec!["backslash"],
            '.' => vec!["dot"],
            '"' => vec!["shift", "apostrophe"],
            _ => vec![&letter],
        };
        keys(port, &codes).await?;
    }
    keys(port, &["ret"]).await
}

fn setup_visible(log: &str) -> bool {
    log.lines().zip(log.lines().skip(1)).any(|(marker, title)| {
        marker == "VISIBLE_WINDOW" && title.starts_with("Windows") && title.ends_with("Setup")
    }) && log.contains("SETUP_PROCESS\r\n")
        && log.contains("YOUGORI_WINPE_PROBE_STARTED")
}

#[test]
fn windows_setup_verification_requires_a_visible_window_and_process() {
    assert!(!setup_visible("YOUGORI_BOOT_WINDOWS_HANDOFF"));
    assert!(!setup_visible(
        "YOUGORI_WINPE_PROBE_STARTED\r\nSETUP_PROCESS\r\nsetup.exe"
    ));
    assert!(setup_visible("YOUGORI_WINPE_PROBE_STARTED\r\nVISIBLE_WINDOW\r\nWindows 11 Setup\r\nSETUP_PROCESS\r\nSetupHost.exe"));
    assert!(probe_log(&[]).is_none());
    assert!(probe_log(&vec![0; 1_474_560]).is_none());
}

#[test]
fn windows_setup_observer_reads_only_the_bounded_fat_log() {
    let mut image =
        super::boot_media::image(include_bytes!("../../boot-helper/test-os.efi")).unwrap();
    let text = b"YOUGORI_WINPE_PROBE_STARTED\r\nVISIBLE_WINDOW\r\nWindows 11 Setup\r\nSETUP_PROCESS\r\nSetupHost.exe\r\n";
    let entry = 19 * 512 + 32;
    image[entry..entry + 11].copy_from_slice(b"PROBE   LOG");
    image[entry + 11] = 0x20;
    image[entry + 26..entry + 28].copy_from_slice(&50_u16.to_le_bytes());
    image[entry + 28..entry + 32].copy_from_slice(&(text.len() as u32).to_le_bytes());
    let data = (33 + 48) * 512;
    image[data..data + text.len()].copy_from_slice(text);
    assert!(setup_visible(&probe_log(&image).unwrap()));
    image[entry + 28..entry + 32].copy_from_slice(&65537_u32.to_le_bytes());
    assert!(probe_log(&image).is_none());
    image[entry + 28..entry + 32].copy_from_slice(&1024_u32.to_le_bytes());
    image[entry + 26..entry + 28].copy_from_slice(&0xfff_u16.to_le_bytes());
    assert!(probe_log(&image).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires YOUGORI_TEST_WINDOWS_ISO and YOUGORI_TEST_WINDOWS_PROBE; disposable disks only; no screenshots or Windows installation"]
async fn windows_setup_reaches_visible_installer() {
    let iso = std::path::PathBuf::from(
        std::env::var_os("YOUGORI_TEST_WINDOWS_ISO").expect("Set Windows ISO"),
    );
    let probe = std::path::PathBuf::from(
        std::env::var_os("YOUGORI_TEST_WINDOWS_PROBE")
            .expect("Build the test probe using scripts/build-windows-setup-probe.ps1"),
    );
    let before = fs::metadata(&iso).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path()).unwrap();
    let original = temp.path().join("blank.qcow2");
    command_output(
        &manager.layout.qemu_img,
        &[
            "create".into(),
            "-f".into(),
            "qcow2".into(),
            path_string(&original),
            "64G".into(),
        ],
        "create disposable test disk",
    )
    .await
    .unwrap();
    let id = "env-windows-setup-test";
    let disk = manager
        .provision_vm(id, original.to_str().unwrap())
        .await
        .unwrap();
    let probe_copy = temp.path().join("probe.img");
    fs::copy(&probe, &probe_copy).unwrap();
    let cpus = std::env::var("YOUGORI_TEST_WINDOWS_CPUS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(12)
        .clamp(1, 24);
    let memory = std::env::var("YOUGORI_TEST_WINDOWS_MEMORY_GB")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(4.0)
        .clamp(4.0, 32.0);
    let policy = serde_json::from_value(json!({
        "cpu":{"min":cpus,"preferred":cpus,"max":cpus,"current":0},
        "memoryGb":{"min":memory,"preferred":memory,"max":memory,"current":0},
        "priority":"normal","dynamic":false
    }))
    .unwrap();
    let started = Instant::now();
    let result: Result<String, String> = async {
        let gpu = std::env::var_os("YOUGORI_TEST_WINDOWS_GPU").is_some();
        manager.start_vm_with_network(id, &disk.disk_path, &iso, &policy, gpu, false).await?;
        if gpu {
            let vms = manager.vms.lock().await;
            let process = vms.get(id).ok_or("Test VM disappeared")?;
            if !process.gpu_enabled || process.gpu.is_none() { return Err("GPU-enabled primary display was not verified".into()); }
            eprintln!("Primary VirtIO VGA GPU adapter verified: {:?}", process.gpu.as_ref().map(|a| &a.name));
        }
        #[cfg(target_os = "windows")]
        {
            use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
            let pid = Pid::from_u32(manager.vms.lock().await.get(id).unwrap().process_id);
            let mut host = System::new();
            host.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true,
                ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always));
            let accelerated = host.process(pid).is_some_and(|process| process.cmd().windows(2)
                .any(|args| args[0] == "-accel" && args[1] == "whpx"));
            if !accelerated { return Err("The Windows Setup regression test requires WHPX; refusing to mistake a software-emulation fallback for a successful fast boot".into()); }
            eprintln!("WHPX hardware acceleration verified");
        }
        let port = manager.vms.lock().await.get(id).unwrap().qmp_port;
        qmp_request(port, "blockdev-add", Some(json!({
            "driver":"raw", "node-name":"setup-probe", "file":{"driver":"file","filename":path_string(&probe_copy)}
        }))).await?;
        qmp_request(port, "device_add", Some(json!({"driver":"usb-storage","id":"setup-probe","drive":"setup-probe"}))).await?;
        let restart_test = std::env::var_os("YOUGORI_TEST_WINDOWS_RESTART").is_some();
        let mut restarted = false;
        let mut next_observer = 45;
        let mut last_log = String::new();
        let mut boot_log = String::new();
        while started.elapsed() < Duration::from_secs(if restart_test { 360 } else { 180 }) {
            if let Ok(trace) = qmp_request(port, "ringbuf-read", Some(json!({"device":"yougori-boot-log","size":4096}))).await {
                if let Some(text) = trace.as_str() { boot_log.push_str(text); }
            }
            if started.elapsed() > Duration::from_secs(next_observer) && last_log.is_empty() {
                start_observer(port).await?;
                next_observer += 35;
            }
            if let Ok(bytes) = fs::read(&probe_copy) {
                if let Some(log) = probe_log(&bytes) {
                    let recent = &log[log.rfind("YOUGORI_WINPE_PROBE_STARTED").unwrap_or(0)..];
                    if setup_visible(recent)
                        && recent.contains("TPM_2_0_DETECTED")
                        && recent.contains("SECURE_BOOT_ENFORCED") {
                        if !restart_test || (restarted && boot_log.matches("YOUGORI_BOOT_WINDOWS_HANDOFF").count() >= 2 && log.matches("YOUGORI_WINPE_PROBE_STARTED").count() >= 2) {
                            eprintln!("Windows Setup verified on {cpus} CPUs / {memory} GB in {:.1}s:\n{log}", started.elapsed().as_secs_f64());
                            return Ok(log);
                        }
                        if !restarted {
                            eprintln!("Windows Setup/security verified before guest restart in {:.1}s", started.elapsed().as_secs_f64());
                            keys(port, &["ctrl", "c"]).await?;
                            keys(port, &["esc"]).await?;
                            for key in ["w","p","e","u","t","i","l","spc","r","e","b","o","o","t","ret"] {
                                keys(port, &[key]).await?;
                            }
                            restarted = true;
                            next_observer = started.elapsed().as_secs() + 50;
                            eprintln!("Requested WinPE guest reboot; requiring a new observer after reboot");
                        }
                    }
                    last_log = if restarted && log.matches("YOUGORI_WINPE_PROBE_STARTED").count() < 2 { String::new() } else { log };
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let stats = qmp_request(port, "query-blockstats", None).await;
        let status = qmp_request(port, "query-status", None).await;
        Err(format!("Windows Setup and security were not verified before the deadline. Observer: {last_log}; Boot: {boot_log}; Status: {status:?}; Storage: {stats:?}; QEMU: {}; Firmware: {}", fs::read_to_string(disk.disk_path.parent().unwrap().join("qemu.log")).unwrap_or_default(), fs::read_to_string(disk.disk_path.parent().unwrap().join("firmware-serial.log")).unwrap_or_default()))
    }.await;
    manager.shutdown_all().await;
    assert_eq!(before.len(), fs::metadata(&iso).unwrap().len());
    assert_eq!(
        before.modified().unwrap(),
        fs::metadata(&iso).unwrap().modified().unwrap()
    );
    result.unwrap();
}
