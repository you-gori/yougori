//! A read-only FAT12 bootstrap for installer ISOs. The tiny EFI application
//! runs inside QEMU, not on the host. It uses the ISO's own boot loaders.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const EFI: &[u8] = include_bytes!("../../boot-helper/bootx64.efi");
const SECTOR: usize = 512;
const DATA: usize = 33 * SECTOR;

fn fat_entry(fat: &mut [u8], cluster: usize, value: u16) {
    let at = cluster + cluster / 2;
    if cluster % 2 == 0 {
        fat[at] = value as u8;
        fat[at + 1] = (fat[at + 1] & 0xf0) | ((value >> 8) as u8 & 0x0f);
    } else {
        fat[at] = (fat[at] & 0x0f) | ((value << 4) as u8);
        fat[at + 1] = (value >> 4) as u8;
    }
}

fn directory_entry(entry: &mut [u8], name: &[u8; 11], directory: bool, cluster: u16, size: u32) {
    entry[..11].copy_from_slice(name);
    entry[11] = if directory { 0x10 } else { 0x20 };
    entry[26..28].copy_from_slice(&cluster.to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
}

pub(super) fn image(executable: &[u8]) -> Result<Vec<u8>, String> {
    if executable.len() < 512 || executable.len() > 64 * 1024 || &executable[..2] != b"MZ" {
        return Err("Invalid bundled x64 boot helper".into());
    }
    // Standard 1.44 MB FAT12 geometry, with only EFI/BOOT/BOOTX64.EFI.
    let mut disk = vec![0_u8; 2880 * SECTOR];
    disk[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    disk[3..11].copy_from_slice(b"YOUGORI ");
    disk[11..13].copy_from_slice(&512_u16.to_le_bytes());
    disk[13] = 1;
    disk[14..16].copy_from_slice(&1_u16.to_le_bytes());
    disk[16] = 2;
    disk[17..19].copy_from_slice(&224_u16.to_le_bytes());
    disk[19..21].copy_from_slice(&2880_u16.to_le_bytes());
    disk[21] = 0xf0;
    disk[22..24].copy_from_slice(&9_u16.to_le_bytes());
    disk[24..26].copy_from_slice(&18_u16.to_le_bytes());
    disk[26..28].copy_from_slice(&2_u16.to_le_bytes());
    disk[38] = 0x29;
    disk[39..43].copy_from_slice(&0x4f44424f_u32.to_le_bytes());
    disk[43..54].copy_from_slice(b"YOUGORI    ");
    disk[54..62].copy_from_slice(b"FAT12   ");
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    let mut fat = vec![0_u8; 9 * SECTOR];
    fat[..3].copy_from_slice(&[0xf0, 0xff, 0xff]);
    fat_entry(&mut fat, 2, 0xfff);
    fat_entry(&mut fat, 3, 0xfff);
    let clusters = executable.len().div_ceil(SECTOR);
    for cluster in 4..4 + clusters {
        fat_entry(
            &mut fat,
            cluster,
            if cluster == 3 + clusters {
                0xfff
            } else {
                (cluster + 1) as u16
            },
        );
    }
    disk[SECTOR..10 * SECTOR].copy_from_slice(&fat);
    disk[10 * SECTOR..19 * SECTOR].copy_from_slice(&fat);
    directory_entry(&mut disk[19 * SECTOR..], b"EFI        ", true, 2, 0);
    directory_entry(&mut disk[DATA..], b".          ", true, 2, 0);
    directory_entry(&mut disk[DATA + 32..], b"..         ", true, 0, 0);
    directory_entry(&mut disk[DATA + 64..], b"BOOT       ", true, 3, 0);
    directory_entry(&mut disk[DATA + SECTOR..], b".          ", true, 3, 0);
    directory_entry(&mut disk[DATA + SECTOR + 32..], b"..         ", true, 2, 0);
    directory_entry(
        &mut disk[DATA + SECTOR + 64..],
        b"BOOTX64 EFI",
        false,
        4,
        executable.len() as u32,
    );
    disk[DATA + 2 * SECTOR..DATA + 2 * SECTOR + executable.len()].copy_from_slice(executable);
    Ok(disk)
}

pub(super) fn prepare(directory: &Path) -> Result<PathBuf, String> {
    let bytes = image(EFI)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let path = directory.join(format!("installer-boot-{}.img", &digest[..16]));
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != bytes.len() as u64
            {
                return Err("The managed installer boot helper is not a safe regular file".into());
            }
            if fs::read(&path).map_err(|e| e.to_string())? != bytes {
                return Err("The managed installer boot helper failed its integrity check".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let temporary = directory.join(format!(".installer-boot-{}.tmp", uuid::Uuid::new_v4()));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            let result = file.write_all(&bytes).and_then(|_| file.sync_all());
            drop(file);
            let result = result.and_then(|_| fs::rename(&temporary, &path));
            if let Err(error) = result {
                // Remove only the unique file created above, never VM/user data.
                let _ = fs::remove_file(&temporary);
                return Err(format!("Prepare installer boot helper: {error}"));
            }
        }
        Err(e) => return Err(e.to_string()),
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{command_output, path_string, RuntimeManager};
    use std::time::{Duration, Instant};

    async fn boot_trace(port: u16) -> String {
        super::super::vm::qmp_request(
            port,
            "ringbuf-read",
            Some(serde_json::json!({
                "device":"yougori-boot-log", "size":4096, "format":"utf8"
            })),
        )
        .await
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
    }

    fn test_iso() -> Vec<u8> {
        let boot = image(include_bytes!("../../boot-helper/test-os.efi")).unwrap();
        let sectors = 22 + boot.len().div_ceil(2048);
        let mut iso = vec![0_u8; sectors * 2048];
        for (sector, kind) in [(16, 1), (17, 0), (18, 255)] {
            iso[sector * 2048] = kind;
            iso[sector * 2048 + 1..sector * 2048 + 6].copy_from_slice(b"CD001");
            iso[sector * 2048 + 6] = 1;
        }
        let p = 16 * 2048;
        iso[p + 80..p + 84].copy_from_slice(&(sectors as u32).to_le_bytes());
        iso[p + 84..p + 88].copy_from_slice(&(sectors as u32).to_be_bytes());
        iso[p + 120..p + 124].copy_from_slice(&[1, 0, 0, 1]);
        iso[p + 124..p + 128].copy_from_slice(&[1, 0, 0, 1]);
        iso[p + 128..p + 132].copy_from_slice(&[0, 8, 8, 0]);
        iso[17 * 2048 + 7..17 * 2048 + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
        iso[17 * 2048 + 71..17 * 2048 + 75].copy_from_slice(&19_u32.to_le_bytes());
        let c = 19 * 2048;
        iso[c] = 1;
        iso[c + 1] = 0xef;
        iso[c + 30] = 0x55;
        iso[c + 31] = 0xaa;
        let sum = 0_u16.wrapping_sub(0xef01).wrapping_sub(0xaa55);
        iso[c + 28..c + 30].copy_from_slice(&sum.to_le_bytes());
        iso[c + 32] = 0x88;
        iso[c + 38..c + 40].copy_from_slice(&2880_u16.to_le_bytes());
        iso[c + 40..c + 44].copy_from_slice(&22_u32.to_le_bytes());
        iso[22 * 2048..22 * 2048 + boot.len()].copy_from_slice(&boot);
        iso
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "boots a disposable unsigned EFI fixture under Secure Boot; no screenshots or user VM changes"]
    async fn secure_boot_rejects_unsigned_installer() {
        let temp = tempfile::tempdir().unwrap();
        let manager =
            RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path()).unwrap();
        // The name selects the secure profile; the contents are ONLY our
        // unsigned test program, which must never execute under that profile.
        let source = temp.path().join("Win11-unsigned-test.iso");
        fs::write(&source, test_iso()).unwrap();
        let id = "env-unsigned-secure-test";
        let disk = manager
            .provision_vm(id, source.to_str().unwrap())
            .await
            .unwrap();
        let policy = serde_json::from_value(serde_json::json!({
            "cpu":{"min":2,"preferred":2,"max":2,"current":0},
            "memoryGb":{"min":1,"preferred":1,"max":1,"current":0},
            "priority":"normal","dynamic":false
        }))
        .unwrap();
        let result: Result<String, String> = async {
            manager
                .start_vm_with_network(id, &disk.disk_path, &source, &policy, false, false)
                .await?;
            let port = manager.vms.lock().await.get(id).unwrap().qmp_port;
            let deadline = Instant::now() + Duration::from_secs(45);
            let mut trace = String::new();
            while Instant::now() < deadline {
                trace.push_str(&boot_trace(port).await);
                if trace.contains("YOUGORI_BOOT_NO_INSTALLER")
                    || trace.contains("YOUGORI_BOOT_TEST_OS")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(trace)
        }
        .await;
        manager.shutdown_all().await;
        let trace = result.unwrap();
        eprintln!("Secure Boot rejection: {trace}");
        assert!(
            trace.contains("YOUGORI_BOOT_START"),
            "our explicitly trusted bootstrap must run"
        );
        assert!(
            trace.contains("YOUGORI_BOOT_LOAD_FAILED"),
            "firmware must reject unsigned code"
        );
        assert!(trace.contains("YOUGORI_BOOT_NO_INSTALLER"));
        assert!(!trace.contains("YOUGORI_BOOT_TEST_OS"));
        assert!(!trace.contains("YOUGORI_BOOT_INSTALLER_HANDOFF"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "guest-requested cold/warm reboots and shutdown on a disposable EFI disk; no Windows installation or user VM changes"]
    async fn installer_guest_restarts_keep_process_console_and_installed_disk() -> Result<(), String>
    {
        restart_regression(false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "same guest reboot regression with Windows 11 Secure Boot/TPM profile, using only a disposable trusted fixture"]
    async fn installer_guest_restarts_with_secure_boot() -> Result<(), String> {
        restart_regression(true).await
    }

    async fn restart_regression(secure: bool) -> Result<(), String> {
        use crate::runtime::VmPowerState;
        let temp = tempfile::tempdir().unwrap();
        let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path())?;
        let id = "env-restart-regression";
        let result = async {
            let iso = temp.path().join("installer.iso");
            fs::write(&iso, test_iso()).map_err(|e| e.to_string())?;
            let original_iso = fs::read(&iso).map_err(|e| e.to_string())?;
            let raw = temp.path().join("installed.img");
            fs::write(&raw, image(include_bytes!("../../boot-helper/test-restart.efi"))?).map_err(|e| e.to_string())?;
            let source = temp.path().join("installed.qcow2");
            command_output(&manager.layout.qemu_img, &["convert".into(), "-f".into(), "raw".into(), "-O".into(), "qcow2".into(), path_string(&raw), path_string(&source)], "create restart test disk").await?;
            let disk = manager.provision_vm(id, source.to_str().unwrap()).await?;
            let directory = disk.disk_path.parent().unwrap();
            if secure {
            assert_eq!(hex::encode(Sha256::digest(include_bytes!("../../boot-helper/test-restart.efi"))),
                "5a122e5cc14922679b5de985f26070cbdd10497f6c6800ca0ef0c4b2f3af4b38",
                "Rebuilt fixture: recompute its Authenticode hash with pesign before trusting it in the test VM");
            super::super::vm_security::prepare_required(&manager.layout, directory, &source, true).await?;
            let security = super::super::vm_security::profile(directory)?.unwrap().directory(directory)?;
            let vars_path = security.join("uefi-vars.json");
            let mut vars: serde_json::Value = serde_json::from_slice(&fs::read(&vars_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            // Trust only this fixture in this disposable VM, never in the shipped database.
            let mut signature = vec![0x26,0x16,0xc4,0xc1,0x4c,0x50,0x92,0x40,0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28];
            signature.extend(76_u32.to_le_bytes()); signature.extend(0_u32.to_le_bytes()); signature.extend(48_u32.to_le_bytes());
            signature.extend([0_u8;16]);
            signature.extend(hex::decode("81b0b61e841efe21202a7d21f0f7ba19094a7a51ffafe5d0d5d130687d13170d").unwrap());
            let db = vars["variables"].as_array_mut().unwrap().iter_mut().find(|v| v["name"] == "db").unwrap();
            db["data"] = serde_json::json!(format!("{}{}", db["data"].as_str().unwrap(), hex::encode(signature)));
            fs::write(&vars_path, serde_json::to_vec(&vars).unwrap()).map_err(|e| e.to_string())?;
            }
            let original_security_profile = super::super::vm_security::profile(directory)?;
            let policy = serde_json::from_value(serde_json::json!({
                "cpu":{"min":2,"preferred":2,"max":2,"current":0},
                "memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},
                "priority":"normal","dynamic":false
            })).unwrap();
            let console = manager.start_vm(id, &disk.disk_path, &iso, &policy, false).await?;
            let (pid, port) = { let processes = manager.vms.lock().await; let process = processes.get(id).unwrap(); (process.process_id, process.qmp_port) };
            let display_port: u16 = console.websocket_url.rsplit(':').next().unwrap().parse().unwrap();
            let deadline = Instant::now() + Duration::from_secs(180);
            let mut trace = String::new();
            while Instant::now() < deadline {
                assert_eq!(manager.vm_power_state(id).await?, VmPowerState::Running, "guest reboot must not be treated as stopped");
                assert_eq!(manager.vms.lock().await.get(id).unwrap().process_id, pid);
                assert_eq!(manager.vm_console(id).await?.websocket_url, console.websocket_url);
                assert_eq!(manager.vm_console(id).await?.password, console.password);
                tokio::net::TcpStream::connect(("127.0.0.1", display_port)).await.map_err(|e| e.to_string())?;
                let chunk = super::super::vm::qmp_request(port, "ringbuf-read", Some(serde_json::json!({"device":"yougori-boot-log","size":4096,"format":"utf8"}))).await?;
                let chunk = chunk.as_str().unwrap_or_default();
                if !chunk.is_empty() { eprintln!("{chunk}"); }
                trace.push_str(chunk);
                if trace.contains("RESTART_TEST_COMPLETE") { break; }
                let state = super::super::vm::qmp_request(port, "query-status", None).await?;
                if state["status"] == "paused" || state["status"] == "internal-error" {
                    let log = fs::read_to_string(temp.path().join("runtime/environments").join(id).join("qemu.log")).unwrap_or_default();
                    return Err(format!("Guest stopped executing: {state}\n{trace}\n{log}"));
                }
                if trace.contains("_ERROR") || trace.contains("RESET_RETURNED") { return Err(trace); }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            for count in 0..=3 { assert!(trace.contains(&format!("RESTART_TEST_BOOT_{count}")), "{trace}"); }
            assert_eq!(trace.matches("RESTART_TEST_STALE_SNP_RAM").count(), 3, "{trace}");
            assert!(trace.contains("RESTART_TEST_COMPLETE"), "{trace}");
            assert!(!trace.contains("YOUGORI_BOOT_START"), "restarts must prefer the installed disk, not start the ISO again: {trace}");
            assert_eq!(fs::read(&iso).map_err(|e| e.to_string())?, original_iso);
            let deadline = Instant::now() + Duration::from_secs(20);
            while manager.vm_is_running(id).await? && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Viewer/resource probes can race the telemetry loop after shutdown.
            // None may consume the successful exit before telemetry classifies it.
            assert!(manager.vm_console(id).await.is_err());
            assert!(manager.vm_action(id, "resume").await.is_err());
            assert!(manager.update_vm_resources(id, 2.0, 0.5).await.is_err());
            let power = manager.vm_power_state(id).await?;
            assert_eq!(power, VmPowerState::Stopped, "normal guest shutdown is not a runtime error");
            assert!(disk.disk_path.exists(), "shutdown must preserve the installed disk");
            assert_eq!(super::super::vm_security::profile(directory)?, original_security_profile,
                "guest restarts must not replace the TPM/Secure Boot identity");
            if secure { assert!(super::super::vm_security::capture(directory)?.is_some()); }
            eprintln!("Verified same PID/display through three guest cold/warm reboots, installed-disk priority with ISO attached, persisted guest files, then clean shutdown.\n{trace}");
            Ok(())
        }.await;
        manager.shutdown_all().await;
        result
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "boots only disposable EFI fixtures to check generic ISO fallback and installed-disk priority; no screenshots or user VM changes"]
    async fn installer_boot_generic_iso_and_installed_disk_priority() {
        let temp = tempfile::tempdir().unwrap();
        let manager =
            RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path()).unwrap();
        let source = temp.path().join("fixture.iso");
        fs::write(&source, test_iso()).unwrap();
        let policy = serde_json::from_value(serde_json::json!({
            "cpu":{"min":1,"preferred":1,"max":1,"current":0},
            "memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},
            "priority":"normal","dynamic":false
        }))
        .unwrap();
        for installed in [false, true] {
            let id = if installed {
                "env-installed-boot"
            } else {
                "env-installer-boot"
            };
            let disk_source = temp.path().join(format!("{id}.qcow2"));
            if installed {
                let raw = temp.path().join("installed.img");
                fs::write(
                    &raw,
                    image(include_bytes!("../../boot-helper/test-os.efi")).unwrap(),
                )
                .unwrap();
                command_output(
                    &manager.layout.qemu_img,
                    &[
                        "convert".into(),
                        "-f".into(),
                        "raw".into(),
                        "-O".into(),
                        "qcow2".into(),
                        path_string(&raw),
                        path_string(&disk_source),
                    ],
                    "create installed EFI fixture",
                )
                .await
                .unwrap();
            } else {
                command_output(
                    &manager.layout.qemu_img,
                    &[
                        "create".into(),
                        "-f".into(),
                        "qcow2".into(),
                        path_string(&disk_source),
                        "64M".into(),
                    ],
                    "create empty EFI fixture",
                )
                .await
                .unwrap();
            }
            let disk = manager
                .provision_vm(id, disk_source.to_str().unwrap())
                .await
                .unwrap();
            manager
                .start_vm(id, &disk.disk_path, &source, &policy, false)
                .await
                .unwrap();
            let port = manager.vms.lock().await.get(id).unwrap().qmp_port;
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut trace = String::new();
            while Instant::now() < deadline {
                trace.push_str(&boot_trace(port).await);
                if trace.contains("YOUGORI_BOOT_TEST_OS")
                    || trace.contains("YOUGORI_BOOT_NO_INSTALLER")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            eprintln!("Installed={installed}: {trace}");
            manager.shutdown_all().await;
            assert!(trace.contains("YOUGORI_BOOT_TEST_OS"));
            assert_eq!(
                trace.contains("YOUGORI_BOOT_INSTALLER_HANDOFF"),
                !installed
            );
            assert_eq!(trace.contains("YOUGORI_BOOT_START"), !installed);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "boots a disposable VM against YOUGORI_TEST_WINDOWS_ISO read-only; no keys, screenshots, OS installation, or user VM changes"]
    async fn installer_boot_real_windows_loader_handoff_needs_no_keyboard() {
        let source = PathBuf::from(
            std::env::var_os("YOUGORI_TEST_WINDOWS_ISO")
                .expect("Set YOUGORI_TEST_WINDOWS_ISO to a local x64 Windows ISO"),
        );
        assert!(source.is_file());
        let before = fs::metadata(&source).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let manager =
            RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path()).unwrap();
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
            "create test disk",
        )
        .await
        .unwrap();
        let disk = manager
            .provision_vm("env-boot-test", original.to_str().unwrap())
            .await
            .unwrap();
        let cpus = std::env::var("YOUGORI_TEST_WINDOWS_CPUS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(2)
            .clamp(1, 12);
        let policy = serde_json::from_value(serde_json::json!({
            "cpu":{"min":cpus,"preferred":cpus,"max":cpus,"current":0},
            "memoryGb":{"min":4,"preferred":4,"max":4,"current":0},
            "priority":"normal","dynamic":false
        }))
        .unwrap();
        manager
            .start_vm("env-boot-test", &disk.disk_path, &source, &policy, false)
            .await
            .unwrap();
        let port = manager
            .vms
            .lock()
            .await
            .get("env-boot-test")
            .unwrap()
            .qmp_port;
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut passed = false;
        let mut trace = String::new();
        while Instant::now() < deadline {
            trace.push_str(&boot_trace(port).await);
            if trace.contains("YOUGORI_BOOT_NO_INSTALLER")
                || trace.contains("YOUGORI_BOOT_INSTALLER_RETURNED")
            {
                break;
            }
            if trace.contains("YOUGORI_BOOT_WINDOWS_HANDOFF") {
                let stats = super::super::vm::qmp_request(port, "query-blockstats", None)
                    .await
                    .unwrap();
                let read = stats
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|item| item["node-name"] == "yougori-install-media")
                    .filter_map(|item| item["stats"]["rd_bytes"].as_u64())
                    .max()
                    .unwrap_or(0);
                if read > 512 * 1024 * 1024 {
                    eprintln!(
                        "Windows loader handoff only (not a Setup readiness check); ISO bytes read: {read}"
                    );
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    passed = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        eprintln!("Boot trace: {trace}");
        let status = super::super::vm::qmp_request(port, "query-status", None)
            .await
            .unwrap();
        eprintln!("Final CPU status: {status}");
        eprintln!(
            "QEMU log: {}",
            fs::read_to_string(disk.disk_path.parent().unwrap().join("qemu.log"))
                .unwrap_or_default()
        );
        passed &= status["status"] == "running";
        if !passed {
            eprintln!(
                "Block stats: {}",
                super::super::vm::qmp_request(port, "query-blockstats", None)
                    .await
                    .unwrap()
            );
            eprintln!(
                "CPU status: {}",
                super::super::vm::qmp_request(port, "query-status", None)
                    .await
                    .unwrap()
            );
        }
        manager.shutdown_all().await;
        assert!(passed, "Windows installer did not load: {trace}");
        let after = fs::metadata(source).unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    }
    #[test]
    fn installer_boot_image_is_bounded_and_contains_only_our_efi_app() {
        let disk = image(EFI).unwrap();
        assert_eq!(disk.len(), 1_474_560);
        assert_eq!(&disk[510..512], &[0x55, 0xaa]);
        assert_eq!(&disk[DATA + 2 * SECTOR..DATA + 2 * SECTOR + EFI.len()], EFI);
        assert_eq!(&disk[SECTOR..10 * SECTOR], &disk[10 * SECTOR..19 * SECTOR]);
        assert!(image(&vec![0; 100_000]).is_err());
        // PE32+ x64 EFI application, not a host executable.
        let pe = u32::from_le_bytes(EFI[60..64].try_into().unwrap()) as usize;
        assert_eq!(&EFI[pe..pe + 4], b"PE\0\0");
        assert_eq!(&EFI[pe + 4..pe + 6], &0x8664_u16.to_le_bytes());
        assert_eq!(&EFI[pe + 24 + 68..pe + 24 + 70], &10_u16.to_le_bytes());
    }
    #[test]
    fn installer_boot_helper_reuses_verified_bytes_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare(dir.path()).unwrap();
        assert_eq!(prepare(dir.path()).unwrap(), path);
        fs::write(&path, b"wrong").unwrap();
        assert!(prepare(dir.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"wrong");
    }
}
