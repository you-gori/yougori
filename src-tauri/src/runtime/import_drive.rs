use super::{vm, RuntimeManager};
use crate::models::{Environment, EnvironmentKind};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedDrive {
    pub id: String,
    pub attached: bool,
    pub bytes: u64,
}

fn real_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Imported-files storage cannot be a linked folder".into());
        }
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Imported-files storage is not a private directory".into());
    }
    Ok(())
}

pub(super) fn import_drives(environment: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(all_import_drives(environment)?
        .into_iter()
        .filter(|drive| drive.attached)
        .map(|drive| {
            let path = environment
                .join("imported-files")
                .join(format!("{}.img", drive.id));
            (drive.id, path)
        })
        .collect())
}

pub(super) fn storage_paths(environment: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(all_import_drives(environment)?
        .into_iter()
        .map(|drive| {
            environment.join("imported-files").join(format!(
                "{}.{}",
                drive.id,
                if drive.attached { "img" } else { "detached" }
            ))
        })
        .collect())
}

fn all_import_drives(environment: &Path) -> Result<Vec<ImportedDrive>, String> {
    real_directory(environment)?;
    let folder = environment.join("imported-files");
    if !folder.try_exists().map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    real_directory(&folder)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(&folder).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if path
            .extension()
            .is_none_or(|e| e != "img" && e != "detached")
            || id.len() != 32
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("An imported drive was replaced by a link".into());
            }
        }
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("An imported drive is not a regular file".into());
        }
        result.push(ImportedDrive {
            id: id.to_string(),
            attached: path.extension().is_some_and(|e| e == "img"),
            bytes: metadata.len(),
        });
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

pub(super) fn drive_arguments(environment: &Path) -> Result<Vec<String>, String> {
    let mut arguments = Vec::new();
    for (id, path) in import_drives(environment)? {
        let node = format!("import-{}", &id[..16]);
        arguments.extend([
            "-blockdev".into(),
            json!({"driver":"raw","node-name":node,"file":{"driver":"file","filename":path}})
                .to_string(),
            "-device".into(),
            format!("usb-storage,drive={node},id=usb-{node},removable=on"),
        ]);
    }
    Ok(arguments)
}

impl RuntimeManager {
    pub fn imported_drives(&self, environment: &Environment) -> Result<Vec<ImportedDrive>, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return engine.imported_drives(environment); }

        if environment.kind != EnvironmentKind::FullVm {
            return Err("Imported-files drives are for full VMs".into());
        }
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        vm::validate_runtime_identifier("virtual machine", id)?;
        all_import_drives(&self.data_root.join("environments").join(id))
    }

    pub async fn set_import_drive_attached(
        &self,
        environment: &Environment,
        transfer: &str,
        attached: bool,
    ) -> Result<Vec<ImportedDrive>, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.set_import_drive_attached(environment, transfer, attached)).await; }

        let drives = self.imported_drives(environment)?;
        let drive = drives
            .iter()
            .find(|drive| drive.id == transfer)
            .ok_or("Imported drive not found")?;
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        if environment.status != crate::models::EnvironmentStatus::Stopped
            || self.vm_is_running(id).await?
        {
            return Err(
                "Shut down this VM before connecting or disconnecting an imported drive".into(),
            );
        }
        self.check_external_vm(id, false).await?;
        if drive.attached == attached {
            return Ok(drives);
        }
        if attached && drives.iter().filter(|drive| drive.attached).count() >= 12 {
            return Err(
                "Disconnect an imported drive first; a VM can have 12 connected at once".into(),
            );
        }
        let folder = self
            .data_root
            .join("environments")
            .join(id)
            .join("imported-files");
        let source = folder.join(format!(
            "{transfer}.{}",
            if drive.attached { "img" } else { "detached" }
        ));
        let target = folder.join(format!(
            "{transfer}.{}",
            if attached { "img" } else { "detached" }
        ));
        if target.try_exists().map_err(|e| e.to_string())? {
            return Err("A saved imported drive already occupies that destination".into());
        }
        // Disconnect retains the independent copy and any edits made inside the VM.
        fs::rename(source, target).map_err(|e| e.to_string())?;
        self.imported_drives(environment)
    }

    pub async fn attach_import_drive(
        &self,
        environment: &Environment,
        source: &Path,
        transfer: &str,
    ) -> Result<String, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.attach_import_drive(environment, source, transfer)).await; }

        if environment.kind != EnvironmentKind::FullVm {
            return Err("Imported-files drives are for full VMs".into());
        }
        if transfer.len() != 32 || !transfer.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid import identifier".into());
        }
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        vm::validate_runtime_identifier("virtual machine", id)?;
        let lock = self.vm_lifecycle_mutex(id).await;
        let _guard = lock.lock().await;
        let qmp = {
            let mut vms = self.vms.lock().await;
            let vm = vms.get_mut(id).ok_or("Start the VM before copying files")?;
            if vm.child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("The VM stopped before the copy completed".into());
            }
            vm.qmp.clone()
        };
        let environment_root = self.data_root.join("environments").join(id);
        if import_drives(&environment_root)?.len() >= 12 {
            return Err("This VM already has 12 imported-files drives. Shut it down and disconnect an unused drive in its configuration before adding more.".into());
        }
        let folder = environment_root.join("imported-files");
        if !folder.exists() {
            fs::create_dir(&folder).map_err(|e| e.to_string())?;
        }
        real_directory(&folder)?;
        let target = folder.join(format!("{transfer}.img"));
        if target.try_exists().map_err(|e| e.to_string())? {
            return Err("Imported-files drive already exists".into());
        }
        // Both paths are Yougori-owned staging/storage. Source selections never
        // reach QEMU and are never moved, mounted, linked, or written.
        fs::rename(source, &target).map_err(|e| e.to_string())?;
        let node = format!("import-{}", &transfer[..16]);
        let attach = async {
            vm::qmp_execute_bounded(&qmp, "blockdev-add", Some(json!({"driver":"raw","node-name":node,"file":{"driver":"file","filename":target}})), Duration::from_secs(10)).await?;
            vm::qmp_execute_bounded(&qmp, "device_add", Some(json!({"driver":"usb-storage","drive":node,"id":format!("usb-{node}"),"removable":true})), Duration::from_secs(10)).await
        }.await;
        if let Err(error) = attach {
            // Keep the independently copied image: a timed-out QMP command may
            // still have attached it. The next VM boot reconnects persisted drives.
            return Err(format!("Files were copied, but attaching the drive was not confirmed: {error}. Restart the VM to reconnect its imported drive."));
        }
        Ok(format!("YOUGORI · {}", &transfer[..8]))
    }
}
