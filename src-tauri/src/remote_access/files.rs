use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cap_std::fs::{Dir, OpenOptions};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};

pub(super) fn validate_guest_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/')
        || root.len() > 4096
        || root.contains(['\0', '\\'])
        || root.split('/').any(|p| p == "..")
    {
        return Err("Choose an absolute folder inside the environment".into());
    }
    Ok(())
}
pub(super) fn validate_pc_root(root: &str, yougori_roots: &[PathBuf]) -> Result<(), String> {
    if !Path::new(root).is_absolute() {
        return Err("Choose an absolute PC folder path".into());
    }
    let path = Path::new(root)
        .canonicalize()
        .map_err(|_| "Choose an existing PC folder")?;
    if !path.is_dir() {
        return Err("Choose a folder".into());
    }
    crate::host_files::ensure_shareable_folder(&path, yougori_roots, true)
}
/// Yougori's app data, environment storage and every storage-drive runtime.
pub(super) fn yougori_roots(app: &AppHandle) -> Vec<PathBuf> {
    let mut roots = vec![app.state::<RemoteAccess>().root.clone(), app.state::<WorkspaceManager>().storage_directory().to_owned()];
    roots.extend(app.state::<RuntimeManager>().storage_pool_roots());
    roots
}
fn relative(value: &str) -> Result<&Path, String> {
    let path = Path::new(if value.is_empty() { "." } else { value });
    if value.len() > 4096
        || value.contains(['\\', ':', '\0'])
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err("Path must stay inside the shared folder".into());
    }
    Ok(path)
}
fn io_error(_: std::io::Error) -> String {
    "File operation failed. Check the name, access rights, and whether another user changed it."
        .into()
}
fn info(root: &Dir, path: &Path) -> Result<Value, String> {
    let m = root.symlink_metadata(path).map_err(io_error)?;
    if m.file_type().is_symlink() || (!m.is_file() && !m.is_dir()) {
        return Err("Only ordinary files and folders are shared".into());
    }
    Ok(
        json!({"name":path.file_name().unwrap_or_default().to_string_lossy(),"directory":m.is_dir(),"size":m.len()}),
    )
}
fn ordinary(file: &cap_std::fs::File) -> Result<(), String> {
    let m = file.metadata().map_err(io_error)?;
    if !m.is_file() {
        return Err("Choose an ordinary file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
        {
            return Err("Hard-linked or unavailable files cannot be shared".into());
        }
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if m.nlink() != 1 {
            return Err("Hard-linked files cannot be shared".into());
        }
    }
    Ok(())
}
pub(super) fn pc_operation(
    folder: &str,
    permission: &Permission,
    p: Value,
) -> Result<Value, String> {
    let root = Dir::open_ambient_dir(folder, cap_std::ambient_authority()).map_err(io_error)?;
    let path = relative(p["path"].as_str().unwrap_or(""))?;
    let operation = p["operation"].as_str().ok_or("Missing file operation")?;
    if p["offset"].as_u64().unwrap_or(0) > 1 << 40 || p["length"].as_u64().unwrap_or(0) > 1 << 40 {
        return Err("Invalid file range".into());
    }
    let writing = !matches!(operation, "list" | "stat" | "read");
    if writing && (*permission == Permission::View || path == Path::new(".")) {
        return Err("This file operation is not permitted".into());
    }
    // Reject symlinks explicitly; Dir additionally confines all resolution to
    // the opened directory, including changes made concurrently by local users.
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        if root
            .symlink_metadata(&prefix)
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("Links are not shared".into());
        }
    }
    match operation {
        "stat" => Ok(json!({"info":info(&root,path)?})),
        "list" => {
            let mut entries = Vec::new();
            for entry in root.read_dir(path).map_err(io_error)?.take(5001) {
                if entries.len() == 5000 {
                    return Err("Folder exceeds 5,000 entries; choose a smaller folder".into());
                }
                let entry = entry.map_err(io_error)?;
                if let Ok(value) = info(&root, &path.join(entry.file_name())) {
                    entries.push(value)
                }
            }
            Ok(json!({"entries":entries}))
        }
        "read" => {
            let mut f = root.open(path).map_err(io_error)?;
            ordinary(&f)?;
            f.seek(SeekFrom::Start(p["offset"].as_u64().unwrap_or(0)))
                .map_err(io_error)?;
            let mut data = vec![0; p["length"].as_u64().unwrap_or(65536).min(65536) as usize];
            let count = f.read(&mut data).map_err(io_error)?;
            Ok(json!({"data":B64.encode(&data[..count])}))
        }
        "replace" => {
            let expected = B64
                .decode(
                    p["expectedData"]
                        .as_str()
                        .ok_or("Reload the file before saving")?,
                )
                .map_err(|_| "Invalid previous file data")?;
            let data = B64
                .decode(p["data"].as_str().unwrap_or(""))
                .map_err(|_| "Invalid file data")?;
            if expected.len() > 65536 || data.len() > 65536 {
                return Err("Text editing is limited to 64 KiB".into());
            }
            let mut old = root.open(path).map_err(io_error)?;
            ordinary(&old)?;
            let mut actual = Vec::new();
            std::io::Read::by_ref(&mut old)
                .take(65537)
                .read_to_end(&mut actual)
                .map_err(io_error)?;
            if actual != expected {
                return Err("File changed; reopen it before saving".into());
            }
            let temp = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(format!(".yougori-save-{}", uuid::Uuid::new_v4().simple()));
            let result = (|| {
                let mut file = root
                    .open_with(&temp, OpenOptions::new().write(true).create_new(true))
                    .map_err(io_error)?;
                file.write_all(&data).map_err(io_error)?;
                file.sync_all().map_err(io_error)?;
                file.set_permissions(old.metadata().map_err(io_error)?.permissions())
                    .map_err(io_error)?;
                drop(file);
                drop(old);
                root.rename(&temp, &root, path).map_err(io_error)?;
                Ok(json!({"count":data.len()}))
            })();
            if result.is_err() {
                let _ = root.remove_file(&temp);
            }
            result
        }
        "create" => {
            root.open_with(path, OpenOptions::new().write(true).create_new(true))
                .map_err(io_error)?;
            Ok(json!({}))
        }
        "mkdir" => {
            root.create_dir(path).map_err(io_error)?;
            Ok(json!({}))
        }
        "write" => {
            let data = B64
                .decode(p["data"].as_str().unwrap_or(""))
                .map_err(|_| "Invalid file data")?;
            if data.len() > 65536 {
                return Err("File chunks must be at most 64 KiB".into());
            }
            let mut file = root
                .open_with(path, OpenOptions::new().write(true))
                .map_err(io_error)?;
            ordinary(&file)?;
            file.seek(SeekFrom::Start(p["offset"].as_u64().unwrap_or(0)))
                .map_err(io_error)?;
            file.write_all(&data).map_err(io_error)?;
            Ok(json!({"count":data.len()}))
        }
        "truncate" => {
            let file = root
                .open_with(path, OpenOptions::new().write(true))
                .map_err(io_error)?;
            ordinary(&file)?;
            file.set_len(p["length"].as_u64().ok_or("Missing file length")?)
                .map_err(io_error)?;
            Ok(json!({}))
        }
        "remove" => {
            if root.symlink_metadata(path).map_err(io_error)?.is_dir() {
                root.remove_dir(path)
            } else {
                root.remove_file(path)
            }
            .map_err(io_error)?;
            Ok(json!({}))
        }
        _ => Err("Unsupported file operation".into()),
    }
}
pub(super) async fn dispatch(
    app: &AppHandle,
    grant: &Grant,
    mut p: Value,
) -> Result<Value, String> {
    let folder = grant
        .folder
        .as_ref()
        .ok_or("No folder is shared with this recipient")?;
    relative(p["path"].as_str().unwrap_or(""))?;
    if grant.target_id == "my-pc" {
        validate_pc_root(folder, &yougori_roots(app))?;
        let folder = folder.clone();
        let permission = grant.permission.clone();
        return tokio::task::spawn_blocking(move || pc_operation(&folder, &permission, p))
            .await
            .map_err(|_| "File task failed")?;
    }
    let env = target(app, &grant.target_id)?;
    p["id"] = json!(env.runtime_id.as_deref().unwrap_or(&env.id));
    p["root"] = json!(folder);
    p["readOnly"] = json!(grant.permission == Permission::View);
    app.state::<RuntimeManager>()
        .workspace_request(&env, "/v1/remote/files", p)
        .await
}
