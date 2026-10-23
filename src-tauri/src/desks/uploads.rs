//! Inbound-only, owner-scoped upload staging. No path or byte-read operation is exposed.
use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::io::Write;

const MAX_BYTES: u64 = 100 * 1024 * 1024;
struct Incoming {
    path: String,
    bytes: u64,
    size: u64,
}
struct Upload {
    owner: String,
    environment: String,
    directory: tempfile::TempDir,
    files: Vec<Incoming>,
    size: u64,
    touched: std::time::Instant,
}
#[derive(Default)]
pub(crate) struct Uploads {
    active: tokio::sync::Mutex<HashMap<String, Upload>>,
}

fn filename(name: &str) -> Result<(), String> {
    if name.len() > 180 || !crate::file_export::valid_name(name) {
        return Err("Choose an ordinary file name without folder separators".into());
    }
    Ok(())
}
fn relative(path: &str) -> Result<(), String> {
    if path.len() > 4096 || path.split('/').count() > 24 {
        return Err("Folder path is too deep or long".into());
    }
    for part in path.split('/') {
        filename(part)?
    }
    Ok(())
}
pub(crate) fn start_cleanup(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            app.state::<Uploads>()
                .active
                .lock()
                .await
                .retain(|_, u| u.touched.elapsed() < Duration::from_secs(300));
        }
    });
}
pub(crate) async fn action(
    app: &AppHandle,
    environment: &str,
    owner: &str,
    p: &Value,
) -> Result<Value, String> {
    let manager = app.state::<Uploads>();
    let mut uploads = manager.active.lock().await;
    uploads.retain(|_, u| u.touched.elapsed() < Duration::from_secs(300));
    match p["action"].as_str().unwrap_or("") {
        "begin" => {
            if uploads.len() >= 16 || uploads.values().filter(|u| u.owner == owner).count() >= 2 {
                return Err("Finish or cancel an active upload first".into());
            }
            let manifest = p["files"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![json!({"path":p["name"],"size":p["size"]})]);
            if manifest.is_empty() || manifest.len() > 1000 {
                return Err("Choose between 1 and 1,000 files per upload".into());
            }
            let mut files = Vec::new();
            let mut size = 0u64;
            let mut paths = std::collections::BTreeSet::new();
            for item in manifest {
                let path = item["path"].as_str().ok_or("Missing file path")?;
                relative(path)?;
                let bytes = item["size"]
                    .as_u64()
                    .filter(|n| *n <= MAX_BYTES)
                    .ok_or("Upload at most 100 MiB per file")?;
                if !paths.insert(path.to_ascii_lowercase()) {
                    return Err("Upload contains duplicate file paths".into());
                }
                size += bytes;
                files.push(Incoming {
                    path: path.into(),
                    bytes: 0,
                    size: bytes,
                });
            }
            if size > 512 * 1024 * 1024
                || uploads.values().map(|u| u.size).sum::<u64>() + size > 1024 * 1024 * 1024
            {
                return Err(
                    "Upload staging is full; use a batch up to 512 MiB or wait for active uploads"
                        .into(),
                );
            }
            let directory = folder(app).join("incoming");
            std::fs::create_dir_all(&directory).map_err(|_| "Upload storage unavailable")?;
            let directory =
                tempfile::tempdir_in(directory).map_err(|_| "Upload storage unavailable")?;
            for file in &files {
                let path = directory.path().join(&file.path);
                std::fs::create_dir_all(path.parent().ok_or("Invalid path")?)
                    .map_err(|_| "Cannot prepare upload folders")?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|_| "Upload paths conflict")?;
            }
            let id = format!("upload-{}", uuid::Uuid::new_v4().simple());
            uploads.insert(
                id.clone(),
                Upload {
                    owner: owner.into(),
                    environment: environment.into(),
                    directory,
                    files,
                    size,
                    touched: std::time::Instant::now(),
                },
            );
            Ok(json!({"uploadId":id}))
        }
        "chunk" => {
            let upload = uploads
                .get_mut(p["uploadId"].as_str().unwrap_or(""))
                .filter(|u| u.owner == owner && u.environment == environment)
                .ok_or("Upload expired or belongs to another session")?;
            let encoded = p["data"]
                .as_str()
                .filter(|s| s.len() <= 90000)
                .ok_or("Invalid upload chunk")?;
            let bytes = B64.decode(encoded).map_err(|_| "Invalid upload encoding")?;
            let index = p["file"].as_u64().unwrap_or(0);
            let file = upload
                .files
                .get_mut(usize::try_from(index).map_err(|_| "Invalid file index")?)
                .ok_or("Invalid file index")?;
            if bytes.len() > 65536
                || p["offset"].as_u64() != Some(file.bytes)
                || file.bytes + bytes.len() as u64 > file.size
            {
                return Err("Upload offset or size mismatch; cancel and retry".into());
            }
            let mut handle = std::fs::OpenOptions::new()
                .append(true)
                .open(upload.directory.path().join(&file.path))
                .map_err(|_| "Upload file is unavailable")?;
            handle
                .write_all(&bytes)
                .map_err(|_| "Could not save upload; check free disk space")?;
            file.bytes += bytes.len() as u64;
            upload.touched = std::time::Instant::now();
            Ok(json!({"received":file.bytes}))
        }
        "cancel" | "finish" => {
            let id = p["uploadId"].as_str().unwrap_or("");
            let upload = uploads
                .get(id)
                .filter(|u| u.owner == owner && u.environment == environment)
                .ok_or("Upload expired or belongs to another session")?;
            if p["action"] == "cancel" {
                uploads.remove(id);
                return Ok(json!({"cancelled":true}));
            }
            if upload.files.iter().any(|file| file.bytes != file.size) {
                return Err("Upload is incomplete".into());
            }
            let upload = uploads.remove(id).unwrap();
            drop(uploads);
            let mut paths = std::collections::BTreeSet::new();
            for file in &upload.files {
                paths.insert(
                    upload
                        .directory
                        .path()
                        .join(file.path.split('/').next().ok_or("Invalid upload path")?)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            let result = crate::file_import::copy_files(
                environment,
                paths.into_iter().collect(),
                &app.state::<PlatformStore>(),
                &app.state::<crate::runtime::RuntimeManager>(),
                |_| {},
            )
            .await;
            crate::security::record(
                Event::new("desk.upload")
                    .env(environment)
                    .text("recipient", owner)
                    .outcome(&result),
            );
            result?;
            Ok(json!({"uploaded":true,"bytes":upload.size}))
        }
        _ => Err("Only begin, chunk, finish, and cancel are supported for desk uploads".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upload_names_cannot_choose_host_paths() {
        for name in ["../secret", "C:\\x", "a/b", "NUL", "a:stream", ""] {
            assert!(filename(name).is_err(), "{name}")
        }
        assert!(filename("report.pdf").is_ok());
    }
    #[test]
    fn folder_paths_stay_inside_staging() {
        for path in [
            "/absolute",
            "../secret",
            "folder/../secret",
            "folder//file",
            "folder/NUL",
            "folder/C:secret",
            "folder/trailing.",
        ] {
            assert!(relative(path).is_err(), "{path}")
        }
        assert!(relative("Research 2026/Experiment/results.csv").is_ok());
        assert!(relative(&vec!["deep"; 25].join("/")).is_err());
    }
}
