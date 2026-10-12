//! Native inference with the existing isolated API/publisher frontend.
//! Only verified GGUF data reaches the native process; repository code stays out.
use super::*;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub(crate) fn relative_weight(name: &str) -> Result<&Path, String> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains(['\\', ':', '\0'])
        || !name.ends_with(".gguf")
        || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("Invalid native model weight path".into());
    }
    Ok(path)
}

pub(crate) async fn verify(path: PathBuf, size: u64, digest: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        if digest.len() != 64 || !digest.bytes().all(|c| c.is_ascii_hexdigit()) || size == 0 {
            return Err("Missing native model checksum".into());
        }
        let mut file = std::fs::File::open(path).map_err(|e| format!("Open native model: {e}"))?;
        if file.metadata().map_err(|e| e.to_string())?.len() != size {
            return Err("Native model size mismatch".into());
        }
        let mut hash = Sha256::new();
        let mut bytes = vec![0; 4 * 1024 * 1024];
        loop {
            let count = file.read(&mut bytes).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            hash.update(&bytes[..count]);
        }
        if format!("{:x}", hash.finalize()) != digest.to_ascii_lowercase() {
            return Err("Native model checksum mismatch".into());
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Prepare on the selected storage root, outside runtime metadata. Read-only
/// host mounts keep downloads/publishing and native inference on the same files.
pub(super) async fn download(
    model: &str,
    check: &Value,
    resources: &ModelResources,
    app: &AppHandle,
) -> Result<PathBuf, String> {
    let runtime = app.state::<RuntimeManager>();
    runtime.native_model_runtime()?; // fail before a potentially large download
    let engine = runtime.storage_runtime_on_drive(resources.storage_drive.as_deref())?;
    let root = engine
        .as_deref()
        .unwrap_or(&runtime)
        .storage_root()
        .parent()
        .ok_or("Missing model storage root")?
        .join("native-models");
    let revision = check["revision"]
        .as_str()
        .filter(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or("Missing pinned model revision")?;
    let key = format!(
        "{:x}",
        Sha256::digest(format!("{model}@{revision}:{}", check["quant"]))
    );
    let folder = root.join(key);
    tokio::fs::create_dir_all(&folder)
        .await
        .map_err(|e| e.to_string())?;
    let folder = folder.canonicalize().map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(3600))
        .build()
        .map_err(|e| e.to_string())?;
    for item in check["files"].as_array().ok_or("Missing GGUF files")? {
        let name = item["name"].as_str().ok_or("Missing weight name")?;
        let relative = relative_weight(name)?;
        let size = item["size"].as_u64().ok_or("Missing weight size")?;
        let digest = item["sha256"].as_str().ok_or("Missing weight checksum")?;
        let path = folder.join(relative);
        let parent = path.parent().ok_or("Missing weight directory")?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
        if !parent
            .canonicalize()
            .map_err(|e| e.to_string())?
            .starts_with(&folder)
        {
            return Err("Native model directory escapes its cache".into());
        }
        if path.is_file() && verify(path.clone(), size, digest.into()).await.is_ok() {
            continue;
        }
        let mut url = url::Url::parse("https://huggingface.co/").unwrap();
        url.path_segments_mut()
            .unwrap()
            .extend(model.split('/'))
            .extend(["resolve", revision])
            .extend(name.split('/'));
        let mut request = client.get(url);
        if check["hubTokenRequired"] != false {
            if let Some(token) = huggingface::token() {
                request = request.bearer_auth(token);
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "Native model download failed")?;
        if !response.status().is_success() {
            return Err(format!(
                "Native model download returned HTTP {}",
                response.status()
            ));
        }
        // Unique staging names keep simultaneous preparations independent.
        let staging = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        let mut output = tokio::fs::File::from_std(staging.reopen().map_err(|e| e.to_string())?);
        let mut received = 0u64;
        while let Some(chunk) =
            tokio::time::timeout(std::time::Duration::from_secs(120), response.chunk())
                .await
                .map_err(|_| "Native model download stalled")?
                .map_err(|_| "Native model download interrupted")?
        {
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or("Weight download overflow")?;
            if received > size {
                return Err("Native model download exceeds the verified size".into());
            }
            output.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        output.sync_all().await.map_err(|e| e.to_string())?;
        drop(output);
        verify(staging.path().to_owned(), size, digest.into()).await?;
        staging.persist(&path).map_err(|e| e.to_string())?;
    }
    Ok(folder)
}

pub(super) fn configure(
    environment: &mut Value,
    protected: &mut Value,
    backend: compute::Backend,
    cpu: f64,
    memory: f64,
) -> Result<(), String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    environment["YOUGORI_NATIVE_PORT"] = json!(listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .port()
        .to_string());
    environment["YOUGORI_NATIVE_BACKEND"] = json!(backend.name());
    environment["YOUGORI_MODEL_CPU_THREADS"] = json!((cpu.floor() as u64).clamp(1, 64).to_string());
    environment["YOUGORI_NATIVE_MEMORY_GB"] = json!(memory.to_string());
    environment["YOUGORI_GPU_OPTIMIZER"] = json!("0");
    if backend == compute::Backend::MacCpu {
        environment["YOUGORI_MODEL_CPU"] = json!("1");
    }
    let reference = format!("native-model-{}", uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(
        &reference,
        &format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
    )?;
    protected["YOUGORI_NATIVE_TOKEN"] = json!(reference);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn weights_cannot_select_arbitrary_host_paths() {
        for name in [
            "/tmp/a.gguf",
            "../a.gguf",
            "a/../../b.gguf",
            "C:/a.gguf",
            "a\\b.gguf",
            "a.py",
            "",
        ] {
            assert!(relative_weight(name).is_err(), "{name}");
        }
        assert!(relative_weight("Q4/model-00001-of-00002.gguf").is_ok());
    }
    #[tokio::test]
    async fn verifies_bytes_and_length_before_native_execution() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"model").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"model"));
        assert!(verify(file.path().into(), 5, digest.clone()).await.is_ok());
        assert!(verify(file.path().into(), 6, digest).await.is_err());
        assert!(verify(file.path().into(), 5, "0".repeat(64)).await.is_err());
    }
}
