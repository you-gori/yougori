//! Verify prepared images before provisioning. Every host imports the same immutable bytes.
use super::*;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub(super) async fn resolve(
    app: &AppHandle,
    order: &DeskOrder,
    membership: &member::Membership,
) -> Result<String, String> {
    let Some(expected) = &order.image_sha256 else {
        return Ok(order.spec.image.clone());
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid image checksum".into());
    }
    let directory = folder(app).join("images");
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|e| e.to_string())?;
    let path = directory.join(format!("{expected}.img"));
    if path.is_file() {
        let path_copy = path.clone();
        let expected = expected.clone();
        let valid = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let mut file = std::fs::File::open(path_copy).map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            std::io::copy(&mut file, &mut hash).map_err(|e| e.to_string())?;
            Ok(hex::encode(hash.finalize()) == expected)
        })
        .await
        .map_err(|e| e.to_string())??;
        if valid {
            return Ok(path.to_string_lossy().into_owned());
        }
        return Err("Cached image failed its checksum; the host administrator must remove the damaged cache file".into());
    }
    if order.spec.image.starts_with("grid-image:") {
        // Raw pieces from the hub, hashed as they land; the file is only named once it matches.
        let temporary = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
        let mut file = tokio::fs::File::from_std(temporary.reopen().map_err(|e| e.to_string())?);
        let mut offset = 0u64;
        let mut hash = Sha256::new();
        let max = (order.spec.disk_gb * 1024.0 * 1024.0 * 1024.0) as u64;
        loop {
            let (size, bytes) = membership.desk_image_bytes(expected, offset).await?;
            if size == 0 || size > max {
                return Err("Invalid prepared image size".into());
            }
            if bytes.is_empty() || offset + bytes.len() as u64 > size {
                return Err("Prepared image transfer was interrupted".into());
            }
            hash.update(&bytes);
            file.write_all(&bytes)
                .await
                .map_err(|_| "Could not save image; check free disk space")?;
            offset += bytes.len() as u64;
            if offset == size {
                break;
            }
        }
        if hex::encode(hash.finalize()) != *expected {
            return Err("Prepared image checksum mismatch; nothing was provisioned".into());
        }
        file.sync_all().await.map_err(|e| e.to_string())?;
        drop(file);
        match temporary.persist_noclobber(&path) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        return Ok(path.to_string_lossy().into_owned());
    }
    let url = url::Url::parse(&order.spec.image).map_err(|_| "Invalid image URL")?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("Prepared images require HTTPS without embedded credentials".into());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(3600))
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "Image download failed; check the host's access to the image server")?
        .error_for_status()
        .map_err(|_| "The image server refused the download")?;
    let max = (order.spec.disk_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    if response.content_length().is_some_and(|n| n > max) {
        return Err("Image is larger than the desk's disk allocation".into());
    }
    let temporary = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
    let mut file = tokio::fs::File::from_std(temporary.reopen().map_err(|e| e.to_string())?);
    let mut count = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Image download was interrupted")?
    {
        count += chunk.len() as u64;
        if count > max {
            return Err("Image exceeds the desk's disk allocation".into());
        }
        hash.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| "Could not save downloaded image; check free disk space")?;
    }
    if count == 0 || hex::encode(hash.finalize()) != *expected {
        return Err("Image checksum mismatch; nothing was provisioned".into());
    }
    file.flush().await.map_err(|e| e.to_string())?;
    file.sync_all().await.map_err(|e| e.to_string())?;
    drop(file);
    // Concurrent desks may download the same image. Never replace an existing cache entry.
    match temporary.persist_noclobber(&path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(path.to_string_lossy().into_owned())
}

/// Import a local prepared disk into the hub's private, content-addressed catalog cache.
/// This is available only to the local grid owner; remote admins publish HTTPS/OCI sources.
pub(crate) async fn import(app: &AppHandle, mut request: Value) -> Result<Value, String> {
    crate::deskgrid::with_hub(app, |_| Ok(())).await?;
    let path = std::path::PathBuf::from(
        request["path"]
            .as_str()
            .ok_or("Choose a prepared disk image")?,
    );
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|_| "Image file is unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err("Choose an ordinary nonempty prepared disk file".into());
    }
    let max = request["spec"]["diskGb"]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 1. && *n <= 2048.)
        .ok_or("Choose the disk allocation first")?;
    if metadata.len() > (max * 1024. * 1024. * 1024.) as u64 {
        return Err("The image exceeds the workspace disk allocation".into());
    }
    if request["spec"]["kind"] != "vm" {
        return Err("Local image imports require a prepared full VM disk".into());
    }
    let directory = folder(app).join("images");
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|e| e.to_string())?;
    let temporary = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
    let mut source = tokio::fs::File::open(path)
        .await
        .map_err(|_| "Image file is unavailable")?;
    let mut destination = tokio::fs::File::from_std(temporary.reopen().map_err(|e| e.to_string())?);
    use tokio::io::AsyncReadExt;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = source
            .read(&mut bytes)
            .await
            .map_err(|_| "Image read failed")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > metadata.len() {
            return Err("Image changed while importing; try again after it is closed".into());
        }
        hash.update(&bytes[..n]);
        destination
            .write_all(&bytes[..n])
            .await
            .map_err(|_| "Cannot store image; check free disk space")?;
    }
    if total != metadata.len() {
        return Err("Image changed while importing; try again after it is closed".into());
    }
    destination.sync_all().await.map_err(|e| e.to_string())?;
    drop(destination);
    let checksum = hex::encode(hash.finalize());
    let destination = directory.join(format!("{checksum}.img"));
    match temporary.persist_noclobber(&destination) {
        Ok(_) => {}
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.to_string()),
    }
    request
        .as_object_mut()
        .ok_or("Invalid image request")?
        .remove("path");
    request["action"] = json!("imageAdd");
    request["sha256"] = json!(checksum);
    request["spec"]["image"] = json!(format!("grid-image:{checksum}"));
    crate::deskgrid::with_hub(app, |hub| hub.enterprise(request)).await
}
