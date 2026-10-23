//! Local project import. Reads a snapshot once; never runs host-side project commands.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{io::Read, path::Path};
use yougori_grid::{
    bounty::SourceFile,
    bounty_project::{snapshot, Target},
};

use yougori_grid::bounty_project::excluded_name as excluded;
fn add(
    files: &mut Vec<SourceFile>,
    total: &mut usize,
    path: String,
    bytes: Vec<u8>,
) -> Result<(), String> {
    if !yougori_grid::bounty_project::safe_path(&path) {
        return Err(format!("Unsafe project path: {path}"));
    }
    *total += bytes.len();
    if bytes.len() > 8 * 1024 * 1024 || *total > 64 * 1024 * 1024 || files.len() >= 4000 {
        return Err("Project exceeds 4000 files, 8 MiB per file or 64 MiB total. Select a smaller project folder.".into());
    }
    if yougori_grid::bounty_project::has_private_key(&bytes) {
        return Err(format!(
            "Remove the private key from {path} before importing"
        ));
    }
    files.push(SourceFile {
        path,
        data: STANDARD.encode(bytes),
    });
    Ok(())
}
pub(crate) fn import(path: &Path) -> Result<(Vec<SourceFile>, Value), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("Cannot open project: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("Choose a real project folder or file, not a symbolic link".into());
    }
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;
    if meta.is_file()
        && path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| format!("Cannot read ZIP project: {e}"))?;
        if zip.len() > 8000 {
            return Err("ZIP has too many entries".into());
        }
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().to_owned();
            if entry.enclosed_name().is_none()
                || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
            {
                return Err("ZIP contains an unsafe path or symbolic link".into());
            }
            if name.split('/').any(excluded) {
                skipped.push(name);
                continue;
            }
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            add(&mut files, &mut total, name, bytes)?;
        }
        // Archives commonly wrap a project in one top-level folder.
        if let Some(prefix) = files
            .first()
            .and_then(|f| f.path.split_once('/').map(|p| format!("{}/", p.0)))
        {
            if files.iter().all(|f| f.path.starts_with(&prefix)) {
                for file in &mut files {
                    file.path = file.path[prefix.len()..].into();
                }
            }
        }
    } else {
        let root = if meta.is_dir() {
            path
        } else {
            path.parent().ok_or("File has no parent folder")?
        };
        let mut pending = vec![path.to_path_buf()];
        while let Some(item) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&item).map_err(|e| e.to_string())?;
            let name = item
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("Project has a non-Unicode filename")?;
            if (item != path && excluded(name)) || metadata.file_type().is_symlink() {
                skipped.push(
                    item.strip_prefix(root)
                        .unwrap_or(&item)
                        .to_string_lossy()
                        .into_owned(),
                );
                continue;
            }
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&item).map_err(|e| e.to_string())? {
                    pending.push(entry.map_err(|e| e.to_string())?.path());
                }
                if pending.len() > 8000 {
                    return Err("Too many project entries; select a smaller folder".into());
                }
            } else if metadata.is_file() {
                if excluded(name) {
                    return Err("Choose project code, not a secret or credential file".into());
                }
                let relative = item
                    .strip_prefix(root)
                    .map_err(|_| "Project escaped its selected folder")?
                    .to_string_lossy()
                    .replace('\\', "/");
                let mut bytes = Vec::new();
                std::fs::File::open(&item)
                    .map_err(|e| e.to_string())?
                    .take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                add(&mut files, &mut total, relative, bytes)?;
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    snapshot(&files)?;
    let target = detect(&files);
    Ok((
        files.clone(),
        // Every path is listed: a publisher has to be able to see all of what they are about
        // to share, and all of what was left out.
        json!({"name":path.file_stem().and_then(|v|v.to_str()).unwrap_or("Project"),"fileCount":files.len(),"bytes":total,"files":files.iter().map(|f|&f.path).collect::<Vec<_>>(),"excluded":skipped,"suggestedTarget":target}),
    ))
}
fn detect(files: &[SourceFile]) -> Target {
    let has = |path: &str| files.iter().any(|f| f.path == path);
    let mut target: Target =
        serde_json::from_value(json!({"kind":"source","port":3000,"healthPath":"/"})).unwrap();
    if let Some(pkg) = files
        .iter()
        .find(|f| f.path == "package.json")
        .and_then(|f| STANDARD.decode(&f.data).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    {
        target.setup_command = if has("package-lock.json") {
            "npm ci"
        } else {
            "npm install"
        }
        .into();
        if pkg["scripts"]["start"].is_string() {
            target.kind = "web".into();
            target.start_command = "npm start".into();
        } else if pkg["scripts"]["dev"].is_string() {
            target.kind = "web".into();
            target.start_command = "npm run dev -- --host 0.0.0.0 --port 3000".into();
        }
        if pkg["scripts"]["test"].is_string() {
            target.test_command = "npm test".into();
        }
    } else if has("requirements.txt") {
        target.setup_command =
            "python3 -m venv .venv && .venv/bin/pip install -r requirements.txt".into();
        if has("app.py") {
            target.kind = "api".into();
            target.start_command = ".venv/bin/python app.py".into();
            target.port = 5000;
        } else if has("main.py") {
            target.kind = "api".into();
            target.start_command = ".venv/bin/uvicorn main:app --host 0.0.0.0 --port 3000".into();
        }
    } else if has("index.html") {
        target.kind = "web".into();
        target.start_command = "python3 -m http.server 3000 --bind 0.0.0.0".into();
    } else if has("server.js") {
        target.kind = "web".into();
        target.start_command = "node server.js".into();
    }
    target
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_compressed_zip_and_rejects_hidden_private_key_content() {
        use std::io::Write;
        let folder=tempfile::tempdir().unwrap();
        let archive=folder.path().join("project.zip");
        let mut zip=zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        let options=zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("project/index.html",options).unwrap();zip.write_all(b"<h1>Fixture</h1>").unwrap();
        zip.start_file("project/.env",options).unwrap();zip.write_all(b"PRIVATE=fixture").unwrap();zip.finish().unwrap();
        let (files,view)=import(&archive).unwrap();assert_eq!(files.len(),1);assert_eq!(files[0].path,"index.html");assert_eq!(view["suggestedTarget"]["kind"],"web");
        let source=folder.path().join("innocent.txt");std::fs::write(&source,"-----BEGIN PRIVATE KEY-----\nfixture").unwrap();
        assert!(import(&source).is_err());
    }
    #[test]
    fn imports_real_folders_excludes_secrets_and_detects_run_recipe() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"start":"node server.js","test":"node --test"}}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "PASSWORD=secret").unwrap();
        let (files, view) = import(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(view["suggestedTarget"]["startCommand"], "npm start");
        assert_eq!(view["excluded"], json!([".env"]));
    }
}
