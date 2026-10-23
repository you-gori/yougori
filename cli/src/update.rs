//! `yougori update` and `yougori uninstall`.
//!
//! The release manifest (served by yougori.com, written by scripts/release-manifest.mjs):
//! `{"version":"1.2.0","notes":"…","assets":{"windows-x86_64":{"url":"https://…/Yougori_1.2.0_x64-setup.exe","sha256":"…"},
//!   "windows-x86_64-engine":{"url":"https://…/yougori-engine-1.2.0-windows-x86_64.zip","sha256":"…"}}}`
//! A download must match its SHA-256. On Windows every Yougori-built executable in it must carry a
//! valid signature from the same publisher as the installed copy, and on macOS the same Developer
//! ID team, so a compromised website alone cannot ship one. The third-party runtime is checked
//! against its own SHA256SUMS. Linux packages have no publisher signature: engine updates there
//! need an explicit `YOUGORI_ALLOW_UNSIGNED=1`, the same trust as re-running install.sh.
//! `-engine` assets are archives of the standalone engine for installs without the desktop app.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Write, sync::atomic::{AtomicBool, Ordering}};

/// Set once an update or an uninstall starts replacing or removing Yougori: from there on,
/// stopping part way would leave Yougori broken, so the command finishes even after Ctrl+C.
static COMMITTED: AtomicBool = AtomicBool::new(false);

/// Whether this process has started replacing or removing Yougori (see [`COMMITTED`]).
pub fn committed() -> bool {
    COMMITTED.load(Ordering::SeqCst)
}

/// Marks the point of no return, right before the step that stops or replaces Yougori.
fn commit() {
    COMMITTED.store(true, Ordering::SeqCst);
}

pub const DEFAULT_MANIFEST: &str = "https://yougori.com/releases/latest.json";

pub fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "aarch64") => "windows-aarch64",
        ("windows", _) => "windows-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        ("macos", _) => "macos-x86_64",
        (_, "aarch64") => "linux-aarch64",
        _ => "linux-x86_64",
    }
}

fn manifest_url() -> Result<String, String> {
    let url = std::env::var("YOUGORI_RELEASES_URL").unwrap_or_else(|_| DEFAULT_MANIFEST.into());
    let parsed = reqwest::Url::parse(&url).map_err(|_| "The release server must use HTTPS without credentials")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("The release server must use HTTPS without credentials".into());
    }
    Ok(url)
}

/// The release asset for this install: the desktop installer, or the standalone engine archive
/// when only the engine is installed.
fn asset_key(engine_only: bool) -> String {
    if engine_only { format!("{}-engine", platform()) } else { platform().to_owned() }
}

fn download_name(url: &str) -> String {
    reqwest::Url::parse(url).ok()
        .and_then(|url| url.path_segments().and_then(|segments| segments.last()).map(str::to_owned))
        .filter(|name| !name.is_empty() && name != "." && name != ".." && !name.contains(['\\', ':', '?', '*', '"', '<', '>', '|']))
        .unwrap_or_else(|| "Yougori-setup".into())
}

pub(crate) fn engine_only_install() -> bool {
    crate::client::desktop_executable(None).is_err() && crate::client::engine_executable().is_some()
}

/// Compares this CLI's version with a release manifest.
pub fn compare(manifest: &Value, current: &str) -> Result<Value, String> {
    compare_asset(manifest, current, &asset_key(false))
}

fn compare_asset(manifest: &Value, current: &str, key: &str) -> Result<Value, String> {
    let latest = manifest["version"].as_str().ok_or("The release manifest has no version")?;
    let newer = semver::Version::parse(latest).map_err(|_| "The release manifest has an invalid version")?
        > semver::Version::parse(current).map_err(|e| e.to_string())?;
    let asset = &manifest["assets"][key];
    let available = crate::release_notice::asset_available(asset);
    let notes: String = manifest["notes"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(2000).collect();
    Ok(json!({
        "current": current, "latest": latest, "updateAvailable": newer && available, "downloadAvailable": available, "notes": notes,
        "platform": key, "download": asset["url"], "sha256": asset["sha256"],
    }))
}

fn choose_manifest(stable: Value, preview: Option<Value>, key: &str) -> Result<(Value, &'static str), String> {
    let stable_status = compare_asset(&stable, env!("CARGO_PKG_VERSION"), key)?;
    if stable_status["downloadAvailable"] == true { return Ok((stable, "stable")); }
    if let Some(preview) = preview {
        if compare_asset(&preview, env!("CARGO_PKG_VERSION"), key).ok().is_some_and(|status| status["downloadAvailable"] == true) {
            return Ok((preview, "preview"));
        }
    }
    Ok((stable, "stable"))
}

async fn manifest(key: &str) -> Result<(Value, &'static str), String> {
    let url = manifest_url()?;
    let client = reqwest::Client::builder().https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(std::time::Duration::from_secs(20)).build().map_err(|e| e.to_string())?;
    let stable = crate::release_notice::fetch(&client, &url).await?;
    if std::env::var_os("YOUGORI_RELEASES_URL").is_some() { return Ok((stable, "custom")); }
    // Preview is considered only after production confirms no package for this
    // installation. A production server outage never switches channels.
    let status = compare_asset(&stable, env!("CARGO_PKG_VERSION"), key)?;
    let preview = if status["downloadAvailable"] == false {
        crate::release_notice::fetch(&client, "https://yougori.com/releases/preview.json").await.ok()
    } else { None };
    choose_manifest(stable, preview, key)
}

pub async fn check() -> Result<Value, String> {
    let key = asset_key(engine_only_install());
    let (manifest, channel) = manifest(&key).await?;
    let mut status = compare_asset(&manifest, env!("CARGO_PKG_VERSION"), &key)?;
    status["channel"] = channel.into();
    Ok(status)
}

/// Streams the installer to disk while hashing it; nothing runs unless the hash matches.
async fn download(url: &str, expected: &str, path: &std::path::Path) -> Result<(), String> {
    if !crate::release_notice::asset_available(&json!({"url":url,"sha256":expected})) {
        return Err("The release manifest must give an HTTPS download and a SHA-256".into());
    }
    let mut response = reqwest::Client::builder().https_only(true)
        .timeout(std::time::Duration::from_secs(900)).build().map_err(|e| e.to_string())?
        .get(url).send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Download failed: {}", response.status()));
    }
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        total += chunk.len() as u64;
        if total > 8 * 1024 * 1024 * 1024 {
            return Err("The installer is larger than 8 GB".into());
        }
        hash.update(&chunk);
        file.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    let actual = hash.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>();
    if !actual.eq_ignore_ascii_case(expected) {
        let _ = std::fs::remove_file(path);
        return Err("The download does not match the published SHA-256; nothing was installed".into());
    }
    Ok(())
}

#[cfg(windows)]
fn signature_command(path: &std::path::Path, script: &str) -> std::process::Command {
    let mut command = std::process::Command::new("powershell.exe");
    // PowerShell 7 prepends its own module folders to PSModulePath; Windows PowerShell
    // then cannot load its Security module and every genuine signature looks invalid.
    command.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("YOUGORI_SIGNATURE_PATH", path)
        .env_remove("PSModulePath");
    command
}

#[cfg(windows)]
fn signer(path: &std::path::Path) -> Result<String, String> {
    // Authenticode: the status must be Valid; the subject identifies the publisher.
    // PowerShell appends arguments after -Command to its source text rather than
    // binding them to $args. Keep paths in the child environment as literal data.
    let script = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'); $s = Get-AuthenticodeSignature -LiteralPath $env:YOUGORI_SIGNATURE_PATH; if ($s.Status -ne 'Valid') { exit 3 }; $s.SignerCertificate.Subject";
    let output = signature_command(path, script)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("{} is not validly signed", path.display()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub async fn install(yes: bool) -> Result<Value, String> {
    let status = check().await?;
    if status["updateAvailable"] != true {
        return Ok(json!({"upToDate": true, "version": status["current"]}));
    }
    let url = status["download"].as_str().ok_or_else(|| format!("No {} download in this release yet", status["platform"].as_str().unwrap_or("")))?.to_owned();
    if status["channel"] == "preview" {
        return Ok(json!({"updateAvailable": true, "latest": status["latest"], "channel": "preview", "notes": status["notes"], "next": "This unsigned preview uses the explicit preview installer. Finish your work, then use the installation command at https://yougori.com/#hero-cli or download the app at https://yougori.com/#download. Your environments remain running until you install."}));
    }
    if !yes {
        return Ok(json!({"updateAvailable": true, "latest": status["latest"], "notes": status["notes"], "next": "Run `yougori update --yes` to download and install it. Yougori stops its workloads while it updates."}));
    }
    if engine_only_install() && !cfg!(windows) && !cfg!(target_os = "macos") && !allow_unsigned() {
        return Ok(json!({"updateAvailable": true, "latest": status["latest"], "verified": false, "next": "Linux engine packages are verified only by the website's SHA-256, without a publisher signature. Re-run the installer (curl -fsSL https://yougori.com/install.sh | sh), or set YOUGORI_ALLOW_UNSIGNED=1 and run `yougori update --yes` to accept it."}));
    }
    remove_stale_downloads();
    let folder = tempfile::Builder::new().prefix(UPDATE_PREFIX).tempdir().map_err(|e| e.to_string())?.keep();
    let installer = folder.join(download_name(&url));
    // Ctrl+C during the download leaves nothing behind. The spinner this runs under abandons the
    // whole call rather than returning here, so the removal has to happen on the way out: a plain
    // `remove_dir_all` after an early return would simply never run. Disarmed once the files are
    // in place, because after that point the folder is the installer the update is running from.
    let mut downloaded = Scratch(Some(folder.clone()));
    if let Err(error) = download(&url, status["sha256"].as_str().unwrap_or(""), &installer).await {
        return Err(error);
    }
    if engine_only_install() {
        // The archive and its unpacked copy are not needed once the files are in place.
        commit();
        return replace_engine(&installer, &folder, &status).await;
    }
    #[cfg(windows)]
    {
        // An installer that fails its signature check is not kept on disk.
        let verified = (|| {
            let current = crate::client::desktop_executable(None)?;
            let expected = signer(&current).map_err(|_| "This Yougori is a development build without a signature; update it from source instead".to_string())?;
            if signer(&installer)? != expected {
                return Err("The installer is signed by a different publisher than your Yougori; nothing was installed".to_string());
            }
            Ok(())
        })();
        if let Err(error) = verified {
            return Err(error);
        }
        // The installer is this folder's reason to exist from here on, and it runs after this
        // command returns, so the folder stays. `remove_stale_downloads` collects it next time.
        downloaded.0 = None;
        commit();
        // Workloads stop gracefully before files are replaced.
        let mut quit = crate::client::request("app_quit", json!({}));
        quit.confirmed = true;
        let _ = crate::client::call(&quit).await;
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        std::process::Command::new(&installer).arg("/S").spawn().map_err(|e| format!("Cannot start the installer: {e}"))?;
        return Ok(json!({"installing": status["latest"], "installer": installer, "next": "The installer runs in the background. Run `yougori doctor` when it finishes."}));
    }
    #[cfg(not(windows))]
    {
        // The person opens this installer themselves, so it must still be there afterwards.
        downloaded.0 = None;
        Ok(json!({"downloaded": installer, "version": status["latest"], "next": "Open the downloaded installer to finish updating."}))
    }
}

/// A download folder that is removed however this call ends, including when the spinner around it
/// gives up on Ctrl+C and never returns here. Set to `None` once the folder is the installer the
/// person or the update is about to run from.
struct Scratch(Option<std::path::PathBuf>);
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(folder) = self.0.take() {
            let _ = std::fs::remove_dir_all(folder);
        }
    }
}

async fn quit_engine() {
    let mut quit = crate::client::request("app_quit", json!({}));
    quit.confirmed = true;
    if crate::client::call(&quit).await.is_ok() {
        // Workloads stop gracefully before files are replaced.
        for _ in 0..120 {
            if crate::client::call(&crate::client::request("app_status", json!({}))).await.is_err() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

/// Unpacks a verified engine archive over the engine's folder. Files in use are renamed aside
/// first (Windows cannot overwrite a running executable, such as this CLI).
async fn replace_engine(archive: &std::path::Path, folder: &std::path::Path, status: &Value) -> Result<Value, String> {
    let current = crate::client::engine_executable().ok_or("The standalone engine was not found")?;
    let target = current.parent().ok_or("Cannot locate the engine folder")?.to_path_buf();
    remove_old_executables(&target);
    let staged = folder.join("unpacked");
    std::fs::create_dir_all(&staged).map_err(|e| e.to_string())?;
    // Windows' own bsdtar reads zip archives; a GNU tar earlier on PATH would not.
    let tar = if cfg!(windows) { std::path::Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join("tar.exe") } else { "tar".into() };
    let unpacked = std::process::Command::new(tar).arg("-xf").arg(archive).arg("-C").arg(&staged).status().map_err(|e| format!("Cannot unpack the update: {e}"))?;
    if !unpacked.success() {
        return Err("Cannot unpack the update; nothing was changed".into());
    }
    let engine_name = current.file_name().ok_or("Invalid engine path")?;
    let new_engine = staged.join(engine_name);
    if !new_engine.is_file() {
        return Err("The update does not contain the engine; nothing was changed".into());
    }
    let payloads = signed_payloads(&staged)?;
    let cli = staged.join("cli").join(if cfg!(windows) { "yougori.exe" } else { "yougori" });
    if !cli.is_file() {
        return Err("The update does not contain the CLI; nothing was changed".into());
    }
    #[cfg(windows)]
    {
        let expected = signer(&current).map_err(|_| "This engine is a development build without a signature; update it from source instead".to_string())?;
        for binary in &payloads {
            if signer(binary)? != expected {
                return Err(format!("{} is not signed by your Yougori's publisher; nothing was changed", binary.strip_prefix(&staged).unwrap_or(binary).display()));
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = payloads;
        if !allow_unsigned() {
            if !cfg!(target_os = "macos") {
                return Err("Linux engine packages have no publisher signature. Set YOUGORI_ALLOW_UNSIGNED=1 to accept this update; nothing was changed".into());
            }
            let team = codesign_team(&current)?.ok_or("This engine has no Developer ID signature; update it from source or re-run the installer")?;
            for binary in [&new_engine, &cli] {
                if !codesign_verify(binary, &team) {
                    return Err(format!("{} is not signed by your Yougori's Developer ID team; nothing was changed", binary.strip_prefix(&staged).unwrap_or(binary).display()));
                }
            }
        }
    }
    quit_engine().await;
    copy_over(&staged, &target)?;
    Ok(json!({"updated": status["latest"], "folder": target, "next": "Run `yougori doctor` to start the updated engine and check it."}))
}

fn allow_unsigned() -> bool {
    std::env::var("YOUGORI_ALLOW_UNSIGNED").as_deref() == Ok("1")
}

/// Yougori-built executables in an engine archive. The release signs every PE file except the
/// third-party `runtime/`, which the engine checks against its SHA256SUMS. Links are refused.
fn signed_payloads(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>, String> {
    fn walk(folder: &std::path::Path, top: bool, found: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        for entry in std::fs::read_dir(folder).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err("The update contains links; nothing was changed".into());
            }
            let path = entry.path();
            if kind.is_dir() {
                if !(top && entry.file_name().to_string_lossy().eq_ignore_ascii_case("runtime")) {
                    walk(&path, false, found)?;
                }
            } else if path.extension().is_some_and(|ext| ["exe", "dll", "sys", "msi"].iter().any(|pe| ext.eq_ignore_ascii_case(pe))) {
                found.push(path);
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(root, true, &mut found)?;
    found.sort();
    Ok(found)
}

/// The Developer ID team that signed a macOS binary, from `codesign -dv` output.
fn team_identifier(details: &str) -> Option<String> {
    details.lines()
        .find_map(|line| line.trim().strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|team| team.len() == 10 && team.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        .map(str::to_owned)
}

#[cfg_attr(windows, allow(dead_code))]
fn codesign_team(path: &std::path::Path) -> Result<Option<String>, String> {
    let output = std::process::Command::new("codesign").arg("-dv").arg("--verbose=2").arg(path)
        .output().map_err(|e| format!("Cannot inspect the engine signature: {e}"))?;
    Ok(team_identifier(&String::from_utf8_lossy(&output.stderr)))
}

#[cfg_attr(windows, allow(dead_code))]
fn codesign_verify(path: &std::path::Path, team: &str) -> bool {
    std::process::Command::new("codesign").arg("--verify").arg("--strict")
        .arg(format!("-R=anchor apple generic and certificate leaf[subject.OU] = \"{team}\""))
        .arg(path).status().is_ok_and(|status| status.success())
}

const UPDATE_PREFIX: &str = "yougori-update-";

/// Deletes update downloads older than an hour. The Windows installer runs from its download
/// folder after this process exits, so a folder can only be removed by a later update.
fn remove_stale_downloads() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for entry in entries.flatten() {
        let old = entry.metadata().ok().filter(|meta| meta.is_dir())
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > std::time::Duration::from_secs(3600));
        if old && entry.file_name().to_string_lossy().starts_with(UPDATE_PREFIX) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Deletes `*.old-<pid>` files that [`copy_over`] set aside because they were in use. Files
/// still held by a running process stay until a later call.
pub fn remove_old_executables(folder: &std::path::Path) {
    fn sweep(folder: &std::path::Path, depth: usize) {
        let Ok(entries) = std::fs::read_dir(folder) else { return };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                if depth > 0 { sweep(&path, depth - 1); }
            } else if kind.is_file() && set_aside(&path) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    sweep(folder, 3);
}

fn set_aside(path: &std::path::Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()).and_then(|ext| ext.strip_prefix("old-"))
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

fn copy_over(from: &std::path::Path, to: &std::path::Path) -> Result<(), String> {
    for entry in std::fs::read_dir(from).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let destination = to.join(entry.file_name());
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            std::fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
            copy_over(&entry.path(), &destination)?;
        } else {
            if destination.exists() && std::fs::copy(entry.path(), &destination).is_ok() { continue; }
            if destination.exists() {
                let aside = destination.with_extension(format!("old-{}", std::process::id()));
                std::fs::rename(&destination, &aside).map_err(|e| format!("{} is in use: {e}", destination.display()))?;
            }
            std::fs::copy(entry.path(), &destination).map_err(|e| format!("Cannot write {}: {e}", destination.display()))?;
        }
    }
    Ok(())
}

/// Removes the app but keeps environments and data unless the user deletes the data folder themselves.
pub async fn uninstall(yes: bool) -> Result<Value, String> {
    if !yes {
        return Ok(json!({"next": "Run `yougori uninstall --yes` to remove Yougori. Environments and their data stay on disk; the result shows where."}));
    }
    commit();
    let data = crate::public::call("get_storage_location", json!({})).await.ok();
    if let Ok(mut settings) = crate::public::call("get_platform_state", json!({})).await.map(|s| s["settings"].clone()) {
        settings["launchAtStartup"] = false.into();
        let _ = crate::public::call("update_settings", json!({"settings": settings})).await;
    }
    let mut quit = crate::client::request("app_quit", json!({}));
    quit.confirmed = true;
    let _ = crate::client::call(&quit).await;
    #[cfg(windows)]
    {
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let script = "Get-ChildItem HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -eq 'Yougori' } | Select-Object -First 1 -ExpandProperty UninstallString";
        let output = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().map_err(|e| e.to_string())?;
        let command = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let executable = command.trim_matches('"').split("\" ").next().unwrap_or("").trim_matches('"').to_owned();
        if executable.is_empty() || !std::path::Path::new(&executable).is_file() {
            return Err("Yougori's uninstaller was not found. Remove it in Windows Settings, under Apps.".into());
        }
        std::process::Command::new(&executable).arg("/S").spawn().map_err(|e| e.to_string())?;
        return Ok(json!({"uninstalling": true, "dataKept": data, "next": "Environments and their data were kept. Delete that folder yourself only if you no longer need them."}));
    }
    #[cfg(not(windows))]
    Ok(json!({"stopped": true, "dataKept": data, "next": "Remove the Yougori app (drag it to the Trash on macOS, or remove the yougori package using your package manager on Debian/Ubuntu). Environments and their data were kept."}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newer_releases_are_detected_for_this_platform() {
        let manifest = json!({"version":"9.0.0","notes":"n","assets":{platform():{"url":"https://example.com/setup.exe","sha256":"a".repeat(64)},asset_key(true):{"url":"https://example.com/engine.zip","sha256":"b".repeat(64)}}});
        let status = compare(&manifest, "1.0.0").unwrap();
        assert_eq!((status["updateAvailable"].as_bool(), status["download"].as_str()), (Some(true), Some("https://example.com/setup.exe")));
        let engine = compare_asset(&manifest, "1.0.0", &asset_key(true)).unwrap();
        assert_eq!((engine["download"].as_str(), engine["platform"].as_str()), (Some("https://example.com/engine.zip"), Some(asset_key(true).as_str())));
        assert_eq!(compare(&json!({"version":"1.0.0"}), "1.0.0").unwrap()["updateAvailable"], false);
        assert!(compare(&json!({"version":"latest"}), "1.0.0").is_err());
    }
    #[test]
    fn missing_invalid_and_unsafe_packages_are_not_updates() {
        for asset in [json!(null), json!({"url":"https://example.com/x","sha256":"z".repeat(64)}), json!({"url":"https://user:secret@example.com/x","sha256":"a".repeat(64)}), json!({"url":"http://example.com/x","sha256":"a".repeat(64)})] {
            let manifest = json!({"version":"9.0.0","assets":{platform():asset}});
            let status = compare(&manifest, "1.0.0").unwrap();
            assert_eq!(status["updateAvailable"], false);
            assert_eq!(status["downloadAvailable"], false);
        }
    }
    #[test]
    fn explicit_checks_find_preview_but_do_not_replace_available_stable_packages() {
        let key = asset_key(true);
        let missing = json!({"version":"1.0.1","assets":{}});
        let package = |version| json!({"version":version,"assets":{&key:{"url":"https://example.com/engine.tar.gz","sha256":"a".repeat(64)}}});
        let (selected, channel) = choose_manifest(missing.clone(), Some(package("9.0.0")), &key).unwrap();
        assert_eq!((selected["version"].as_str(), channel), (Some("9.0.0"), "preview"));
        let (selected, channel) = choose_manifest(package("2.0.0"), Some(package("9.0.0")), &key).unwrap();
        assert_eq!((selected["version"].as_str(), channel), (Some("2.0.0"), "stable"));
        assert_eq!(choose_manifest(missing, Some(package("invalid")), &key).unwrap().1, "stable");
    }
    #[test]
    fn signed_download_queries_and_fragments_do_not_become_filenames() {
        assert_eq!(download_name("https://example.com/release/Yougori-setup.exe?signature=abc/def#download"), "Yougori-setup.exe");
        assert_eq!(download_name("https://example.com/release/engine.tar.gz?source=command"), "engine.tar.gz");
        assert_eq!(download_name("https://example.com/"), "Yougori-setup");
    }
    #[test]
    #[cfg(windows)]
    fn signature_paths_are_literal_including_spaces_quotes_and_shell_characters() {
        let path = std::path::Path::new("C:\\Program Files\\Yougori's & fixtures\\日本語.exe");
        let output = signature_command(path, "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); [Console]::Write($env:YOUGORI_SIGNATURE_PATH)").output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8(output.stdout).unwrap(), path.to_string_lossy());
    }
    #[test]
    fn engine_updates_replace_files_and_keep_other_ones() {
        let from = tempfile::tempdir().unwrap();
        let to = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(from.path().join("runtime/appliance")).unwrap();
        std::fs::write(from.path().join("runtime/appliance/initramfs"), b"new").unwrap();
        std::fs::write(from.path().join("yougori-engine"), b"engine 2").unwrap();
        std::fs::create_dir_all(to.path().join("runtime/appliance")).unwrap();
        std::fs::write(to.path().join("runtime/appliance/initramfs"), b"old").unwrap();
        std::fs::write(to.path().join("keep.txt"), b"mine").unwrap();
        copy_over(from.path(), to.path()).unwrap();
        assert_eq!(std::fs::read(to.path().join("runtime/appliance/initramfs")).unwrap(), b"new");
        assert_eq!(std::fs::read(to.path().join("yougori-engine")).unwrap(), b"engine 2");
        assert_eq!(std::fs::read(to.path().join("keep.txt")).unwrap(), b"mine");
    }
    #[test]
    fn files_set_aside_by_an_update_are_removed_later() {
        let root = tempfile::tempdir().unwrap();
        for name in ["yougori-engine.old-41", "cli/yougori.old-7", "vault/helper.old-12", "cli/yougori.exe", "notes.old-draft", "data.old-"] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        }
        remove_old_executables(root.path());
        for (name, kept) in [("yougori-engine.old-41", false), ("cli/yougori.old-7", false), ("vault/helper.old-12", false),
            ("cli/yougori.exe", true), ("notes.old-draft", true), ("data.old-", true)] {
            assert_eq!(root.path().join(name).exists(), kept, "{name}");
        }
    }

    #[test]
    fn every_yougori_executable_outside_the_runtime_needs_the_release_signature() {
        let root = tempfile::tempdir().unwrap();
        for name in ["yougori-engine.exe", "cli/yougori.exe", "cli/yougori-cli.exe", "vault/yougori-vault.exe", "vault/helper.DLL",
            "runtime/qemu/qemu-system-x86_64.exe", "runtime/qemu/libglib.dll", "LICENSE", "third-party-sources/notes.txt"] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"fixture").unwrap();
        }
        let found: Vec<String> = signed_payloads(root.path()).unwrap().iter()
            .map(|path| path.strip_prefix(root.path()).unwrap().to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(found, ["cli/yougori-cli.exe", "cli/yougori.exe", "vault/helper.DLL", "vault/yougori-vault.exe", "yougori-engine.exe"]);
    }
    #[test]
    fn macos_team_is_read_from_codesign_details() {
        assert_eq!(team_identifier("Executable=/x\nIdentifier=com.yougori\nTeamIdentifier=AB12CD34EF\n").as_deref(), Some("AB12CD34EF"));
        for details in ["TeamIdentifier=not set", "TeamIdentifier=short", "Identifier=com.yougori"] {
            assert_eq!(team_identifier(details), None);
        }
    }
    #[tokio::test]
    async fn downloads_must_be_https_with_a_hash() {
        let path = std::env::temp_dir().join("yougori-update-test");
        assert!(download("http://example.com/x", &"0".repeat(64), &path).await.is_err());
        assert!(download("https://example.com/x", "short", &path).await.is_err());
        assert!(download("https://example.com/x", &"z".repeat(64), &path).await.is_err());
        assert!(download("https://user:secret@example.com/x", &"a".repeat(64), &path).await.is_err());
    }
}
