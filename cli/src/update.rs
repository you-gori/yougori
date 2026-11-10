//! `yougori update` and `yougori uninstall`.
//!
//! The release manifest (served by yougori.com, written by scripts/release-manifest.mjs):
//! `{"version":"1.2.0","notes":"…","assets":{"windows-x86_64":{"url":"https://…/Yougori_1.2.0_x64-setup.exe","sha256":"…"},
//!   "windows-x86_64-engine":{"url":"https://…/yougori-engine-1.2.0-windows-x86_64.zip","sha256":"…"}}}`
//! A download must match its SHA-256. A signed installation takes only an update signed by its
//! own publisher (on Windows every Yougori-built executable, by the same certificate subject; on
//! macOS the same Developer ID team), so a compromised website alone cannot ship one; it leaves an
//! unsigned preview to the person unless `YOUGORI_ALLOW_UNSIGNED=1`. An unsigned installation (the
//! previews so far, and every Linux package, which has no publisher signature) trusts the website
//! as its installer did: its updates are checked against the published SHA-256 alone, once the
//! person confirms. The third-party runtime is checked against its own SHA256SUMS. `-engine`
//! assets are archives of the standalone engine for installs without the desktop app.
//!
//! An update runs in three steps. [`offer`] decides, before any download, whether this
//! installation can take the release in place; [`prepare`] downloads and checks it; [`finish`]
//! stops Yougori, installs the update and starts Yougori again. The desktop app's Update button
//! runs the first two itself, then hands the installer over and quits.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
};

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
    check_for(engine_only_install()).await
}

async fn check_for(engine_only: bool) -> Result<Value, String> {
    let key = asset_key(engine_only);
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

/// An update this installation can take in place, decided before anything is downloaded.
#[derive(Clone, Debug)]
pub struct Plan {
    pub current: String,
    pub latest: String,
    pub channel: String,
    pub notes: String,
    /// The standalone engine, updated from its `-engine` archive; otherwise the desktop app.
    pub engine_only: bool,
    url: String,
    sha256: String,
    /// The publisher every Yougori executable in the update must be signed by: the installed
    /// copy's. `None` for an unsigned installation, whose updates match the SHA-256 alone.
    publisher: Option<String>,
}

impl Plan {
    /// No publisher signature to match: the update is checked against the published SHA-256 only.
    pub fn unsigned(&self) -> bool {
        self.publisher.is_none()
    }

    /// The answer when a script runs `update` without `--yes`.
    pub fn needs_confirmation(&self) -> Value {
        json!({"updateAvailable": true, "current": self.current, "latest": self.latest, "channel": self.channel,
            "notes": self.notes, "unsigned": self.unsigned(),
            "next": "Run `yougori update --yes` to install it. Yougori stops while it updates, then starts again."})
    }
}

/// What `yougori update` finds.
pub enum Offer {
    /// Nothing newer: the answer to print.
    Current(Value),
    /// A newer release this installation cannot take in place; the answer says where to get it.
    Elsewhere(Value),
    /// A newer release to install in place.
    Ready(Plan),
}

/// Whether the installation this CLI belongs to can take the newest release in place.
pub async fn offer() -> Result<Offer, String> {
    let engine_only = engine_only_install();
    let executable = if engine_only {
        crate::client::engine_executable()
    } else {
        crate::client::desktop_executable(None).ok()
    };
    offer_for(engine_only, executable).await
}

/// [`offer`] for the desktop app running as `app`.
pub async fn offer_for_app(app: PathBuf) -> Result<Offer, String> {
    offer_for(false, Some(app)).await
}

async fn offer_for(engine_only: bool, executable: Option<PathBuf>) -> Result<Offer, String> {
    let status = check_for(engine_only).await?;
    // Reading a signature takes a moment on Windows: only when there is something to install.
    let publisher = executable.as_deref().filter(|_| status["updateAvailable"] == true).and_then(publisher_of);
    decide(&status, engine_only, executable.as_deref(), publisher, allow_unsigned())
}

/// The decision of [`offer`], from the release check and the installation as it was found.
fn decide(status: &Value, engine_only: bool, executable: Option<&Path>, publisher: Option<String>, allow_unsigned: bool) -> Result<Offer, String> {
    if status["updateAvailable"] != true {
        return Ok(Offer::Current(json!({"upToDate": true, "version": status["current"]})));
    }
    let text = |key: &str| status[key].as_str().unwrap_or_default().to_owned();
    let url = status["download"].as_str().ok_or_else(|| format!("No {} download in this release yet", text("platform")))?.to_owned();
    let latest = text("latest");
    let elsewhere = |next: String| Offer::Elsewhere(json!({"updateAvailable": true, "current": status["current"], "latest": status["latest"],
        "channel": status["channel"], "notes": status["notes"], "next": next}));
    let Some(executable) = executable else {
        return Ok(elsewhere(format!("Download Yougori {latest} at https://yougori.com/#download.")));
    };
    if let Some(next) = not_in_place(engine_only, executable, &latest) {
        return Ok(elsewhere(next));
    }
    let preview = text("channel") == "preview";
    let publisher = match publisher {
        Some(_) if preview && allow_unsigned => None,
        Some(_) if preview => return Ok(elsewhere(format!("Yougori {latest} is an unsigned preview and this Yougori is signed, so it is not installed in place. Download it at https://yougori.com/#download, or set YOUGORI_ALLOW_UNSIGNED=1 and run `yougori update --yes` to accept it."))),
        publisher => publisher,
    };
    Ok(Offer::Ready(Plan { current: text("current"), latest, channel: text("channel"), notes: text("notes"), engine_only, url, sha256: text("sha256"), publisher }))
}

/// Why this installation cannot take an update in place, if it cannot.
fn not_in_place(engine_only: bool, executable: &Path, latest: &str) -> Option<String> {
    let download = format!("Download Yougori {latest} at https://yougori.com/#download.");
    if development_build(executable) {
        return Some(format!("This Yougori is a development build, updated from source. {download}"));
    }
    if engine_only {
        return None;
    }
    // The per-user setup updates only an app it installed itself, with its uninstaller beside it.
    if cfg!(windows) && !executable.with_file_name("uninstall.exe").is_file() {
        return Some(format!("This Yougori was installed from the MSI package or by hand, which `yougori update` does not replace. {download}"));
    }
    if cfg!(target_os = "linux") && executable != Path::new("/usr/bin/yougori-desktop") {
        return Some(format!("This Yougori was not installed from the Debian package, which `yougori update` replaces. {download}"));
    }
    None
}

/// A build in the source tree this CLI was compiled from. Installed copies never live there.
fn development_build(executable: &Path) -> bool {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().is_some_and(|tree| executable.starts_with(tree))
}

/// The publisher a Yougori executable is signed by; `None` when it is not signed.
#[cfg(windows)]
fn publisher_of(path: &Path) -> Option<String> {
    signer(path).ok()
}

#[cfg(target_os = "macos")]
fn publisher_of(path: &Path) -> Option<String> {
    codesign_team(path).ok().flatten()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn publisher_of(_: &Path) -> Option<String> {
    None
}

/// Asks a person at a terminal to confirm. Anything but Install leaves everything as it is.
pub fn ask(plan: &Plan) -> Result<(), String> {
    use crate::cli_ui::{self as ui, Choice};
    let what = if plan.engine_only { "the engine" } else { "the desktop app" };
    let mut note = vec![format!("Installed: {}, {what}.", plan.current)];
    if plan.unsigned() {
        note.push("It has no publisher signature: Yougori checks it against the SHA-256 published on yougori.com.".into());
    }
    note.push("Yougori stops its workloads while it updates, then starts again.".into());
    let choices = [Choice::new("Install", "download, check and install it now"), Choice::new("Not now", "nothing changes")];
    match ui::select(&format!("Install Yougori {}?", plan.latest), &note, &choices, 0)? {
        0 => Ok(()),
        _ => Err(crate::wire::cancelled("Nothing was installed.")),
    }
}

/// A downloaded and checked update, ready to install.
pub struct Prepared {
    pub plan: Plan,
    folder: PathBuf,
    package: PathBuf,
    /// The unpacked engine archive; `None` for the desktop app's installer.
    staged: Option<PathBuf>,
}

/// Downloads the update and checks it: the SHA-256, and the installed copy's publisher on
/// everything Yougori built in it. Nothing stops or changes yet, and Ctrl+C leaves nothing behind.
pub async fn prepare(plan: Plan) -> Result<Prepared, String> {
    remove_stale_downloads();
    let folder = tempfile::Builder::new().prefix(UPDATE_PREFIX).tempdir().map_err(|e| e.to_string())?.keep();
    // The spinner this runs under abandons the whole call on Ctrl+C rather than returning here,
    // so the folder goes on the way out. Disarmed once the update is ready to install.
    let mut scratch = Scratch(Some(folder.clone()));
    let package = folder.join(download_name(&plan.url));
    download(&plan.url, &plan.sha256, &package).await?;
    let staged = if plan.engine_only {
        Some(unpack_engine(&package, &folder, plan.publisher.as_deref())?)
    } else {
        check_installer(&package, plan.publisher.as_deref())?;
        None
    };
    scratch.0 = None;
    Ok(Prepared { plan, folder, package, staged })
}

/// Unpacks an engine archive beside it and checks what it holds.
fn unpack_engine(archive: &Path, folder: &Path, publisher: Option<&str>) -> Result<PathBuf, String> {
    let staged = folder.join("unpacked");
    std::fs::create_dir_all(&staged).map_err(|e| e.to_string())?;
    // Windows' own bsdtar reads zip archives; a GNU tar earlier on PATH would not.
    let tar = if cfg!(windows) { Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join("tar.exe") } else { "tar".into() };
    let unpacked = std::process::Command::new(tar).arg("-xf").arg(archive).arg("-C").arg(&staged).status().map_err(|e| format!("Cannot unpack the update: {e}"))?;
    if !unpacked.success() {
        return Err("Cannot unpack the update; nothing was changed".into());
    }
    let engine = staged.join(if cfg!(windows) { "yougori-engine.exe" } else { "yougori-engine" });
    let cli = staged.join("cli").join(if cfg!(windows) { "yougori.exe" } else { "yougori" });
    if !engine.is_file() {
        return Err("The update does not contain the engine; nothing was changed".into());
    }
    if !cli.is_file() {
        return Err("The update does not contain the CLI; nothing was changed".into());
    }
    let payloads = signed_payloads(&staged)?;
    if let Some(publisher) = publisher {
        verify_payloads(&staged, &payloads, [engine.as_path(), cli.as_path()], publisher)?;
    }
    Ok(staged)
}

#[cfg(windows)]
fn verify_payloads(staged: &Path, payloads: &[PathBuf], _: [&Path; 2], publisher: &str) -> Result<(), String> {
    for binary in payloads {
        if signer(binary).ok().as_deref() != Some(publisher) {
            return Err(format!("{} is not signed by your Yougori's publisher; nothing was changed", binary.strip_prefix(staged).unwrap_or(binary).display()));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_payloads(staged: &Path, _: &[PathBuf], binaries: [&Path; 2], team: &str) -> Result<(), String> {
    for binary in binaries {
        if !codesign_verify(binary, team) {
            return Err(format!("{} is not signed by your Yougori's Developer ID team; nothing was changed", binary.strip_prefix(staged).unwrap_or(binary).display()));
        }
    }
    Ok(())
}

/// Checks a downloaded desktop installer before anything stops.
fn check_installer(installer: &Path, publisher: Option<&str>) -> Result<(), String> {
    #[cfg(windows)]
    if let Some(publisher) = publisher {
        if signer(installer).ok().as_deref() != Some(publisher) {
            return Err("The installer is not signed by your Yougori's publisher; nothing was installed".into());
        }
    }
    #[cfg(target_os = "linux")]
    if !installer.extension().is_some_and(|extension| extension == "deb") {
        return Err("This release's Linux download is not a Debian package; nothing was installed".into());
    }
    let _ = (installer, publisher);
    Ok(())
}

/// At a terminal, before anything stops, asks for the administrator access the Linux package
/// needs, so a refused password leaves Yougori running. Elsewhere there is nothing to ask.
pub fn authorize(prepared: &Prepared) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if prepared.staged.is_none() && unsafe { libc::geteuid() } != 0 && crate::cli_ui::can_prompt() {
        let asked = std::process::Command::new("sudo").arg("-v").status().map_err(|e| format!("Cannot run sudo: {e}"))?;
        if !asked.success() {
            return Err("Administrator access is needed to install the Yougori package; nothing was changed.".into());
        }
    }
    let _ = prepared;
    Ok(())
}

/// Stops Yougori, installs the prepared update and starts Yougori again if it was running.
/// From the stop on, the update finishes even after Ctrl+C (see [`committed`]).
pub async fn finish(prepared: Prepared) -> Result<Value, String> {
    if prepared.staged.is_some() {
        finish_engine(prepared).await
    } else {
        finish_desktop(prepared).await
    }
}

/// Whether Yougori runs now, and if so whether without its dashboard.
async fn running_yougori() -> Option<bool> {
    crate::client::call(&crate::client::request("app_status", json!({}))).await.ok().map(|status| status["headless"] != false)
}

/// Stops Yougori if it runs, the way `yougori app quit --yes` does, and says whether it ran.
async fn stop_yougori() -> Result<Option<bool>, String> {
    let running = running_yougori().await;
    commit();
    if running.is_some() {
        crate::client::quit().await.map_err(|error| format!("Yougori did not stop, so nothing was installed: {error}"))?;
    }
    Ok(running)
}

/// Starts Yougori with the CLI just installed, which knows how to start its own version.
async fn start_installed(cli: &Path) -> Result<(), String> {
    let output = tokio::process::Command::new(cli).args(["app", "start", "--format", "json"]).stdin(Stdio::null()).output().await
        .map_err(|e| format!("Cannot start Yougori: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(tail(&output.stdout, &output.stderr))
    }
}

/// Starts Yougori again with the CLI just installed if it ran before the update; whether it
/// started, and what to tell the person.
async fn start_again(running: Option<bool>, cli: &Path) -> (bool, String) {
    match running {
        None => (false, "Start it with `yougori app start`.".into()),
        Some(_) => match start_installed(cli).await {
            Ok(()) => (true, "Yougori runs the new version.".into()),
            Err(error) => (false, format!("The update is installed, but Yougori did not start again ({error}). Run `yougori doctor`.")),
        },
    }
}

/// The end of what a failed command printed, for its error.
fn tail(stdout: &[u8], stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(if stderr.iter().any(|b| !b.is_ascii_whitespace()) { stderr } else { stdout }).trim().to_owned();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(3)..].join(" ")
}

async fn finish_engine(prepared: Prepared) -> Result<Value, String> {
    let Prepared { plan, folder, staged, .. } = prepared;
    let staged = staged.ok_or("The engine update was not unpacked")?;
    let current = crate::client::engine_executable().ok_or("The standalone engine was not found")?;
    let target = current.parent().ok_or("Cannot locate the engine folder")?.to_path_buf();
    let running = stop_yougori().await?;
    remove_old_executables(&target);
    copy_over(&staged, &target)?;
    let _ = std::fs::remove_dir_all(&folder);
    let cli = target.join("cli").join(if cfg!(windows) { "yougori.exe" } else { "yougori" });
    let (started, next) = start_again(running, &cli).await;
    Ok(json!({"updated": plan.latest, "folder": target, "started": started, "next": next}))
}

#[cfg(windows)]
async fn finish_desktop(prepared: Prepared) -> Result<Value, String> {
    let running = stop_yougori().await?;
    // The installer works after this command ends: it closes every running yougori.exe, this one
    // included. /UPDATE keeps the shortcuts as they are; /R opens Yougori again as it ran.
    let mut arguments = vec!["/S", "/UPDATE"];
    if let Some(headless) = running {
        arguments.push("/R");
        if headless {
            arguments.extend(["/ARGS", "--headless"]);
        }
    }
    std::process::Command::new(&prepared.package).args(&arguments).spawn().map_err(|e| format!("Cannot start the installer: {e}"))?;
    let next = if running.is_some() {
        "The installer runs in the background and starts Yougori again in about a minute."
    } else {
        "The installer runs in the background for about a minute. Then start Yougori with `yougori app start`."
    };
    Ok(json!({"installing": prepared.plan.latest, "restarts": running.is_some(), "next": next}))
}

#[cfg(target_os = "linux")]
async fn finish_desktop(prepared: Prepared) -> Result<Value, String> {
    let Some(mut apt) = apt_command() else {
        // Without administrator access nothing stops: the person finishes it.
        return Ok(json!({"downloaded": prepared.package, "version": prepared.plan.latest,
            "next": format!("Finish as administrator with `sudo apt-get install -y {}`, then run `yougori app quit --yes` and `yougori app start`.", prepared.package.display())}));
    };
    let running = stop_yougori().await?;
    apt.args(["install", "-y"]).arg(&prepared.package).stdin(Stdio::null());
    let installed = tokio::task::spawn_blocking(move || apt.output()).await.map_err(|e| e.to_string())?.map_err(|e| format!("Cannot run apt-get: {e}"))?;
    if !installed.status.success() {
        let stopped = if running.is_some() { " Yougori was stopped for the update: start it again with `yougori app start`." } else { "" };
        return Err(format!("apt-get could not install the package ({}).{stopped}", tail(&installed.stdout, &installed.stderr)));
    }
    let _ = std::fs::remove_dir_all(&prepared.folder);
    let (started, next) = start_again(running, Path::new("/usr/bin/yougori")).await;
    Ok(json!({"updated": prepared.plan.latest, "started": started, "next": next}))
}

#[cfg(target_os = "macos")]
async fn finish_desktop(prepared: Prepared) -> Result<Value, String> {
    // The person opens this installer themselves, so it stays and nothing stops.
    Ok(json!({"downloaded": prepared.package, "version": prepared.plan.latest, "next": "Open the downloaded installer to finish updating."}))
}

/// apt-get as administrator: directly as root, or through sudo with credentials already given
/// (see [`authorize`]). `None` when neither is possible without asking.
#[cfg(target_os = "linux")]
fn apt_command() -> Option<std::process::Command> {
    if unsafe { libc::geteuid() } == 0 {
        return Some(std::process::Command::new("apt-get"));
    }
    let given = std::process::Command::new("sudo").args(["-n", "true"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().is_ok_and(|status| status.success());
    given.then(|| {
        let mut sudo = std::process::Command::new("sudo");
        sudo.args(["-n", "apt-get"]);
        sudo
    })
}

/// The desktop app's own Update on Windows. A hidden helper waits until the app (process `app`)
/// has quit, then runs the installer, which opens the app again. The app quits right after this,
/// the way its Quit does; if it does not, the update installs whenever it does.
#[cfg(windows)]
pub fn install_after_exit(prepared: Prepared, app: u32) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let script = "$ErrorActionPreference = 'SilentlyContinue'; Wait-Process -Id ([int]$env:YOUGORI_UPDATE_AFTER); Start-Process -FilePath $env:YOUGORI_UPDATE_INSTALLER -ArgumentList '/S', '/UPDATE', '/R'";
    let spawn = |flags: u32| {
        std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script])
            .env("YOUGORI_UPDATE_AFTER", app.to_string())
            .env("YOUGORI_UPDATE_INSTALLER", &prepared.package)
            // PowerShell 7's module folders keep Windows PowerShell from loading its own cmdlets.
            .env_remove("PSModulePath")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    // Outside the app's job, when the job allows it, so that quitting the app leaves it running.
    spawn(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP))
        .map(drop)
        .map_err(|e| format!("Cannot start the update: {e}"))
}

/// The desktop app's own Update on Debian and Ubuntu: the package installs through the desktop's
/// password dialog (pkexec) while the app runs, then [`reopen_after_exit`] and the app quits.
#[cfg(target_os = "linux")]
pub async fn install_with_password_dialog(prepared: &Prepared) -> Result<(), String> {
    let package = prepared.package.clone();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("pkexec").args(["/usr/bin/apt-get", "install", "-y"]).arg(&package).stdin(Stdio::null()).output()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("Cannot ask for administrator access (pkexec): {e}"))?;
    match output.status.code() {
        Some(0) => Ok(()),
        // pkexec: the dialog was dismissed or the password refused.
        Some(126 | 127) => Err("Administrator access was not given; nothing was installed.".into()),
        _ => Err(format!("The package could not be installed ({}).", tail(&output.stdout, &output.stderr))),
    }
}

/// Opens the updated app once this one (process `app`) has quit.
#[cfg(target_os = "linux")]
pub fn reopen_after_exit(app: u32) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    std::process::Command::new("sh")
        .args(["-c", "while kill -0 \"$1\" 2>/dev/null; do sleep 1; done; exec /usr/bin/yougori-desktop", "yougori-update"])
        .arg(app.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(drop)
        .map_err(|e| format!("Cannot open Yougori again after the update: {e}"))
}

/// What `yougori update` says at a terminal.
pub fn summary(result: &Value) -> Vec<String> {
    use crate::cli_ui as ui;
    let text = |key: &str| result[key].as_str().unwrap_or_default().to_owned();
    let newer = result["latest"].is_string() && result["latest"] != result["current"];
    let (title, detail) = if result["updateAvailable"] == false && result["downloadAvailable"] == false && newer {
        (format!("Yougori {} has no package for this computer yet", text("latest")), format!("installed {}", text("current")))
    } else if result["upToDate"] == true || (result["updateAvailable"] == false && result["latest"].is_string()) {
        let version = if result["version"].is_string() { text("version") } else { text("current") };
        (format!("Yougori {version} is up to date"), String::new())
    } else if result["installing"].is_string() {
        (format!("Installing Yougori {}", text("installing")), "in the background".to_owned())
    } else if result["updated"].is_string() {
        (format!("Yougori {} is installed", text("updated")), if result["started"] == true { "and running".to_owned() } else { String::new() })
    } else if result["downloaded"].is_string() {
        (format!("Yougori {} is downloaded", text("version")), text("downloaded"))
    } else {
        let unsigned = result["unsigned"] == true || result["channel"] == "preview";
        (format!("Yougori {} is available", text("latest")), format!("installed {}{}", text("current"), if unsigned { ", unsigned preview" } else { "" }))
    };
    let mut head = format!("{}  {}", ui::paint("◇", ui::GREEN), ui::bold(&title));
    if !detail.is_empty() {
        head = format!("{head}  {}", ui::muted(&detail));
    }
    let mut lines = vec![head];
    let next = if result["next"].is_string() {
        text("next")
    } else if result["updateAvailable"] == true {
        "Install it with `yougori update`.".to_owned()
    } else {
        String::new()
    };
    if !next.is_empty() {
        lines.push(format!("{}  {}", ui::muted("└"), ui::muted(&next)));
    }
    lines
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn codesign_team(path: &std::path::Path) -> Result<Option<String>, String> {
    let output = std::process::Command::new("codesign").arg("-dv").arg("--verbose=2").arg(path)
        .output().map_err(|e| format!("Cannot inspect the engine signature: {e}"))?;
    Ok(team_identifier(&String::from_utf8_lossy(&output.stderr)))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    fn available(channel: &str) -> Value {
        json!({"current": "1.0.0", "latest": "1.1.0", "updateAvailable": true, "downloadAvailable": true, "notes": "Fixes",
            "platform": "windows-x86_64", "download": "https://example.com/Yougori_1.1.0_x64-setup.exe", "sha256": "a".repeat(64), "channel": channel})
    }

    /// An app folder as the per-user setup leaves it, with its uninstaller beside the app, or not.
    fn installed_app(uninstaller: bool) -> (tempfile::TempDir, PathBuf) {
        let folder = tempfile::tempdir().unwrap();
        let app = folder.path().join(if cfg!(windows) { "yougori.exe" } else { "yougori-desktop" });
        std::fs::write(&app, b"app").unwrap();
        if uninstaller {
            std::fs::write(folder.path().join("uninstall.exe"), b"setup").unwrap();
        }
        (folder, app)
    }

    #[test]
    fn nothing_newer_is_the_whole_answer() {
        let current = json!({"current": "1.1.0", "latest": "1.1.0", "updateAvailable": false});
        let Offer::Current(answer) = decide(&current, false, None, None, false).unwrap() else { panic!("not current") };
        assert_eq!(answer, json!({"upToDate": true, "version": "1.1.0"}));
    }

    #[test]
    fn an_unsigned_installation_takes_updates_checked_against_their_hash() {
        // Every preview so far, and every Linux package.
        let engine = tempfile::tempdir().unwrap();
        let path = engine.path().join("yougori-engine");
        for channel in ["preview", "stable"] {
            let Offer::Ready(plan) = decide(&available(channel), true, Some(&path), None, false).unwrap() else { panic!("{channel}") };
            assert!(plan.unsigned());
            assert_eq!((plan.latest.as_str(), plan.current.as_str(), plan.engine_only), ("1.1.0", "1.0.0", true));
            let answer = plan.needs_confirmation();
            assert_eq!((answer["unsigned"].as_bool(), answer["next"].as_str()), (Some(true), Some("Run `yougori update --yes` to install it. Yougori stops while it updates, then starts again.")));
        }
    }

    #[test]
    fn a_signed_installation_keeps_its_publisher_and_leaves_unsigned_previews_to_the_person() {
        let engine = tempfile::tempdir().unwrap();
        let path = engine.path().join("yougori-engine");
        let signed = Some("CN=Yougori".to_owned());
        let Offer::Ready(plan) = decide(&available("stable"), true, Some(&path), signed.clone(), false).unwrap() else { panic!("stable") };
        assert!(!plan.unsigned());
        let Offer::Elsewhere(answer) = decide(&available("preview"), true, Some(&path), signed.clone(), false).unwrap() else { panic!("preview") };
        assert!(answer["next"].as_str().unwrap().contains("is an unsigned preview and this Yougori is signed"), "{answer}");
        // YOUGORI_ALLOW_UNSIGNED=1 accepts it, as the website's preview command does.
        let Offer::Ready(plan) = decide(&available("preview"), true, Some(&path), signed, true).unwrap() else { panic!("allowed") };
        assert!(plan.unsigned());
    }

    #[test]
    fn builds_in_the_source_tree_are_updated_from_source() {
        let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src-tauri/target/debug/yougori.exe");
        let Offer::Elsewhere(answer) = decide(&available("preview"), false, Some(&build), None, false).unwrap() else { panic!("build") };
        assert!(answer["next"].as_str().unwrap().starts_with("This Yougori is a development build"), "{answer}");
        let Offer::Elsewhere(answer) = decide(&available("preview"), false, None, None, false).unwrap() else { panic!("nothing found") };
        assert_eq!(answer["next"], "Download Yougori 1.1.0 at https://yougori.com/#download.");
    }

    #[test]
    #[cfg(windows)]
    fn only_an_app_the_setup_installed_is_updated_in_place() {
        let (_folder, app) = installed_app(true);
        assert!(matches!(decide(&available("preview"), false, Some(&app), None, false).unwrap(), Offer::Ready(_)));
        let (_folder, app) = installed_app(false);
        let Offer::Elsewhere(answer) = decide(&available("preview"), false, Some(&app), None, false).unwrap() else { panic!("msi") };
        assert!(answer["next"].as_str().unwrap().contains("MSI package"), "{answer}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn only_the_debian_package_is_updated_in_place() {
        let (_folder, app) = installed_app(false);
        let Offer::Elsewhere(answer) = decide(&available("preview"), false, Some(&app), None, false).unwrap() else { panic!("elsewhere") };
        assert!(answer["next"].as_str().unwrap().contains("Debian package"), "{answer}");
        assert!(matches!(decide(&available("preview"), false, Some(Path::new("/usr/bin/yougori-desktop")), None, false).unwrap(), Offer::Ready(_)));
    }

    fn without_colour(lines: Vec<String>) -> String {
        let text = lines.join("\n");
        let mut plain = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() { break; }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    }

    #[test]
    fn a_terminal_reads_what_the_update_did() {
        for (answer, said) in [
            (json!({"upToDate": true, "version": "1.1.0"}), "◇  Yougori 1.1.0 is up to date"),
            (json!({"current": "1.1.0", "latest": "1.1.0", "updateAvailable": false, "downloadAvailable": true}), "◇  Yougori 1.1.0 is up to date"),
            (json!({"current": "1.0.0", "latest": "1.1.0", "updateAvailable": false, "downloadAvailable": false}), "◇  Yougori 1.1.0 has no package for this computer yet  installed 1.0.0"),
            (json!({"current": "1.0.0", "latest": "1.1.0", "updateAvailable": true, "channel": "preview"}), "◇  Yougori 1.1.0 is available  installed 1.0.0, unsigned preview\n└  Install it with `yougori update`."),
            (json!({"updateAvailable": true, "current": "1.0.0", "latest": "1.1.0", "channel": "stable", "next": "Download it."}), "◇  Yougori 1.1.0 is available  installed 1.0.0\n└  Download it."),
            (json!({"installing": "1.1.0", "restarts": true, "next": "It starts again."}), "◇  Installing Yougori 1.1.0  in the background\n└  It starts again."),
            (json!({"updated": "1.1.0", "started": true, "next": "Yougori runs the new version."}), "◇  Yougori 1.1.0 is installed  and running\n└  Yougori runs the new version."),
            (json!({"updated": "1.1.0", "started": false, "next": "Start it."}), "◇  Yougori 1.1.0 is installed\n└  Start it."),
            (json!({"downloaded": "/tmp/Yougori.deb", "version": "1.1.0", "next": "Finish it."}), "◇  Yougori 1.1.0 is downloaded  /tmp/Yougori.deb\n└  Finish it."),
        ] {
            assert_eq!(without_colour(summary(&answer)), said);
        }
    }

    #[test]
    fn a_failure_quotes_the_end_of_what_the_command_said() {
        assert_eq!(tail(b"progress\n", b"E: one\nE: two\nE: three\nE: four\n"), "E: two E: three E: four");
        assert_eq!(tail(b"only the output\n", b" \n"), "only the output");
    }

    #[test]
    fn an_engine_archive_unpacks_beside_it_and_must_hold_the_engine_and_the_cli() {
        let (engine, cli) = if cfg!(windows) { ("yougori-engine.exe", "cli/yougori.exe") } else { ("yougori-engine", "cli/yougori") };
        let tar = if cfg!(windows) { Path::new(&std::env::var_os("SystemRoot").unwrap()).join("System32").join("tar.exe") } else { "tar".into() };
        let archive = |names: &[&str]| {
            let source = tempfile::tempdir().unwrap();
            for name in names {
                let path = source.path().join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, b"fixture").unwrap();
            }
            let folder = tempfile::tempdir().unwrap();
            let file = folder.path().join("engine.tar");
            assert!(std::process::Command::new(&tar).arg("-cf").arg(&file).arg("-C").arg(source.path()).arg(".").status().unwrap().success());
            (folder, file)
        };
        let (folder, file) = archive(&[engine, cli, "runtime/qemu/qemu.dll", "LICENSE"]);
        let staged = unpack_engine(&file, folder.path(), None).unwrap();
        assert!([engine, cli, "runtime/qemu/qemu.dll", "LICENSE"].iter().all(|name| staged.join(name).is_file()));
        let (folder, file) = archive(&[engine, "LICENSE"]);
        assert_eq!(unpack_engine(&file, folder.path(), None).unwrap_err(), "The update does not contain the CLI; nothing was changed");
        let (folder, file) = archive(&[cli, "LICENSE"]);
        assert_eq!(unpack_engine(&file, folder.path(), None).unwrap_err(), "The update does not contain the engine; nothing was changed");
    }

    /// A release's own packages pass every check `prepare` makes after the download, before
    /// anything stops: `YOUGORI_RELEASE_DIR=<release folder> cargo test -- --ignored release_packages`.
    #[test]
    #[ignore]
    fn release_packages_pass_the_checks_made_before_anything_stops() {
        let release = PathBuf::from(std::env::var_os("YOUGORI_RELEASE_DIR").expect("set YOUGORI_RELEASE_DIR to a release folder"));
        let find = |prefix: &str, suffix: &str| std::fs::read_dir(&release).unwrap().flatten().map(|entry| entry.path())
            .find(|path| path.file_name().unwrap().to_string_lossy().starts_with(prefix) && path.to_string_lossy().ends_with(suffix))
            .unwrap_or_else(|| panic!("no {prefix}*{suffix}"));
        let engine = if cfg!(windows) { find("yougori-engine-", ".zip") } else { find("yougori-engine-", ".tar.gz") };
        let folder = tempfile::tempdir().unwrap();
        let staged = unpack_engine(&engine, folder.path(), None).unwrap();
        let payloads = signed_payloads(&staged).unwrap();
        assert!(payloads.len() >= 2, "{payloads:?}");
        assert!(payloads.iter().all(|path| !path.strip_prefix(&staged).unwrap().starts_with("runtime")));
        #[cfg(windows)]
        {
            let setup = find("Yougori_", ".exe");
            check_installer(&setup, None).unwrap();
            // An unsigned preview is refused by an installation signed by a publisher.
            assert!(check_installer(&setup, Some("CN=Yougori")).is_err());
            assert!(unpack_engine(&engine, tempfile::tempdir().unwrap().path(), Some("CN=Yougori")).unwrap_err().contains("is not signed by your Yougori's publisher"));
        }
        #[cfg(target_os = "linux")]
        check_installer(&find("Yougori_", ".deb"), None).unwrap();
    }

    /// The app's Update hands over to a helper that runs the installer only once the app has quit.
    /// A stand-in app lives two seconds; a stand-in installer (a batch file, which shows a console
    /// window for a moment) records its arguments: `cargo test -- --ignored installer_runs_after`.
    #[test]
    #[ignore]
    #[cfg(windows)]
    fn the_installer_runs_after_the_app_has_quit() {
        let folder = tempfile::tempdir().unwrap();
        let installer = folder.path().join("installer.cmd");
        let said = folder.path().join("arguments.txt");
        std::fs::write(&installer, "@echo %*> \"%~dp0arguments.txt\"\r\n").unwrap();
        let mut app = std::process::Command::new("powershell.exe").args(["-NoProfile", "-Command", "Start-Sleep -Seconds 2"]).spawn().unwrap();
        let prepared = Prepared { plan: decide_ready(), folder: folder.path().to_path_buf(), package: installer, staged: None };
        install_after_exit(prepared, app.id()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        assert!(!said.exists(), "the installer ran while the app was still running");
        app.wait().unwrap();
        let quit = std::time::Instant::now();
        while !said.exists() && quit.elapsed() < std::time::Duration::from_secs(20) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(std::fs::read_to_string(&said).unwrap().trim(), "/S /UPDATE /R");
    }

    #[cfg(windows)]
    fn decide_ready() -> Plan {
        let engine = tempfile::tempdir().unwrap();
        let Offer::Ready(plan) = decide(&available("preview"), true, Some(&engine.path().join("yougori-engine.exe")), None, false).unwrap() else { panic!("ready") };
        plan
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
