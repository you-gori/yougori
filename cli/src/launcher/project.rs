//! Directory-bound development environments. Host code is copied, never mounted.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const ROOT: &str = "/yougori/launch";
mod cloud;
const BOOT: &str =
    "trap 'exit 0' TERM INT; mkdir -p /yougori/launch; while :; do sleep 3600 & wait $!; done";
/// Started outside the launcher, the container runs the dev server once a launch has installed
/// its helpers. A first launch stopped before that leaves it waiting, as [`BOOT`] does.
const NODE_AUTOSTART: &str = "if [ -f /yougori/launch/dev.sh ]; then exec bash /yougori/launch/dev.sh; fi; trap 'exit 0' TERM INT; mkdir -p /yougori/launch; while :; do sleep 3600 & wait $!; done";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Setup {
    version: u32,
    directory: String,
    environment: Option<String>,
    gpu: bool,
    allocation: [u32; 3],
    #[serde(default)]
    storage_drive: Option<String>,
    guest_port: u16,
    local_port: u16,
    network: String,
    domain: Option<String>,
    #[serde(default)]
    needs_update: bool,
    #[serde(default)]
    env_files: bool,
    #[serde(default)]
    env_reviewed: bool,
    #[serde(default)]
    custom_command: Option<String>,
    #[serde(default)]
    command_reviewed: bool,
    #[serde(default)]
    two_way: bool,
    #[serde(default)]
    sync_reviewed: bool,
    #[serde(default)]
    sync_priority: Option<sync::Priority>,
    #[serde(default)]
    continuous_sync: bool,
    #[serde(default)]
    sync_timing_reviewed: bool,
    /// A command the check found blocking that the user chose to run anyway.
    #[serde(default)]
    accepted_command: Option<String>,
}

fn directory_key(path: &Path) -> Result<String, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("Cannot open project folder: {e}"))?;
    let value = path
        .to_str()
        .ok_or("The project path must be valid Unicode")?
        .to_owned();
    #[cfg(windows)]
    let value = value.trim_start_matches(r"\\?\").to_lowercase();
    Ok(format!("{:x}", Sha256::digest(value.as_bytes())))
}

fn save(path: &Path, setup: &Setup) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing state folder")?)
        .map_err(|e| e.to_string())?;
    let _on_quit = ui::remove_on_quit(file.path());
    serde_json::to_writer_pretty(&mut file, setup).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path)
        .map_err(|e| format!("Cannot save launcher settings: {e}"))?;
    Ok(())
}

fn load(path: &Path, directory: &Path) -> Result<Option<Setup>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let setup: Setup = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Cannot read saved launcher settings: {e}"))?;
    if setup.version != 1
        || directory_key(Path::new(&setup.directory))? != directory_key(directory)?
    {
        return Err("Saved launcher settings belong to another folder or version.".into());
    }
    if setup.guest_port == 0
        || setup.local_port == 0
        || !matches!(
            setup.network.as_str(),
            "computer" | "lan" | "quick" | "domain"
        )
    {
        return Err("Invalid saved launcher networking settings. Inspect the launcher state file before retrying.".into());
    }
    Ok(Some(setup))
}

fn reconcile_saved_setup(path: &Path, key: &str, saved: Option<Setup>, state: &Value) -> Result<Option<Setup>, String> {
    let Some(mut saved) = saved else { return Ok(None) };
    let environments = state["environments"].as_array().ok_or("Missing environment list; saved settings were kept")?;
    let marker = format!("Yougori launch · {key}");
    let node = environments.iter().find(|node| match &saved.environment {
        Some(id) => node["id"] == *id,
        None => node["description"] == marker,
    });
    match node {
        Some(node) if node["description"] == marker && node["kind"] == "container" => {
            saved.environment = node["id"].as_str().map(str::to_owned);
            if let Some(drive) = node["storageDrive"].as_str() { saved.storage_drive = Some(drive.into()); }
            Ok(Some(saved))
        },
        Some(_) => Err("The saved environment is no longer owned by this project launcher.".into()),
        None => {
            yougori_cli::launcher_state::clear(path)?;
            Ok(None)
        },
    }
}

fn add_project_shortcut(folder: &Path, project: &package::Project) -> Result<(), String> {
    write_project_shortcut(folder, project, false)
}

/// Adds the project's shortcuts where it can. They are a convenience: when the project's
/// files cannot be changed, the launch goes on and says how to start the project instead.
fn shortcut_or_warn(folder: &Path, project: &package::Project) {
    if let Err(error) = add_project_shortcut(folder, project) {
        ui::warn(&format!("{}. Your answers were saved; start this project with yougori launch.", clean(&error)));
    }
}

/// Best-effort shortcut registration only: no engine, prompts or project launch.
pub(super) fn prepare_project_shortcut(folder: &Path) {
    if package::is_project(folder) {
        if let Ok(project) = package::Project::load(folder) {
            let _ = write_project_shortcut(folder, &project, true);
        }
    }
}

pub(super) struct EntryOffer {
    pub name: String,
    pub command: String,
    pub changed: Vec<String>,
}

/// Reuse the last successful file sync as the baseline. Checking the project
/// neither starts the engine nor writes another cache or acknowledges changes.
fn entry_offer(folder: &Path, settings: &Path) -> Result<Option<EntryOffer>, String> {
    if !package::is_project(folder) {
        return Ok(None);
    }
    let project = package::Project::load(folder)?;
    let path = settings.join(format!("{}.json", directory_key(folder)?));
    let setup = load(&path, folder)?;
    let synced = sync::Saved::load(&path.with_extension("sync.json"));
    let has_baseline = setup.as_ref().and_then(|s| s.environment.as_deref())
        .is_some_and(|id| id == synced.environment && !synced.token.is_empty());
    let changed = if has_baseline {
        let filter = sync::Filter::load(folder, setup.as_ref().is_some_and(|s| s.env_files))?;
        // Compare the same files the last sync recorded.
        let filter = if synced.two_way { filter.two_way() } else { filter };
        let current = sync::scan(folder, &filter)?;
        let (changed, removed) = sync::diff(&synced.files, &current);
        let mut files: Vec<_> = changed.union(&removed).cloned().collect();
        files.sort_by_key(|name| (!sync::needs_install(name), name.clone()));
        if files.is_empty() {
            return Ok(None);
        }
        files
    } else {
        Vec::new()
    };
    Ok(Some(EntryOffer {
        name: clean(&project_name(folder)?),
        command: clean(&setup.and_then(|s| s.custom_command).unwrap_or_else(|| project.command_label())),
        changed,
    }))
}

pub(super) async fn offer_on_entry(folder: &Path) -> Result<(), String> {
    if !package::is_project(folder) {
        return Ok(());
    }
    let source = folder.to_owned();
    let offer = ui::busy("Checking project changes", async move {
        tokio::task::spawn_blocking(move || entry_offer(&source, &yougori_cli::launcher_state::directory()?))
            .await
            .map_err(|e| format!("Cannot check this project: {e}"))?
    })
    .await;
    let offer = match offer {
        // Ctrl+C skips the offer: the menu opens as it would without one.
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            return Ok(());
        }
        offer => offer?,
    };
    let Some(offer) = offer else { return Ok(()) };
    let detail = if offer.changed.is_empty() {
        format!("Project detected: {}", offer.name)
    } else {
        let files = offer.changed.iter().take(3).map(|s| clean(s)).collect::<Vec<_>>().join(", ");
        let more = if offer.changed.len() > 3 { format!(" and {} more", offer.changed.len() - 3) } else { String::new() };
        format!("{} · Changed since last sync: {files}{more}", offer.name)
    };
    let run = if offer.command.is_empty() {
        "Set up and run this project".into()
    } else {
        format!("Run {}", offer.command)
    };
    // The launch follows this question: its first question offers Back, which asks this again.
    let mut launching = false;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::select(
                "Do you want to run this project?",
                std::slice::from_ref(&detail),
                &[
                    ui::Choice::new(run.clone(), "inside its Yougori container"),
                    ui::Choice::new("Continue to main menu", ""),
                ],
                usize::from(!launching),
            )
            .map(|selected| {
                launching = selected == 0;
                true
            }),
            1 if launching => run_in(folder, false).await.map(|_| true),
            1 => Ok(false),
            _ => break,
        };
        match steps.next(asked) {
            Err(e) if e == ui::CANCELLED => break,
            result => result?,
        }
    }
    Ok(())
}

/// Writes a project file through a temporary file in its folder, so an interruption
/// never leaves it empty or half written. With `original`, the existing file is
/// replaced (through a link, keeping its permissions) only if it still has that
/// content; returns false when another program changed it meanwhile.
fn write_atomically(path: &Path, original: Option<&str>, contents: &str) -> Result<bool, String> {
    use std::io::Write;
    let target = match original {
        Some(_) => fs::canonicalize(path).map_err(|e| e.to_string())?,
        None => path.to_path_buf(),
    };
    let folder = target.parent().ok_or("Missing project folder")?;
    // The sync filter never transfers .yougori-sync-* files.
    let mut temp = tempfile::Builder::new().prefix(".yougori-sync-").tempfile_in(folder).map_err(|e| e.to_string())?;
    // Never left half written in the project folder, even by a second Ctrl+C that quits at once.
    let _on_quit = ui::remove_on_quit(temp.path());
    temp.write_all(contents.as_bytes()).map_err(|e| e.to_string())?;
    if original.is_some() {
        let permissions = fs::metadata(&target).map_err(|e| e.to_string())?.permissions();
        temp.as_file().set_permissions(permissions).map_err(|e| e.to_string())?;
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    match original {
        Some(original) => {
            if fs::read_to_string(&target).map_err(|e| e.to_string())? != original {
                return Ok(false);
            }
            temp.persist(&target).map_err(|e| e.to_string())?;
        }
        None => match temp.persist_noclobber(&target) {
            Ok(_) => {}
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(e.error.to_string()),
        },
    }
    Ok(true)
}

fn write_project_shortcut(folder: &Path, project: &package::Project, quiet: bool) -> Result<(), String> {
    if project.is_python() {
        let content = package::PYTHON_SHORTCUT;
        let path = folder.join("yougori");
        if path.exists() {
            if !quiet && fs::read_to_string(&path).ok().as_deref() != Some(content) {
                ui::warn("An existing file named yougori was kept. Run this project with yougori launch.");
            }
            return Ok(());
        }
        match write_atomically(&path, None, content) {
            Ok(true) => if !quiet { ui::step("Added python yougori to this project"); },
            Ok(false) => if !quiet { ui::warn("An existing file named yougori was kept. Run this project with yougori launch."); },
            Err(e) => return Err(format!("Could not add the python yougori shortcut to this folder ({e})")),
        }
        return Ok(());
    }
    let path = folder.join("package.json");
    let text = fs::read_to_string(&path).map_err(|e| format!("Could not read package.json to add the Yougori shortcuts ({e})"))?;
    let local = package::add_launch_script(&text);
    let updated = local.as_deref().unwrap_or(&text);
    let cloud = package::add_cloud_script(updated);
    let updated = cloud.as_deref().unwrap_or(updated);
    let change = package::add_change_script(updated);
    if local.is_some() || cloud.is_some() || change.is_some() {
        let written = write_atomically(&path, Some(&text), change.as_deref().unwrap_or(updated))
            .map_err(|e| format!("Could not add the Yougori shortcuts to package.json ({e})"))?;
        if !written {
            if !quiet { ui::warn("package.json changed while adding the Yougori shortcuts, so it was kept. Run this project with yougori launch."); }
            return Ok(());
        }
        if !quiet {
            if local.is_some() { ui::step(&format!("Added {} to package.json", project.shortcut())); }
            if cloud.is_some() { ui::step(&format!("Added {} to package.json", project.script_command("yougori-cloud", ""))); }
            if change.is_some() { ui::step(&format!("Added {} to package.json", project.script_command("yougori-change", ""))); }
        }
    } else if !quiet && project.package["scripts"]["yougori"].as_str() != Some("yougori launch") {
        ui::warn("The existing package.json was kept. Run this project with yougori launch.");
    }
    Ok(())
}

pub(super) fn shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

async fn exec(id: &str, command: &str) -> Result<String, String> {
    let result = call(
        "execute_environment_command",
        json!({"request":{"environmentId":id,"command":command}}),
    )
    .await?;
    if result["exitCode"].as_i64() != Some(0) {
        return Err(format!(
            "Project setup failed: {}{}",
            result["stdout"].as_str().unwrap_or(""),
            result["stderr"].as_str().unwrap_or("")
        ));
    }
    Ok(result["stdout"].as_str().unwrap_or("").into())
}

/// Switches /workspace to a fresh copy, keeping the dependencies installed in the project and in
/// the package `folders` inside it.
fn install_script(destination: &str, package: &Value, folders: &[String]) -> Result<String, String> {
    // The engine returns a private import directory underneath the explicit destination.
    if !destination.starts_with("/yougori/launch/imports/")
        || destination.split('/').any(|p| p == "..")
    {
        return Err("The engine returned an unexpected project copy destination".into());
    }
    let source = shell(&format!("{destination}/project/workspace"));
    let verify = if package.is_null() { format!("test -d {source}") } else { format!("test -f {source}/package.json") };
    let nested: String = folders
        .iter()
        .filter(|folder| !folder.split('/').any(|p| p.is_empty() || p == "." || p == ".."))
        .map(|folder| {
            let (from, to) = (shell(&format!("/workspace/{folder}/node_modules")), shell(&format!("{destination}/project/workspace/{folder}")));
            format!("if [ -d {from} ] && [ ! -L {from} ] && [ -d {to} ] && [ ! -e {to}/node_modules ]; then mv {from} {to}/node_modules; fi\n")
        })
        .collect();
    Ok(format!(
        r#"set -eu
{verify}
{nested}if [ -d /workspace/node_modules ] && [ ! -L /workspace/node_modules ] && [ ! -e {source}/node_modules ]; then mv /workspace/node_modules {source}/node_modules; fi
if [ -L /workspace ]; then rm /workspace; elif [ -e /workspace ]; then echo '/workspace is not owned by the launcher' >&2; exit 1; fi
ln -s {source} /workspace
# Copied host dependencies must be installed for this Linux runtime.
rm -f /yougori/launch/installed-*
# Remove only previous copies in this dedicated launcher's imports directory.
for old in /yougori/launch/imports/*; do
  [ "$old" = {keep} ] || rm -rf -- "$old"
done
"#,
        keep = shell(destination)
    ))
}

fn changed(args: &[String], npm_flag: Option<&str>) -> Result<bool, String> {
    match args {
        [_] => Ok(npm_flag.is_some_and(|s| s == "true" || s == "1")),
        [_, flag] if matches!(flag.as_str(), "--change" | "-change") => Ok(true),
        _ => Err("Usage: yougori launch [--cloud] [--change]. Run an image with yougori run IMAGE; run models with yougori run hf.co/OWNER/MODEL.".into()),
    }
}

fn recommended_storage(bytes: u64) -> Result<u32, String> {
    let gb = (u128::from(bytes) * 2).div_ceil(1_073_741_824).max(1);
    u32::try_from(gb).map_err(|_| "This project is too large to represent its recommended storage".into())
}

fn project_storage(folder: &Path, stop: &AtomicBool) -> Result<(u64, u32), String> {
    // Measure every file the launcher can copy, including ignored data, dependencies and .env.
    // Only metadata is read; large databases do not need to be loaded or hashed.
    let files = sync::scan_until(folder, &sync::Filter::load(folder, true)?, stop)?;
    let bytes = files.values().try_fold(0u64, |total, (size, _)| total.checked_add(*size))
        .ok_or("The project folder size is too large to measure")?;
    Ok((bytes, recommended_storage(bytes)?))
}

/// Runs a blocking scan off the main thread, behind a spinner once it takes a moment, so the
/// display keeps moving and Ctrl+C stops the wait. A stopped scan is told to stop (through the
/// flag it gets) and waited for: the CLI cannot exit while a scan still runs.
async fn scanning<T: Send + 'static>(label: &str, scan: impl FnOnce(&AtomicBool) -> Result<T, String> + Send + 'static) -> Result<T, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let mut task = tokio::task::spawn_blocking(move || scan(&flag));
    let result = busy(label, async { (&mut task).await.map_err(|e| e.to_string())? }).await;
    if result.is_err() && !task.is_finished() {
        stop.store(true, Ordering::Relaxed);
        let _ = task.await;
    }
    result
}

/// The saved access for an answer to "Who can open your app?". A new domain is saved only here,
/// once every question is answered, so going back never saves it twice.
async fn access(network: Network, port: u16) -> Result<(&'static str, Option<String>), String> {
    Ok(match network {
        Network::Computer => ("computer", None),
        Network::Lan => ("lan", None),
        Network::Quick => ("quick", None),
        Network::Domain(domain) => ("domain", Some(domain)),
        Network::NewDomain {
            hostname,
            token,
            host_port,
        } => {
            busy(
                "Saving your domain",
                call(
                    "add_saved_domain",
                    json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":port}),
                ),
            )
            .await?;
            ("domain", Some(hostname))
        }
    })
}

/// Questions of a first launch and --change: storage drive, resources, ports and access. Answers
/// stay while the person goes back and become the setup once every question is answered.
struct Settings {
    /// Host disks while the storage drive is still to be chosen (first launch only).
    drives: Option<Value>,
    host: Value,
    storage: u32,
    note: Vec<String>,
    suggested: [u32; 3],
    app_port: u16,
    environment: Option<String>,
    drive: Option<String>,
    recommended: bool,
    gpu: bool,
    allocation: [u32; 3],
    guest_port: u16,
    local_port: Option<u16>,
    network: Option<Network>,
}

impl Settings {
    const STEPS: usize = 7;

    /// Measures the project and its storage; also returns the project folder's size in bytes.
    async fn prepare(folder: &Path, state: &Value, old: Option<&Setup>) -> Result<(Self, u64), String> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err("First launch and --change need an interactive terminal to choose project resources and access.".into());
        }
        let app_port = old.map_or(package::Project::load(folder)?.port, |s| s.guest_port);
        let source = folder.to_owned();
        let (bytes, measured) = scanning("Measuring project folder for recommended storage", move |stop| project_storage(&source, stop)).await?;
        // Existing disks can grow, but changing recommendations must never shrink them.
        let storage = measured.max(old.map_or(1, |s| s.allocation[2]));
        let (drives, host) = match old {
            None => {
                let host = busy("Checking storage drives", call("refresh_host_metrics", json!({}))).await?["host"].take();
                (Some(host.clone()), host)
            }
            Some(old) => {
                let id = old.environment.as_deref().ok_or("Project environment has no ID")?;
                let env = state["environments"].as_array().and_then(|nodes|nodes.iter().find(|env|env["id"]==id)).ok_or("Project environment is unavailable")?;
                (None, busy("Checking this project's storage", super::storage::for_environment(&state["host"], env)).await?)
            }
        };
        let mut note = vec![format!("Project folder: {} · storage is 2× its size, rounded up to whole GB (minimum 1 GB).", ui::bytes(bytes))];
        if storage > measured {
            note.push(format!("Keeping the existing {storage} GB storage; disks can only grow."));
        }
        let suggested = [2, 4, storage];
        let settings = Self {
            drives,
            host,
            storage,
            note,
            suggested,
            app_port,
            environment: old.and_then(|s| s.environment.clone()),
            drive: old.and_then(|s| s.storage_drive.clone()),
            recommended: true,
            gpu: old.is_some_and(|s| s.gpu),
            allocation: old.map_or(suggested, |s| s.allocation),
            guest_port: app_port,
            local_port: old.map(|s| s.local_port),
            network: None,
        };
        Ok((settings, bytes))
    }

    /// The port the dev server listens on with the resources chosen so far.
    fn port(&self) -> u16 {
        if self.recommended { self.app_port } else { self.guest_port }
    }

    /// Asks question `step`; returns whether it asked anything.
    async fn ask(&mut self, step: usize) -> Result<bool, String> {
        let custom = !self.recommended;
        match step {
            0 => {
                let Some(drives) = &self.drives else { return Ok(false) };
                let selection = super::storage::choose_with_previous(drives, self.storage, self.drive.as_deref())?;
                self.host = selection.host;
                self.drive = selection.drive;
            }
            1 => {
                limits(&self.host, false, self.storage)?;
                let storage = self.storage;
                self.recommended = ui::select(
                    "Choose project resources",
                    &self.note,
                    &[
                        ui::Choice::new(
                            "Recommended",
                            format!("container · 2 CPU · 4 GB memory · {storage} GB storage"),
                        ),
                        ui::Choice::new("Customize", "GPU, resources and ports"),
                    ],
                    usize::from(!self.recommended),
                )? == 0;
            }
            2 if custom => {
                self.gpu = ui::select(
                    "Run this project in",
                    &[],
                    &options(&[
                        "Container — Linux".into(),
                        "GPU container — NVIDIA".into(),
                    ]),
                    usize::from(self.gpu),
                )? == 1;
            }
            3 if custom => self.allocation = sliders(&self.host, false, self.storage, Some(self.allocation))?,
            4 if custom => self.guest_port = port("Port your dev server listens on", self.guest_port)?,
            // Recommended selects resources; access is always an explicit choice
            // during first setup or --change, then saved for subsequent launches.
            5 => self.network = Some(network_with_previous(false, self.environment.as_deref(), Some(live::proxy_port(self.port())), self.network.as_ref()).await?),
            6 if custom => self.local_port = Some(local_port(self.local_port.unwrap_or(self.guest_port))?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Writes the answers into `setup` before the questions that follow them.
    fn apply(&self, setup: &mut Setup) {
        setup.gpu = !self.recommended && self.gpu;
        setup.allocation = if self.recommended { self.suggested } else { self.allocation };
        setup.guest_port = self.port();
        setup.local_port = if self.recommended { self.app_port } else { self.local_port.unwrap_or(self.guest_port) };
        setup.storage_drive = self.drive.clone();
    }

    async fn finish(self, setup: &mut Setup) -> Result<(), String> {
        let port = self.port();
        let (kind, domain) = access(self.network.ok_or("Choose who can open your app")?, port).await?;
        setup.network = kind.into();
        setup.domain = domain;
        Ok(())
    }
}

/// What the command check changed when it last asked, so going back to it asks again about the
/// same command, with the earlier answer selected.
struct Review {
    before: (Option<String>, Option<String>, bool),
    after: Option<String>,
    picked: usize,
}

/// The questions after the resources, for local and cloud launches alike: the run command,
/// .env files, the command check and sync. Each asks only what this launch needs.
struct Questions {
    folder: PathBuf,
    project: package::Project,
    cloud: bool,
    command: bool,
    env: bool,
    timing: bool,
    direction: bool,
    priority: bool,
    /// The person chose to type their own run command.
    custom: bool,
    /// The port given for a run command other than the project's own. It applies once every
    /// question is answered, so going back to choose the project's command keeps the dev port.
    command_port: Option<u16>,
    choices: Option<Vec<plan::RunChoice>>,
    /// The project folder's size, once measured.
    bytes: Option<u64>,
    review: Option<Review>,
    /// What the command check already warned about; checking again after Back repeats nothing.
    warned: std::collections::BTreeSet<String>,
}

impl Questions {
    fn new(folder: &Path, project: &package::Project, setup: &Setup, change: bool, cloud: bool, bytes: Option<u64>) -> Self {
        Self {
            folder: folder.to_owned(),
            project: project.clone(),
            cloud,
            command: change || !setup.command_reviewed,
            env: (change || !setup.env_reviewed) && sync::has_env_files(folder),
            timing: change || !setup.sync_timing_reviewed,
            direction: change || !setup.sync_reviewed,
            priority: change || setup.sync_priority.is_none(),
            custom: false,
            command_port: None,
            choices: None,
            bytes,
            review: None,
            warned: Default::default(),
        }
    }

    /// Asks question `step`: whether it asked anything, or `None` after the last question.
    async fn ask(&mut self, step: usize, setup: &mut Setup) -> Option<Result<bool, String>> {
        Some(match step {
            0 => self.run_command(setup).await,
            1 => self.custom_command(setup),
            2 => self.app_port(setup),
            3 => self.env_files(setup),
            4 => self.check(setup).await,
            5 => self.sync_timing(setup).await,
            6 => self.sync_direction(setup),
            7 => self.sync_priority(setup),
            _ => return None,
        })
    }

    async fn run_command(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.command {
            return Ok(false);
        }
        if self.choices.is_none() {
            let (folder, project) = (self.folder.clone(), self.project.clone());
            self.choices = Some(scanning("Reading your project's scripts", move |_| Ok(plan::run_choices(&folder, &project))).await?);
        }
        let commands = self.choices.as_deref().unwrap_or_default();
        let previous = setup.custom_command.clone();
        if commands.is_empty() {
            setup.custom_command = Some(ui::input("How do you want to run it? Enter your app's command", previous.as_deref().unwrap_or(""), false, &validate_command)?);
            self.custom = false;
            setup.command_reviewed = true;
            return Ok(true);
        }
        let default = self.project.command_label();
        let mut choices: Vec<_> = commands.iter().map(|command| {
            ui::Choice::new(clean(&command.command), clean(&command.detail)).recommended(command.recommended)
        }).collect();
        choices.push(ui::Choice::new("Custom command", "Enter your own command"));
        let initial = previous.as_deref().map_or(0, |previous| commands.iter().position(|command| command.command == previous).unwrap_or(commands.len()));
        let mut note = vec!["The command runs inside the container, in your project folder.".into()];
        if !commands.iter().any(|command| command.recommended) {
            note.push("No clear recommendation from these scripts. Choose the command that starts your app's services.".into());
        }
        let selected = ui::select(
            "How do you want to run it?",
            &note,
            &choices,
            initial,
        )?;
        self.custom = selected == commands.len();
        if let Some(command) = commands.get(selected) {
            setup.custom_command = (command.command != default).then(|| command.command.clone());
        }
        setup.command_reviewed = true;
        Ok(true)
    }

    fn custom_command(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.command || !self.custom {
            return Ok(false);
        }
        let default = self.project.command_label();
        setup.custom_command = Some(ui::input(
            "Run command",
            setup.custom_command.as_deref().unwrap_or(&default),
            false,
            &validate_command,
        )?);
        Ok(true)
    }

    fn app_port(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.command || setup.custom_command.is_none() {
            return Ok(false);
        }
        self.command_port = Some(port("Port your application listens on", self.command_port.unwrap_or(setup.guest_port))?);
        Ok(true)
    }

    /// Writes the answers that apply once every question is answered.
    fn finish(&self, setup: &mut Setup) {
        if let (Some(port), Some(_)) = (self.command_port, &setup.custom_command) {
            setup.guest_port = port;
        }
    }

    fn env_files(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.env {
            return Ok(false);
        }
        let (question, note, copy) = if self.cloud {
            ("Copy .env files to this cloud project?", "These files can contain credentials. Selected files will be sent to the cloud server over SSH.", "Copy them into the cloud container")
        } else {
            ("Copy .env files into the container?", ".env files can contain credentials.", "Copy them into this container — the dev server can read them")
        };
        setup.env_files = ui::select(
            question,
            &[note.into()],
            &options(&["Keep them on this computer".into(), copy.into()]),
            usize::from(setup.env_files),
        )? == 1;
        setup.env_reviewed = true;
        Ok(true)
    }

    /// Back to the command check: it asks again about the command it asked about before, unless
    /// an earlier answer changed the command since. Returns the choice to select.
    fn reopen(&mut self, setup: &mut Setup) -> usize {
        match self.review.take() {
            Some(review) if setup.custom_command == review.after => {
                (setup.custom_command, setup.accepted_command, setup.command_reviewed) = review.before;
                review.picked
            }
            _ => 0,
        }
    }

    /// Reads the run command before anything starts. What cannot work on Linux (Windows programs,
    /// scripts that don't exist) is stopped here, with replacement commands from the project's own
    /// scripts; everything else it notices is shown as a warning.
    async fn check(&mut self, setup: &mut Setup) -> Result<bool, String> {
        let picked = self.reopen(setup);
        let before = (setup.custom_command.clone(), setup.accepted_command.clone(), setup.command_reviewed);
        let reviewed = self.review_command(setup, picked).await;
        match reviewed {
            Ok(Some(picked)) => {
                self.review = Some(Review { before, after: setup.custom_command.clone(), picked });
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                // Going back leaves the command as it was before this question.
                if error == ui::BACK {
                    (setup.custom_command, setup.accepted_command, setup.command_reviewed) = before;
                }
                Err(error)
            }
        }
    }

    /// The command check; returns the first choice made, or `None` when nothing was asked.
    async fn review_command(&mut self, setup: &mut Setup, mut picked: usize) -> Result<Option<usize>, String> {
        let mut current = self.project.clone();
        let mut first = None;
        for _ in 0..5 {
            current.custom_command = setup.custom_command.clone();
            let command = current.command_label();
            let (folder, project, env_files) = (self.folder.clone(), current.clone(), setup.env_files);
            let check = scanning("Checking the run command", move |_| Ok(plan::check(&folder, &project, env_files))).await?;
            let blocking: Vec<String> = check.findings.iter().filter(|f| f.blocking).map(|f| clean(&f.text)).collect();
            if blocking.is_empty() || setup.accepted_command.as_deref() == Some(command.as_str()) {
                for finding in &check.findings {
                    let text = clean(&finding.text);
                    if self.warned.insert(text.clone()) {
                        ui::warn(&text);
                    }
                }
                return Ok(first);
            }
            let mut choices: Vec<ui::Choice> = check.alternatives.iter().map(|c| ui::Choice::new(clean(c), "from your project's scripts")).collect();
            choices.push(ui::Choice::new("Enter another command", ""));
            choices.push(ui::Choice::new(format!("Run {} anyway", clean(&command)), "it is likely to fail"));
            // The list and a command typed instead are one question: Back from typing returns to the list.
            let mut entered = None;
            let mut steps = ui::Wizard::new();
            loop {
                let asked = match steps.step() {
                    0 => ui::select("This command can't run in the Linux container", &blocking, &choices, picked)
                        .map(|choice| { picked = choice; true }),
                    1 if picked == check.alternatives.len() => ui::input("Run command", &command, false, &validate_command)
                        .map(|typed| { entered = Some(typed); true }),
                    1 => Ok(false),
                    _ => break,
                };
                steps.next(asked)?;
            }
            first.get_or_insert(picked);
            setup.custom_command = Some(match picked {
                n if n < check.alternatives.len() => check.alternatives[n].clone(),
                n if n == check.alternatives.len() => entered.ok_or("Enter a command on one line.")?,
                _ => {
                    setup.accepted_command = Some(command);
                    return Ok(first);
                }
            });
            setup.command_reviewed = true;
            picked = 0;
        }
        Ok(first)
    }

    async fn sync_timing(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.timing {
            return Ok(false);
        }
        let bytes = match self.bytes {
            Some(bytes) => bytes,
            None => {
                let folder = self.folder.clone();
                let (bytes, _) = scanning("Measuring project folder for sync recommendation", move |stop| project_storage(&folder, stop)).await?;
                *self.bytes.insert(bytes)
            }
        };
        // Use the same GB unit as the folder-size display and storage chooser.
        let recommend_continuous = bytes < 5 * 1_073_741_824 / 2;
        let initial = if setup.sync_timing_reviewed { setup.continuous_sync } else { recommend_continuous };
        setup.continuous_sync = ui::select(
            "When should project changes sync?",
            &[
                format!("Project folder: {}. Continuous sync is recommended below 2.5 GB; on demand for larger projects.", ui::bytes(bytes)),
                "Sync once when starting. With on-demand sync, press y in the running launcher when switching where you work. Quitting keeps both copies without another sync.".into(),
            ],
            &[
                ui::Choice::new("On demand", "sync when switching where you work").recommended(!recommend_continuous),
                ui::Choice::new("Continuously", "watch files and check for changes while running").recommended(recommend_continuous),
            ], usize::from(initial),
        )? == 1;
        setup.sync_timing_reviewed = true;
        Ok(true)
    }

    fn sync_direction(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !self.direction {
            return Ok(false);
        }
        setup.two_way = ui::select(
            "Which directions can project changes sync?",
            &["Sync includes code, files, folders and supported SQLite database records. Two-way also brings container changes and deletions back to this computer. Your .env choice still applies.".into()],
            &[
                ui::Choice::new("One-way (default)", "from this computer to the environment"),
                ui::Choice::new("Two-way", "both ways, between this computer and the environment"),
            ],
            usize::from(setup.two_way),
        )? == 1;
        setup.sync_reviewed = true;
        Ok(true)
    }

    fn sync_priority(&mut self, setup: &mut Setup) -> Result<bool, String> {
        if !setup.two_way || !self.priority {
            return Ok(false);
        }
        let previous = match setup.sync_priority { Some(sync::Priority::Remote) => 1, Some(sync::Priority::KeepBoth) => 2, _ => 0 };
        setup.sync_priority = Some(match ui::select(
            "If both copies change, which one takes priority?",
            &["Applies to conflicting code, files, deletions and database records. Changes made on only one side still sync both ways.".into()],
            &[
                ui::Choice::new("This computer wins", "use this computer's version, including deletions"),
                ui::Choice::new("Container wins", "use the container's version, including deletions"),
                ui::Choice::new("Keep both versions", "leave conflicts for you to resolve"),
            ], previous,
        )? { 0 => sync::Priority::Local, 1 => sync::Priority::Remote, _ => sync::Priority::KeepBoth });
        Ok(true)
    }
}

/// Every question a launch asks before it starts: the settings of a first launch or --change,
/// then the run command, .env files, the command check and sync. Each question after the first
/// offers Back, which asks the one before it again with its answer selected.
async fn ask_setup(
    folder: &Path,
    project: &package::Project,
    state: &Value,
    existing: Option<Setup>,
    change: bool,
    stop: &Stop,
) -> Result<Setup, String> {
    let (mut settings, mut setup, bytes) = match existing {
        Some(old) if !change => (None, old, None),
        old => {
            let (settings, bytes) = Settings::prepare(folder, state, old.as_ref()).await?;
            let setup = Setup {
                version: 1,
                directory: folder.to_string_lossy().into(),
                needs_update: old.is_some(),
                ..old.unwrap_or_default()
            };
            (Some(settings), setup, Some(bytes))
        }
    };
    let mut questions = Questions::new(folder, project, &setup, change, false, bytes);
    let mut steps = ui::Wizard::new();
    loop {
        if stop.requested() {
            return Err(ui::CANCELLED.into());
        }
        let step = steps.step();
        let asked = match (&mut settings, step) {
            (Some(settings), step) if step < Settings::STEPS => settings.ask(step).await,
            (settings, Settings::STEPS) => {
                if let Some(settings) = settings {
                    settings.apply(&mut setup);
                }
                Ok(false)
            }
            (_, step) if step < Settings::STEPS => Ok(false),
            (_, step) => match questions.ask(step - Settings::STEPS - 1, &mut setup).await {
                Some(asked) => asked,
                None => break,
            },
        };
        steps.next(asked)?;
    }
    questions.finish(&mut setup);
    if let Some(settings) = settings {
        settings.finish(&mut setup).await?;
    }
    Ok(setup)
}

fn snapshot_progress(task: &ui::Task, progress: &Value) {
    let count = |name: &str| progress[name].as_u64().unwrap_or(0);
    if progress["phase"] == "inspect" {
        task.progress("Looking for SQLite databases", count("done"), count("total"), "files");
        return;
    }
    if progress["phase"] == "files" {
        task.detail(&clean(progress["path"].as_str().unwrap_or("")));
        match progress["totalBytes"].as_u64() {
            Some(total) => task.progress("Preparing project files", count("bytes"), total, "bytes"),
            None => task.progress("Preparing project files", count("done"), count("total"), "files"),
        }
        return;
    }
    task.detail(&format!("{} / {} · {}", progress["index"], progress["total"], clean(progress["path"].as_str().unwrap_or("database"))));
    if progress["phase"] == "index" {
        task.progress("Preparing database sync checkpoint", progress["done"].as_u64().unwrap_or(0), progress["records"].as_u64().unwrap_or(0), "records");
    } else if progress["phase"] == "complete" {
        task.progress("Preparing database snapshots", progress["index"].as_u64().unwrap_or(0), progress["total"].as_u64().unwrap_or(0), "databases");
    } else if progress["pages"].as_u64().is_some() {
        task.progress("Creating consistent database snapshot", progress["done"].as_u64().unwrap_or(0), progress["pages"].as_u64().unwrap_or(0), "pages");
    } else { task.copy_status("Creating consistent database snapshot"); }
}

/// Stages the project for its first copy in the background, with its progress on `task`.
/// Ctrl+C stops it within moments, even in the middle of a large file.
async fn stage_project(folder: &Path, manifest: &sync::Manifest, task: &ui::Task, stop: &Arc<AtomicBool>) -> Result<sync::Staged, String> {
    let (folder, manifest, flag) = (folder.to_path_buf(), manifest.clone(), stop.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || sync::stage_progress(&folder, &manifest, &flag, |progress| {
        tx.send(progress.clone()).map_err(|_| "Project preparation cancelled".into())
    }));
    let mut stopping = false;
    loop {
        if !stopping && stop.load(Ordering::Relaxed) {
            stopping = true;
            task.copy_status("Stopping…");
        }
        if let Some(progress) = rx.try_iter().last().filter(|_| !stopping) { snapshot_progress(task, &progress); }
        if worker.is_finished() { return worker.await.map_err(|e| e.to_string())?; }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

/// Copies files into the environment with their progress on `task`. Ctrl+C cancels the
/// transfer in the engine, which never uses a partial copy.
async fn copy_into(id: &str, params: Value, task: &ui::Task, stop: &Stop) -> Result<Value, String> {
    let flag: &AtomicBool = &stop.flag;
    let copy = public::call_with_progress_cancellable("copy_files_to_environment", params, |progress| {
        if !flag.load(Ordering::Relaxed) { task.copy_progress(progress); }
    }, flag);
    let cancel = async {
        while !flag.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        task.copy_status("Stopping the copy…");
        // Best effort: the copy job itself is cancelled as well.
        let _ = tokio::time::timeout(Duration::from_secs(5), call("cancel_file_transfer", json!({"environmentId":id}))).await;
        std::future::pending::<Result<Value, String>>().await
    };
    tokio::select! {
        result = copy => result,
        result = cancel => result,
    }
}

fn validate_command(entry: &str) -> Result<String, String> {
    let command = entry.trim();
    if command.is_empty() || command.chars().any(char::is_control) {
        return Err("Enter a command on one line.".into());
    }
    Ok(command.into())
}

fn project_name(folder: &Path) -> Result<String, String> {
    let name = folder
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Choose a project folder, not a drive root")?
        .trim();
    if name.len() < 2 || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(
            "The project folder name must contain 2–80 bytes and no control characters.".into(),
        );
    }
    Ok(name.into())
}

fn available_name(base: &str, environments: &[Value], own_id: Option<&str>) -> String {
    let taken = |name: &str| {
        environments.iter().any(|e| {
            e["id"].as_str() != own_id
                && e["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
    };
    if !taken(base) {
        return base.into();
    }
    for number in 2.. {
        let suffix = format!(" ({number})");
        let mut shortened = base.to_owned();
        while shortened.len() + suffix.len() > 80 {
            shortened.pop();
        }
        let name = format!("{shortened}{suffix}");
        if !taken(&name) {
            return name;
        }
    }
    unreachable!()
}

fn creation_request(setup: &Setup, key: &str, folder: &Path) -> Result<Value, String> {
    let mut flags = vec![
        "--name".into(),
        "project".into(),
        "--cpu".into(),
        setup.allocation[0].to_string(),
        "--memory".into(),
        format!("{}GB", setup.allocation[1]),
        "--storage".into(),
        format!("{}GB", setup.allocation[2]),
    ];
    if setup.gpu {
        flags.extend(["--gpu".into(), "nvidia".into()]);
    }
    if let Some(drive) = &setup.storage_drive {
        flags.extend(["--storage-drive".into(), drive.clone()]);
    }
    // A dedicated PC cache can be reused across OCI/CUDA runtimes without
    // assigning one container's private volume quota to another container.
    let profile = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or("Cannot locate your user profile")?;
    let cache = PathBuf::from(profile)
        .join(".yougori")
        .join("cache")
        .join("packages");
    fs::create_dir_all(&cache).map_err(|e| format!("Cannot create package cache: {e}"))?;
    flags.extend([
        "--mount".into(),
        format!("{}:/yougori/cache", cache.display()),
    ]);
    flags.push(package::Project::load(folder)?.image());
    let mut request = public::parse_run(&flags, false)?.request;
    request["name"] = json!(project_name(folder)?);
    request["description"] = json!(format!("Yougori launch · {key}"));
    request["containerCommand"] = json!(BOOT);
    Ok(request)
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Launch cancelled.".into())
    } else {
        Ok(())
    }
}

const STOPPING: &str = "Stopping the launch… Press Ctrl+C again to quit now.";

/// A Ctrl+C that arrived as a signal: the first stops the launch, and a new press after that
/// quits at once. A held key repeats its signal, which never counts as a new press.
fn quits(stopping: &AtomicBool, presses: &mut ui::Presses, now: Instant) -> bool {
    let new = presses.press(now);
    stopping.swap(true, Ordering::SeqCst) && new
}

/// The exit code of a launch that got going. Stopped part way, with Ctrl+C or by leaving a
/// question, it exits 130 as any cancelled command does; quitting the running project exits 0.
fn ended(result: Result<(), String>, interrupted: bool) -> Result<i32, String> {
    match result {
        Ok(()) => Ok(0),
        Err(_) if interrupted => Ok(130),
        Err(error) => Err(error),
    }
}

/// Ctrl+C during a launch: the first stops it, at once and visibly, followed by the usual
/// cleanup; a second quits right away. While the launch works, keys are read here, so Ctrl+C is
/// noticed wherever it is and typing never disturbs the display. Questions and the dev server's
/// view read their own keys.
struct Stop {
    flag: Arc<AtomicBool>,
    keys: Option<ui::Interrupts>,
    signal: tokio::task::JoinHandle<()>,
    notice: Option<std::thread::JoinHandle<()>>,
    finished: Arc<AtomicBool>,
}

impl Stop {
    fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        // Ctrl+C arrives as a signal while nothing reads keys.
        let pressed = flag.clone();
        let signal = tokio::spawn(async move {
            let mut presses = ui::Presses::new(false);
            while tokio::signal::ctrl_c().await.is_ok() {
                if quits(&pressed, &mut presses, Instant::now()) {
                    ui::force_exit();
                }
            }
        });
        // The acknowledgement shows under whatever runs, within moments of the first Ctrl+C.
        let finished = Arc::new(AtomicBool::new(false));
        let (done, stopping) = (finished.clone(), flag.clone());
        let notice = std::thread::spawn(move || {
            let mut shown = None;
            while !done.load(Ordering::Relaxed) {
                if shown.is_none() && stopping.load(Ordering::Relaxed) {
                    let line = ui::block();
                    line.set(vec![format!("{}  {}", ui::paint("▲", ui::AMBER), ui::paint(STOPPING, ui::AMBER))]);
                    shown = Some(line);
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        Self { flag, keys: None, signal, notice: Some(notice), finished }
    }

    fn requested(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn check(&self) -> Result<(), String> {
        cancelled(&self.flag)
    }

    /// Reads keys for Ctrl+C while the launch works.
    fn watch(&mut self) {
        if self.keys.is_none() {
            self.keys = Some(ui::Interrupts::watch(self.flag.clone()));
        }
    }

    /// Hands keys back, before something that reads them itself.
    fn release(&mut self) {
        self.keys = None;
    }

    /// Asks something in the middle of the launch, without Back. Leaving the question stops
    /// the launch.
    fn ask<T>(&mut self, question: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let watching = self.keys.take().is_some();
        let answer = ui::without_back(question);
        if answer.as_ref().is_err_and(|error| error == ui::CANCELLED) {
            self.flag.store(true, Ordering::SeqCst);
        }
        if watching {
            self.watch();
        }
        answer
    }

    /// Waits for `work` unless the launch is stopped first. The engine may still finish a
    /// request it received; the cleanup after a stop covers what it changed.
    async fn until<T>(&self, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
        let mut work = std::pin::pin!(work);
        loop {
            self.check()?;
            tokio::select! {
                result = &mut work => return result,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }
}

impl Drop for Stop {
    fn drop(&mut self) {
        self.signal.abort();
        self.keys = None;
        self.finished.store(true, Ordering::Relaxed);
        if let Some(notice) = self.notice.take() {
            let _ = notice.join();
        }
    }
}

fn copy_storage_full(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "disk quota exceeded",
        "no space left on device",
        "not enough space on the disk",
    ]
    .iter()
    .any(|message| error.contains(message))
}

/// A new storage limit as typed: a whole number above the current limit, up to what is available.
fn storage_limit(entry: &str, current: u32, maximum: u32) -> Result<u32, String> {
    entry
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value > current && *value <= maximum)
        .ok_or_else(|| format!("Enter a whole number from {} to {maximum}.", current + 1))
}

fn growth_limits(allocation: &Value) -> Result<(u32, u32), String> {
    let current = allocation["capacityGb"]
        .as_f64()
        .filter(|v| v.is_finite() && *v >= 1.0)
        .ok_or("Cannot determine the container's current storage limit")?
        .ceil() as u32;
    let maximum = allocation["maximumGb"]
        .as_f64()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .ok_or("Cannot determine available storage")?
        .floor()
        .min(16380.0) as u32;
    if maximum <= current {
        return Err("No additional storage is available. Free space on the runtime drive then launch again.".into());
    }
    Ok((current, maximum))
}

async fn offer_copy_storage(
    setup: &mut Setup,
    state_path: &Path,
    stop: &mut Stop,
) -> Result<bool, String> {
    stop.check()?;
    let id = setup
        .environment
        .as_deref()
        .ok_or("Missing environment ID")?;
    let allocation = stop.until(call("get_storage_allocation", json!({"environmentId":id}))).await?;
    let (current, maximum) = growth_limits(&allocation)?;
    let note = format!(
        "  The project copy ran out of storage ({current} GB limit).
  Increase its storage to fit all project files.

"
    );
    let suggested = current
        .saturating_mul(2)
        .max(current.saturating_add(2))
        .min(maximum);
    // One decision in two questions: Back from the new limit asks the first again with its answer
    // kept, and coming forward again offers the limit typed before.
    let mut choice = 0;
    let mut typed = suggested.to_string();
    let capacity = stop.ask(|| {
        let mut steps = ui::Wizard::new();
        loop {
            let asked = match steps.step() {
                0 => choose_with_initial(
                    "Container storage is full",
                    &note,
                    &[
                        "Increase storage and retry copying".into(),
                        "Cancel launch (keep the container)".into(),
                    ],
                    choice,
                )
                .map(|picked| {
                    choice = picked;
                    true
                }),
                1 if choice == 0 => ui::input(
                    &format!("New storage limit in GB · {}–{maximum}", current + 1),
                    &typed,
                    false,
                    &|entry| storage_limit(entry, current, maximum).map(|value| value.to_string()),
                )
                .map(|entry| {
                    typed = entry;
                    true
                }),
                1 => Ok(false),
                _ => break,
            };
            steps.next(asked)?;
        }
        Ok(if choice == 0 { Some(storage_limit(&typed, current, maximum)?) } else { None })
    })?;
    let Some(capacity) = capacity else {
        return Ok(false);
    };
    stop.check()?;
    let growing = ui::task(&format!("Increasing storage from {current} GB to {capacity} GB"));
    call(
        "expand_environment_storage",
        json!({"environmentId":id,"capacityGb":capacity}),
    )
    .await?;
    growing.done(&format!("Storage is now {capacity} GB"));
    setup.allocation[2] = capacity;
    save(state_path, setup)?;
    Ok(true)
}

// Keep the active project and its dependencies; remove only abandoned launcher imports.
// rm does not follow symlinks. No paths supplied by the error message are used.
//
// The import in use is the one /workspace links into: the link is `<import>/project/workspace`
// (see `install_script`). The check used to compare it with `<import>/project`, which it never
// equals, so every import was removed, the one in use included, whenever this ran. A link that
// cannot be read stops the cleanup (`set -e`) rather than counting as no link.
const ACTIVE_IMPORT: &str = r#"active=
if [ -L /workspace ]; then active=$(readlink /workspace); fi"#;
const REMOVE_ABANDONED: &str = r#"for old in /yougori/launch/imports/yougori-import-*; do
  [ -e "$old" ] || continue
  case "$active" in
    "$old"/*) ;;
    *) rm -rf -- "$old" ;;
  esac
done"#;

fn clean_imports() -> String {
    format!("set -eu\n{ACTIVE_IMPORT}\n{REMOVE_ABANDONED}")
}

/// Whether /workspace holds the project already: `existing`, `empty` or `missing`. A listing
/// that fails is a failure, never an empty workspace, because empty means copying the project in
/// again and clearing abandoned imports first.
const WORKSPACE_PROBE: &str = r#"if [ -d /workspace ]; then
  listing=$(ls -A /workspace) || exit 1
  if [ -n "$listing" ]; then printf existing; else printf empty; fi
else
  printf missing
fi"#;

/// Whether the project has to be copied in, from the probe's answer (the cloud probe also says
/// "copying" for a copy that stopped part way). Anything else is refused.
fn needs_copy(answer: &str) -> Result<bool, String> {
    match answer.trim() {
        "existing" => Ok(false),
        "empty" | "missing" | "copying" => Ok(true),
        _ => Err("Yougori could not tell whether the environment already has this project, so it copied nothing and removed nothing. Try again.".into()),
    }
}

fn port_in_use(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("cannot bind host port")
        && [
            "os error 10048",
            "address already in use",
            "os error 98",
            "os error 48",
        ]
        .iter()
        .any(|message| error.contains(message))
}

fn local_publication_params(id: &str, network: &str, guest_port: u16, host_port: u16) -> Value {
    // "This computer" stays on 127.0.0.1; the other choices also serve the local network.
    let kind = if matches!(network, "lan" | "quick" | "domain") { "local" } else { "loopback" };
    let mut params = json!({"environmentId":id,"port":live::proxy_port(guest_port),"kind":kind});
    if host_port != 0 {
        params["hostPort"] = json!(host_port);
    }
    params
}

/// Publications of the other local kind at this port, which `params` replaces: older
/// launchers reached only this PC, and "This computer" once reached the local network.
/// Returns their IDs and the params to publish, which leave the port to the engine while
/// a remaining publication, such as a tunnel sharing a replaced listener, holds it.
fn local_replacements(publications: &[Value], mut params: Value) -> (Vec<String>, Value) {
    let mut replaced = Vec::new();
    let mut held = false;
    for publication in publications {
        let other_kind = matches!(publication["kind"].as_str(), Some("loopback" | "local"))
            && publication["kind"] != params["kind"];
        match publication["id"].as_str() {
            Some(id) if other_kind && publication["port"] == params["port"] => {
                replaced.push(id.to_owned())
            }
            _ => held |= publication["hostPort"] == params["hostPort"],
        }
    }
    if held && !replaced.is_empty() {
        if let Some(params) = params.as_object_mut() {
            params.remove("hostPort");
        }
    }
    (replaced, params)
}

/// This environment's quick link or domain routes at this port. "This computer" and "Local
/// network" remove them: the engine saves each route and restores it when it restarts.
fn public_routes(publications: &[Value], id: &str, port: u16) -> Vec<String> {
    publications
        .iter()
        .filter(|p| p["environmentId"] == id && p["port"] == port && p["kind"] == "cloudflare")
        .filter_map(|p| p["id"].as_str().map(str::to_owned))
        .collect()
}

async fn publish_local(
    setup: &mut Setup,
    state_path: &Path,
    stop: &mut Stop,
) -> Result<(), String> {
    let id = setup
        .environment
        .as_deref()
        .ok_or("Missing environment ID")?;
    let services = stop.until(call("list_environment_services", json!({"environmentId":id}))).await?;
    let (replaced, params) = local_replacements(
        services["publications"].as_array().map(Vec::as_slice).unwrap_or_default(),
        local_publication_params(id, &setup.network, setup.guest_port, setup.local_port),
    );
    for publication_id in replaced {
        stop.until(call(
            "unpublish_environment_service",
            json!({"publicationId":publication_id}),
        ))
        .await?;
    }
    let publication = match stop.until(call("publish_environment_service", params.clone())).await {
        Ok(publication) => publication,
        Err(error) if !stop.requested() && port_in_use(&error) => {
            let note = format!(
                "  Local port {} is already being used.
  Your project has been copied successfully.

",
                setup.local_port
            );
            if stop.ask(|| choose_with_note(
                "Choose another local port",
                &note,
                &[
                    "Use an available port and continue".into(),
                    "Cancel launch (keep the container)".into(),
                ],
            ))? != 0
            {
                return Err(format!("Local port {} is in use. Stop the application using it or run yougori launch --change to choose another.", setup.local_port));
            }
            stop.check()?;
            // An omitted hostPort asks the engine to bind a free port atomically.
            let automatic = local_publication_params(id, &setup.network, setup.guest_port, 0);
            stop.until(call("publish_environment_service", automatic)).await?
        }
        Err(error) => return Err(error),
    };
    let actual = publication["hostPort"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= u16::MAX as u64)
        .ok_or("The engine did not return the published local port")? as u16;
    if actual != setup.local_port {
        ui::warn(&format!("Local address changed to http://127.0.0.1:{actual} (saved for this project)"));
        setup.local_port = actual;
        save(state_path, setup)?;
    }
    Ok(())
}

async fn launch(
    setup: &mut Setup,
    state_path: &Path,
    folder: &Path,
    _package: &Value,
    key: &str,
    change: bool,
    stop: &mut Stop,
) -> Result<live::Live, String> {
    let mut project = package::Project::load(folder)?;
    project.custom_command = setup.custom_command.clone();
    if let Some(root) = &project.workspace_root {
        return Err(format!("This package belongs to a workspace. Launch from {} so workspace dependencies are copied too.", root.display()));
    }
    let remembered = setup.environment.take();
    stop.check()?;
    let state = busy("Looking up this project's container", call("get_platform_state", json!({}))).await?;
    let marker = format!("Yougori launch · {key}");
    let environments = state["environments"]
        .as_array()
        .ok_or("Missing environment list")?;
    let found = if let Some(id) = &remembered {
        environments.iter().find(|e| e["id"] == *id)
    } else {
        environments.iter().find(|e| e["description"] == marker)
    };
    if remembered.is_some() && found.is_none() {
        yougori_cli::launcher_state::clear(state_path)?;
        return Err("This project's container was deleted while it was launching. Run yougori launch again to set it up afresh.".into());
    }
    if let Some(env) = found {
        if env["description"] != marker || env["kind"] != "container" {
            return Err(
                "The saved environment is no longer owned by this project launcher.".into(),
            );
        }
        if env["runtime"]
            .as_str()
            .is_some_and(|runtime| runtime != project.image())
        {
            return Err(format!("This saved container uses {} but the project needs {}. Its data was kept. Remove this project's container when ready, then launch again to create one with the required image.", env["runtime"], project.runtime_label()));
        }
        setup.environment = Some(env["id"].as_str().ok_or("Missing environment ID")?.into());
    } else {
        setup.environment = None;
    }
    let name = available_name(
        &project_name(folder)?,
        environments,
        setup.environment.as_deref(),
    );
    save(state_path, setup)?;
    let container = ui::task(&if setup.environment.is_some() {
        format!("Starting {}", clean(&name))
    } else {
        format!("Creating {} · {}", clean(&name), project.runtime_label())
    });
    if setup.environment.is_none() {
        container.detail("the first run downloads the runtime image");
    }
    // Changes to an existing container are quick and finish before a stop takes effect.
    if let Some(id) = &setup.environment {
        if found.is_some_and(|env| env["name"] != name) {
            call(
                "rename_environment",
                json!({"environmentId":id,"name":name}),
            )
            .await?;
        }
        call(
            "set_environment_status",
            json!({"environmentId":id,"status":"stopped"}),
        )
        .await?;
        stop.check()?;
        if change || setup.needs_update {
            call(
                "update_environment_gpu",
                json!({"environmentId":id,"enabled":setup.gpu}),
            )
            .await?;
            let range = |v| json!({"min":v,"preferred":v,"max":v,"current":v});
            call("update_resource_policy", json!({"environmentId":id,"resourcePolicy":{"cpu":range(setup.allocation[0]),"memoryGb":range(setup.allocation[1]),"priority":"normal"}})).await?;
            call(
                "expand_environment_storage",
                json!({"environmentId":id,"capacityGb":setup.allocation[2]}),
            )
            .await?;
        }
    } else {
        let mut request = creation_request(setup, key, folder)?;
        request["name"] = json!(name);
        let result = match stop.until(call("run_workload", json!({"request":request,"start":false}))).await {
            Ok(result) => result,
            // The engine finishes creating the container, which stays stopped; the next
            // launch finds it by its description.
            Err(error) if stop.requested() => return Err(error),
            Err(error) => {
                if let Ok(state) = call("get_platform_state", json!({})).await {
                    setup.environment = state["environments"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|e| e["description"] == marker)
                        .and_then(|e| e["id"].as_str())
                        .map(str::to_owned);
                    save(state_path, setup)?;
                }
                return Err(error);
            }
        };
        setup.environment = Some(
            result["id"]
                .as_str()
                .ok_or("Created environment did not return an ID")?
                .into(),
        );
        save(state_path, setup)?;
    }
    call(
        "update_container_startup_command",
        json!({"environmentId":setup.environment,"command":BOOT}),
    )
    .await?;
    setup.needs_update = false;
    save(state_path, setup)?;
    stop.check()?;
    let id = setup
        .environment
        .as_deref()
        .ok_or("Missing environment ID")?;
    // Boot clears the prior ready marker before waiting for this run's freshly copied code.
    call(
        "set_environment_status",
        json!({"environmentId":id,"status":"running"}),
    )
    .await?;
    container.done(&format!("Container {} running", clean(&name)));
    stop.check()?;
    let mut files = ui::task("Syncing project files");
    stop.until(exec(id, "mkdir -p /yougori/launch/imports")).await?;
    let filter = sync::Filter::load(folder, setup.env_files)?;
    let (source, flag) = (folder.to_owned(), stop.flag.clone());
    // A stop ends the scan at its next folder; it is waited for, as the CLI cannot exit before.
    let manifest = tokio::task::spawn_blocking(move || sync::scan_until(&source, &filter, &flag))
        .await
        .map_err(|e| e.to_string())??;
    let bytes: u64 = manifest.values().map(|(size, _)| size).sum();
    let total = format!(
        "{} files · {}",
        manifest.len(),
        ui::bytes(bytes)
    );
    files.detail(&total);
    let sync_path = state_path.with_extension("sync.json");
    let mut saved = sync::Saved::load(&sync_path);
    let remote_token = stop.until(exec(id, "cat /yougori/launch/sync-token 2>/dev/null || true")).await?;
    let id = id.to_owned();
    let installs = plan::installs(folder, &project, &manifest);
    let reconcile = saved.needs_reconcile(&id, &remote_token);
    // A missing checkpoint is not a missing workspace. Never replace an existing
    // project (and its runtime data) just to recover interrupted sync metadata.
    let probed = stop.until(async { exec(&id, WORKSPACE_PROBE).await.map_err(|error| format!("Yougori could not tell whether the environment already has this project, so it copied nothing and removed nothing. Try again. ({error})")) }).await?;
    let copied = needs_copy(&probed)?;
    saved.adopt(&id, copied);
    let mut initial_databases = std::collections::BTreeSet::new();
    if copied {
        files.set("Copying project into the container");
        files.copy_status("Preparing project files");
        let staging = stage_project(folder, &manifest, &files, &stop.flag).await?;
        files.detail(&total);
        let copy = loop {
            // Removing an abandoned copy can take a while; the next launch finishes it.
            stop.until(exec(&id, &clean_imports())).await?;
            files.copy_status("Waiting for copy progress");
            match copy_into(&id, json!({"environmentId":id,"paths":[staging.path().join("project")],"destination":format!("{ROOT}/imports")}), &files, stop).await {
                Ok(copy) => break copy,
                Err(error) if stop.requested() => return Err(error),
                Err(error) if copy_storage_full(&error) => {
                    if !offer_copy_storage(setup, state_path, stop).await? { return Err("Project copy cancelled because storage is full.".into()); }
                }
                Err(error) => return Err(error),
            }
        };
        files.set("Setting up project sync");
        let destination = copy["destination"]
            .as_str()
            .ok_or("Missing copy destination")?;
        let nested: Vec<String> = installs.iter().filter(|i| i.folder != "." && !i.marker.starts_with('/')).map(|i| i.folder.clone()).collect();
        exec(
            &id,
            &install_script(destination, &project.package, &nested)?,
        )
        .await?;
        saved.files = manifest.clone();
        saved.token.clear();
        saved.pending.clear();
        initial_databases = staging.databases.keys().cloned().collect();
        saved.databases = staging.databases;
        saved.environment = id.clone();
        saved.common.clear();
        saved.directories.clear();
        // A fresh copy leaves both sides the same, so nothing is left to keep apart.
        saved.unknown.clear();
        saved.unreadable = false;
        saved.save(&sync_path)?;
    }
    stop.check()?;
    let mut live = stop.until(live::Live::prepare(&id, folder, &project, &manifest, setup.two_way, setup.guest_port, &sync_path, saved)).await?;
    live.priority = setup.sync_priority.unwrap_or_default();
    live.env_files = setup.env_files;
    live.initial_databases = initial_databases;
    if !setup.two_way && !copied && reconcile {
        files.set("Comparing project files to resume sync");
        stop.until(live.reconcile_one_way(&manifest)).await?;
    }
    // A stop between transfers leaves the sync journal for the next launch to recover.
    let changes = loop {
        let result = stop.until(async {
            if setup.two_way { live.sync_both(setup.env_files).await } else { live.sync_to(manifest.clone()).await }
        }).await;
        match result {
            Err(error) if !stop.requested() && copy_storage_full(&error) => {
                if !offer_copy_storage(setup, state_path, stop).await? {
                    return Err(error);
                }
            }
            result => break result?,
        }
    };
    files.done(&if setup.two_way {
        format!("Two-way sync checked · {changes} file changes")
    } else if copied {
        format!("Copied {total}")
    } else if changes == 0 {
        "Project files up to date".into()
    } else {
        format!(
            "Synced {changes} changed file{}",
            if changes == 1 { "" } else { "s" }
        )
    });
    if let Some(text) = plan::describe(&installs) {
        ui::info(&clean(&text));
    }
    let publishing = ui::task("Publishing");
    let mut public = Vec::new();
    // A saved domain can reserve the same host port as the project's old loopback
    // publication. Give the domain its configured port before choosing localhost.
    let network = match setup.network.as_str() {
        "lan" => Network::Lan,
        "quick" => Network::Quick,
        "domain" => Network::Domain(setup.domain.clone().ok_or("Missing saved domain")?),
        _ => Network::Computer,
    };
    let domain_uses_local_port = if let Network::Domain(ref hostname) = network {
        let domains = stop.until(call("list_saved_domains", json!({}))).await?;
        let host_port = domains
            .as_array()
            .into_iter()
            .flatten()
            .find(|domain| domain["hostname"] == *hostname)
            .and_then(|domain| domain["hostPort"].as_u64());
        if let Some(host_port) = host_port {
            let services = stop.until(call("list_environment_services", json!({"environmentId":id}))).await?;
            for publication in services["publications"].as_array().into_iter().flatten() {
                if publication["kind"] == "loopback"
                    && publication["hostPort"].as_u64() == Some(host_port)
                {
                    if let Some(publication_id) = publication["id"].as_str() {
                        stop.until(call(
                            "unpublish_environment_service",
                            json!({"publicationId":publication_id}),
                        ))
                        .await?;
                    }
                }
            }
        }
        host_port == Some(setup.local_port as u64)
    } else {
        false
    };
    if let Some(params) = (!matches!(network, Network::Lan))
        .then(|| publish_params(&network, &id, live::proxy_port(setup.guest_port)))
        .flatten()
    {
        let publication = stop.until(domains::publish(params)).await.map_err(|error| {
            if matches!(network, Network::Domain(_)) && port_in_use(&error) {
                format!("The saved domain's local tunnel port is already in use. Change its port in Yougori's saved public access setup, then launch again. {error}")
            } else {
                error
            }
        })?;
        for url in publication["urls"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            public.push(clean(url));
        }
    } else {
        // This computer and Local network: remove a public link left by an earlier choice.
        let services = stop.until(call("list_environment_services", json!({"environmentId":id}))).await?;
        for publication_id in public_routes(
            services["publications"].as_array().map(Vec::as_slice).unwrap_or_default(),
            &id,
            live::proxy_port(setup.guest_port),
        ) {
            stop.until(call(
                "unpublish_environment_service",
                json!({"publicationId":publication_id}),
            ))
            .await?;
        }
    }
    // The local publication serves this PC and, unless "This computer" was chosen, its local network.
    if domain_uses_local_port {
        // Port zero asks the engine to allocate a free localhost port atomically.
        setup.local_port = 0;
    }
    publish_local(setup, state_path, stop).await?;
    publishing.done(&format!(
        "Published at {}",
        ui::paint(&format!("http://127.0.0.1:{}", setup.local_port), ui::SKY)
    ));
    for url in public {
        ui::info(&format!("public  {url}"));
    }
    stop.check()?;
    stop.until(live.start()).await?;
    ui::outro(&format!(
        "{} {}",
        ui::muted("$"),
        clean(&project.command_label())
    ));
    ui::line("");
    Ok(live)
}

pub(super) async fn run(args: &[String]) -> Result<i32, String> {
    let result = if args.iter().any(|arg| arg == "--cloud") {
        let args: Vec<_> = args.iter().filter(|arg| arg.as_str() != "--cloud").cloned().collect();
        let change = changed(&args, std::env::var("npm_config_change").ok().as_deref())?;
        cloud::run_in(&std::env::current_dir().map_err(|e| e.to_string())?, change).await
    } else {
        let change = changed(args, std::env::var("npm_config_change").ok().as_deref())?;
        run_in(&std::env::current_dir().map_err(|e| e.to_string())?, change).await
    };
    // Run from the command line, no question comes before the first one: Back there cancels.
    result.map_err(|error| if error == ui::BACK { ui::CANCELLED.into() } else { error })
}

pub(super) async fn run_in(folder: &Path, change: bool) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("The project launcher needs an interactive terminal. For scripts use yougori run -d IMAGE or yougori up.".into());
    }
    let folder = folder
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let project = package::Project::load(&folder)?;
    let package = project.package.clone();
    let key = directory_key(&folder)?;
    let settings = yougori_cli::launcher_state::directory()?;
    fs::create_dir_all(&settings).map_err(|e| e.to_string())?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(settings.join(format!("{key}.lock")))
        .map_err(|e| e.to_string())?;
    lock.try_lock().map_err(|_| {
        "This project is already open in another yougori launch terminal. Stop it there first."
    })?;
    let path = settings.join(format!("{key}.json"));
    let existing = load(&path, &folder)?;
    let _session = ui::Session::start("launch", "Run your project in a container");
    super::releases::offer(false).await?;
    let name = project_name(&folder)
        .map(|name| clean(&name))
        .unwrap_or_else(|_| "project".into());
    ui::intro(
        &name,
        &format!(
            "{} · {}",
            clean(
                existing.as_ref()
                    .and_then(|s| s.custom_command.as_deref())
                    .unwrap_or(&project.command_label()),
            ),
            project.runtime_label()
        ),
    );
    let mut stop = Stop::new();
    stop.watch();
    // The engine step lasts until the engine has answered, so the launch never looks stuck.
    let engine = ui::task("Starting Yougori engine");
    let state = match stop.until(async {
        client::start(None).await?;
        call("get_platform_state", json!({})).await
    }).await {
        Err(_) if stop.requested() => {
            engine.clear();
            drop(stop);
            ui::outro("Cancelled. Nothing was started.");
            return Ok(130);
        }
        state => state?,
    };
    let had_settings = existing.is_some();
    // The engine is ready even when the saved settings no longer match it.
    let existing = reconcile_saved_setup(&path, &key, existing, &state);
    engine.done("Engine ready");
    let existing = existing?;
    if had_settings && existing.is_none() {
        ui::step("This project's earlier container no longer exists, so it is set up again");
    }
    // Questions read their own keys.
    stop.release();
    let mut setup = ask_setup(&folder, &project, &state, existing, change, &stop).await?;
    // The answers are kept first, so a project file that cannot be changed never costs them.
    save(&path, &setup)?;
    shortcut_or_warn(&folder, &project);
    stop.watch();
    let result = async {
        let mut live = launch(&mut setup, &path, &folder, &package, &key, change, &mut stop).await?;
        // The dev server's view reads its own keys, Ctrl+C included.
        stop.release();
        let result = live
            .watch(&name, setup.local_port, setup.env_files, setup.two_way, setup.continuous_sync, setup.gpu, &stop.flag)
            .await;
        stop.watch();
        if result.is_ok() && setup.continuous_sync {
            let syncing = ui::task("Syncing your latest changes");
            let synced = live.sync_current(setup.env_files, setup.two_way).await;
            syncing.clear();
            if let Err(error) = synced { ui::warn(&format!("Final sync incomplete: {}. Environment files are kept for the next launch.", clean(&error))); }
        }
        live.close().await;
        result
    }
    .await;
    // A Ctrl+C during the cleanup never hides an error the launch already had.
    let interrupted = stop.requested();
    stop.watch();
    let cleanup = if let Some(id) = setup.environment.as_deref() {
        let stopping = ui::task(&format!("Stopping {name}"));
        let stopped = call(
            "set_environment_status",
            json!({"environmentId":id,"status":"stopped"}),
        )
        .await;
        match &stopped {
            Ok(_) => {
                stopping.done(&format!("Stopped {name}"));
                // Saved so that yougori start runs the dev server again later. Missing it changes
                // only that, so it is said and the launch still ends as it would have.
                if let Err(error) = call("update_container_startup_command", json!({"environmentId":id,"command":NODE_AUTOSTART})).await {
                    ui::warn(&format!(
                        "{name} stopped, but its startup command was not saved ({}), so yougori start will not run the dev server on its own. Launching the project again still does.",
                        clean(&error)
                    ));
                }
            }
            Err(_) => stopping.fail("Could not confirm the container stopped"),
        }
        stopped.map(|_| ())
    } else {
        Ok(())
    };
    drop(stop);
    ui::outro(&format!(
        "{} starts this project again · {} edits settings · yougori opens the menu",
        project.launch_hint(&folder, ""),
        project.launch_hint(&folder, "--change"),
    ));
    drop(lock);
    match cleanup {
        Err(e) => {
            let state = call("get_platform_state", json!({})).await.unwrap_or_default();
            let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
            let container = setup.environment.as_deref().map_or_else(|| "NAME".to_owned(), |id| yougori_cli::container_tools::handle(environments, id));
            Err(format!(
                "Could not confirm {name}'s container stopped ({e}). Check it with yougori ps, and stop it with {}.",
                shell_words::join(["yougori", "stop", &container])
            ))
        }
        Ok(()) => ended(result, interrupted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_storage_doubles_folder_bytes_before_rounding_up() {
        let gb = 1_073_741_824;
        for (bytes, expected) in [(0, 1), (1, 1), (gb / 2, 1), (gb / 2 + 1, 2), (gb, 2), (gb + 1, 3), (gb * 82 / 10, 17)] {
            assert_eq!(recommended_storage(bytes).unwrap(), expected, "{bytes} bytes");
        }
        assert!(recommended_storage(u64::MAX).is_err());
    }

    #[test]
    fn storage_measurement_counts_dependencies_ignored_data_and_env_files() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = 0;
        for (path, contents) in [
            (".gitignore", "data/\nnode_modules/\n"),
            ("data/app.db", "database"),
            ("node_modules/library/index.js", "dependency"),
            (".git/objects/example", "git object"),
            ("server/.env", "EXAMPLE=value"),
            ("snapshots/backup", "snapshot"),
        ] {
            let file = root.path().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, contents).unwrap();
            expected += contents.len() as u64;
        }
        fs::write(root.path().join(".yougori-sync-temporary"), "transfer internals").unwrap();
        let going = AtomicBool::new(false);
        assert_eq!(project_storage(root.path(), &going).unwrap(), (expected, 1));
        assert!(project_storage(&root.path().join("missing"), &going).is_err());
        assert!(project_storage(root.path(), &AtomicBool::new(true)).is_err(), "a stopped measurement ends early");
    }

    #[test]
    fn entry_offer_detects_new_changed_and_deleted_project_files_without_writing_state() {
        let folder = tempfile::tempdir().unwrap();
        let settings = tempfile::tempdir().unwrap();
        assert!(entry_offer(folder.path(), settings.path()).unwrap().is_none());
        let package = folder.path().join("package.json");
        fs::write(&package, r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let first = entry_offer(folder.path(), settings.path()).unwrap().unwrap();
        assert_eq!(first.command, "npm run dev");
        assert!(first.changed.is_empty());
        assert_eq!(fs::read_dir(settings.path()).unwrap().count(), 0);

        // A normal launch has registered its shortcut and saved sync metadata.
        prepare_project_shortcut(folder.path());
        fs::write(folder.path().join("app.js"), "first").unwrap();
        let key = directory_key(folder.path()).unwrap();
        let path = settings.path().join(format!("{key}.json"));
        let setup: Setup = serde_json::from_value(json!({
            "version":1,"directory":folder.path(),"environment":"env-test",
            "gpu":false,"allocation":[2,4,6],"guest_port":3000,"local_port":3000,
            "network":"computer","domain":null,"custom_command":"npm run preview"
        })).unwrap();
        save(&path, &setup).unwrap();
        let synced = sync::Saved {
            environment: "env-test".into(), token: "synced".into(),
            files: sync::scan(folder.path(), &sync::Filter::load(folder.path(), false).unwrap()).unwrap(),
            ..Default::default()
        };
        let sync_path = path.with_extension("sync.json");
        synced.save(&sync_path).unwrap();
        let baseline = fs::read(&sync_path).unwrap();
        prepare_project_shortcut(folder.path());
        assert!(entry_offer(folder.path(), settings.path()).unwrap().is_none());

        fs::create_dir(folder.path().join("node_modules")).unwrap();
        fs::write(folder.path().join("node_modules/dependency.js"), "copied").unwrap();
        fs::write(folder.path().join(".env"), "PRIVATE=value").unwrap();
        assert_eq!(entry_offer(folder.path(), settings.path()).unwrap().unwrap().changed, ["node_modules/dependency.js"]);

        fs::write(&package, r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"16"}}"#).unwrap();
        fs::remove_file(folder.path().join("app.js")).unwrap();
        fs::write(folder.path().join("new.js"), "new file").unwrap();
        for _ in 0..2 {
            let offer = entry_offer(folder.path(), settings.path()).unwrap().unwrap();
            assert_eq!(offer.command, "npm run preview", "use the saved custom command");
            assert_eq!(offer.changed, ["package.json", "app.js", "new.js", "node_modules/dependency.js"]);
            assert_eq!(fs::read(&sync_path).unwrap(), baseline, "checking or skipping must not consume changes");
        }
        // Deleted nodes lose their baseline through the existing settings cleanup.
        yougori_cli::launcher_state::clear(&path).unwrap();
        let offer = entry_offer(folder.path(), settings.path()).unwrap().unwrap();
        assert_eq!(offer.command, "npm run dev");
        assert!(offer.changed.is_empty());
    }

    #[test]
    fn entry_offer_supports_python_and_rejects_invalid_projects() {
        let folder = tempfile::tempdir().unwrap();
        let settings = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("main.py"), "print('hello')").unwrap();
        let offer = entry_offer(folder.path(), settings.path()).unwrap().unwrap();
        assert!(offer.command.starts_with("python "));
        assert!(offer.command.contains("main.py"));
        fs::write(folder.path().join("package.json"), "invalid").unwrap();
        assert!(entry_offer(folder.path(), settings.path()).is_err());
        assert_eq!(fs::read_dir(settings.path()).unwrap().count(), 0);
    }

    #[test]
    fn saved_settings_follow_node_lifetime_not_running_status() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("setup.json");
        let setup: Setup = serde_json::from_value(json!({
            "version":1,"directory":folder.path(),"environment":"env-project",
            "gpu":false,"allocation":[2,4,6],"guest_port":3000,"local_port":3000,
            "network":"computer","domain":null,"custom_command":"npm start","command_reviewed":true
        })).unwrap();
        save(&path, &setup).unwrap();
        fs::write(path.with_extension("sync.json"), "saved sync").unwrap();
        for status in ["running", "stopped", "error"] {
            let state = json!({"environments":[{"id":"env-project","description":"Yougori launch · key","kind":"container","status":status}]});
            let retained = reconcile_saved_setup(&path, "key", Some(setup.clone()), &state).unwrap().unwrap();
            assert_eq!(retained.custom_command.as_deref(), Some("npm start"));
            assert!(path.exists());
        }
        assert!(reconcile_saved_setup(&path, "key", Some(setup.clone()), &json!({})).is_err());
        assert!(path.exists(), "An invalid engine response must not erase preferences");
        assert!(reconcile_saved_setup(&path, "key", Some(setup), &json!({"environments":[]})).unwrap().is_none());
        assert!(!path.exists());
        assert!(!path.with_extension("sync.json").exists());
    }

    #[tokio::test]
    #[ignore = "Requires a running Yougori engine; creates and deletes an isolated Node.js test container"]
    async fn project_launch_reuses_container_refreshes_code_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let package = json!({"name":"yougori-launch-test","version":"1.0.0","scripts":{"dev":"vite"},"devDependencies":{"vite":"7.3.6"}});
        fs::write(dir.path().join("package.json"), package.to_string()).unwrap();
        fs::write(dir.path().join("index.html"), "first").unwrap();
        fs::write(dir.path().join("removed.txt"), "old").unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut setup = Setup {
            version: 1,
            directory: dir.path().to_string_lossy().into(),
            environment: None,
            gpu: false,
            allocation: [1, 2, 4],
            storage_drive: None,
            guest_port: 3000,
            local_port: port,
            network: "computer".into(),
            domain: None,
            needs_update: false,
            env_files: false,
            env_reviewed: false,
            custom_command: None,
            command_reviewed: false,
            two_way: false,
            sync_reviewed: false,
            sync_priority: None,
            continuous_sync: true,
            sync_timing_reviewed: true,
            accepted_command: None,
        };
        let settings = tempfile::tempdir().unwrap();
        let path = settings.path().join("state.json");
        let key = directory_key(dir.path()).unwrap();
        let mut stop = Stop::new();
        let result: Result<(), String> = async {
            let mut live = launch(
                &mut setup,
                &path,
                dir.path(),
                &package,
                &key,
                false,
                &mut stop,
            )
            .await?;
            let id = setup.environment.clone().unwrap();
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            for expected in ["first", "hot-save", "second"] {
                if expected == "hot-save" {
                    let stopped = AtomicBool::new(false);
                    let edit_and_cancel = async {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        fs::write(dir.path().join("index.html"), "hot-save").unwrap();
                        let mut served = false;
                        for _ in 0..50 {
                            if let Ok(reply) = client.get(format!("http://127.0.0.1:{port}")).send().await {
                                if reply.text().await.unwrap_or_default().contains("hot-save") { served = true; break; }
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        stopped.store(true, Ordering::Relaxed);
                        served
                    };
                    let (watched, served) = tokio::join!(live.watch("test", port, false, false, true, false, &stopped), edit_and_cancel);
                    watched?;
                    assert!(served, "the file watcher must deliver a save without relaunching");
                }
                if expected == "second" {
                    live.close().await;
                    call(
                        "set_environment_status",
                        json!({"environmentId":id,"status":"stopped"}),
                    )
                    .await?;
                    fs::remove_file(dir.path().join("removed.txt")).unwrap();
                    fs::write(dir.path().join("index.html"), "second").unwrap();
                    live = launch(
                        &mut setup,
                        &path,
                        dir.path(),
                        &package,
                        &key,
                        false,
                        &mut stop,
                    )
                    .await?;
                    assert_eq!(setup.environment.as_deref(), Some(id.as_str()));
                    exec(&id, "test ! -e /workspace/removed.txt").await?;
                }
                let mut ready = false;
                for _ in 0..120 {
                    if let Ok(reply) = client.get(format!("http://127.0.0.1:{port}")).send().await {
                        if reply.text().await.unwrap_or_default().contains(expected) {
                            ready = true;
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                if !ready {
                    let logs = call("get_environment_logs", json!({"environmentId":id})).await?;
                    return Err(format!("Project did not serve {expected}: {logs}"));
                }
            }
            // Public host validation through the actual in-container proxy.
            let reply = client.get(format!("http://127.0.0.1:{port}")).header("Host", "test.example.com").send().await.map_err(|e| e.to_string())?;
            assert_eq!(reply.status(), 200);
            assert!(reply.text().await.unwrap_or_default().contains("second"));
            // Verify a real, temporary Cloudflare quick link as part of explicit live tests.
            let publication = call("publish_environment_service", json!({"environmentId":id,"port":live::proxy_port(setup.guest_port),"kind":"cloudflare"})).await?;
            let url = publication["urls"].as_array().and_then(|xs| xs.first()).and_then(Value::as_str).ok_or("Quick link returned no URL")?;
            let mut public_ready = false;
            for _ in 0..30 {
                if let Ok(reply) = client.get(url).send().await {
                    if reply.status().is_success() && reply.text().await.unwrap_or_default().contains("second") { public_ready = true; break; }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if !public_ready { return Err("The temporary quick link did not serve the test project".into()); }
            live.close().await;
            call(
                "set_environment_status",
                json!({"environmentId":id,"status":"stopped"}),
            )
            .await?;
            let state = call("get_platform_state", json!({})).await?;
            assert!(state["environments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["id"] == id && e["status"] == "stopped"));
            Ok(())
        }
        .await;
        if let Some(id) = &setup.environment {
            if result.is_err() {
                eprintln!(
                    "Test logs: {:?}",
                    call("get_environment_logs", json!({"environmentId":id})).await
                );
            }
            let cleanup = call("delete_environment", json!({"environmentId":id})).await;
            assert!(
                cleanup.is_ok(),
                "Test container cleanup failed: {cleanup:?}"
            );
        }
        result.unwrap();
    }
    fn reviewed() -> Setup {
        Setup {
            command_reviewed: true,
            env_reviewed: true,
            sync_reviewed: true,
            sync_timing_reviewed: true,
            sync_priority: Some(sync::Priority::Local),
            ..Default::default()
        }
    }

    #[test]
    fn questions_ask_what_the_saved_setup_lacks_and_everything_with_change() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let asks = |questions: &Questions| [questions.command, questions.env, questions.timing, questions.direction, questions.priority];
        assert_eq!(asks(&Questions::new(folder.path(), &project, &reviewed(), false, false, None)), [false; 5]);
        assert_eq!(asks(&Questions::new(folder.path(), &project, &reviewed(), true, false, None)), [true, false, true, true, true], "no .env file to ask about");
        fs::write(folder.path().join(".env"), "KEY=value").unwrap();
        assert_eq!(asks(&Questions::new(folder.path(), &project, &Setup::default(), false, false, None)), [true; 5]);
        assert_eq!(asks(&Questions::new(folder.path(), &project, &reviewed(), true, true, None)), [true; 5]);
    }

    #[tokio::test]
    async fn questions_the_saved_setup_answers_ask_nothing() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"7"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let mut setup = reviewed();
        let mut questions = Questions::new(folder.path(), &project, &setup, false, false, None);
        for step in 0..8 {
            assert_eq!(questions.ask(step, &mut setup).await, Some(Ok(false)), "step {step}");
        }
        assert!(questions.ask(8, &mut setup).await.is_none());
        assert!(questions.bytes.is_none(), "nothing was measured");
    }

    #[tokio::test]
    async fn the_command_check_warns_once_however_often_going_back_runs_it() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"set NODE_ENV=development && vite"},"devDependencies":{"vite":"7"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let mut setup = reviewed();
        let mut questions = Questions::new(folder.path(), &project, &setup, false, false, None);
        assert_eq!(questions.ask(4, &mut setup).await, Some(Ok(false)), "a warning asks nothing");
        let warned = questions.warned.clone();
        assert!(warned.iter().any(|text| text.contains("`set NODE_ENV=development` is Windows cmd syntax")), "{warned:?}");
        // Back past the check and forward again checks the command again without repeating it.
        assert_eq!(questions.ask(4, &mut setup).await, Some(Ok(false)));
        assert_eq!(questions.warned, warned);
    }

    #[tokio::test]
    async fn a_port_given_for_another_command_applies_only_while_that_command_is_chosen() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let mut questions = Questions::new(folder.path(), &project, &Setup::default(), false, false, None);
        // The port was given for a custom command; going back, the project's own command was chosen.
        questions.command_port = Some(8080);
        let mut setup = Setup { guest_port: 5173, ..Default::default() };
        assert_eq!(questions.ask(2, &mut setup).await, Some(Ok(false)), "no port question without a command of their own");
        questions.finish(&mut setup);
        assert_eq!(setup.guest_port, 5173);
        setup.custom_command = Some("node server.js".into());
        questions.finish(&mut setup);
        assert_eq!(setup.guest_port, 8080);
    }

    #[test]
    fn going_back_to_the_command_check_asks_about_the_same_command_again() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let mut questions = Questions::new(folder.path(), &project, &Setup::default(), false, false, None);
        let review = || Review { before: (Some("npm run production".into()), None, false), after: Some("npm run dev:full".into()), picked: 1 };
        // The check replaced a Windows-only command with the second suggestion.
        let mut setup = Setup { custom_command: Some("npm run dev:full".into()), command_reviewed: true, ..Default::default() };
        questions.review = Some(review());
        assert_eq!(questions.reopen(&mut setup), 1);
        assert_eq!(setup.custom_command.as_deref(), Some("npm run production"));
        assert!(!setup.command_reviewed);
        assert!(questions.review.is_none());
        // A command an earlier answer changed is checked afresh.
        let mut setup = Setup { custom_command: Some("npm start".into()), ..Default::default() };
        questions.review = Some(review());
        assert_eq!(questions.reopen(&mut setup), 0);
        assert_eq!(setup.custom_command.as_deref(), Some("npm start"));
        assert_eq!(questions.reopen(&mut setup), 0, "nothing to reopen");
    }

    #[test]
    fn resource_answers_become_the_setup_and_recommended_keeps_custom_answers_for_later() {
        let mut settings = Settings {
            drives: None,
            host: json!({}),
            storage: 6,
            note: Vec::new(),
            suggested: [2, 4, 6],
            app_port: 3000,
            environment: None,
            drive: Some("D:\\".into()),
            recommended: false,
            gpu: true,
            allocation: [8, 16, 40],
            guest_port: 5173,
            local_port: Some(8080),
            network: None,
        };
        let mut setup = Setup::default();
        settings.apply(&mut setup);
        assert!(setup.gpu);
        assert_eq!((setup.allocation, setup.guest_port, setup.local_port), ([8, 16, 40], 5173, 8080));
        assert_eq!(setup.storage_drive.as_deref(), Some("D:\\"));
        // Going back to choose Recommended keeps the custom answers for another change of mind.
        settings.recommended = true;
        settings.apply(&mut setup);
        assert!(!setup.gpu);
        assert_eq!((setup.allocation, setup.guest_port, setup.local_port), ([2, 4, 6], 3000, 3000));
        assert_eq!((settings.allocation, settings.guest_port), ([8, 16, 40], 5173));
        // Before its question, the local port follows the dev server's port.
        settings.recommended = false;
        settings.local_port = None;
        settings.apply(&mut setup);
        assert_eq!(setup.local_port, 5173);
    }

    #[tokio::test]
    async fn ctrl_c_stops_waiting_at_once_and_leaving_a_question_stops_the_launch() {
        let stop = Stop::new();
        assert_eq!(stop.until(async { Ok::<_, String>(7) }).await, Ok(7));
        let flag = stop.flag.clone();
        let started = std::time::Instant::now();
        let waiting = stop.until(async {
            flag.store(true, Ordering::SeqCst);
            std::future::pending::<Result<(), String>>().await
        });
        assert_eq!(waiting.await, Err("Launch cancelled.".into()));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(stop.until(async { Ok::<_, String>(()) }).await.is_err(), "nothing new starts once stopped");
        let mut stop = Stop::new();
        assert_eq!(stop.ask(|| Ok::<_, String>(1)), Ok(1));
        assert!(!stop.requested());
        assert_eq!(stop.ask(|| Err::<(), _>(ui::CANCELLED.to_string())), Err(ui::CANCELLED.into()));
        assert!(stop.requested(), "leaving a question in the middle of a launch stops it");
    }

    #[test]
    fn a_held_ctrl_c_never_quits_at_once_and_a_new_press_does() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let stopping = AtomicBool::new(false);
        let mut presses = ui::Presses::new(false);
        assert!(!quits(&stopping, &mut presses, at(0)));
        assert!(stopping.load(Ordering::SeqCst), "the first Ctrl+C stops the launch");
        // Held down, the key repeats after a pause, then quickly, for seconds.
        for ms in (500..4000).step_by(35) {
            assert!(!quits(&stopping, &mut presses, at(ms)), "repeat at {ms} ms");
        }
        // Let go, then pressed again.
        assert!(quits(&stopping, &mut presses, at(4400)));
        // The key watcher or a question stopped the launch: a signal right after that may still
        // be the same key held down; a new press quits.
        let stopping = AtomicBool::new(true);
        let mut presses = ui::Presses::new(false);
        assert!(!quits(&stopping, &mut presses, at(0)));
        assert!(!quits(&stopping, &mut presses, at(40)));
        assert!(quits(&stopping, &mut presses, at(1500)));
    }

    #[test]
    fn a_launch_stopped_part_way_exits_130_and_quitting_the_project_exits_0() {
        assert_eq!(ended(Ok(()), false), Ok(0));
        // Ctrl+C in the running project's view quits it, as q does.
        assert_eq!(ended(Ok(()), true), Ok(0));
        assert_eq!(ended(Err("Launch cancelled.".into()), true), Ok(130));
        assert_eq!(ended(Err(ui::CANCELLED.into()), true), Ok(130), "left a question in the middle of the launch");
        assert_eq!(ended(Err("Copy failed".into()), false), Err("Copy failed".into()));
    }

    #[test]
    fn a_container_whose_first_launch_stopped_early_waits_when_started_instead_of_failing() {
        assert!(NODE_AUTOSTART.ends_with(BOOT), "without the helpers it waits as a new container does");
        let bash = if cfg!(windows) { "C:/Program Files/Git/bin/bash.exe" } else { "bash" };
        // Waiting ends when the container stops; here the first wait asks for that itself.
        let fixture = r#"
root=$(mktemp -d)
script=${AUTOSTART//\/yougori\/launch/$root}
start() { bash --noprofile --norc -c "sleep() { echo waiting; kill -TERM \$\$; }; $script"; echo "exit $?"; }
start
printf 'echo dev server; exit 3\n' > "$root/dev.sh"
start
rm -rf "$root"
"#;
        let output = std::process::Command::new(bash).args(["--noprofile", "--norc", "-c", fixture]).env("AUTOSTART", NODE_AUTOSTART)
            .output().expect("Bash is required for the startup command test");
        assert_eq!(String::from_utf8_lossy(&output.stdout), "waiting\nexit 0\ndev server\nexit 3\n", "{}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn detects_only_address_conflicts_for_port_recovery() {
        assert!(port_in_use(
            "publish_environment_service: Cannot bind host port: Only one usage (os error 10048)"
        ));
        assert!(port_in_use(
            "Cannot bind host port: Address already in use (os error 98)"
        ));
        assert!(port_in_use(
            "Cannot bind host port: Address already in use (os error 48)"
        ));
        assert!(!port_in_use(
            "Cannot bind host port: Permission denied (os error 13)"
        ));
        assert!(!port_in_use(
            "Cannot bind host port: Network is unreachable"
        ));
        assert!(!port_in_use("other operation: os error 10048"));
    }

    #[test]
    fn automatic_local_port_omits_host_port_for_cli_validation() {
        let automatic = local_publication_params("env-test", "lan", 3000, 0);
        assert!(automatic.get("hostPort").is_none());
        crate::catalog::find("publish_environment_service")
            .unwrap()
            .validate(&automatic)
            .unwrap();
        let fixed = local_publication_params("env-test", "lan", 3000, 5281);
        assert_eq!(fixed["hostPort"], 5281);
        crate::catalog::find("publish_environment_service")
            .unwrap()
            .validate(&fixed)
            .unwrap();
    }

    #[test]
    fn this_computer_publishes_on_loopback_and_other_choices_on_the_local_network() {
        let port = live::proxy_port(3000);
        for (network, kind) in [
            ("computer", "loopback"),
            ("lan", "local"),
            ("quick", "local"),
            ("domain", "local"),
        ] {
            let params = local_publication_params("env-test", network, 3000, 5281);
            assert_eq!(
                params,
                json!({"environmentId":"env-test","port":port,"kind":kind,"hostPort":5281}),
                "{network}"
            );
            crate::catalog::find("publish_environment_service")
                .unwrap()
                .validate(&params)
                .unwrap();
        }
        let publication = |id: &str, kind: &str, port: u16, host_port: u16| {
            json!({"id":id,"kind":kind,"port":port,"hostPort":host_port})
        };
        // A saved "This computer" project replaces its network-reachable publication and keeps its port.
        let computer = local_publication_params("env-test", "computer", 3000, 5281);
        let existing = [
            publication("pub-lan", "local", port, 5281),
            publication("pub-other-port", "local", port + 1, 5282),
            publication("pub-quick", "cloudflare", port, 45001),
        ];
        assert_eq!(
            local_replacements(&existing, computer.clone()),
            (vec!["pub-lan".to_string()], computer.clone())
        );
        // Launching again keeps its own publication.
        let current = [publication("pub-computer", "loopback", port, 5281)];
        assert_eq!(local_replacements(&current, computer.clone()), (vec![], computer));
        // Local network replaces the loopback one, and leaves the port to the engine
        // when a tunnel still shares that listener.
        let lan = local_publication_params("env-test", "lan", 3000, 5281);
        assert_eq!(
            local_replacements(&current, lan.clone()),
            (vec!["pub-computer".to_string()], lan.clone())
        );
        let shared = [current[0].clone(), publication("pub-domain", "cloudflare", port, 5281)];
        assert_eq!(
            local_replacements(&shared, lan),
            (
                vec!["pub-computer".to_string()],
                local_publication_params("env-test", "lan", 3000, 0)
            )
        );
    }

    #[test]
    fn this_computer_and_local_network_remove_an_earlier_public_link() {
        let port = live::proxy_port(3000);
        let publication = |id: &str, environment: &str, kind: &str, port: u16, status: &str| {
            json!({"id":id,"environmentId":environment,"kind":kind,"port":port,"status":status})
        };
        let publications = [
            publication("pub-quick", "env-test", "cloudflare", port, "active"),
            // A saved domain whose node is stopped still comes back when the engine restarts.
            publication("pub-domain", "env-test", "cloudflare", port, "stopped"),
            publication("pub-local", "env-test", "local", port, "active"),
            publication("pub-loopback", "env-test", "loopback", port, "active"),
            publication("pub-other-port", "env-test", "cloudflare", port + 1, "active"),
            publication("pub-other-node", "env-other", "cloudflare", port, "active"),
        ];
        assert_eq!(
            public_routes(&publications, "env-test", port),
            ["pub-quick", "pub-domain"]
        );
        assert!(public_routes(&publications[2..], "env-test", port).is_empty());
    }

    #[test]
    fn copy_storage_recovery_checks_errors_and_available_capacity() {
        assert!(copy_storage_full(
            "Copy incomplete: disk quota exceeded (job xyz)"
        ));
        assert!(copy_storage_full("write: No space left on device"));
        assert!(!copy_storage_full("Permission denied"));
        assert!(!copy_storage_full("Connection timed out"));
        assert_eq!(
            growth_limits(&json!({"capacityGb":2,"maximumGb":8.9})).unwrap(),
            (2, 8)
        );
        assert!(growth_limits(&json!({"capacityGb":8,"maximumGb":8})).is_err());
        assert!(growth_limits(&json!({})).is_err());
        assert_eq!(
            growth_limits(&json!({"capacityGb":2,"maximumGb":20000})).unwrap(),
            (2, 16380)
        );
    }

    #[test]
    fn a_storage_limit_outside_its_range_is_explained_where_it_was_typed() {
        assert_eq!(storage_limit(" 12 ", 8, 40), Ok(12));
        assert_eq!(storage_limit("40", 8, 40), Ok(40));
        for entry in ["8", "41", "0", "-3", "12.5", "twelve", ""] {
            assert_eq!(storage_limit(entry, 8, 40), Err("Enter a whole number from 9 to 40.".into()), "{entry}");
        }
    }

    #[test]
    fn a_package_json_that_cannot_be_read_is_named_with_what_was_being_done() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(source.path()).unwrap();
        // A folder where package.json cannot be read as a file.
        let folder = tempfile::tempdir().unwrap();
        fs::create_dir(folder.path().join("package.json")).unwrap();
        let error = add_project_shortcut(folder.path(), &project).unwrap_err();
        assert!(error.starts_with("Could not read package.json to add the Yougori shortcuts ("), "{error}");
        // The launch goes on: this only warns.
        shortcut_or_warn(folder.path(), &project);
    }

    /// PROVES that clearing abandoned imports keeps the one /workspace links into, and that a
    /// workspace that cannot be listed is never taken for an empty one.
    ///
    /// /workspace links to `<import>/project/workspace`, and the keep-check compared the link with
    /// `<import>/project`, so it could never match: every import was removed, the one in use
    /// included, whenever the cleanup ran. It runs whenever the probe reads the workspace as
    /// empty, and the probe read a failing `ls -A` as empty. Either half was enough to remove the
    /// container's copy of the project, with any work in it that had not synced back yet.
    ///
    /// The scripts run under `sh`, with the container's paths moved into a temporary folder. The
    /// link itself is stood in for, because not every computer that runs these tests can make one.
    #[test]
    fn clearing_imports_keeps_the_one_in_use_and_an_unlisted_workspace_is_not_empty() {
        let root = tempfile::tempdir().unwrap();
        let unix = |path: &Path| path.to_string_lossy().replace('\\', "/");
        let (imports, workspace) = (root.path().join("imports"), root.path().join("workspace"));
        let moved = |script: &str| script.replace("/yougori/launch/imports", &unix(&imports)).replace("/workspace", &unix(&workspace));
        let sh = |script: String| std::process::Command::new("sh").arg("-c").arg(script).output();
        for import in ["yougori-import-live", "yougori-import-old"] {
            fs::create_dir_all(imports.join(import).join("project/workspace")).unwrap();
            fs::write(imports.join(import).join("project/workspace/app.js"), "work").unwrap();
        }
        let live = format!("{}/yougori-import-live/project/workspace", unix(&imports));
        let Ok(cleared) = sh(format!("set -eu\nactive='{live}'\n{}", moved(REMOVE_ABANDONED))) else {
            eprintln!("skipped: this computer has no sh to run the container's scripts with");
            return;
        };
        assert!(cleared.status.success(), "{}", String::from_utf8_lossy(&cleared.stderr));
        assert!(imports.join("yougori-import-live/project/workspace/app.js").exists(), "the import in use is kept, with the work in it");
        assert!(!imports.join("yougori-import-old").exists(), "an abandoned import is removed");
        assert!(ACTIVE_IMPORT.contains("readlink /workspace") && clean_imports().contains(ACTIVE_IMPORT) && clean_imports().contains(REMOVE_ABANDONED));

        let probe = |script: String| {
            let output = sh(script).unwrap();
            (output.status.success(), String::from_utf8_lossy(&output.stdout).into_owned())
        };
        assert_eq!(probe(moved(WORKSPACE_PROBE)), (true, "missing".to_owned()));
        fs::create_dir(&workspace).unwrap();
        assert_eq!(probe(moved(WORKSPACE_PROBE)), (true, "empty".to_owned()));
        fs::write(workspace.join("app.js"), "work").unwrap();
        assert_eq!(probe(moved(WORKSPACE_PROBE)), (true, "existing".to_owned()));
        // A listing that fails is a failure, never an empty workspace.
        let failing = moved(WORKSPACE_PROBE).replace("ls -A ", "ls -A /no/such/folder ");
        assert_ne!(failing, moved(WORKSPACE_PROBE));
        assert!(!probe(failing).0, "a workspace that cannot be listed is not called empty");
        assert_eq!(needs_copy("existing"), Ok(false));
        assert_eq!((needs_copy("empty"), needs_copy("missing")), (Ok(true), Ok(true)));
        assert!(needs_copy("").is_err(), "no answer is not an empty workspace");
    }

    #[test]
    fn flags_ports_and_startup_are_project_specific() {
        assert!(changed(&["launch".into(), "-change".into()], None).unwrap());
        assert!(changed(&["launch".into()], Some("true")).unwrap());
        assert!(changed(&["launch".into(), "nginx".into()], None).is_err());
        let p = json!({"scripts":{"dev":"vite --port 4000"}});
        assert!(install_script("/etc", &p, &[]).is_err());
        assert!(install_script("/yougori/launch/imports/../../etc", &p, &[]).is_err());
        let script = install_script("/yougori/launch/imports/yougori-import-1", &p, &["server".into(), "../x".into()]).unwrap();
        assert!(script.contains("mv '/workspace/server/node_modules' '/yougori/launch/imports/yougori-import-1/project/workspace/server'/node_modules"));
        assert!(!script.contains("../x"), "package folders never leave the copy");
    }
    #[test]
    fn custom_commands_accept_shell_syntax_but_reject_empty_and_control_characters() {
        assert_eq!(validate_command("  npm run build && npm start  ").unwrap(), "npm run build && npm start");
        assert!(validate_command("  ").is_err());
        assert!(validate_command("npm run dev\nwhoami").is_err());
        assert!(validate_command("node\0server.js").is_err());
    }
    #[test]
    fn menu_registration_adds_shortcuts_without_launching_and_tolerates_invalid_projects() {
        let dir = tempfile::tempdir().unwrap();
        prepare_project_shortcut(dir.path());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let path = dir.path().join("package.json");
        fs::write(&path, r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        prepare_project_shortcut(dir.path());
        let registered = fs::read_to_string(&path).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&registered).unwrap()["scripts"]["yougori"], "yougori launch");
        assert_eq!(serde_json::from_str::<Value>(&registered).unwrap()["scripts"]["yougori-change"], "yougori launch --change");
        prepare_project_shortcut(dir.path());
        assert_eq!(fs::read_to_string(&path).unwrap(), registered);
        fs::write(&path, r#"{"scripts":{"dev":"vite","yougori-change":"custom settings"}}"#).unwrap();
        prepare_project_shortcut(dir.path());
        assert_eq!(serde_json::from_str::<Value>(&fs::read_to_string(&path).unwrap()).unwrap()["scripts"]["yougori-change"], "custom settings");
        fs::write(&path, "invalid json").unwrap();
        prepare_project_shortcut(dir.path());
        assert_eq!(fs::read_to_string(&path).unwrap(), "invalid json");
        let python = tempfile::tempdir().unwrap();
        fs::write(python.path().join("main.py"), "print('hello')").unwrap();
        prepare_project_shortcut(python.path());
        assert!(python.path().join("yougori").is_file());
        assert_eq!(fs::read_dir(python.path()).unwrap().count(), 2);
    }

    #[test]
    fn python_shortcut_is_idempotent_and_preserves_conflicting_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.py"), "print('hello')").unwrap();
        let project = package::Project::load(dir.path()).unwrap();
        add_project_shortcut(dir.path(), &project).unwrap();
        let content = fs::read(dir.path().join("yougori")).unwrap();
        add_project_shortcut(dir.path(), &project).unwrap();
        assert_eq!(fs::read(dir.path().join("yougori")).unwrap(), content);
        fs::write(dir.path().join("yougori"), "user content").unwrap();
        add_project_shortcut(dir.path(), &project).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join("yougori")).unwrap(), "user content");
        assert!(!dir.path().join("package.json").exists());
    }

    #[test]
    fn project_files_are_replaced_whole_or_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::write(&path, "{}\n").unwrap();
        assert!(write_atomically(&path, Some("{}\n"), "{\"scripts\":{}}\n").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"scripts\":{}}\n");
        // Another program saved the file after it was read: its version stays.
        assert!(!write_atomically(&path, Some("{}\n"), "lost edit").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"scripts\":{}}\n");
        assert!(!write_atomically(&path, None, "x").unwrap());
        // No temporary files are left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn state_is_directory_bound_and_npm_script_preserves_existing_commands() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"vite","yougori":"custom"}}"#,
        )
        .unwrap();
        add_project_shortcut(
            dir.path(),
            &package::Project::load(dir.path()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            package::Project::load(dir.path()).unwrap().package["scripts"]["yougori"],
            "custom"
        );
        let setup = Setup {
            version: 1,
            directory: dir.path().to_string_lossy().into(),
            environment: Some("env-test".into()),
            gpu: false,
            allocation: [2, 4, 10],
            storage_drive: Some("D:\\".into()),
            guest_port: 3000,
            local_port: 3000,
            network: "computer".into(),
            domain: None,
            needs_update: false,
            env_files: false,
            env_reviewed: false,
            custom_command: Some("npm run build && npm start".into()),
            command_reviewed: true,
            two_way: false,
            sync_reviewed: true,
            sync_priority: Some(sync::Priority::Remote),
            continuous_sync: true,
            sync_timing_reviewed: true,
            accepted_command: None,
        };
        let path = dir.path().join("state.json");
        save(&path, &setup).unwrap();
        save(&path, &setup).unwrap();
        assert_eq!(
            load(&path, dir.path()).unwrap().unwrap().environment,
            setup.environment
        );
        assert!(load(&path, other.path()).is_err());
        let saved = load(&path, dir.path()).unwrap().unwrap();
        assert_eq!(saved.custom_command, setup.custom_command);
        assert!(saved.command_reviewed);
        assert_eq!(saved.sync_priority, Some(sync::Priority::Remote));
        assert!(saved.continuous_sync);
        assert!(saved.sync_timing_reviewed);
        assert_eq!(saved.storage_drive, Some("D:\\".into()));
        let mut legacy = serde_json::to_value(&setup).unwrap();
        legacy.as_object_mut().unwrap().remove("custom_command");
        legacy.as_object_mut().unwrap().remove("storage_drive");
        legacy.as_object_mut().unwrap().remove("command_reviewed");
        legacy.as_object_mut().unwrap().remove("two_way");
        legacy.as_object_mut().unwrap().remove("sync_reviewed");
        legacy.as_object_mut().unwrap().remove("sync_priority");
        legacy.as_object_mut().unwrap().remove("continuous_sync");
        legacy.as_object_mut().unwrap().remove("sync_timing_reviewed");
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let legacy = load(&path, dir.path()).unwrap().unwrap();
        assert!(legacy.custom_command.is_none());
        assert!(!legacy.command_reviewed);
        assert!(!legacy.two_way);
        assert!(!legacy.sync_reviewed);
        assert!(legacy.sync_priority.is_none());
        assert!(!legacy.continuous_sync, "existing projects must migrate to on-demand sync");
        assert!(!legacy.sync_timing_reviewed);
        assert!(legacy.storage_drive.is_none());
        assert_eq!(
            directory_key(dir.path()).unwrap(),
            directory_key(&dir.path().join(".")).unwrap()
        );
        let request =
            creation_request(&setup, &directory_key(dir.path()).unwrap(), dir.path()).unwrap();
        assert_eq!(request["containerCommand"], BOOT);
        assert_eq!(request["storageDrive"], "D:\\");
        assert_eq!(request["runtime"], "docker.io/library/node:24-bookworm");
        assert_eq!(
            request["name"],
            dir.path().file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(
            project_name(Path::new("parent/My Website")).unwrap(),
            "My Website"
        );
        let others = vec![json!({"id":"other","name":"My Website"})];
        assert_eq!(
            available_name("My Website", &others, None),
            "My Website (2)"
        );
        assert_eq!(
            available_name("My Website", &others, Some("other")),
            "My Website"
        );
    }
}
