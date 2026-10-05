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
const NODE_AUTOSTART: &str = "exec bash /yougori/launch/dev.sh";
const HINT: &str = "yougori launch starts this project again · yougori launch --change edits settings · yougori opens the menu";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Setup {
    version: u32,
    directory: String,
    environment: Option<String>,
    gpu: bool,
    allocation: [u32; 3],
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
    let Some(saved) = saved else { return Ok(None) };
    let environments = state["environments"].as_array().ok_or("Missing environment list; saved settings were kept")?;
    let marker = format!("Yougori launch · {key}");
    let node = environments.iter().find(|node| match &saved.environment {
        Some(id) => node["id"] == *id,
        None => node["description"] == marker,
    });
    match node {
        Some(node) if node["description"] == marker && node["kind"] == "container" => Ok(Some(saved)),
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
    let checking = ui::task("Checking project changes");
    let source = folder.to_owned();
    let offer = tokio::task::spawn_blocking(move || {
        entry_offer(&source, &yougori_cli::launcher_state::directory()?)
    }).await.map_err(|e| format!("Cannot check this project: {e}"))?;
    checking.clear();
    let Some(offer) = offer? else { return Ok(()) };
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
    let selected = ui::select(
        "Do you want to run this project?",
        &[detail],
        &[
            ui::Choice::new(run, "inside its Yougori container"),
            ui::Choice::new("Continue to main menu", ""),
        ],
        1,
    );
    match selected {
        Ok(0) => { run_in(folder, false).await?; }
        Err(e) if e != ui::CANCELLED => return Err(e),
        _ => {},
    }
    Ok(())
}

fn write_project_shortcut(folder: &Path, project: &package::Project, quiet: bool) -> Result<(), String> {
    if project.is_python() {
        use std::io::Write;
        let content = include_str!("assets/python-yougori.py");
        let path = folder.join("yougori");
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
                if !quiet { ui::step("Added python yougori to this project"); }
            },
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !quiet && fs::read_to_string(&path).ok().as_deref() != Some(content) {
                    ui::warn("An existing file named yougori was kept. Run this project with yougori launch.");
                }
            },
            Err(e) => return Err(format!("Cannot add the Python shortcut: {e}")),
        }
        return Ok(());
    }
    let path = folder.join("package.json");
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let local = package::add_launch_script(&text);
    let updated = local.as_deref().unwrap_or(&text);
    let cloud = package::add_cloud_script(updated);
    let updated = cloud.as_deref().unwrap_or(updated);
    let change = package::add_change_script(updated);
    if local.is_some() || cloud.is_some() || change.is_some() {
        fs::write(path, change.as_deref().unwrap_or(updated)).map_err(|e| e.to_string())?;
        if !quiet {
            if local.is_some() { ui::step(&format!("Added {} to package.json", project.shortcut())); }
            if cloud.is_some() { ui::step("Added npm run yougori-cloud to package.json"); }
            if change.is_some() { ui::step("Added npm run yougori-change to package.json"); }
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
        _ => Err("Usage: yougori launch [--change]. Run an image with yougori run IMAGE; run models with yougori run hf.co/OWNER/MODEL.".into()),
    }
}

fn recommended_storage(bytes: u64) -> Result<u32, String> {
    let gb = (u128::from(bytes) * 2).div_ceil(1_073_741_824).max(1);
    u32::try_from(gb).map_err(|_| "This project is too large to represent its recommended storage".into())
}

fn project_storage(folder: &Path) -> Result<(u64, u32), String> {
    // Measure every file the launcher can copy, including ignored data, dependencies and .env.
    // Only metadata is read; large databases do not need to be loaded or hashed.
    let files = sync::scan(folder, &sync::Filter::load(folder, true)?)?;
    let bytes = files.values().try_fold(0u64, |total, (size, _)| total.checked_add(*size))
        .ok_or("The project folder size is too large to measure")?;
    Ok((bytes, recommended_storage(bytes)?))
}

async fn configure(
    folder: &Path,
    _package: &Value,
    state: &Value,
    old: Option<&Setup>,
) -> Result<Setup, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("First launch and --change need an interactive terminal to choose project resources and access.".into());
    }
    let app_port = old.map_or(package::Project::load(folder)?.port, |s| s.guest_port);
    let measuring = ui::task("Measuring project folder for recommended storage");
    let source = folder.to_owned();
    let measured = tokio::task::spawn_blocking(move || project_storage(&source)).await
        .map_err(|e| format!("Cannot measure project folder: {e}"))?;
    measuring.clear();
    let (bytes, measured_storage) = measured?;
    // Existing disks can grow, but changing recommendations must never shrink them.
    let storage = measured_storage.max(old.map_or(1, |s| s.allocation[2]));
    let suggested = [2, 4, storage];
    let mut note = vec![format!("Project folder: {} · storage is 2× its size, rounded up to whole GB (minimum 1 GB).", ui::bytes(bytes))];
    if storage > measured_storage {
        note.push(format!("Keeping the existing {storage} GB storage; disks can only grow."));
    }
    let recommended = ui::select(
        "Choose project resources",
        &note,
        &[
            ui::Choice::new(
                "Recommended",
                format!("container · 2 CPU · 4 GB memory · {storage} GB storage"),
            ),
            ui::Choice::new("Customize", "GPU, resources and ports"),
        ],
        0,
    )? == 0;
    let gpu = !recommended
        && choose(
            "Run this project in",
            &[
                "Container — Linux".into(),
                "GPU container — NVIDIA".into(),
            ],
        )? == 1;
    let allocation = if recommended {
        suggested
    } else {
        resources(&state["host"], false, Some(old.map_or(suggested, |s| s.allocation)))?
    };
    let guest_port = if recommended {
        app_port
    } else {
        port("Port your dev server listens on", app_port)?
    };
    // Recommended selects resources; access is always an explicit choice
    // during first setup or --change, then saved for subsequent launches.
    let network = network(false, old.and_then(|s| s.environment.as_deref()), Some(live::proxy_port(guest_port))).await?;
    let local_port = if recommended {
        guest_port
    } else {
        local_port(old.map_or(guest_port, |s| s.local_port))?
    };
    let (kind, domain) = match network {
        Network::Computer => ("computer", None),
        Network::Lan => ("lan", None),
        Network::Quick => ("quick", None),
        Network::Domain(domain) => ("domain", Some(domain)),
        Network::NewDomain {
            hostname,
            token,
            host_port,
        } => {
            call(
                "add_saved_domain",
                json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest_port}),
            )
            .await?;
            ("domain", Some(hostname))
        }
    };
    Ok(Setup {
        version: 1,
        directory: folder.to_string_lossy().into(),
        environment: old.and_then(|s| s.environment.clone()),
        gpu,
        allocation,
        guest_port,
        local_port,
        network: kind.into(),
        domain,
        needs_update: old.is_some(),
        ..old.cloned().unwrap_or_default()
    })
}

fn choose_sync(setup: &mut Setup, change: bool, folder: &Path) -> Result<(), String> {
    if change || !setup.sync_timing_reviewed {
        let measuring = ui::task("Measuring project folder for sync recommendation");
        let (bytes, _) = project_storage(folder)?;
        measuring.clear();
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
    }
    if change || !setup.sync_reviewed {
        setup.two_way = ui::select(
            "Which directions can project changes sync?",
            &["Sync includes code, files, folders and supported SQLite database records. Two-way also brings container changes and deletions back to this computer. Your .env choice still applies.".into()],
            &[
                ui::Choice::new("One-way (default)", "this computer → environment"),
                ui::Choice::new("Two-way", "this computer ↔ environment"),
            ],
            usize::from(setup.two_way),
        )? == 1;
        setup.sync_reviewed = true;
    }
    if setup.two_way && (change || setup.sync_priority.is_none()) {
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
    }
    Ok(())
}

fn snapshot_progress(task: &ui::Task, progress: &Value) {
    if progress["phase"] == "files" {
        task.detail(&clean(progress["path"].as_str().unwrap_or("")));
        task.progress("Preparing project files", progress["done"].as_u64().unwrap_or(0), progress["total"].as_u64().unwrap_or(0), "files");
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

async fn stage_project(folder: &Path, manifest: &sync::Manifest, task: &ui::Task, cancel: &AtomicBool) -> Result<sync::Staged, String> {
    let (folder, manifest) = (folder.to_path_buf(), manifest.clone());
    let stopped = Arc::new(AtomicBool::new(false));
    let flag = stopped.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || sync::stage_progress(&folder, &manifest, |progress| {
        if flag.load(Ordering::Relaxed) { return Err("Project preparation cancelled; both copies kept".into()); }
        tx.send(progress.clone()).map_err(|_| "Project preparation cancelled".into())
    }));
    loop {
        if cancel.load(Ordering::Relaxed) { stopped.store(true, Ordering::Relaxed); }
        if let Some(progress) = rx.try_iter().last() { snapshot_progress(task, &progress); }
        if worker.is_finished() { return worker.await.map_err(|e| e.to_string())?; }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

fn choose_command(
    folder: &Path,
    project: &package::Project,
    previous: Option<&str>,
) -> Result<Option<String>, String> {
    let default = project.command_label();
    let commands = plan::run_choices(folder, project);
    if commands.is_empty() {
        return ui::input("How do you want to run it? Enter your app's command", previous.unwrap_or(""), false, &validate_command).map(Some);
    }
    let mut choices: Vec<_> = commands.iter().map(|command| {
        ui::Choice::new(clean(&command.command), clean(&command.detail)).recommended(command.recommended)
    }).collect();
    choices.push(ui::Choice::new("Custom command", "Enter your own command"));
    let initial = previous.map_or(0, |previous| commands.iter().position(|command| command.command == previous).unwrap_or(commands.len()));
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
    if let Some(command) = commands.get(selected) {
        return Ok((command.command != default).then(|| command.command.clone()));
    }
    ui::input(
        "Run command",
        previous.unwrap_or(&default),
        false,
        &validate_command,
    ).map(Some)
}

/// Reads the run command before anything starts. What cannot work on Linux (Windows programs,
/// scripts that don't exist) is stopped here, with replacement commands from the project's own
/// scripts; everything else it notices is shown as a warning.
fn review_command(folder: &Path, project: &package::Project, setup: &mut Setup) -> Result<(), String> {
    let mut current = project.clone();
    for _ in 0..5 {
        current.custom_command = setup.custom_command.clone();
        let command = current.command_label();
        let check = plan::check(folder, &current, setup.env_files);
        let blocking: Vec<String> = check.findings.iter().filter(|f| f.blocking).map(|f| clean(&f.text)).collect();
        if blocking.is_empty() || setup.accepted_command.as_deref() == Some(command.as_str()) {
            for finding in &check.findings {
                ui::warn(&clean(&finding.text));
            }
            return Ok(());
        }
        let mut choices: Vec<ui::Choice> = check.alternatives.iter().map(|c| ui::Choice::new(clean(c), "from your project's scripts")).collect();
        choices.push(ui::Choice::new("Enter another command", ""));
        choices.push(ui::Choice::new(format!("Run {} anyway", clean(&command)), "it is likely to fail"));
        let picked = ui::select("This command can't run in the Linux container", &blocking, &choices, 0)?;
        setup.custom_command = Some(match picked {
            n if n < check.alternatives.len() => check.alternatives[n].clone(),
            n if n == check.alternatives.len() => ui::input("Run command", &command, false, &validate_command)?,
            _ => {
                setup.accepted_command = Some(command);
                return Ok(());
            }
        });
        setup.command_reviewed = true;
    }
    Ok(())
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
    cancel: &AtomicBool,
) -> Result<bool, String> {
    cancelled(cancel)?;
    let id = setup
        .environment
        .as_deref()
        .ok_or("Missing environment ID")?;
    let allocation = call("get_storage_allocation", json!({"environmentId":id})).await?;
    let (current, maximum) = growth_limits(&allocation)?;
    let note = format!(
        "  The project copy ran out of storage ({current} GB limit).
  Increase its storage to fit all project files.

"
    );
    if choose_with_note(
        "Container storage is full",
        &note,
        &[
            "Increase storage and retry copying".into(),
            "Cancel launch (keep the container)".into(),
        ],
    )? != 0
    {
        return Ok(false);
    }
    let suggested = current
        .saturating_mul(2)
        .max(current.saturating_add(2))
        .min(maximum);
    let capacity = loop {
        let input = text(
            &format!("New storage limit in GB · {}–{maximum}", current + 1),
            &suggested.to_string(),
            false,
        )?;
        if let Ok(value) = input.parse::<u32>() {
            if value > current && value <= maximum {
                break value;
            }
        }
    };
    cancelled(cancel)?;
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
const CLEAN_IMPORTS: &str = r#"set -eu
active=$(readlink /workspace 2>/dev/null || true)
for old in /yougori/launch/imports/yougori-import-*; do
  [ "$active" = "$old/project" ] || rm -rf -- "$old"
done"#;

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

fn local_publication_params(id: &str, guest_port: u16, host_port: u16) -> Value {
    let mut params = json!({"environmentId":id,"port":live::proxy_port(guest_port),"kind":"local"});
    if host_port != 0 {
        params["hostPort"] = json!(host_port);
    }
    params
}

async fn publish_local(
    setup: &mut Setup,
    state_path: &Path,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let id = setup
        .environment
        .as_deref()
        .ok_or("Missing environment ID")?;
    // Replace publications made by older launchers, which reached only this PC.
    let services = call("list_environment_services", json!({"environmentId":id})).await?;
    let mut replaced_loopback = false;
    for publication in services["publications"].as_array().into_iter().flatten() {
        if publication["kind"] == "loopback"
            && publication["port"] == live::proxy_port(setup.guest_port)
        {
            if let Some(publication_id) = publication["id"].as_str() {
                call(
                    "unpublish_environment_service",
                    json!({"publicationId":publication_id}),
                )
                .await?;
                replaced_loopback = true;
            }
        }
    }
    let params = local_publication_params(
        id,
        setup.guest_port,
        if replaced_loopback {
            0
        } else {
            setup.local_port
        },
    );
    let publication = match call("publish_environment_service", params.clone()).await {
        Ok(publication) => publication,
        Err(error) if port_in_use(&error) => {
            cancelled(cancel)?;
            let note = format!(
                "  Local port {} is already being used.
  Your project has been copied successfully.

",
                setup.local_port
            );
            if choose_with_note(
                "Choose another local port",
                &note,
                &[
                    "Use an available port and continue".into(),
                    "Cancel launch (keep the container)".into(),
                ],
            )? != 0
            {
                return Err(format!("Local port {} is in use. Stop the application using it or run yougori launch --change to choose another.", setup.local_port));
            }
            cancelled(cancel)?;
            // An omitted hostPort asks the engine to bind a free port atomically.
            let automatic = local_publication_params(id, setup.guest_port, 0);
            call("publish_environment_service", automatic).await?
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
    cancel: &AtomicBool,
) -> Result<live::Live, String> {
    let mut project = package::Project::load(folder)?;
    project.custom_command = setup.custom_command.clone();
    if let Some(root) = &project.workspace_root {
        return Err(format!("This package belongs to a workspace. Launch from {} so workspace dependencies are copied too.", root.display()));
    }
    let remembered = setup.environment.take();
    cancelled(cancel)?;
    let state = call("get_platform_state", json!({})).await?;
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
        return Err("This project's node was deleted during launch. Run the project again to choose fresh settings.".into());
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
        cancelled(cancel)?;
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
        let result = match call("run_workload", json!({"request":request,"start":false})).await {
            Ok(result) => result,
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
    cancelled(cancel)?;
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
    cancelled(cancel)?;
    let mut files = ui::task("Syncing project files");
    exec(id, "mkdir -p /yougori/launch/imports").await?;
    let filter = sync::Filter::load(folder, setup.env_files)?;
    let manifest = sync::scan(folder, &filter)?;
    let bytes: u64 = manifest.values().map(|(size, _)| size).sum();
    let total = format!(
        "{} files · {}",
        manifest.len(),
        ui::bytes(bytes)
    );
    files.detail(&total);
    let sync_path = state_path.with_extension("sync.json");
    let mut saved = sync::Saved::load(&sync_path);
    let remote_token = exec(id, "cat /yougori/launch/sync-token 2>/dev/null || true").await?;
    let id = id.to_owned();
    let installs = plan::installs(folder, &project, &manifest);
    let reconcile = saved.needs_reconcile(&id, &remote_token);
    // A missing checkpoint is not a missing workspace. Never replace an existing
    // project (and its runtime data) just to recover interrupted sync metadata.
    let copied = exec(&id, "if [ -d /workspace ] && [ -n \"$(ls -A /workspace)\" ]; then printf existing; fi").await?.trim() != "existing";
    let mut initial_databases = std::collections::BTreeSet::new();
    if copied {
        files.set("Copying project into the container");
        files.copy_status("Preparing project files");
        let staging = stage_project(folder, &manifest, &files, cancel).await?;
        let copy = loop {
            cancelled(cancel)?;
            exec(&id, CLEAN_IMPORTS).await?;
            files.copy_status("Waiting for copy progress");
            match public::call_with_progress("copy_files_to_environment", json!({"environmentId":id,"paths":[staging.path().join("project")],"destination":format!("{ROOT}/imports")}), |progress| files.copy_progress(progress)).await {
                Ok(copy) => break copy,
                Err(error) if copy_storage_full(&error) => {
                    if !offer_copy_storage(setup, state_path, cancel).await? { return Err("Project copy cancelled because storage is full.".into()); }
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
        saved.save(&sync_path)?;
    }
    let mut live =
        live::Live::prepare(&id, folder, &project, &manifest, setup.two_way, setup.guest_port, &sync_path, saved).await?;
    live.priority = setup.sync_priority.unwrap_or_default();
    live.env_files = setup.env_files;
    live.initial_databases = initial_databases;
    if !setup.two_way && !copied && reconcile {
        files.set("Comparing project files to resume sync");
        live.reconcile_one_way(&manifest).await?;
    }
    let changes = loop {
        let result = if setup.two_way { live.sync_both(setup.env_files).await } else { live.sync_to(manifest.clone()).await };
        match result {
            Err(error) if copy_storage_full(&error) => {
                if !offer_copy_storage(setup, state_path, cancel).await? {
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
        let domains = call("list_saved_domains", json!({})).await?;
        let host_port = domains
            .as_array()
            .into_iter()
            .flatten()
            .find(|domain| domain["hostname"] == *hostname)
            .and_then(|domain| domain["hostPort"].as_u64());
        if let Some(host_port) = host_port {
            let services = call("list_environment_services", json!({"environmentId":id})).await?;
            for publication in services["publications"].as_array().into_iter().flatten() {
                if publication["kind"] == "loopback"
                    && publication["hostPort"].as_u64() == Some(host_port)
                {
                    if let Some(publication_id) = publication["id"].as_str() {
                        call(
                            "unpublish_environment_service",
                            json!({"publicationId":publication_id}),
                        )
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
        let publication = domains::publish(params).await.map_err(|error| {
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
    }
    // The local publication serves this PC and devices on its local network.
    if domain_uses_local_port {
        // Port zero asks the engine to allocate a free localhost port atomically.
        setup.local_port = 0;
    }
    publish_local(setup, state_path, cancel).await?;
    publishing.done(&format!(
        "Published at {}",
        ui::paint(&format!("http://127.0.0.1:{}", setup.local_port), ui::SKY)
    ));
    for url in public {
        ui::info(&format!("public  {url}"));
    }
    cancelled(cancel)?;
    live.start().await?;
    ui::outro(&format!(
        "{} {}",
        ui::muted("$"),
        clean(&project.command_label())
    ));
    ui::line("");
    Ok(live)
}

pub(super) async fn run(args: &[String]) -> Result<i32, String> {
    if args.iter().any(|arg| arg == "--cloud") {
        let args: Vec<_> = args.iter().filter(|arg| arg.as_str() != "--cloud").cloned().collect();
        let change = changed(&args, std::env::var("npm_config_change").ok().as_deref())?;
        return cloud::run_in(&std::env::current_dir().map_err(|e| e.to_string())?, change).await;
    }
    let change = changed(args, std::env::var("npm_config_change").ok().as_deref())?;
    run_in(&std::env::current_dir().map_err(|e| e.to_string())?, change).await
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
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            flag.store(true, Ordering::Relaxed);
        }
    });
    let engine = ui::task("Starting Yougori engine");
    client::start(None).await?;
    engine.done("Engine ready");
    if cancel.load(Ordering::Relaxed) {
        ui::outro("Cancelled");
        return Ok(0);
    }
    let state = call("get_platform_state", json!({})).await?;
    let had_settings = existing.is_some();
    let existing = reconcile_saved_setup(&path, &key, existing, &state)?;
    if had_settings && existing.is_none() {
        ui::step("Previous node no longer exists — setting up this project again");
    }
    let mut setup = if change || existing.is_none() {
        configure(&folder, &package, &state, existing.as_ref()).await?
    } else {
        existing.unwrap()
    };
    if change || !setup.command_reviewed {
        setup.custom_command = choose_command(&folder, &project, setup.custom_command.as_deref())?;
        if setup.custom_command.is_some() {
            setup.guest_port = port("Port your application listens on", setup.guest_port)?;
        }
        setup.command_reviewed = true;
    }
    if sync::has_env_files(&folder) && (change || !setup.env_reviewed) {
        setup.env_reviewed = true;
        setup.env_files = choose_with_note(
            "Copy .env files into the container?",
            ".env files can contain credentials.",
            &[
                "Keep them on this computer".into(),
                "Copy them into this container — the dev server can read them".into(),
            ],
        )? == 1;
    }
    review_command(&folder, &project, &mut setup)?;
    choose_sync(&mut setup, change, &folder)?;
    add_project_shortcut(&folder, &project)?;
    save(&path, &setup)?;
    let result = async {
        let mut live = launch(&mut setup, &path, &folder, &package, &key, change, &cancel).await?;
        let result = live
            .watch(&name, setup.local_port, setup.env_files, setup.two_way, setup.continuous_sync, setup.gpu, &cancel)
            .await;
        if result.is_ok() && setup.continuous_sync {
            if let Err(error) = live.sync_current(setup.env_files, setup.two_way).await { ui::warn(&format!("Final sync incomplete: {}. Environment files are kept for the next launch.", clean(&error))); }
        }
        live.close().await;
        result
    }
    .await;
    let cleanup = if let Some(id) = setup.environment.as_deref() {
        let stopping = ui::task(&format!("Stopping {name}"));
        let stopped = call(
            "set_environment_status",
            json!({"environmentId":id,"status":"stopped"}),
        )
        .await;
        match &stopped {
            Ok(_) => stopping.done(&format!("Stopped {name}")),
            Err(_) => stopping.fail("Could not confirm the container stopped"),
        }
        match stopped {
            Ok(_) => match call("update_container_startup_command", json!({"environmentId":id,"command":NODE_AUTOSTART})).await {
                Ok(_) => Ok(()),
                Err(error) => Err(format!("The node stopped, but its website startup command could not be saved: {error}")),
            },
            Err(error) => Err(error),
        }
    } else {
        Ok(())
    };
    ui::outro(if project.is_python() { HINT } else { "npm run yougori starts this project again · npm run yougori-change edits settings · yougori opens the menu" });
    signal.abort();
    drop(lock);
    match (result, cleanup) {
        (_, Err(e)) => Err(format!("Could not confirm the project container stopped: {e}. Check yougori ps and stop it there.")),
        (Err(e), _) if !cancel.load(Ordering::Relaxed) => Err(e),
        _ => Ok(0),
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
        assert_eq!(project_storage(root.path()).unwrap(), (expected, 1));
        assert!(project_storage(&root.path().join("missing")).is_err());
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
        let cancel = AtomicBool::new(false);
        let result: Result<(), String> = async {
            let mut live = launch(
                &mut setup,
                &path,
                dir.path(),
                &package,
                &key,
                false,
                &cancel,
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
                        &cancel,
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
        let automatic = local_publication_params("env-test", 3000, 0);
        assert!(automatic.get("hostPort").is_none());
        crate::catalog::find("publish_environment_service")
            .unwrap()
            .validate(&automatic)
            .unwrap();
        let fixed = local_publication_params("env-test", 3000, 5281);
        assert_eq!(fixed["hostPort"], 5281);
        crate::catalog::find("publish_environment_service")
            .unwrap()
            .validate(&fixed)
            .unwrap();
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
        let mut legacy = serde_json::to_value(&setup).unwrap();
        legacy.as_object_mut().unwrap().remove("custom_command");
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
        assert_eq!(
            directory_key(dir.path()).unwrap(),
            directory_key(&dir.path().join(".")).unwrap()
        );
        let request =
            creation_request(&setup, &directory_key(dir.path()).unwrap(), dir.path()).unwrap();
        assert_eq!(request["containerCommand"], BOOT);
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
