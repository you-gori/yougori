//! Guided command paths. Dispatch through the same CLI validation and job handling
//! as scripted commands; never build a shell command from user input.
use super::*;
use std::path::{Path, PathBuf};

pub(super) fn activity_label(args: &[String]) -> &'static str {
    let first = args.first().map(String::as_str).unwrap_or("");
    let second = args.get(1).map(String::as_str).unwrap_or("");
    match (first, second) {
        ("rm", _) | ("env", "delete") => "Deleting environment and cleaning up its data",
        ("start", _) | ("env", "start") => "Starting environment",
        ("stop", _) | ("env", "stop") => "Stopping environment",
        ("restart", _) | ("env", "restart") => "Restarting environment",
        ("env", "create") => "Creating environment",
        ("env", "open") => "Opening environment",
        ("env", "resources") => "Updating CPU and memory",
        ("rename", _) => "Renaming environment",
        ("cp", _) => "Copying files",
        ("logs", _) => "Loading environment logs",
        ("snapshot", "create") => "Creating snapshot",
        ("snapshot", "restore") => "Restoring snapshot",
        ("snapshot", "delete") => "Deleting snapshot",
        ("backup", "export") => "Exporting backup",
        ("backup", "import") => "Importing backup",
        ("backup", "restore") => "Restoring backup",
        ("storage", "prune") => "Reclaiming storage",
        ("storage", "location") => "Updating storage location",
        ("gpu", "setup") => "Installing GPU runtime",
        ("share", "add") => "Sharing folder",
        ("app", "quit") => "Stopping Yougori and its workloads",
        ("app", "show") => "Opening Yougori desktop",
        ("app", "autostart") => "Loading startup settings",
        ("app", "start") => "Starting Yougori engine",
        ("update", _) => "Checking for updates",
        ("doctor", _) => "Checking Yougori",
        ("status" | "ps" | "inspect", _) => "Loading environment details",
        ("model", _) => "Loading model information",
        ("neocloud", "install") => "Installing provider CLI",
        ("neocloud", "prices") => "Checking GPU stock and prices",
        ("neocloud", _) => "Loading Neocloud information",
        _ => "Working",
    }
}

fn menu(title: &str, items: &[&str]) -> Result<usize, String> {
    choose(
        title,
        &items.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
    )
}

fn confirm(title: &str, detail: &str) -> Result<(), String> {
    if choose_with_note(title, detail, &["Cancel".into(), "Continue".into()])? == 1 {
        Ok(())
    } else {
        Err(ui::CANCELLED.into())
    }
}

async fn execute(args: &[&str]) -> Result<(), String> {
    if matches!(
        args.first(),
        Some(
            &"env"
                | &"share"
                | &"snapshot"
                | &"backup"
                | &"neocloud"
                | &"storage"
                | &"gpu"
                | &"connection"
                | &"remote"
                | &"lan"
                | &"domain"
                | &"download"
        )
    ) {
        let starting = ui::task("Connecting to Yougori engine");
        client::start(None).await?;
        starting.clear();
    }
    // Box the future because a command can itself open the model launcher.
    // Pause the painter while the normal CLI writes its result or live output.
    let args: Vec<String> = args.iter().map(|s| (*s).into()).collect();
    let interactive = super::requested(&args);
    if !interactive {
        ui::pause(true);
    }
    let result = Box::pin(crate::run(args)).await;
    if !interactive {
        ui::pause(false);
    }
    match result? {
        0 => Ok(()),
        130 => Err(ui::CANCELLED.into()),
        code => Err(format!(
            "The action finished with status {code}. See the result above."
        )),
    }
}

async fn state() -> Result<Value, String> {
    let loading = ui::task("Loading environments");
    client::start(None).await?;
    let state = call("get_platform_state", json!({})).await?;
    loading.clear();
    Ok(state)
}

fn select_record(title: &str, records: &[Value]) -> Result<Value, String> {
    if records.is_empty() {
        ui::info("Nothing here yet.");
        return Err(ui::CANCELLED.into());
    }
    let mut labels: Vec<String> = records
        .iter()
        .map(|v| {
            format!(
                "{} — {} · {}",
                v["name"].as_str().unwrap_or("Unnamed"),
                v["status"].as_str().unwrap_or("saved"),
                v["id"].as_str().unwrap_or("")
            )
        })
        .collect();
    labels.push("Back".into());
    let index = choose(title, &labels)?;
    records
        .get(index)
        .cloned()
        .ok_or_else(|| ui::CANCELLED.into())
}

async fn environment() -> Result<Value, String> {
    let state = state().await?;
    select_record(
        "Choose an environment",
        state["environments"]
            .as_array()
            .ok_or("Invalid environment list")?,
    )
}

fn id(record: &Value) -> Result<&str, String> {
    record["id"]
        .as_str()
        .ok_or_else(|| "This item has no ID. Refresh and try again.".into())
}

#[derive(Clone, Copy, PartialEq)]
enum PathKind {
    Folder,
    File,
    Either,
}

fn path_entries(folder: &Path, kind: PathKind) -> Result<Vec<PathBuf>, String> {
    let mut entries = Vec::new();
    for entry in
        std::fs::read_dir(folder).map_err(|e| format!("Cannot browse {}: {e}", folder.display()))?
    {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() || (kind != PathKind::Folder && path.is_file()) {
            entries.push(path);
        }
    }
    entries.sort_by_key(|p| {
        (
            !p.is_dir(),
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
        )
    });
    Ok(entries)
}

fn validate_path(entry: &str, kind: PathKind) -> Result<PathBuf, String> {
    let path = PathBuf::from(entry.trim().trim_matches('"'));
    if path.is_dir() || (kind != PathKind::Folder && path.is_file()) {
        Ok(path)
    } else {
        Err("Choose an existing, accessible file or folder of the requested type.".into())
    }
}

fn browse(title: &str, kind: PathKind) -> Result<PathBuf, String> {
    let mut folder = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        let entries = match path_entries(&folder, kind) {
            Ok(entries) => entries,
            Err(error) => {
                ui::warn(&clean(&error));
                Vec::new()
            }
        };
        let mut choices = vec![
            if kind == PathKind::File {
                "Choose a file below".into()
            } else {
                "Use this folder".into()
            },
            "Parent folder".into(),
            "Enter or paste a path — includes other drives".into(),
            "Back".into(),
        ];
        choices.extend(entries.iter().map(|p| {
            format!(
                "{} — {}",
                p.file_name().unwrap_or_default().to_string_lossy(),
                if p.is_dir() { "folder" } else { "file" }
            )
        }));
        match choose_with_note(title, &folder.display().to_string(), &choices)? {
            0 if kind != PathKind::File => return Ok(folder),
            0 => {}
            1 => {
                if let Some(parent) = folder.parent() {
                    folder = parent.into();
                }
            }
            2 => {
                let entry = ui::input("Path", "", false, &|s| {
                    validate_path(s, kind).map(|p| p.to_string_lossy().into_owned())
                })?;
                let path = validate_path(&entry, kind)?;
                if path.is_dir() {
                    folder = path;
                } else {
                    return Ok(path);
                }
            }
            3 => return Err(ui::CANCELLED.into()),
            index => {
                let path = entries[index - 4].clone();
                if path.is_dir() {
                    folder = path;
                } else {
                    return Ok(path);
                }
            }
        }
    }
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| "This path cannot be represented as text.".into())
}

fn create_args(
    kind: &str,
    name: &str,
    source: &str,
    allocation: [u32; 3],
    internet: bool,
    storage_drive: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = [
        "env",
        "create",
        "--kind",
        kind,
        "--name",
        name,
        if kind == "vm" { "--source" } else { "--image" },
        source,
        "--cpu",
        &allocation[0].to_string(),
        "--memory",
        &allocation[1].to_string(),
        "--storage",
        &allocation[2].to_string(),
        "--internet",
        if internet { "true" } else { "false" },
        "--yes",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect();
    if let Some(drive)=storage_drive {args.extend(["--storage-drive".into(),drive.into()]);}
    args
}

async fn create() -> Result<(), String> {
    let kind = match menu(
        "Create an environment",
        &[
            "Container — Linux workspace",
            "GPU container — NVIDIA CUDA",
            "MicroVM — lightweight virtual machine",
            "Virtual machine — choose an ISO or disk",
            "Back",
        ],
    )? {
        0 => "container",
        1 => "gpu",
        2 => "microvm",
        3 => "vm",
        _ => return Ok(()),
    };
    let name = text("Environment name", "", false)?;
    let source = if kind == "vm" {
        path_text(&browse("Choose an ISO or disk image", PathKind::File)?)?.to_owned()
    } else if kind == "microvm" {
        "builtin:alpine".into()
    } else {
        text(
            "Container image",
            if kind == "gpu" {
                "ubuntu:24.04"
            } else {
                "alpine:3.24"
            },
            false,
        )?
    };
    let host = call("refresh_host_metrics", json!({})).await?;
    let selected=super::storage::choose(&host["host"],None,if kind=="microvm" {6}else{1})?;
    let allocation = super::sliders(&selected.host, false, if kind=="microvm" {6}else{1}, None)?;
    let internet = menu("Internet access", &["Enabled", "Disabled"])? == 0;
    let mut args = create_args(kind, &name, &source, allocation, internet, selected.drive.as_deref());
    if matches!(kind, "container" | "gpu")
        && menu(
            "Container startup",
            &[
                "Keep workspace running — open it when needed",
                "Run the image's default service",
            ],
        )? == 1
    {
        args.extend(["--startup".into(), "image".into()]);
    }
    confirm(
        "Create environment?",
        &format!(
            "{} · {kind}\n{}\n{}\nStorage drive: {}\nInternet: {}",
            clean(&name),
            clean(&source),
            allocation_text(allocation),
            selected.label,
            if internet { "enabled" } else { "disabled" }
        ),
    )?;
    execute(&args.iter().map(String::as_str).collect::<Vec<_>>()).await?;
    let created = state().await?["environments"]
        .as_array()
        .and_then(|items| {
            items.iter().find(|env| {
                env["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name.trim()))
            })
        })
        .cloned()
        .ok_or("The created environment was not found. Open Manage an environment to refresh.")?;
    if kind == "vm" {
        if menu(
            "Open this environment now?",
            &["Open environment window", "Return to menu"],
        )? == 0 {
            execute(&["env", "open", id(&created)?]).await?;
        }
    } else if choose_with_note(
        "Open this environment now?",
        "Start it and use its shell in this terminal. Type exit or press Ctrl+] to return; the environment keeps running.",
        &["Start and open terminal here".into(), "Keep it stopped and return to menu".into()],
    )? == 0 {
        open_terminal_here(&created, true).await?;
    }
    Ok(())
}

fn terminal_needs_start(env: &Value) -> Result<bool, String> {
    if matches!(env["kind"].as_str(), Some("fullVm" | "computerBranch")) {
        return Err("This environment has no interactive guest terminal. Use Open environment window for its console.".into());
    }
    match env["status"].as_str() {
        Some("running") => Ok(false),
        Some("stopped" | "paused") => Ok(true),
        Some("error") => Err("Fix this environment's error before opening its terminal. Details shows the last error.".into()),
        _ => Err("Wait for this environment to finish its current action before opening its terminal.".into()),
    }
}

async fn open_terminal_here(env: &Value, start_authorized: bool) -> Result<(), String> {
    let env_id = id(env)?;
    if terminal_needs_start(env)? {
        if !start_authorized
            && choose_with_note(
                "Start and open this environment?",
                "Its shell will use this terminal. Exiting the shell leaves the environment running.",
                &["Start and open terminal here".into(), "Back".into()],
            )? != 0
        {
            return Ok(());
        }
        execute(&["start", env_id]).await?;
    }
    // execute pauses the menu painter and restores it after the PTY closes,
    // including errors. The shell owns this console, not a new desktop window.
    execute(&["terminal", env_id]).await
}

async fn manage() -> Result<(), String> {
    let env = environment().await?;
    let env_id = id(&env)?;
    let title = format!(
        "{} · {}",
        env["name"].as_str().unwrap_or("Environment"),
        env["status"].as_str().unwrap_or("unknown")
    );
    match menu(
        &clean(&title),
        &[
            "Details",
            "Start",
            "Stop",
            "Restart",
            "Open terminal here",
            "Open environment window",
            "Logs",
            "Rename",
            "Create snapshot",
            "Export backup",
            "Files and shared folders",
            "Published services",
            "Delete environment",
            "CPU and memory",
            "Publish a service",
            "Environment download link",
            "Back",
        ],
    )? {
        0 => execute(&["inspect", env_id]).await,
        1 => execute(&["start", env_id]).await,
        selected @ (2 | 3) => {
            let action = if selected == 2 { "stop" } else { "restart" };
            confirm(
                &format!("{action} {}?", clean(&title)),
                "Running work in this environment will be interrupted.",
            )?;
            execute(&[action, env_id]).await
        }
        4 => open_terminal_here(&env, false).await,
        5 => execute(&["env", "open", env_id]).await,
        6 => execute(&["logs", env_id]).await,
        7 => {
            let name = text("New name", env["name"].as_str().unwrap_or(""), false)?;
            execute(&["rename", env_id, &name]).await
        }
        8 => {
            let name = text("Snapshot name", "before-change", false)?;
            confirm("Create snapshot?", &clean(&title))?;
            execute(&["snapshot", "create", env_id, "--name", &name, "--yes"]).await
        }
        9 => {
            let folder = browse("Save backup in", PathKind::Folder)?;
            confirm(
                "Export backup?",
                &format!("{}\n{}", clean(&title), clean(path_text(&folder)?)),
            )?;
            execute(&[
                "backup",
                "export",
                env_id,
                "--folder",
                path_text(&folder)?,
                "--yes",
            ])
            .await
        }
        10 => files(env_id).await,
        11 => execute(&["ports", "list", env_id]).await,
        12 => {
            confirm(
                "Permanently delete this environment?",
                &format!(
                    "{}\nIts managed data will be permanently deleted.",
                    clean(&title)
                ),
            )?;
            execute(&["rm", env_id, "--yes"]).await
        }
        13 => {
            let host = state().await?;
            let slider = |key: &str, label, unit, maximum: u32| {
                let current = env["resourcePolicy"][key]["preferred"]
                    .as_f64()
                    .unwrap_or(2.0)
                    .ceil()
                    .max(1.0) as u32;
                let minimum = env["resourcePolicy"][key]["min"]
                    .as_f64()
                    .unwrap_or(1.0)
                    .ceil()
                    .max(1.0) as u32;
                ui::Slider {
                    label,
                    unit,
                    value: current.max(minimum),
                    min: minimum,
                    max: maximum.max(current).max(minimum),
                    default: current,
                }
            };
            let mut sliders = [
                slider(
                    "cpu",
                    "CPU",
                    "cores",
                    host["host"]["totalCpu"].as_u64().unwrap_or(2) as u32,
                ),
                slider(
                    "memoryGb",
                    "Memory",
                    "GB",
                    host["host"]["totalMemoryGb"]
                        .as_f64()
                        .unwrap_or(4.0)
                        .floor() as u32,
                ),
            ];
            ui::sliders("CPU and memory", "Changes preferred and maximum allocations; keeps storage and minimum reservations.", &mut sliders)?;
            let cpu = sliders[0].value.to_string();
            let memory = sliders[1].value.to_string();
            confirm(
                "Change CPU and memory limits?",
                &format!("{}\n{cpu} CPU · {memory} GB memory", clean(&title)),
            )?;
            execute(&[
                "env",
                "resources",
                env_id,
                "--cpu",
                &cpu,
                "--cpu-max",
                &cpu,
                "--memory",
                &memory,
                "--memory-max",
                &memory,
                "--yes",
            ])
            .await
        }
        14 => {
            let guest_port = port("Service port inside this environment", 3000)?;
            let access = network(false, Some(env_id), Some(guest_port)).await?;
            if let Some(params) = publish_params(&access, env_id, guest_port) {
                confirm("Publish this service?", &format!("{}\nPort {guest_port} will be accessible using the selected network or public link.", clean(&title)))?;
                let publishing = ui::task("Publishing service");
                if let Network::NewDomain {
                    hostname,
                    token,
                    host_port,
                } = &access
                {
                    call("add_saved_domain", json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest_port})).await?;
                }
                domains::publish(params).await?;
                publishing.done("Service published");
            }
            execute(&["ports", "list", env_id]).await
        }
        15 => download_link(&env).await,
        _ => Ok(()),
    }
}

async fn download_link(env: &Value) -> Result<(), String> {
    let env_id = id(env)?;
    let links = call("list_environment_downloads", json!({})).await?;
    let link = links.as_array().and_then(|items| items.iter().find(|item| item["environmentId"] == env_id));
    let count = link.and_then(|item| item["downloads"].as_u64()).unwrap_or(0);
    ui::info(&format!("Downloads (all time): {count}"));
    if link.is_some_and(|item| item["active"] == true) {
        ui::info(&format!("Download link: {}", link.unwrap()["url"].as_str().unwrap_or("")));
        if menu("Environment download link", &["Turn off download link", "Back"])? == 0 {
            execute(&["download", "off", env_id]).await?;
        }
        return Ok(());
    }
    let domains = super::domains::available(None, None).await?;
    let mut choices = vec![ui::Choice::new("Quick public link", "Temporary address")];
    choices.extend(domains.iter().map(|item| {
        let host = item.domain["hostname"].as_str().unwrap_or("");
        if links.as_array().is_some_and(|links| links.iter().any(|link| link["active"] == true && link["domain"] == host)) {
            ui::Choice::new(host, "In use by another download link").disabled()
        } else { item.choice() }
    }));
    choices.push(ui::Choice::new("Back", ""));
    let choice = ui::select("Download link address", &[], &choices, 0)?;
    if choice == choices.len() - 1 { return Ok(()); }
    confirm("Create a complete environment download?", "Anyone with the link can copy all files and credentials inside this environment. The link lasts while this CLI is open; Ctrl+C turns it off. The environment must be stopped for a consistent copy.")?;
    if env["status"] != "stopped" {
        if !matches!(env["status"].as_str(), Some("running" | "paused")) { return Err("Wait until this environment is ready before making a copy.".into()); }
        confirm("Stop this environment to prepare its copy?", "Running work will be interrupted. It stays stopped after creating the link.")?;
        execute(&["stop", env_id]).await?;
    }
    let mut args = vec!["download", "on", env_id, "--yes"];
    if choice > 0 { args.extend(["--domain", domains[choice - 1].domain["hostname"].as_str().ok_or("Invalid saved domain")?]); }
    execute(&args).await
}

async fn files(env: &str) -> Result<(), String> {
    match menu(
        "Files and shared folders",
        &[
            "Browse environment files",
            "Copy a PC file or folder into environment",
            "Copy from environment to PC",
            "View shared PC folders",
            "Share a PC folder",
            "Back",
        ],
    )? {
        0 => {
            browse_guest(env).await?;
            Ok(())
        }
        1 => {
            let path = browse("Choose a file or folder to copy", PathKind::Either)?;
            confirm(
                "Copy into environment?",
                &format!("{}\nDestination: {env}", clean(path_text(&path)?)),
            )?;
            execute(&["cp", path_text(&path)?, env]).await
        }
        2 => {
            let source = browse_guest(env).await?;
            let folder = browse("Choose a destination folder on this PC", PathKind::Folder)?;
            confirm(
                "Copy to this PC?",
                &format!("{}\n{}", clean(&source), clean(path_text(&folder)?)),
            )?;
            execute(&["cp", &format!("{env}:{source}"), path_text(&folder)?]).await
        }
        3 => execute(&["share", "list", env]).await,
        4 => {
            let folder = browse("Choose a PC folder to share", PathKind::Folder)?;
            let writable = menu("Folder access", &["Read only", "Read and write"])? == 1;
            confirm(
                "Share this folder?",
                &format!(
                    "{}\nEnvironment: {env}\n{}",
                    clean(path_text(&folder)?),
                    if writable {
                        "The environment can change files in this folder."
                    } else {
                        "The environment can read files in this folder."
                    }
                ),
            )?;
            execute(&[
                "share",
                "add",
                env,
                "--path",
                path_text(&folder)?,
                "--read-only",
                if writable { "false" } else { "true" },
                "--yes",
            ])
            .await
        }
        _ => Ok(()),
    }
}

fn guest_child(parent: &str, name: &str) -> Result<String, String> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err("The environment returned an invalid file name.".into());
    }
    Ok(format!("{}/{name}", parent.trim_end_matches('/')))
}

async fn browse_guest(env: &str) -> Result<String, String> {
    let mut path = String::new();
    loop {
        let loading = ui::task("Loading environment files");
        let result = call(
            "list_environment_folders",
            json!({"environmentId":env,"path":path}),
        )
        .await?;
        loading.clear();
        path = result["path"]
            .as_str()
            .ok_or("Invalid environment folder")?
            .into();
        let entries = result["entries"]
            .as_array()
            .ok_or("Invalid environment files")?;
        let mut choices = vec![
            "Use this folder".into(),
            "Parent folder".into(),
            "Back".into(),
        ];
        choices.extend(entries.iter().map(|e| {
            format!(
                "{} — {}",
                e["name"].as_str().unwrap_or("?"),
                if e["directory"] == true {
                    "folder"
                } else {
                    "file"
                }
            )
        }));
        match choose_with_note("Environment files", &path, &choices)? {
            0 => return Ok(path),
            1 => {
                path = path
                    .trim_end_matches('/')
                    .rsplit_once('/')
                    .map(|(p, _)| if p.is_empty() { "/" } else { p })
                    .unwrap_or("/")
                    .into()
            }
            2 => return Err(ui::CANCELLED.into()),
            index => {
                let entry = &entries[index - 3];
                let child = guest_child(&path, entry["name"].as_str().ok_or("Invalid file name")?)?;
                if entry["directory"] == true {
                    path = child;
                } else {
                    return Ok(child);
                }
            }
        }
    }
}

async fn models() -> Result<(), String> {
    let action = menu(
        "Models",
        &[
            "Run a Hugging Face model — guided GPU setup",
            "Chat with a model",
            "Model status",
            "Saved conversations",
            "API access",
            "Usage",
            "Back",
        ],
    )?;
    if action == 6 {
        return Ok(());
    }
    if action == 0 {
        let model = text("Hugging Face model (OWNER/MODEL or link)", "", false)?;
        return execute(&["run", &format!("hf.co/{}", public::model_name(&model))]).await;
    }
    let state = state().await?;
    let models: Vec<Value> = state["environments"]
        .as_array()
        .ok_or("Invalid environment list")?
        .iter()
        .filter(|v| {
            v["description"]
                .as_str()
                .is_some_and(|s| s.starts_with("Hugging Face · "))
        })
        .cloned()
        .collect();
    let env = select_record("Choose a model environment", &models)?;
    if action == 4 {
        confirm(
            "Show API credentials?",
            "The API key will be visible in this terminal.",
        )?;
    }
    execute(&[
        "model",
        ["", "chat", "status", "history", "access", "usage"][action],
        id(&env)?,
    ])
    .await
}

async fn backups() -> Result<(), String> {
    match menu(
        "Snapshots and backups",
        &[
            "List snapshots",
            "Restore a snapshot",
            "Delete a snapshot",
            "List cloud backups",
            "Restore a cloud backup",
            "Import a local backup",
            "Back",
        ],
    )? {
        0 => execute(&["snapshot", "list"]).await,
        action @ (1 | 2 | 4) => {
            let state = state().await?;
            let (key, group, verb) = if action == 4 {
                ("backupRuns", "backup", "restore")
            } else {
                (
                    "snapshots",
                    "snapshot",
                    if action == 1 { "restore" } else { "delete" },
                )
            };
            let record = select_record(
                "Choose a saved item",
                state[key].as_array().ok_or("Invalid saved item list")?,
            )?;
            confirm(
                &format!(
                    "{verb} {}?",
                    clean(record["name"].as_str().unwrap_or(id(&record)?))
                ),
                if verb == "restore" {
                    "This replaces the environment's current data with the saved data."
                } else {
                    "This permanently deletes the saved snapshot."
                },
            )?;
            execute(&[group, verb, id(&record)?, "--yes"]).await
        }
        3 => execute(&["backup", "list"]).await,
        5 => {
            let file = browse("Choose a Yougori backup", PathKind::File)?;
            confirm("Import as a new environment?", &clean(path_text(&file)?))?;
            execute(&["backup", "import", path_text(&file)?, "--yes"]).await
        }
        _ => Ok(()),
    }
}

async fn neocloud() -> Result<(), String> {
    match menu("Neocloud", &["RunPod"])? {
        0 => runpod().await,
        _ => Ok(()),
    }
}

async fn runpod() -> Result<(), String> {
    match menu(
        "RunPod",
        &[
            "CLI installation and provider status",
            "Install RunPod CLI",
            "Sign in with API key",
            "Account",
            "GPU prices and availability",
            "CPU prices and availability",
            "Deployments",
            "Back",
        ],
    )? {
        0 => execute(&["neocloud", "providers"]).await,
        1 => {
            confirm(
                "Install RunPod CLI?",
                "Downloads and installs the provider CLI for your user.",
            )?;
            execute(&["neocloud", "install", "--provider", "runpod", "--yes"]).await
        }
        2 => {
            let key = text("RunPod API key (hidden)", "", true)?;
            confirm(
                "Save RunPod credentials?",
                "Yougori will verify the key and save it in the system credential store.",
            )?;
            let saving = ui::task("Verifying and saving RunPod credentials");
            client::start(None).await?;
            // Secrets stay in memory and the same-user IPC connection, never argv or command history.
            call(
                "neocloud_authenticate",
                json!({"provider":"runpod", "apiKey":key}),
            )
            .await?;
            saving.done("RunPod credentials saved");
            Ok(())
        }
        3 => execute(&["neocloud", "account", "--provider", "runpod"]).await,
        action @ (4 | 5) => {
            execute(&[
                "neocloud",
                "prices",
                "--provider",
                "runpod",
                "--product",
                if action == 4 { "gpu" } else { "cpu" },
                "--format",
                "table",
            ])
            .await
        }
        6 => execute(&["neocloud", "list"]).await,
        _ => Ok(()),
    }
}

async fn system() -> Result<(), String> {
    match menu(
        "Yougori settings and tools",
        &[
            "Check this computer",
            "Resource usage",
            "Storage location",
            "Choose storage folder",
            "GPU runtime status",
            "Install GPU runtime",
            "Startup at login",
            "Check for updates",
            "Open desktop app",
            "Stop Yougori and all workloads",
            "Back",
        ],
    )? {
        0 => execute(&["doctor"]).await,
        1 => execute(&["top", "--once"]).await,
        2 => execute(&["storage", "location"]).await,
        3 => {
            let folder = browse("Choose storage folder", PathKind::Folder)?;
            confirm("Change storage location?", &clean(path_text(&folder)?))?;
            execute(&["storage", "location", "--set", path_text(&folder)?, "--yes"]).await
        }
        4 => execute(&["gpu", "status"]).await,
        5 => {
            confirm(
                "Install GPU runtime?",
                "Installs or updates Yougori's dedicated NVIDIA CUDA runtime.",
            )?;
            execute(&["gpu", "setup", "--yes"]).await
        }
        6 => {
            match menu(
                "Startup at login",
                &[
                    "Show current setting",
                    "Start background engine",
                    "Open desktop",
                    "Disable",
                    "Back",
                ],
            )? {
                0 => execute(&["app", "autostart", "status"]).await,
                1 => execute(&["app", "autostart", "on"]).await,
                2 => execute(&["app", "autostart", "on", "--dashboard"]).await,
                3 => execute(&["app", "autostart", "off"]).await,
                _ => Ok(()),
            }
        }
        7 => super::releases::offer(true).await,
        8 => execute(&["app", "show"]).await,
        9 => {
            confirm(
                "Stop Yougori completely?",
                "All running workloads will stop.",
            )?;
            execute(&["app", "quit", "--yes"]).await
        }
        _ => Ok(()),
    }
}

async fn vault() -> Result<(), String> {
    match menu(
        "MCP Vault",
        &[
            "Open Personal Vault — unlock and manage your vault in the app",
            "Vault status — connection and pending requests",
            "Review approval requests — open approvals in the app",
            "Add a vault item — open the app's entry form",
            "MCP connection setup — how to connect your client",
            "Back",
        ],
    )? {
        0 => execute(&["vault", "open"]).await,
        1 => execute(&["vault", "status"]).await,
        2 => execute(&["vault", "approve"]).await,
        3 => execute(&["vault", "add"]).await,
        4 => {
            ui::info("Open Personal Vault in the app to unlock it and choose your MCP connection settings.");
            ui::info("For a local stdio MCP client, use this server configuration:");
            let executable = std::env::current_exe().map_err(|e| e.to_string())?;
            let config = json!({"mcpServers":{"yougori-vault":{"command":executable,"args":["vault","mcp"]}}});
            for line in serde_json::to_string_pretty(&config)
                .map_err(|e| e.to_string())?
                .lines()
            {
                ui::line(line);
            }
            ui::info(
                "Review connection and protected-operation requests in Personal Vault in the app.",
            );
            if menu("MCP connection setup", &["Open Personal Vault", "Back"])? == 0 {
                execute(&["vault", "open"]).await?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) async fn run(args: &[String]) -> Result<i32, String> {
    if args != ["cli"] {
        return Err("Usage: yougori cli (no additional arguments)".into());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "yougori needs an interactive terminal. Run yougori help to see commands for scripts."
                .into(),
        );
    }
    if !ui::can_prompt() {
        return Err("This terminal cannot display interactive menus. Open Windows Terminal or another ANSI terminal, and remove TERM=dumb if set.".into());
    }
    let _session = ui::Session::start("cli", "Choose what you want to do");
    super::releases::offer(false).await?;
    if let Ok(folder) = std::env::current_dir() {
        // Inspect before registering the shortcut so our package.json edit is
        // not mistaken for a change the user made.
        if let Err(error) = project::offer_on_entry(&folder).await {
            if error != ui::CANCELLED { ui::warn(&clean(&error)); }
        }
        project::prepare_project_shortcut(&folder);
    }
    loop {
        let selected = match menu(
            "Yougori",
            &[
                "Overview — environments, services and jobs",
                "Run a project — choose a Node.js or Python folder",
                "Create an environment — container, GPU, microVM or VM",
                "Manage an environment — terminal, start, stop, files and backups",
                "Models — run, chat and API access",
                "Neocloud — RunPod account, prices and deployments",
                "MCP Vault — vault, approvals and MCP connections",
                "Snapshots and backups — browse, restore and import saved data",
                "Connections and sharing — private connections, shares and ports",
                "Set up my domains — save domains and connect your apps",
                "Yougori settings and tools — storage, startup, updates and diagnostics",
                "Command reference — available commands and usage examples",
                "Exit — keep workloads running",
            ],
        ) {
            Ok(index) => index,
            Err(e) if e == ui::CANCELLED => break,
            Err(e) => return Err(e),
        };
        if selected == 12 {
            break;
        }
        let result: Result<(), String> = async {
            match selected {
                0 => execute(&["status"]).await,
                1 => {
                    let folder = browse("Choose a project folder", PathKind::Folder)?;
                    let change = menu(
                        "Project settings",
                        &[
                            "Use saved settings, or set up a new project",
                            "Change settings",
                            "Back",
                        ],
                    )?;
                    if change != 2 {
                        project::run_in(&folder, change == 1).await?;
                    }
                    Ok(())
                }
                2 => create().await,
                3 => manage().await,
                4 => models().await,
                5 => neocloud().await,
                6 => vault().await,
                7 => backups().await,
                8 => match menu(
                    "Connections and sharing",
                    &[
                        "Private connections",
                        "Remote shares",
                        "LAN shares",
                        "Published ports",
                        "Public access setups — save a domain and app port",
                        "Back",
                    ],
                )? {
                    0 => execute(&["connection", "list"]).await,
                    1 => execute(&["remote", "list"]).await,
                    2 => execute(&["lan", "list"]).await,
                    3 => execute(&["ports", "list", "--all"]).await,
                    4 => domains::run().await,
                    _ => Ok(()),
                },
                9 => domains::run().await,
                10 => system().await,
                11 => execute(&["help"]).await,
                _ => Ok(()),
            }
        }
        .await;
        match result {
            Err(e) if e == ui::CANCELLED => {}
            Err(e) => ui::warn(&clean(&e)),
            Ok(()) => {}
        }
    }
    ui::outro("Menu closed. Your workloads keep running.");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminals_start_only_stopped_or_paused_guests_and_leave_busy_guests_alone() {
        for kind in ["container", "microVm", "cloud"] {
            assert!(!terminal_needs_start(&json!({"kind":kind,"status":"running"})).unwrap());
            for status in ["stopped", "paused"] {
                assert!(terminal_needs_start(&json!({"kind":kind,"status":status})).unwrap());
            }
            for status in ["error", "provisioning", "deleting", "unknown"] {
                assert!(terminal_needs_start(&json!({"kind":kind,"status":status})).is_err());
            }
        }
        for kind in ["fullVm", "computerBranch"] {
            assert!(terminal_needs_start(&json!({"kind":kind,"status":"stopped"})).is_err());
        }
    }

    #[test]
    fn generated_creations_preserve_paths_names_and_resource_choices() {
        for kind in ["container", "gpu", "microvm", "vm"] {
            let source = match kind {
                "vm" if cfg!(windows) => r"C:\My Images\linux.iso",
                "vm" => "/tmp/My Images/linux.iso",
                "microvm" => "builtin:alpine",
                _ => "alpine:3.24",
            };
            let args = create_args(kind, "My workspace", source, [3, 6, 30], true, Some("D:\\"));
            let parsed =
                yougori_cli::parse::parse(&args, |_| panic!("No file input needed")).unwrap();
            assert!(parsed.request.confirmed);
            let request = &parsed.request.params["request"];
            assert_eq!(request["name"], "My workspace");
            assert_eq!(request["runtime"], source);
            assert_eq!(request["resourcePolicy"]["cpu"]["preferred"], 3.0);
            assert_eq!(request["storageGb"], 30.0);
            assert_eq!(request["storageDrive"], "D:\\");
            assert_eq!(request["gpuAccess"], kind == "gpu");
            assert_eq!(request["networkAccess"], true);
        }
    }

    #[test]
    fn browser_filters_sorts_and_accepts_quoted_paths_with_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("My project");
        std::fs::create_dir(&folder).unwrap();
        let file = temp.path().join("A file.iso");
        std::fs::write(&file, b"test").unwrap();
        assert_eq!(
            path_entries(temp.path(), PathKind::Folder).unwrap(),
            vec![folder.clone()]
        );
        assert_eq!(
            path_entries(temp.path(), PathKind::File).unwrap(),
            vec![folder.clone(), file.clone()]
        );
        assert_eq!(
            validate_path(&format!("\"{}\"", folder.display()), PathKind::Folder).unwrap(),
            folder
        );
        assert!(validate_path(file.to_str().unwrap(), PathKind::Folder).is_err());
        assert!(validate_path(
            temp.path().join("missing").to_str().unwrap(),
            PathKind::Either
        )
        .is_err());
    }

    #[test]
    fn guest_browser_joins_only_single_literal_file_names() {
        assert_eq!(guest_child("/", "My folder").unwrap(), "/My folder");
        assert_eq!(
            guest_child("/workspace", "a.txt").unwrap(),
            "/workspace/a.txt"
        );
        for name in ["..", "../secret", "a/b", "a\\b", "\x1b[2J"] {
            assert!(guest_child("/workspace", name).is_err());
        }
    }
}
