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
    menu_at(title, items, 0)
}

/// [`menu`] with `initial` preselected, such as an earlier answer asked again.
fn menu_at(title: &str, items: &[&str], initial: usize) -> Result<usize, String> {
    choose_with_initial(
        title,
        "",
        &items.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
        initial,
    )
}

fn confirm(title: &str, detail: &str) -> Result<(), String> {
    if choose_with_note(title, detail, &["Cancel".into(), "Continue".into()])? == 1 {
        Ok(())
    } else {
        Err(ui::CANCELLED.into())
    }
}

/// Asks questions in turn, each after the first with Back. `ask(step)` asks one and says whether
/// it asked anything, or gives `None` once every question is answered.
fn in_turn(mut ask: impl FnMut(usize) -> Option<Result<bool, String>>) -> Result<(), String> {
    let mut steps = ui::Wizard::new();
    loop {
        let Some(asked) = ask(steps.step()) else {
            return Ok(());
        };
        steps.next(asked)?;
    }
}

/// Whether an action went Back, so its menu shows again. Other errors pass through.
fn went_back(result: Result<(), String>) -> Result<bool, String> {
    match result {
        Err(error) if error == ui::BACK => Ok(true),
        other => other.map(|()| false),
    }
}

/// Waits for an action the engine carries out. Ctrl+C stops waiting but not the action, so the
/// menu says so before it shows again.
async fn engine_action<T>(label: &str, work: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    let result = busy(label, work).await;
    if result.as_ref().is_err_and(|error| error == ui::CANCELLED) {
        ui::info("Stopped waiting. Yougori finishes this in the background.");
    }
    result
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
        busy("Connecting to Yougori engine", client::start(None)).await?;
    }
    // Box the future because a command can itself open the model launcher.
    // Pause the painter while the normal CLI writes its result or live output.
    let args: Vec<String> = args.iter().map(|s| (*s).into()).collect();
    // Guided create/start actions need a human receipt, not the complete
    // platform-state JSON (including unrelated recovery reports).
    if args.starts_with(&["env".into(), "create".into()]) {
        let invocation = yougori_cli::parse::parse(&args, |_| Err("This action takes no JSON input".into()))?;
        engine_action("Creating environment", call(&invocation.request.method, invocation.request.params)).await?;
        let name = args.windows(2).find(|pair| pair[0] == "--name").map(|pair| pair[1].as_str()).unwrap_or("Environment");
        ui::info(&format!("Created {}.", clean(name)));
        return Ok(());
    }
    if args.first().is_some_and(|arg| matches!(arg.as_str(), "start" | "stop" | "restart")) {
        engine_action(activity_label(&args), async {
            public::handle(&args).await?.ok_or_else(|| "This lifecycle action was not recognized".to_owned())
        })
        .await?;
        let action = match args[0].as_str() { "start" => "Started", "stop" => "Stopped", _ => "Restarted" };
        ui::info(&format!("{action} environment."));
        return Ok(());
    }
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
    busy("Loading environments", async {
        client::start(None).await?;
        call("get_platform_state", json!({})).await
    })
    .await
}

/// One of `records`. Back, and an empty list, return [`ui::BACK`] to the menu that asked.
fn select_record(title: &str, records: &[Value]) -> Result<Value, String> {
    if records.is_empty() {
        ui::info("Nothing here yet.");
        return Err(ui::BACK.into());
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
        .ok_or_else(|| ui::BACK.into())
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

/// A file or folder on this PC, browsed from the current folder. Its Back item returns
/// [`ui::BACK`]; Back from the typed path returns to the list.
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
                let entry = match ui::input("Path", "", false, &|s| {
                    validate_path(s, kind).map(|p| p.to_string_lossy().into_owned())
                }) {
                    Ok(entry) => entry,
                    Err(error) if error == ui::BACK => continue,
                    Err(error) => return Err(error),
                };
                let path = validate_path(&entry, kind)?;
                if path.is_dir() {
                    folder = path;
                } else {
                    return Ok(path);
                }
            }
            3 => return Err(ui::BACK.into()),
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

/// The kinds the create menu offers, in its order.
const KINDS: [&str; 4] = ["container", "gpu", "microvm", "vm"];

/// Asks for a new environment in turn, each question after the first with Back, then creates it.
async fn create() -> Result<(), String> {
    let mut kind = KINDS[0];
    let mut name = String::new();
    let mut source = String::new();
    let mut host = None;
    let mut selected: Option<super::storage::Selection> = None;
    let mut allocation = None;
    let mut internet = true;
    let mut image_startup = false;
    let mut steps = ui::Wizard::new();
    loop {
        let minimum = if kind == "microvm" { 6 } else { 1 };
        let asked = match steps.step() {
            0 => match menu_at(
                "Create an environment",
                &[
                    "Container — Linux workspace",
                    "GPU container — NVIDIA CUDA",
                    "MicroVM — lightweight virtual machine",
                    "Virtual machine — choose an ISO or disk",
                    "Back",
                ],
                KINDS.iter().position(|k| *k == kind).unwrap_or(0),
            ) {
                Ok(picked) if picked < KINDS.len() => {
                    // A different kind needs a different image or disk.
                    if KINDS[picked] != kind {
                        source.clear();
                    }
                    kind = KINDS[picked];
                    Ok(true)
                }
                Ok(_) => return Ok(()),
                Err(error) => Err(error),
            },
            1 => text("Environment name", &name, false).map(|entry| {
                name = entry;
                true
            }),
            2 if kind == "microvm" => {
                source = "builtin:alpine".into();
                Ok(false)
            }
            2 if kind == "vm" => browse("Choose an ISO or disk image", PathKind::File)
                .and_then(|path| path_text(&path).map(str::to_owned))
                .map(|path| {
                    source = path;
                    true
                }),
            2 => {
                let image = if !source.is_empty() {
                    source.clone()
                } else if kind == "gpu" {
                    "ubuntu:24.04".into()
                } else {
                    "alpine:3.24".into()
                };
                text("Container image", &image, false).map(|entry| {
                    source = entry;
                    true
                })
            }
            3 => {
                if host.is_none() {
                    host = Some(busy("Reading this computer's drives and memory", call("refresh_host_metrics", json!({}))).await?["host"].take());
                }
                let host = host.as_ref().ok_or("Cannot read this computer's drives")?;
                super::storage::choose_with_previous(host, minimum, selected.as_ref().map(|s| s.label.as_str())).map(|selection| {
                    selected = Some(selection);
                    true
                })
            }
            4 => {
                let selection = selected.as_ref().ok_or("Choose a storage drive first")?;
                super::sliders(&selection.host, false, minimum, allocation).map(|chosen| {
                    allocation = Some(chosen);
                    true
                })
            }
            5 => menu_at("Internet access", &["Enabled", "Disabled"], usize::from(!internet)).map(|picked| {
                internet = picked == 0;
                true
            }),
            6 if matches!(kind, "container" | "gpu") => menu_at(
                "Container startup",
                &[
                    "Keep workspace running — open it when needed",
                    "Run the image's default service",
                ],
                usize::from(image_startup),
            )
            .map(|picked| {
                image_startup = picked == 1;
                true
            }),
            6 => {
                image_startup = false;
                Ok(false)
            }
            7 => {
                let selection = selected.as_ref().ok_or("Choose a storage drive first")?;
                let allocation = allocation.ok_or("Choose the resources first")?;
                confirm(
                    "Create environment?",
                    &format!(
                        "{} · {kind}\n{}\n{}\nStorage drive: {}\nInternet: {}",
                        clean(&name),
                        clean(&source),
                        allocation_text(allocation),
                        selection.label,
                        if internet { "enabled" } else { "disabled" }
                    ),
                )
                .map(|()| true)
            }
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let selected = selected.ok_or("Choose a storage drive first")?;
    let allocation = allocation.ok_or("Choose the resources first")?;
    let mut args = create_args(kind, &name, &source, allocation, internet, selected.drive.as_deref());
    if image_startup {
        args.extend(["--startup".into(), "image".into()]);
    }
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
            return Err(ui::BACK.into());
        }
        execute(&["start", env_id]).await?;
    }
    // execute pauses the menu painter and restores it after the PTY closes,
    // including errors. The shell owns this console, not a new desktop window.
    execute(&["terminal", env_id]).await
}

async fn manage() -> Result<(), String> {
    loop {
        let env = environment().await?;
        // Back from its actions returns to the list of environments.
        if !went_back(environment_actions(&env).await)? {
            return Ok(());
        }
    }
}

/// One environment's actions until Back, which returns [`ui::BACK`].
async fn environment_actions(env: &Value) -> Result<(), String> {
    let env_id = id(env)?;
    let title = format!(
        "{} · {}",
        env["name"].as_str().unwrap_or("Environment"),
        env["status"].as_str().unwrap_or("unknown")
    );
    loop {
        let result = match menu(
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
            4 => open_terminal_here(env, false).await,
            5 => execute(&["env", "open", env_id]).await,
            6 => execute(&["logs", env_id]).await,
            7 => {
                let name = text("New name", env["name"].as_str().unwrap_or(""), false)?;
                execute(&["rename", env_id, &name]).await
            }
            8 => async {
                let mut name = String::new();
                in_turn(|step| Some(match step {
                    0 => text("Snapshot name", if name.is_empty() { "before-change" } else { &name }, false).map(|entry| {
                        name = entry;
                        true
                    }),
                    1 => confirm("Create snapshot?", &clean(&title)).map(|()| true),
                    _ => return None,
                }))?;
                execute(&["snapshot", "create", env_id, "--name", &name, "--yes"]).await
            }
            .await,
            9 => async {
                let mut folder = PathBuf::new();
                in_turn(|step| Some(match step {
                    0 => browse("Save backup in", PathKind::Folder).map(|chosen| {
                        folder = chosen;
                        true
                    }),
                    1 => path_text(&folder).and_then(|path| confirm(
                        "Export backup?",
                        &format!("{}\n{}", clean(&title), clean(path)),
                    )).map(|()| true),
                    _ => return None,
                }))?;
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
            .await,
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
            13 => async {
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
                in_turn(|step| Some(match step {
                    0 => ui::sliders("CPU and memory", "Changes preferred and maximum allocations; keeps storage and minimum reservations.", &mut sliders).map(|()| true),
                    1 => confirm(
                        "Change CPU and memory limits?",
                        &format!("{}\n{} CPU · {} GB memory", clean(&title), sliders[0].value, sliders[1].value),
                    )
                    .map(|()| true),
                    _ => return None,
                }))?;
                let cpu = sliders[0].value.to_string();
                let memory = sliders[1].value.to_string();
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
            .await,
            14 => publish_service(env_id, &title).await,
            15 => download_link(env).await,
            _ => return Err(ui::BACK.into()),
        };
        // Back from an action returns to these actions.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// Asks for the service port, who can reach it and a confirmation in turn, each after the first
/// with Back, then publishes it.
async fn publish_service(env_id: &str, title: &str) -> Result<(), String> {
    let mut guest_port = 3000;
    let mut access: Option<Network> = None;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => port("Service port inside this environment", guest_port).map(|chosen| {
                guest_port = chosen;
                true
            }),
            1 => network_with_previous(false, Some(env_id), Some(guest_port), access.as_ref()).await.map(|chosen| {
                access = Some(chosen);
                true
            }),
            // This computer needs no publication, so there is nothing to confirm.
            2 if access.as_ref().is_some_and(|access| publish_params(access, env_id, guest_port).is_none()) => Ok(false),
            2 => confirm("Publish this service?", &format!("{}\nPort {guest_port} will be accessible using the selected network or public link.", clean(title))).map(|()| true),
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let access = access.ok_or("Choose who can reach the service")?;
    if let Some(params) = publish_params(&access, env_id, guest_port) {
        stage("Publishing service", |_| "Service published".into(), async {
            if let Network::NewDomain {
                hostname,
                token,
                host_port,
            } = &access
            {
                call("add_saved_domain", json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest_port})).await?;
            }
            domains::publish(params).await
        })
        .await?;
    }
    execute(&["ports", "list", env_id]).await
}

async fn download_link(env: &Value) -> Result<(), String> {
    let env_id = id(env)?;
    let links = busy("Loading download links", call("list_environment_downloads", json!({}))).await?;
    let link = links.as_array().and_then(|items| items.iter().find(|item| item["environmentId"] == env_id));
    let count = link.and_then(|item| item["downloads"].as_u64()).unwrap_or(0);
    ui::info(&format!("Downloads (all time): {count}"));
    if link.is_some_and(|item| item["active"] == true) {
        ui::info(&format!("Download link: {}", link.unwrap()["url"].as_str().unwrap_or("")));
        if menu("Environment download link", &["Turn off download link", "Back"])? != 0 {
            return Err(ui::BACK.into());
        }
        return execute(&["download", "off", env_id]).await;
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
    let mut choice = 0;
    let needs_stop = env["status"] != "stopped";
    in_turn(|step| Some(match step {
        0 => match ui::select("Download link address", &[], &choices, choice) {
            Ok(picked) if picked == choices.len() - 1 => Err(ui::BACK.into()),
            Ok(picked) => {
                choice = picked;
                Ok(true)
            }
            Err(error) => Err(error),
        },
        1 => confirm("Create a complete environment download?", "Anyone with the link can copy all files and credentials inside this environment. The link lasts while this CLI is open; Ctrl+C turns it off. The environment must be stopped for a consistent copy.").map(|()| true),
        2 if needs_stop && !matches!(env["status"].as_str(), Some("running" | "paused")) => Err("Wait until this environment is ready before making a copy.".into()),
        2 if needs_stop => confirm("Stop this environment to prepare its copy?", "Running work will be interrupted. It stays stopped after creating the link.").map(|()| true),
        2 => Ok(false),
        _ => return None,
    }))?;
    if needs_stop {
        execute(&["stop", env_id]).await?;
    }
    let mut args = vec!["download", "on", env_id, "--yes"];
    if choice > 0 { args.extend(["--domain", domains[choice - 1].domain["hostname"].as_str().ok_or("Invalid saved domain")?]); }
    execute(&args).await
}

/// The environment's files and shared folders until Back, which returns [`ui::BACK`].
async fn files(env: &str) -> Result<(), String> {
    loop {
        let result = match menu(
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
            0 => browse_guest(env).await.map(|_| ()),
            1 => {
                let mut path = PathBuf::new();
                match in_turn(|step| Some(match step {
                    0 => browse("Choose a file or folder to copy", PathKind::Either).map(|chosen| {
                        path = chosen;
                        true
                    }),
                    1 => path_text(&path).and_then(|text| confirm(
                        "Copy into environment?",
                        &format!("{}\nDestination: {env}", clean(text)),
                    )).map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => execute(&["cp", path_text(&path)?, env]).await,
                    Err(error) => Err(error),
                }
            }
            2 => copy_to_pc(env).await,
            3 => execute(&["share", "list", env]).await,
            4 => {
                let mut folder = PathBuf::new();
                let mut writable = false;
                match in_turn(|step| Some(match step {
                    0 => browse("Choose a PC folder to share", PathKind::Folder).map(|chosen| {
                        folder = chosen;
                        true
                    }),
                    1 => menu_at("Folder access", &["Read only", "Read and write"], usize::from(writable)).map(|picked| {
                        writable = picked == 1;
                        true
                    }),
                    2 => path_text(&folder).and_then(|text| confirm(
                        "Share this folder?",
                        &format!(
                            "{}\nEnvironment: {env}\n{}",
                            clean(text),
                            if writable {
                                "The environment can change files in this folder."
                            } else {
                                "The environment can read files in this folder."
                            }
                        ),
                    )).map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => execute(&[
                        "share",
                        "add",
                        env,
                        "--path",
                        path_text(&folder)?,
                        "--read-only",
                        if writable { "false" } else { "true" },
                        "--yes",
                    ])
                    .await,
                    Err(error) => Err(error),
                }
            }
            _ => return Err(ui::BACK.into()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// Asks for the environment file, the folder on this PC and a confirmation in turn, each after
/// the first with Back, then copies the file.
async fn copy_to_pc(env: &str) -> Result<(), String> {
    let mut source = String::new();
    let mut folder = PathBuf::new();
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => browse_guest(env).await.map(|chosen| {
                source = chosen;
                true
            }),
            1 => browse("Choose a destination folder on this PC", PathKind::Folder).map(|chosen| {
                folder = chosen;
                true
            }),
            2 => path_text(&folder)
                .and_then(|text| confirm("Copy to this PC?", &format!("{}\n{}", clean(&source), clean(text))))
                .map(|()| true),
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    execute(&["cp", &format!("{env}:{source}"), path_text(&folder)?]).await
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

/// A file or folder in the environment. Its Back item returns [`ui::BACK`].
async fn browse_guest(env: &str) -> Result<String, String> {
    let mut path = String::new();
    loop {
        let result = busy(
            "Loading environment files",
            call("list_environment_folders", json!({"environmentId":env,"path":path})),
        )
        .await?;
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
            2 => return Err(ui::BACK.into()),
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

/// The model actions until Back. Back from a model list returns to them.
async fn models() -> Result<(), String> {
    loop {
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
        let result = if action == 0 {
            match text("Hugging Face model (OWNER/MODEL or link)", "", false) {
                Ok(model) => execute(&["run", &format!("hf.co/{}", public::model_name(&model))]).await,
                Err(error) => Err(error),
            }
        } else {
            model_action(action).await
        };
        if !went_back(result)? {
            return Ok(());
        }
    }
}

async fn model_action(action: usize) -> Result<(), String> {
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
    let mut env = Value::Null;
    in_turn(|step| Some(match step {
        0 => select_record("Choose a model environment", &models).map(|record| {
            env = record;
            true
        }),
        1 if action == 4 => confirm(
            "Show API credentials?",
            "The API key will be visible in this terminal.",
        )
        .map(|()| true),
        1 => Ok(false),
        _ => return None,
    }))?;
    execute(&[
        "model",
        ["", "chat", "status", "history", "access", "usage"][action],
        id(&env)?,
    ])
    .await
}

async fn backups() -> Result<(), String> {
    loop {
        let result = match menu(
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
            action @ (1 | 2 | 4) => saved_item(action).await,
            3 => execute(&["backup", "list"]).await,
            5 => {
                let mut file = PathBuf::new();
                match in_turn(|step| Some(match step {
                    0 => browse("Choose a Yougori backup", PathKind::File).map(|chosen| {
                        file = chosen;
                        true
                    }),
                    1 => path_text(&file)
                        .and_then(|text| confirm("Import as a new environment?", &clean(text)))
                        .map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => execute(&["backup", "import", path_text(&file)?, "--yes"]).await,
                    Err(error) => Err(error),
                }
            }
            _ => return Ok(()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// Restores or deletes a snapshot, or restores a cloud backup: the item, then a confirmation.
async fn saved_item(action: usize) -> Result<(), String> {
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
    let records = state[key].as_array().ok_or("Invalid saved item list")?;
    let mut record = Value::Null;
    in_turn(|step| Some(match step {
        0 => select_record("Choose a saved item", records).map(|chosen| {
            record = chosen;
            true
        }),
        1 => id(&record).and_then(|item| confirm(
            &format!(
                "{verb} {}?",
                clean(record["name"].as_str().unwrap_or(item))
            ),
            if verb == "restore" {
                "This replaces the environment's current data with the saved data."
            } else {
                "This permanently deletes the saved snapshot."
            },
        )).map(|()| true),
        _ => return None,
    }))?;
    execute(&[group, verb, id(&record)?, "--yes"]).await
}

async fn neocloud() -> Result<(), String> {
    loop {
        match menu("Neocloud", &["RunPod", "Back"])? {
            // Back from RunPod returns here.
            0 => if !went_back(runpod().await)? {
                return Ok(());
            },
            _ => return Ok(()),
        }
    }
}

/// RunPod's actions. Back returns [`ui::BACK`].
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
            let mut key = String::new();
            in_turn(|step| Some(match step {
                0 => text("RunPod API key (hidden)", "", true).map(|entry| {
                    key = entry;
                    true
                }),
                1 => confirm(
                    "Save RunPod credentials?",
                    "Yougori will verify the key and save it in the system credential store.",
                )
                .map(|()| true),
                _ => return None,
            }))?;
            stage("Verifying and saving RunPod credentials", |_| "RunPod credentials saved".into(), async {
                client::start(None).await?;
                // Secrets stay in memory and the same-user IPC connection, never argv or command history.
                call(
                    "neocloud_authenticate",
                    json!({"provider":"runpod", "apiKey":key}),
                )
                .await
            })
            .await?;
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
        _ => Err(ui::BACK.into()),
    }
}

async fn system() -> Result<(), String> {
    loop {
        let result = match menu(
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
                let mut folder = PathBuf::new();
                match in_turn(|step| Some(match step {
                    0 => browse("Choose storage folder", PathKind::Folder).map(|chosen| {
                        folder = chosen;
                        true
                    }),
                    1 => path_text(&folder)
                        .and_then(|text| confirm("Change storage location?", &clean(text)))
                        .map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => execute(&["storage", "location", "--set", path_text(&folder)?, "--yes"]).await,
                    Err(error) => Err(error),
                }
            }
            4 => execute(&["gpu", "status"]).await,
            5 => {
                confirm(
                    "Install GPU runtime?",
                    "Installs or updates Yougori's dedicated NVIDIA CUDA runtime.",
                )?;
                execute(&["gpu", "setup", "--yes"]).await
            }
            6 => match menu(
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
                _ => Err(ui::BACK.into()),
            },
            7 => super::releases::offer(true).await,
            8 => execute(&["app", "show"]).await,
            9 => {
                confirm(
                    "Stop Yougori completely?",
                    "All running workloads will stop.",
                )?;
                execute(&["app", "quit", "--yes"]).await
            }
            _ => return Ok(()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

async fn vault() -> Result<(), String> {
    loop {
        let result = match menu(
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
                    execute(&["vault", "open"]).await
                } else {
                    Err(ui::BACK.into())
                }
            }
            _ => return Ok(()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// A project folder and how to use its settings, asked in turn; Back from the settings returns
/// to the folder.
fn project_folder() -> Result<(PathBuf, bool), String> {
    let mut folder = PathBuf::new();
    let mut change = 0;
    in_turn(|step| Some(match step {
        0 => browse("Choose a project folder", PathKind::Folder).map(|chosen| {
            folder = chosen;
            true
        }),
        1 => match menu_at(
            "Project settings",
            &[
                "Use saved settings, or set up a new project",
                "Change settings",
                "Back",
            ],
            change,
        ) {
            Ok(2) => Err(ui::BACK.into()),
            Ok(picked) => {
                change = picked;
                Ok(true)
            }
            Err(error) => Err(error),
        },
        _ => return None,
    }))?;
    Ok((folder, change == 1))
}

async fn connections() -> Result<(), String> {
    loop {
        let result = match menu(
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
            _ => return Ok(()),
        };
        // Back from the setups returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
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
            if !left(&error) { ui::warn(&clean(&error)); }
        }
        project::prepare_project_shortcut(&folder);
    }
    loop {
        // The home menu has nothing to go back to; Esc and Exit close it.
        let selected = match ui::without_back(|| menu(
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
        )) {
            Ok(index) => index,
            Err(e) if left(&e) => break,
            Err(e) => return Err(e),
        };
        if selected == 12 {
            break;
        }
        let result: Result<(), String> = async {
            match selected {
                0 => execute(&["status"]).await,
                1 => {
                    let (folder, change) = project_folder()?;
                    project::run_in(&folder, change).await?;
                    Ok(())
                }
                2 => create().await,
                3 => manage().await,
                4 => models().await,
                5 => neocloud().await,
                6 => vault().await,
                7 => backups().await,
                8 => connections().await,
                9 => domains::run().await,
                10 => system().await,
                11 => execute(&["help"]).await,
                _ => Ok(()),
            }
        }
        .await;
        match result {
            // Leaving a question or going Back from a menu returns here.
            Err(e) if left(&e) => {}
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
    fn questions_in_turn_go_back_to_the_last_one_asked() {
        let mut visited = Vec::new();
        let mut backed = false;
        in_turn(|step| {
            visited.push(step);
            Some(match step {
                0 => Ok(true),
                // Skipped, so Back passes over it.
                1 => Ok(false),
                2 if !backed => {
                    backed = true;
                    Err(ui::BACK.into())
                }
                2 => Ok(true),
                _ => return None,
            })
        })
        .unwrap();
        assert_eq!(visited, [0, 1, 2, 0, 1, 2, 3]);
        // Back from the first question leaves for the menu that asked; Cancel always leaves.
        assert_eq!(in_turn(|_| Some(Err(ui::BACK.into()))), Err(ui::BACK.into()));
        assert_eq!(in_turn(|step| Some(if step == 0 { Ok(true) } else { Err(ui::CANCELLED.into()) })), Err(ui::CANCELLED.into()));
        assert_eq!(went_back(Err(ui::BACK.into())), Ok(true));
        assert_eq!(went_back(Ok(())), Ok(false));
        assert_eq!(went_back(Err(ui::CANCELLED.into())), Err(ui::CANCELLED.into()));
        assert_eq!(went_back(Err("Engine stopped".into())), Err("Engine stopped".into()));
    }

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
