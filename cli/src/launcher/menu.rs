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
        ("grids", "list") => "Looking for the grids on this computer",
        ("grids", "status") => "Asking the grid how it is",
        ("grids", "log") => "Reading what the grid recorded",
        ("grids", _) => "Asking the grid",
        _ => "Working",
    }
}

fn menu(title: &str, items: &[&str]) -> Result<usize, String> {
    menu_at(title, items, 0)
}

/// [`menu`] with `initial` preselected, such as an earlier answer asked again.
///
/// Every list here is reached from another menu or an earlier question, so Escape goes Back to
/// it, exactly as a Back row does. Without this, Escape returned [`ui::CANCELLED`] and dropped
/// the person on the home menu from three levels down. A list with its own Back row gets no
/// second one. The home menu, which has nowhere to go back to, does not come through here.
fn menu_at(title: &str, items: &[&str], initial: usize) -> Result<usize, String> {
    ui::with_back(|| choose_with_initial(title, "", &items.iter().map(|s| (*s).into()).collect::<Vec<_>>(), initial))
}

/// A yes-or-no question before an action. Asked straight from a menu as often as inside a
/// wizard, so Escape goes Back to where it was asked; Cancel still leaves.
fn confirm(title: &str, detail: &str) -> Result<(), String> {
    if ui::with_back(|| choose_with_note(title, detail, &["Cancel".into(), "Continue".into()]))? == 1 {
        Ok(())
    } else {
        Err(ui::CANCELLED.into())
    }
}

/// Asks questions in turn, every one of them with Back. `ask(step)` asks one and says whether it
/// asked anything, or gives `None` once every question is answered.
///
/// Back from the first question leaves with [`ui::BACK`], which is the menu that asked showing
/// again. That is why the first one offers Back too: these are only ever reached from a menu, so
/// there is always somewhere to go back to, and without it Escape at the first question returned
/// [`ui::CANCELLED`] — which means leave — and dropped the person out of the launcher from the
/// first question of a wizard they had just opened.
fn in_turn(mut ask: impl FnMut(usize) -> Option<Result<bool, String>>) -> Result<(), String> {
    ui::with_back(|| {
    let mut steps = ui::Wizard::new();
    loop {
        let Some(asked) = ask(steps.step()) else {
            return Ok(());
        };
        steps.next(asked)?;
    }
    })
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

/// Carries out an action and says, in one sentence, what it did.
///
/// The menu used to run these the way a typed command runs, which ends by printing the engine's
/// whole reply: a screen of pretty JSON with identifiers in it, after somebody chose "Delete
/// environment" from a list and confirmed it. The reply is the engine answering the CLI, not the
/// product answering the person, and nothing in it tells them anything they did not already know
/// except that it worked.
///
/// `receipt` is written by the caller because the caller is the only one that knows what the
/// person called the thing. It is a finished sentence in the past tense: what happened, to what.
async fn action(args: &[&str], receipt: &str) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|part| (*part).to_string()).collect();
    engine_action(activity_label(&args), carry_out(&args)).await?;
    ui::info(&clean(receipt));
    Ok(())
}

/// One engine request for an action, through whichever door the CLI itself would have used.
///
/// The two doors are not interchangeable. `public::handle` owns the short verbs — `rm`, `cp`,
/// `rename` and the rest of [`public::COMMANDS`] — and does work around the request that the
/// parser knows nothing about; everything else is parsed into one request and sent. Picking the
/// wrong one does not fail loudly, it quietly does less, so this asks the same question the CLI
/// asks: is this verb one of `public`'s.
async fn carry_out(args: &[String]) -> Result<Value, String> {
    // A typed command expects the engine to be running already; the menu starts it, as it always
    // has, rather than ending a chosen action in "start it with yougori app start".
    client::start(None).await?;
    if args.first().is_some_and(|first| public::COMMANDS.contains(&first.as_str())) {
        return public::handle(args).await?.ok_or_else(|| "This action was not recognized".to_owned());
    }
    let invocation = yougori_cli::parse::parse(args, |_| Err("This action takes no JSON input".into()))?;
    call(&invocation.request.method, invocation.request.params).await
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
    // A command that asks its own questions owns the keyboard, and answers Ctrl+C itself.
    if super::requested(&args) {
        return outcome(Some(Box::pin(crate::run(args)).await));
    }
    let label = activity_label(&args);
    ui::pause(true);
    // Ctrl+C is waited on rather than left to the operating system. Without this it arrived as a
    // signal and ended the process where it stood, in the middle of a delete, an export, a copy,
    // a driver install or a restore: the painter never put back the cursor it had hidden, the
    // last spinner stayed on the screen with nothing turning it, and the shell prompt came back
    // underneath both. Waiting on it here ends the wait instead, and the menu carries on.
    //
    // Deliberately not an `Interrupts` watch, which is how the rest of the launcher reads
    // Ctrl+C: that one turns raw mode on, and these commands print their own lines, which in raw
    // mode walk away down the screen a column at a time.
    let ran = tokio::select! {
        ran = Box::pin(crate::run(args)) => Some(ran),
        _ = tokio::signal::ctrl_c() => None,
    };
    ui::pause(false);
    if ran.is_none() {
        ui::info(&stopped_waiting(label));
    }
    outcome(ran)
}

/// What the menu makes of a command it ran: `None` when Ctrl+C ended the wait before the command
/// finished, otherwise what the command returned.
///
/// 130 is the exit code a command uses for its own Ctrl+C, so the two ways of stopping arrive at
/// the same place and are told to the person in the same words.
fn outcome(ran: Option<Result<i32, String>>) -> Result<(), String> {
    match ran {
        None | Some(Ok(130)) => Err(ui::CANCELLED.into()),
        Some(Err(error)) => Err(error),
        Some(Ok(0)) => Ok(()),
        Some(Ok(code)) => Err(format!("The action finished with status {code}. See the result above.")),
    }
}

/// What a person is told when they stop waiting for an action.
///
/// It does not say the action was undone, because nothing here knows that: the engine may have
/// had the request for a while, or may never have received it. What it can do is name what was
/// being waited for and where to look, which is the useful half of the answer.
fn stopped_waiting(label: &str) -> String {
    format!("{} — stopped waiting. Anything Yougori had already begun finishes on its own; yougori ps shows what is running.", label.trim_end_matches('.'))
}

async fn state() -> Result<Value, String> {
    busy("Loading environments", async {
        client::start(None).await?;
        call("get_platform_state", json!({})).await
    })
    .await
}

/// What to call each of `records` in a list somebody is choosing from.
///
/// The name and what it is doing, and nothing else. The identifier used to be on every line —
/// `Work · running · env-7f3a9c2d-...` — which is the longest and least memorable part of a line
/// whose whole job is to be recognised at a glance, and it pushed the two words that matter off
/// the side of a narrow terminal.
///
/// It comes back only where it has to: when two of them are called the same thing, those lines,
/// and only those, get enough of the identifier to tell them apart. Somebody who named two
/// environments `api` has asked for the last six characters; nobody else has.
fn record_labels(records: &[Value]) -> Vec<String> {
    let name_of = |value: &Value| value["name"].as_str().unwrap_or("Unnamed").to_owned();
    let names: Vec<String> = records.iter().map(name_of).collect();
    records
        .iter()
        .zip(&names)
        .map(|(value, name)| {
            let label = format!("{name} — {}", value["status"].as_str().unwrap_or("saved"));
            if names.iter().filter(|other| *other == name).count() > 1 {
                return format!("{label} · {}", tail(value["id"].as_str().unwrap_or("")));
            }
            label
        })
        .collect()
}

/// The last few characters of an identifier: enough to tell two things with one name apart, and
/// short enough that nobody is reading a UUID.
fn tail(id: &str) -> &str {
    match id.char_indices().nth_back(5) {
        Some((at, _)) => &id[at..],
        None => id,
    }
}

/// One of `records`. Back, and an empty list, return [`ui::BACK`] to the menu that asked.
fn select_record(title: &str, records: &[Value]) -> Result<Value, String> {
    if records.is_empty() {
        ui::info("Nothing here yet.");
        return Err(ui::BACK.into());
    }
    let mut labels = record_labels(records);
    labels.push("Back".into());
    // The list has a Back of its own, and Escape means the same thing: every one of these is
    // opened from a menu, so leaving the list is returning to it rather than leaving Yougori.
    let index = ui::with_back(|| choose(title, &labels))?;
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
        // The end of creating it: "Return to menu" is the way back, so no second Back row.
        if ui::without_back(|| {
            choose_with_initial("Open this environment now?", "", &["Open environment window".into(), "Return to menu".into()], 0)
        })? == 0 {
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
            && ui::with_back(|| {
                choose_with_note(
                    "Start and open this environment?",
                    "Its shell will use this terminal. Exiting the shell leaves the environment running.",
                    &["Start and open terminal here".into(), "Back".into()],
                )
            })? != 0
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
    // What the person calls it, for the sentence an action leaves behind. The title carries the
    // status too, which belongs over a menu and not in "Deleted Work · running."
    let name = env["name"].as_str().unwrap_or("this environment");
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
                let renamed = ui::with_back(|| text("New name", name, false))?;
                action(&["rename", env_id, &renamed], &format!("Renamed to {}.", clean(&renamed))).await
            }
            8 => async {
                let mut snapshot = String::new();
                in_turn(|step| Some(match step {
                    0 => text("Snapshot name", if snapshot.is_empty() { "before-change" } else { &snapshot }, false).map(|entry| {
                        snapshot = entry;
                        true
                    }),
                    1 => confirm("Create snapshot?", &clean(&title)).map(|()| true),
                    _ => return None,
                }))?;
                action(&["snapshot", "create", env_id, "--name", &snapshot, "--yes"], &format!("Snapshot {} taken of {}.", clean(&snapshot), clean(name))).await
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
                let into = path_text(&folder)?.to_owned();
                action(
                    &["backup", "export", env_id, "--folder", &into, "--yes"],
                    &format!("{} backed up to {}.", clean(name), clean(&into)),
                )
                .await
            }
            .await,
            10 => files(env_id, name).await,
            11 => execute(&["ports", "list", env_id]).await,
            12 => {
                confirm(
                    "Permanently delete this environment?",
                    &format!(
                        "{}\nIts managed data will be permanently deleted.",
                        clean(&title)
                    ),
                )?;
                action(&["rm", env_id, "--yes"], &format!("Deleted {}, and the data it managed.", clean(name))).await
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
                action(
                    &["env", "resources", env_id, "--cpu", &cpu, "--cpu-max", &cpu, "--memory", &memory, "--memory-max", &memory, "--yes"],
                    &format!("{} now has {cpu} CPU and {memory} GB of memory.", clean(name)),
                )
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
            // The first question goes Back to the environment's menu; the wizard offers Back on the rest.
            0 => ui::with_back(|| port("Service port inside this environment", guest_port)).map(|chosen| {
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
        return action(&["download", "off", env_id], &format!("Download link for {} turned off.", clean(env["name"].as_str().unwrap_or("this environment")))).await;
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
    // Everything that can be refused is settled before anything is stopped.
    let mut args = vec![env_id.to_owned(), "--yes".to_owned()];
    if choice > 0 {
        let host = domains[choice - 1].domain["hostname"].as_str().ok_or("That saved domain has no address. Choose another, or the quick public link.")?;
        args.extend(["--domain".to_owned(), host.to_owned()]);
    }
    let name = clean(env["name"].as_str().unwrap_or("this environment"));
    if needs_stop {
        execute(&["stop", env_id]).await?;
    }
    // The link lives only while this waits: it shows the address, counts downloads and turns the
    // link off at Ctrl+C, then comes back here. It answers Ctrl+C itself, so nothing races it for
    // the key and leaves the link answering until its lease runs out.
    ui::pause(true);
    let held = yougori_cli::downloads::run(&args).await;
    ui::pause(false);
    match held {
        Ok(()) => Ok(()),
        // Stopped only for this copy: the person decides whether it runs again.
        Err(error) if needs_stop => after_failed_download(&name, env_id, &error).await,
        Err(error) => Err(error),
    }
}

/// The environment was stopped to make a download link that did not work. It was running a moment
/// ago and the person never meant to leave it stopped, so they are asked, with starting it again
/// first.
async fn after_failed_download(name: &str, env_id: &str, error: &str) -> Result<(), String> {
    let picked = ui::without_back(|| {
        ui::select(
            &format!("{name} is stopped"),
            &[format!("The download link did not work: {}", clean(error))],
            &[ui::Choice::new(format!("Start {name} again"), "as it was before"), ui::Choice::new("Leave it stopped", "")],
            0,
        )
    });
    if matches!(picked, Ok(0)) {
        return execute(&["start", env_id]).await;
    }
    ui::info(&format!("{name} stays stopped. Start it again from its menu, or with yougori start {}.", shell_words::quote(env_id)));
    Ok(())
}

/// Starting at sign-in, changed (or only read, with `None`) and said in one sentence.
async fn sign_in_startup(enable: Option<bool>, dashboard: bool) -> Result<(), String> {
    let label = if enable.is_some() { "Updating sign-in startup" } else { "Loading startup settings" };
    let setting = engine_action(label, crate::autostart(enable, dashboard)).await?;
    ui::info(match (enable, setting["mode"].as_str()) {
        (Some(false), _) => "Yougori will no longer start when you sign in.",
        (Some(true), Some("dashboard")) => "Yougori will start when you sign in, and open its dashboard.",
        (Some(true), _) => "Yougori will start its background engine when you sign in.",
        (None, Some("dashboard")) => "Yougori starts when you sign in, and opens its dashboard.",
        (None, Some("background engine")) => "Yougori starts its background engine when you sign in.",
        (None, _) => "Yougori does not start when you sign in.",
    });
    Ok(())
}

/// The environment's files and shared folders until Back, which returns [`ui::BACK`].
async fn files(env: &str, name: &str) -> Result<(), String> {
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
                        &format!("{}\nInto {}", clean(text), clean(name)),
                    )).map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => {
                        let from = path_text(&path)?.to_owned();
                        action(&["cp", &from, env], &format!("Copied {} into {}.", clean(&from), clean(name))).await
                    }
                    Err(error) => Err(error),
                }
            }
            2 => copy_to_pc(env, name).await,
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
                            "{}\nWith {}\n{}",
                            clean(text),
                            clean(name),
                            if writable {
                                "The environment can change files in this folder."
                            } else {
                                "The environment can read files in this folder."
                            }
                        ),
                    )).map(|()| true),
                    _ => return None,
                })) {
                    Ok(()) => {
                        let shared = path_text(&folder)?.to_owned();
                        action(
                            &["share", "add", env, "--path", &shared, "--read-only", if writable { "false" } else { "true" }, "--yes"],
                            &format!("{} shared with {}, {}.", clean(&shared), clean(name), if writable { "read and write" } else { "read only" }),
                        )
                        .await
                    }
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
async fn copy_to_pc(env: &str, name: &str) -> Result<(), String> {
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
                .and_then(|text| confirm("Copy to this PC?", &format!("{} from {}\nTo {}", clean(&source), clean(name), clean(text))))
                .map(|()| true),
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let into = path_text(&folder)?.to_owned();
    action(
        &["cp", &format!("{env}:{source}"), &into],
        &format!("Copied {} from {} to {}.", clean(&source), clean(name), clean(&into)),
    )
    .await
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
        match ui::with_back(|| choose_with_note("Environment files", &path, &choices))? {
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
            // Asked straight from the menu and then handed to the model launcher, which does
            // not come back here. Escape has to return to the menu rather than leave.
            match ui::with_back(|| text("Hugging Face model (OWNER/MODEL or link)", "", false)) {
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
            picked @ (1 | 2 | 4) => saved_item(picked).await,
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
                    Ok(()) => {
                        let from = path_text(&file)?.to_owned();
                        action(&["backup", "import", &from, "--yes"], &format!("{} imported as a new environment.", clean(&from))).await
                    }
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
async fn saved_item(picked: usize) -> Result<(), String> {
    let state = state().await?;
    let (key, group, verb) = if picked == 4 {
        ("backupRuns", "backup", "restore")
    } else {
        (
            "snapshots",
            "snapshot",
            if picked == 1 { "restore" } else { "delete" },
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
    let called = clean(record["name"].as_str().unwrap_or("it")).to_string();
    let done = match (group, verb) {
        ("backup", _) => format!("Restored from the cloud backup {called}."),
        (_, "restore") => format!("Restored from the snapshot {called}."),
        _ => format!("Deleted the snapshot {called}."),
    };
    action(&[group, verb, id(&record)?, "--yes"], &done).await
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
            action(&["neocloud", "install", "--provider", "runpod", "--yes"], "RunPod CLI installed.").await
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
                    Ok(()) => {
                        let into = path_text(&folder)?.to_owned();
                        action(&["storage", "location", "--set", &into, "--yes"], &format!("Yougori now keeps its storage in {}.", clean(&into))).await
                    }
                    Err(error) => Err(error),
                }
            }
            4 => execute(&["gpu", "status"]).await,
            5 => {
                confirm(
                    "Install GPU runtime?",
                    "Installs or updates Yougori's dedicated NVIDIA CUDA runtime.",
                )?;
                action(&["gpu", "setup", "--yes"], "GPU runtime installed. Environments that ask for a GPU can use it now.").await
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
                0 => sign_in_startup(None, false).await,
                1 => sign_in_startup(Some(true), false).await,
                2 => sign_in_startup(Some(true), true).await,
                3 => sign_in_startup(Some(false), false).await,
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
                "Company Access Grid — sign-in, approvals and agent setup",
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
            5 => access_grid().await,
            _ => return Ok(()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// One grid's status. With more than one grid on this computer the status cannot guess which,
/// and a menu has no `--grid` to type, so the grid is chosen here first, with Back.
async fn one_grid_status() -> Result<(), String> {
    let listed = busy("Looking for the grids on this computer", async {
        client::start(None).await?;
        call("grids_realm", json!({"request": {"do": "list"}})).await
    })
    .await?;
    let grids = listed["found"].as_array().cloned().unwrap_or_default();
    if grids.len() < 2 {
        return execute(&["grids", "status"]).await;
    }
    let mut choices: Vec<String> = grids.iter().map(|grid| clean(grid["name"].as_str().unwrap_or("Unnamed grid"))).collect();
    choices.push("Back".into());
    let picked = ui::with_back(|| choose_with_initial("Which grid?", "", &choices, 0))?;
    let Some(grid) = grids.get(picked) else { return Err(ui::BACK.into()) };
    let which = grid["handle"].as_str().or_else(|| grid["name"].as_str()).ok_or("That grid has no name to ask it by.")?;
    execute(&["grids", "status", "--grid", which]).await
}

/// The four grids in one place: the Closed Neo Grid, the Sandbox Grid, the Access Grid and
/// Swarm Mining. This is the first entry that names all four together. Nothing here starts a
/// research worker; `yougori start bounty` keeps that, with its own questions.
async fn grids() -> Result<(), String> {
    loop {
        let result = match menu(
            "Grids",
            &[
                "Every grid on this computer",
                "One grid's status",
                "What each grid is allowed to do",
                "Command reference for grids",
                "Back",
            ],
        )? {
            0 => execute(&["grids", "list"]).await,
            1 => one_grid_status().await,
            2 => {
                ui::info("A grid is asked only what it does: models, desks, credentials or research.");
                for noun in yougori_cli::grids::NOUNS.iter().filter(|noun| **noun != "realm") {
                    let doing: Vec<&str> = yougori_cli::grids::verbs_of(noun)
                        .first()
                        .map(|verb| verb.needs.iter().map(|capability| capability.doing()).collect())
                        .unwrap_or_default();
                    let allowed = if doing.is_empty() { "any grid".to_owned() } else { format!("a grid that can {}", yougori_cli::grids::join_words(&doing)) };
                    ui::line(&format!("{noun}: {allowed}"));
                }
                execute(&["grids", "list"]).await
            }
            3 => execute(&["grids", "--help"]).await,
            _ => return Ok(()),
        };
        // Back from an action returns to this menu.
        if !went_back(result)? {
            return Ok(());
        }
    }
}

/// The company's Access Grid: credentials agents use without seeing them. Hosting, people,
/// credentials and rules are managed in the app or with `yougori access …`.
async fn access_grid() -> Result<(), String> {
    loop {
        let result = match menu(
            "Access Grid",
            &[
                "Status — your sign-in and what your agents may use",
                "Requests — what waits for an approver",
                "Activity — uses, decisions and changes",
                "Agent setup — connect an MCP client",
                "Back",
            ],
        )? {
            0 => execute(&["access", "status"]).await,
            1 => execute(&["access", "requests"]).await,
            2 => execute(&["access", "log"]).await,
            3 => {
                ui::info("Sign in first, in the app's Access Grid section or with yougori access signin --invite INVITE --username NAME.");
                ui::info("For a local stdio MCP client, use this server configuration:");
                let executable = std::env::current_exe().map_err(|e| e.to_string())?;
                let config = json!({"mcpServers":{"yougori-access":{"command":executable,"args":["access","mcp"]}}});
                for line in serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?.lines() {
                    ui::line(line);
                }
                ui::info("Agents then use company credentials through Access Grid and never see their values.");
                menu("Agent setup", &["Back"])?;
                Err(ui::BACK.into())
            }
            // Opened from MCP Vault: Back returns there, not to the home menu.
            _ => return Err(ui::BACK.into()),
        };
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
        let selected = match ui::without_back(|| choose_with_initial(
            "Yougori",
            "",
            &[
                "Overview — environments, services and jobs",
                "Run a project — choose a Node.js or Python folder",
                "Create an environment — container, GPU, microVM or VM",
                "Manage an environment — terminal, start, stop, files and backups",
                "Models — run, chat and API access",
                "Grids — models, desks, credentials and research in one place",
                "Neocloud — RunPod account, prices and deployments",
                "MCP Vault — vault, approvals and MCP connections",
                "Snapshots and backups — browse, restore and import saved data",
                "Connections and sharing — private connections, shares and ports",
                "Set up my domains — save domains and connect your apps",
                "Yougori settings and tools — storage, startup, updates and diagnostics",
                "Command reference — available commands and usage examples",
                "Exit — keep workloads running",
            ]
            .map(String::from),
            0,
        )) {
            Ok(index) => index,
            Err(e) if left(&e) => break,
            Err(e) => return Err(e),
        };
        // The list above is dispatched by position, so an entry inserted into it moves every
        // one below it: this guard and the arms underneath are renumbered with it, together.
        if selected == 13 {
            break;
        }
        let result: Result<(), String> = async {
            match selected {
                0 => execute(&["status"]).await,
                1 => {
                    // Held across the await: the folder question and the run that follows both
                    // sit inside this menu, so Escape returns here instead of dropping the person
                    // out of the launcher. The guard puts the flag back even if either step
                    // returns early, which a plain restore after the call would not.
                    let _offering = ui::Offering::new();
                    let (folder, change) = project_folder()?;
                    project::run_in(&folder, change).await?;
                    Ok(())
                }
                2 => create().await,
                3 => manage().await,
                4 => models().await,
                5 => grids().await,
                6 => neocloud().await,
                7 => vault().await,
                8 => backups().await,
                9 => connections().await,
                10 => domains::run().await,
                11 => system().await,
                12 => execute(&["help"]).await,
                _ => Ok(()),
            }
        }
        .await;
        match result {
            // Leaving a question or going Back from a menu returns here.
            Err(e) if left(&e) => {}
            // A cancellation that says what it left behind is a note, not a failure.
            Err(e) if yougori_cli::wire::cancellation(&e).is_some() => {
                let said = yougori_cli::wire::cancellation(&e).unwrap_or_default();
                if !said.is_empty() {
                    ui::info(&ui::muted(&clean(&said)));
                }
            }
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

    /// PROVES that Ctrl+C during a menu action is answered rather than ending the process, and
    /// that both ways of stopping are told to the person in the same words.
    ///
    /// The press used to reach this process as a signal and end it where it stood. What that
    /// left behind was the state the painter was in at that instant: a hidden cursor nothing put
    /// back, and the last spinner frozen on the screen under a shell prompt. The menu now waits
    /// on the press itself, so there is an outcome to decide rather than a process to bury, and
    /// this is that decision.
    ///
    /// DOES NOT PROVE that the action was undone. Nothing here knows whether the engine had the
    /// request, which is exactly why the sentence below does not claim it either.
    #[test]
    fn stopping_a_menu_action_is_answered_rather_than_ending_the_process() {
        // Ctrl+C before the command finished, and a command that stopped itself, are one answer.
        assert_eq!(outcome(None), Err(ui::CANCELLED.into()));
        assert_eq!(outcome(Some(Ok(130))), Err(ui::CANCELLED.into()));
        // And that answer is one the menu treats as leaving a question, not as a failure.
        assert!(left(&outcome(None).unwrap_err()));

        assert_eq!(outcome(Some(Ok(0))), Ok(()));
        assert_eq!(outcome(Some(Err("The engine stopped".into()))), Err("The engine stopped".into()));
        let other = outcome(Some(Ok(2))).unwrap_err();
        assert!(other.contains("status 2") && !left(&other), "{other}");

        // The note names what was being waited for and where to look, and claims nothing about
        // whether it happened.
        let said = stopped_waiting(activity_label(&["rm".into(), "env-1".into()]));
        assert!(said.starts_with("Deleting environment"), "{said}");
        assert!(said.contains("yougori ps"), "{said}");
        for claim in ["undone", "cancelled", "nothing was"] {
            assert!(!said.to_lowercase().contains(claim), "it does not claim what it cannot know: {said}");
        }
    }

    /// PROVES that a list somebody chooses from shows names, and shows an identifier only where
    /// a name does not tell two things apart.
    ///
    /// Every line used to end in the identifier — the longest and least memorable part of a line
    /// whose whole job is to be recognised at a glance, and on a narrow terminal it pushed the
    /// name and the status off the side. The identifier is useful in exactly one case, which is
    /// the one it now appears in.
    #[test]
    fn a_list_shows_names_and_falls_back_to_an_identifier_only_to_tell_two_apart() {
        let records = vec![
            json!({"name": "Work", "status": "running", "id": "env-7f3a9c2d1b4e"}),
            json!({"name": "Notes", "status": "stopped", "id": "env-aa11bb22cc33"}),
        ];
        assert_eq!(record_labels(&records), ["Work — running", "Notes — stopped"]);

        // Two called the same thing: those two carry enough to tell them apart, and the one
        // with a name of its own is left alone.
        let records = vec![
            json!({"name": "api", "status": "running", "id": "env-7f3a9c2d1b4e"}),
            json!({"name": "api", "status": "stopped", "id": "env-aa11bb22cc33"}),
            json!({"name": "Notes", "status": "stopped", "id": "env-dd44ee55ff66"}),
        ];
        assert_eq!(record_labels(&records), ["api — running · 2d1b4e", "api — stopped · 22cc33", "Notes — stopped"]);

        // Nothing named, nothing known: still a line, never an empty one.
        assert_eq!(record_labels(&[json!({})]), ["Unnamed — saved"]);
        // A short or missing identifier is shown whole rather than panicking on a byte index,
        // and a multi-byte name is cut on characters.
        assert_eq!(tail("env-1"), "env-1");
        assert_eq!(tail(""), "");
        assert_eq!(tail("ααααααααα"), "αααααα");
    }

    /// PROVES that an action is carried out through the same door the CLI itself would use.
    ///
    /// There are two, and they are not interchangeable. `public::handle` owns the short verbs and
    /// does work around the request that the parser knows nothing about; everything else is
    /// parsed into one request and sent. Choosing the wrong one does not fail loudly — it
    /// quietly does less than the typed command would — so the one thing worth pinning is that
    /// the question asked here is the same question the CLI asks.
    #[test]
    fn an_action_goes_through_the_same_door_a_typed_command_would() {
        for verb in ["rm", "cp", "rename", "logs", "inspect"] {
            assert!(public::COMMANDS.contains(&verb), "{verb} is one of public's, and must stay one");
        }
        for verb in ["snapshot", "backup", "share", "download", "env", "gpu", "storage", "neocloud", "app"] {
            assert!(!public::COMMANDS.contains(&verb), "{verb} is parsed into one request; if it moves, carry_out has to move with it");
        }
        // And every action the menu runs has an activity label, so the spinner and the note
        // after a stopped wait both name what was happening rather than saying "working".
        for args in [
            vec!["rm", "env-1", "--yes"],
            vec!["rename", "env-1", "new"],
            vec!["cp", "a", "env-1"],
            vec!["snapshot", "create", "env-1"],
            vec!["snapshot", "restore", "snap-1"],
            vec!["snapshot", "delete", "snap-1"],
            vec!["backup", "export", "env-1"],
            vec!["backup", "import", "file"],
            vec!["backup", "restore", "run-1"],
            vec!["share", "add", "env-1"],
            vec!["env", "resources", "env-1"],
            vec!["gpu", "setup", "--yes"],
            vec!["storage", "location", "--set", "D:\\"],
            vec!["neocloud", "install", "--provider", "runpod"],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            let label = activity_label(&args);
            assert!(!label.is_empty() && label != "Working", "{args:?} has no label of its own");
        }
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
