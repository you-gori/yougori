//! A terminal home over the existing commands, not a second runtime or settings store.
use crate::{cli_ui as ui, public};
use serde_json::{json, Value};
use std::{
    io::{self, IsTerminal},
    process::Stdio,
};

fn cancelled(error: &str) -> bool {
    error == ui::BACK || error == ui::CANCELLED || crate::wire::cancellation(error).is_some()
}

fn text(value: &Value, key: &str) -> String {
    // Names and engine errors are data, never terminal escape sequences.
    value[key]
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

fn pick(title: &str, items: &[(&str, &str)]) -> Result<usize, String> {
    let choices: Vec<_> = items
        .iter()
        .map(|(label, hint)| ui::Choice::new(*label, *hint))
        .collect();
    ui::without_back(|| ui::select(title, &[], &choices, 0))
}

fn field(title: &str, initial: &str) -> Result<String, String> {
    ui::input_prefilled(title, initial, &|s| {
        let s = s.trim();
        if s.chars().any(char::is_control) {
            Err("Use a single line.".into())
        } else {
            Ok(s.into())
        }
    })
}

fn required(title: &str) -> Result<String, String> {
    ui::input(title, "", false, &|s| {
        let s = s.trim();
        if s.is_empty() || s.starts_with('-') || s.chars().any(char::is_control) {
            Err("Enter a name or path, not an option.".into())
        } else {
            Ok(s.into())
        }
    })
}

fn switch(title: &str, note: &str, enabled: bool) -> Result<bool, String> {
    ui::select(
        title,
        &[note.into()],
        &[
            ui::Choice::new("Off", "Disabled"),
            ui::Choice::new("On", "Enabled"),
        ],
        usize::from(enabled),
    )
    .map(|i| i == 1)
}

fn confirm(title: &str, note: &str) -> Result<bool, String> {
    pick(
        title,
        &[
            ("Cancel", "Return without changing anything"),
            ("Continue", note),
        ],
    )
    .map(|i| i == 1)
}

fn report(result: Result<(), String>) {
    if let Err(error) = result {
        if cancelled(&error) {
            ui::take_interrupt();
        } else {
            ui::warn(
                &error
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>(),
            );
        }
    }
}

/// Give the child sole ownership of terminal input and painting. In particular, do not run
/// Interrupts::watch here: it would steal keys from model chat and setup questions.
async fn command(args: &[&str]) -> Result<(), String> {
    ui::info(&format!("yougori {}", args.join(" ")));
    let status = {
        let _paused = ui::Paused::new();
        let mut child =
            tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
                .args(args)
                .env_remove("YOUGORI_HUB_CONSOLE")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("Cannot start the command: {e}"))?;
        loop {
            tokio::select! {
                status = child.wait() => break status.map_err(|e| e.to_string())?,
                // The child receives Ctrl+C as well and owns its cancellation/cleanup.
                _ = tokio::signal::ctrl_c() => {}
            }
        }
    };
    ui::take_interrupt();
    if !status.success() {
        ui::warn(
            "The command ended without completing. Read its message above; it was not retried.",
        );
    }
    Ok(())
}

async fn read(method: &str, params: Value) -> Result<Value, String> {
    ui::busy("Reading current state", public::send(method, params, false))
        .await
        .map_err(|error| {
            format!("{error} If the engine is stopped, use Yougori settings → Start engine.")
        })
}

async fn vm(params: Value) -> Result<Value, String> {
    ui::busy(
        "Applying your Sandbox VM choice",
        public::send("sandbox_vm", params, true),
    )
    .await
}

#[derive(Debug, Default)]
struct Launch {
    image: String,
    cpu: String,
    memory: String,
    workspace: String,
    routes: String,
    tree: bool,
    ask: bool,
    grid_hosting: Vec<usize>,
    gpu: bool,
}

impl Launch {
    fn request(&self) -> Result<Value, String> {
        let cpu: u64 = self
            .cpu
            .parse()
            .map_err(|_| "CPU must be a whole number.")?;
        let memory: f64 = self.memory.parse().map_err(|_| "Enter RAM in GB.")?;
        if !(1..=255).contains(&cpu) || !memory.is_finite() || !(0.5..=64.0).contains(&memory) {
            return Err(
                "Choose 1–255 CPUs and 0.5–64 GB RAM. The engine checks available capacity.".into(),
            );
        }
        let mut value = json!({"action":"launch", "cpu":cpu, "memoryGb":memory});
        if self.gpu {
            if memory < 4.0 { return Err("GPU VMs require at least 4 GB RAM.".into()); }
            value["gpu"] = json!(true);
        }
        if !self.grid_hosting.is_empty() {
            value["gridHosting"] = json!(self.grid_hosting.iter().map(|i| ["gpu", "sandbox"][*i]).collect::<Vec<_>>());
        }
        if !self.image.is_empty() {
            value["image"] = json!(self.image);
        }
        if !self.workspace.is_empty() {
            if !std::path::Path::new(&self.workspace).is_dir() {
                return Err("The workspace folder does not exist.".into());
            }
            value["workspace"] = json!(self.workspace);
        }
        if !self.routes.is_empty() {
            let file = std::fs::File::open(&self.routes)
                .map_err(|e| format!("Cannot read the routes file: {e}"))?;
            use std::io::Read;
            let routes: Value = serde_json::from_reader(file.take(1024 * 1024))
                .map_err(|e| format!("Invalid routes JSON: {e}"))?;
            if !routes.is_array() {
                return Err("Routes must be a JSON array.".into());
            }
            value["routes"] = routes;
        }
        Ok(value)
    }
}

/// Display metadata only; launch still uses the exact engine-owned digest.
fn image_name(image: &Value) -> String {
    let source = &image["source"];
    let repository = text(source, "repository");
    if !repository.is_empty() {
        let repository = repository.strip_prefix("library/").unwrap_or(&repository);
        let reference = text(source, "reference");
        return if reference.starts_with("sha256:") {
            format!("{repository} (pinned)")
        } else if reference.is_empty() {
            repository.into()
        } else {
            format!("{repository}:{reference}")
        };
    }
    let process = &image["image"]["process"];
    // Imported tool images carry their public build description in TOOL_SPEC. Read only its
    // package/kind, never render the environment (which can contain credentials).
    let spec = process["env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(|s| s.strip_prefix("TOOL_SPEC="))
        .filter(|s| s.len() <= 16384)
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    if let Some(spec) = spec {
        let package = text(&spec, "package");
        let name = if package.is_empty() {
            text(&spec, "kind")
        } else {
            package.rsplit('/').next().unwrap_or(&package).into()
        };
        if !name.is_empty() {
            let name = name.replace(['-', '_'], " ");
            let mut chars = name.chars();
            return chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default();
        }
    }
    if process["entrypoint"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| s.as_str() == Some("/opt/solver/vm_guest.py"))
    {
        return "Inference Solver base".into();
    }
    "Imported image".into()
}

fn image_choices(images: &[Value]) -> Vec<ui::Choice> {
    let names: Vec<_> = images.iter().map(image_name).collect();
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    let mut choices = vec![ui::Choice::new(
        "Minimal Linux guest",
        "Built-in Sandbox VM",
    )];
    for (image, name) in images.iter().zip(&names) {
        let count = seen.entry(name).or_default();
        *count += 1;
        let label = if names.iter().filter(|other| *other == name).count() > 1 {
            format!("{name} (saved build {count})")
        } else {
            name.clone()
        };
        let hint = if image["error"].is_string() {
            text(image, "error")
        } else if image["source"]["kind"] == "registry" {
            "Imported OCI image".into()
        } else {
            "Saved application image".into()
        };
        let choice = ui::Choice::new(label, hint);
        choices.push(if image["error"].is_string() {
            choice.disabled()
        } else {
            choice
        });
    }
    choices
}

async fn launch() -> Result<(), String> {
    let images = read("sandbox_vm", json!({"action":"image","operation":"list"})).await?;
    let images = images
        .as_array()
        .ok_or("The engine did not return an image list.")?;
    let choices = image_choices(images);
    let capabilities = read("sandbox_vm", json!({"action":"capabilities"})).await?;
    let gpu_available = capabilities["gpu"]["available"] == true;
    let mut form = Launch {
        cpu: "2".into(),
        memory: "2".into(),
        ..Default::default()
    };
    let mut image_at = 0;
    {
        let mut wizard = ui::Wizard::new();
        loop {
            let asked = match wizard.step() {
                0 => ui::select(
                    "Choose a Sandbox VM image",
                    &[
                        "These are saved images, not running VMs.".into(),
                        "Import other OCI images from the Sandbox VMs menu.".into(),
                        if gpu_available { "GPU acceleration is available; choose it in the next steps.".into() } else { text(&capabilities["gpu"], "reason") },
                    ],
                    &choices,
                    image_at,
                )
                .map(|i| {
                    image_at = i;
                    form.image = if i == 0 {
                        String::new()
                    } else {
                        text(&images[i - 1], "id")
                    };
                    true
                }),
                1 => ui::input_prefilled("CPU cores", &form.cpu, &|s| {
                    s.parse::<u64>()
                        .ok()
                        .filter(|n| (1..=255).contains(n))
                        .map(|n| n.to_string())
                        .ok_or("Choose 1–255 cores.".into())
                })
                .map(|s| {
                    form.cpu = s;
                    true
                }),
                2 => ui::input_prefilled("Memory in GB", &form.memory, &|s| {
                    s.parse::<f64>()
                        .ok()
                        .filter(|n| n.is_finite() && (0.5..=64.0).contains(n))
                        .map(|n| n.to_string())
                        .ok_or("Choose 0.5–64 GB.".into())
                })
                .map(|s| {
                    form.memory = s;
                    true
                }),
                3 => ui::input_prefilled(
                    "Folder to copy into the VM (optional)",
                    &form.workspace,
                    &|s| {
                        let s = s.trim().trim_matches('"');
                        if s.is_empty() || std::path::Path::new(s).is_dir() {
                            Ok(s.into())
                        } else {
                            Err("Choose an existing folder, or leave this empty.".into())
                        }
                    },
                )
                .map(|s| {
                    form.workspace = s;
                    true
                }),
                4 => switch(
                    "Show this computer's file tree?",
                    "Names only. This does not grant access to file contents.",
                    form.tree,
                )
                .map(|v| {
                    form.tree = v;
                    true
                }),
                5 => switch(
                    "Allow the VM to request host-file access?",
                    "Each path needs your approval: read or read/write, once or until revoked.",
                    form.ask,
                )
                .map(|v| {
                    form.ask = v;
                    true
                }),
                6 => field(
                    "Network routes JSON file (empty = networking off)",
                    &form.routes,
                )
                .and_then(|s| {
                    form.routes = s.trim_matches('"').into();
                    form.request().map(|_| true)
                }),
                7 => ui::multiselect("Add Grid Hosting", &["Install grid tools and an AI skill. No hardware is shared automatically; GPU acceleration is a separate choice.".into()], &[
                    ui::Choice::new("GPU Grid", "Accept contributed model servers"),
                    ui::Choice::new("Sandbox Grid", "Schedule work using contributed CPU and memory"),
                ], &form.grid_hosting, false).map(|picked| { form.grid_hosting = picked; true }),
                8 if gpu_available => switch("Enable GPU acceleration in this VM?", "CUDA runs inside a separate VM. The GPU is shared with the PC; Windows asks to approve the VM helper.", form.gpu)
                    .map(|enabled| { form.gpu=enabled; if enabled && form.memory.parse::<f64>().unwrap_or(0.)<4. {form.memory="4".into();} true }),
                _ => break,
            };
            wizard.next(asked)?;
        }
    }
    let request = form.request()?;
    let summary = format!(
        "{} cores · {} GB RAM · folder copy: {} · tree: {} · access requests: {} · network: {}",
        form.cpu,
        form.memory,
        if form.workspace.is_empty() {
            "none"
        } else {
            &form.workspace
        },
        form.tree,
        form.ask,
        if form.routes.is_empty() {
            "off"
        } else {
            "declared routes only"
        }
    );
    ui::info("A copied folder changes on this computer only after you review and promote files.");
    if !confirm("Launch this Sandbox VM?", &summary)? {
        return Ok(());
    }
    let result = vm(request).await?;
    let id = result["sandbox"]
        .as_str()
        .ok_or("The launch returned no sandbox ID. Check sandbox status before retrying.")?;
    ui::step(&format!("Sandbox VM ready: {id}"));
    // Defaults grant nothing. If applying the chosen switches fails, keep the new VM visible
    // and report its ID; never launch it again or stop unrelated workloads.
    if form.tree || form.ask {
        vm(json!({"action":"host_access","sandbox":id,"operation":"policy",
            "policy":{"treeVisible":form.tree,"askForAccess":form.ask}})).await
            .map_err(|e| format!("VM {id} was created, but its host-access switches were not applied: {e}. Manage it under Sandbox VMs."))?;
    }
    sandbox_actions(id).await
}

async fn select_sandbox() -> Result<String, String> {
    let state = read("sandbox_vm", json!({"action":"status"})).await?;
    let rows = state["sandboxes"]
        .as_array()
        .ok_or("The engine did not return its Sandbox VMs.")?;
    choose_record("Choose a Sandbox VM", rows, "sandbox", "state")
}

fn choose_record(
    title: &str,
    rows: &[Value],
    id_key: &str,
    hint_key: &str,
) -> Result<String, String> {
    if rows.is_empty() {
        return Err("Nothing here yet. Create one from the menu first.".into());
    }
    let choices: Vec<_> = rows
        .iter()
        .map(|row| {
            let name = text(row, "name");
            let id = text(row, id_key);
            ui::Choice::new(
                if name.is_empty() { id.clone() } else { name },
                format!("{} · {id}", text(row, hint_key)),
            )
        })
        .collect();
    let i = ui::with_back(|| ui::select(title, &[], &choices, 0))?;
    rows[i][id_key]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or("This record has no ID.".into())
}

async fn access(id: &str) -> Result<(), String> {
    let state = read(
        "sandbox_vm",
        json!({"action":"host_access","sandbox":id,"operation":"status"}),
    )
    .await?;
    let tree = switch(
        "Show the computer's file tree?",
        "Names only; no file contents.",
        state["policy"]["treeVisible"] == true,
    )?;
    let ask = switch(
        "Allow requests to access host files?",
        "Every requested path still needs approval.",
        state["policy"]["askForAccess"] == true,
    )?;
    if confirm(
        "Save these permission switches?",
        &format!("File tree: {tree} · Allow requests: {ask}"),
    )? {
        vm(
            json!({"action":"host_access","sandbox":id,"operation":"policy",
            "policy":{"treeVisible":tree,"askForAccess":ask}}),
        )
        .await?;
    }
    Ok(())
}

async fn sandbox_actions(id: &str) -> Result<(), String> {
    loop {
        let choice = match pick(
            &format!("Sandbox VM · {id}"),
            &[
                ("Run a command", "Inside this isolated VM"),
                ("Review workspace", "Inspect changed files and diffs"),
                (
                    "Host-file switches",
                    "Tree visibility and permission requests",
                ),
                ("Permissions", "View pending requests and existing grants"),
                ("Stop VM", "Stop this VM only"),
                ("Back", "Sandbox VMs"),
            ],
        ) {
            Ok(i) => i,
            Err(e) if cancelled(&e) => {
                ui::take_interrupt();
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let outcome = match choice {
            0 => {
                async {
                    let input = required("Command to run in the guest")?;
                    // Shell text belongs to the guest, never a host shell/argument expansion.
                    command(&["sandbox", "exec", id, "--input", &input, "--yes"]).await
                }
                .await
            }
            1 => command(&["sandbox", "review", id]).await,
            2 => access(id).await,
            3 => permissions(id).await,
            4 => {
                if confirm("Stop this Sandbox VM?", id)? {
                    command(&["sandbox", "stop", id, "--yes"]).await?;
                    return Ok(());
                }
                Ok(())
            }
            _ => return Ok(()),
        };
        report(outcome);
    }
}

async fn permissions(id: &str) -> Result<(), String> {
    let state = read(
        "sandbox_vm",
        json!({"action":"host_access","sandbox":id,"operation":"status"}),
    )
    .await?;
    match pick(
        "Host-file permissions",
        &[
            ("Back", "Keep permissions unchanged"),
            (
                "Approve a request",
                "Choose read or read/write, once or until revoked",
            ),
            ("Deny a request", "Refuse this requested path"),
            ("Revoke a grant", "Remove existing access"),
        ],
    )? {
        0 => Ok(()),
        action => {
            let key = if action == 3 { "grant" } else { "request" };
            let rows: Vec<_> = state[if action == 3 { "grants" } else { "requests" }]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| action == 3 || row["state"] == "pending")
                .cloned()
                .collect();
            if rows.is_empty() {
                ui::info("No pending requests or grants for this action.");
                return Ok(());
            }
            let choices: Vec<_> = rows
                .iter()
                .map(|row| {
                    ui::Choice::new(
                        text(row, "path"),
                        format!("{} · {}", text(row, "mode"), text(row, "duration")),
                    )
                })
                .collect();
            let index = ui::with_back(|| {
                ui::select(
                    "Choose the exact host path",
                    &["A folder approval includes its descendants.".into()],
                    &choices,
                    0,
                )
            })?;
            let row = &rows[index];
            let target = row["id"]
                .as_str()
                .ok_or("This permission record has no ID.")?;
            let mut params = json!({"action":"host_access","sandbox":id,
                "operation":match action { 1=>"approve", 2=>"deny", _=>"revoke" }});
            params[key] = json!(target);
            if action == 1 {
                let mode = if row["mode"] == "read_write" {
                    pick(
                        "Access to the requested path",
                        &[
                            ("Read", "Read contents"),
                            ("Read and write", "May change actual host files"),
                        ],
                    )?
                } else {
                    0
                };
                let duration = pick(
                    "How long?",
                    &[
                        ("Once", "One access"),
                        ("Until revoked", "Persistent for this VM"),
                    ],
                )?;
                params["mode"] = json!(if mode == 0 { "read" } else { "read_write" });
                params["duration"] = json!(if duration == 0 { "once" } else { "always" });
            }
            let summary = format!(
                "{} · {} · {} · {}",
                text(&params, "operation"),
                text(row, "path"),
                text(&params, "mode"),
                text(&params, "duration")
            );
            if confirm("Apply this permission decision?", &summary)? {
                vm(params).await?;
            }
            Ok(())
        }
    }
}

async fn sandboxes() -> Result<(), String> {
    loop {
        let choice = pick(
            "Sandbox VMs",
            &[
                ("Manage a Sandbox VM", "Commands, workspace and permissions"),
                ("New Sandbox VM", "Image, resources, files and network"),
                (
                    "Import OCI image",
                    "Import an OCI layout through a disposable VM",
                ),
                ("Check VM readiness", "Read-only launch preflight"),
                ("Back", "Home"),
            ],
        )?;
        let outcome = match choice {
            0 => {
                async {
                    let id = select_sandbox().await?;
                    sandbox_actions(&id).await
                }
                .await
            }
            1 => launch().await,
            2 => {
                async {
                    let path = required("OCI layout folder")?;
                    let size = ui::input("Image root size in GB", "2", false, &|s| {
                        s.parse::<u64>()
                            .ok()
                            .filter(|n| (1..=64).contains(n))
                            .map(|n| n.to_string())
                            .ok_or("Choose 1–64 GB.".into())
                    })?;
                    if confirm("Import this OCI image?", &path)? {
                        command(&[
                            "sandbox",
                            "image",
                            "import",
                            "--layout",
                            &path,
                            "--root-gb",
                            &size,
                            "--owner-selected",
                            "true",
                            "--yes",
                        ])
                        .await?;
                    }
                    Ok(())
                }
                .await
            }
            3 => command(&["sandbox", "plan"]).await,
            _ => return Ok(()),
        };
        report(outcome);
    }
}

async fn environments(models: bool) -> Result<(), String> {
    let state = read("get_platform_state", json!({})).await?;
    let rows: Vec<_> = state["environments"]
        .as_array()
        .ok_or("The engine returned no environments.")?
        .iter()
        .filter(|e| !models || crate::overview::env_type(e) == "model")
        .cloned()
        .collect();
    let id = choose_record("Choose an environment", &rows, "id", "status")?;
    loop {
        let i = pick(
            &format!("Environment · {id}"),
            &[
                ("Status", "Current state"),
                (
                    if models { "Chat" } else { "Open terminal" },
                    "Exit the session to return here",
                ),
                ("Start", "Start this environment"),
                ("Stop", "Stop this environment"),
                ("Logs", "Recent output"),
                ("Back", "Home"),
            ],
        )?;
        let outcome = match i {
            0 => command(&["inspect", &id]).await,
            1 if models => command(&["model", "chat", &id]).await,
            1 => command(&["terminal", &id]).await,
            2 => command(&["start", "--environment", &id]).await,
            3 => {
                if confirm("Stop this environment?", &id)? {
                    command(&["stop", &id]).await
                } else {
                    Ok(())
                }
            }
            4 => command(&["logs", &id]).await,
            _ => return Ok(()),
        };
        report(outcome);
    }
}

async fn models() -> Result<(), String> {
    loop {
        let result = match pick(
            "Models",
            &[
                ("Run a model", "Guided model setup and chat"),
                ("Manage a model", "Chat, start, stop and inspect"),
                ("GPU status", "Current compute availability"),
                ("Back", "Home"),
            ],
        )? {
            0 => command(&["model", "run"]).await,
            1 => environments(true).await,
            2 => command(&["gpu", "status"]).await,
            _ => return Ok(()),
        };
        report(result);
    }
}

async fn setups() -> Result<(), String> {
    loop {
        let result = match pick("Setups and Hub", &[
            ("Run a template", "Local folder or hub/PUBLISHER/NAME"),
            ("My setups", "List current setups"),
            ("Manage a setup", "Configure, continue, start or stop"),
            ("Search Hub", "Find shared templates"),
            ("Installed tools", "List registered tools"),
            ("Back", "Home"),
        ])? {
            0 => async { let source = required("Template folder or Hub reference")?; command(&["template","run",&source]).await }.await,
            1 => command(&["template","list"]).await,
            2 => async {
                let reply = ui::busy("Reading your setups", crate::hub::run(
                    &["template".into(),"list".into(),"--format".into(),"json".into()])).await?;
                let mut rows: Vec<_> = reply.value["instances"].as_array().into_iter().flatten()
                    .map(|row| json!({"id":row["instance"],"name":row["instance"],"status":row["status"]})).collect();
                rows.extend(reply.value["setups"].as_array().into_iter().flatten()
                    .map(|row| json!({"id":row["id"],"name":row["name"],"status":row["state"]})));
                let name = choose_record("Choose a setup", &rows, "id", "status")?;
                let verbs = ["status","configure","continue","start","stop","logs"];
                let i = pick("Manage setup", &[("Status","Read current state"), ("Configure","Change setup inputs"),
                    ("Continue","Resume an unfinished setup"), ("Start","Start this setup"), ("Stop","Stop this setup"), ("Logs","Recent output"), ("Back","Setups")])?;
                if let Some(verb) = verbs.get(i) {
                    if *verb != "stop" || confirm("Stop this setup?", &name)? {
                        command(&["template",verb,&name]).await?;
                    }
                }
                Ok(())
            }.await,
            3 => async { let query = required("Search templates")?; command(&["template","search",&query]).await }.await,
            4 => command(&["tool","list"]).await,
            _ => return Ok(()),
        };
        report(result);
    }
}

async fn settings() -> Result<(), String> {
    loop {
        let result = match pick(
            "Yougori settings",
            &[
                ("Start engine", "Connect the CLI to Yougori"),
                ("Open desktop app", "Open the dashboard"),
                ("Health check", "Engine, runtimes, GPU, disk and PATH"),
                ("Storage location", "View the current storage drive"),
                ("Check for updates", "Check available versions"),
                ("Command reference", "All CLI commands"),
                ("Back", "Home"),
            ],
        )? {
            0 => command(&["app", "start"]).await,
            1 => command(&["app", "show"]).await,
            2 => command(&["doctor"]).await,
            3 => command(&["storage", "location"]).await,
            4 => command(&["update", "--check"]).await,
            5 => command(&["--help"]).await,
            _ => return Ok(()),
        };
        report(result);
    }
}

pub async fn run() -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !ui::can_prompt() {
        return Err("The menu needs an interactive terminal. Open PowerShell or a terminal and run yougori. For scripts, use yougori --help.".into());
    }
    let _session = ui::Session::start("Yougori", "Your computer, models and setups");
    loop {
        let choice = match pick(
            "Home",
            &[
                ("New Sandbox VM", "Choose image, resources and permissions"),
                ("Sandbox VMs", "Manage isolated VMs and host-file access"),
                ("My environments", "Manage existing environments"),
                ("Models", "Run, chat and manage models"),
                ("Setups and Hub", "Run templates and configure your setups"),
                ("Activity", "Live CPU, memory and workload activity"),
                ("Yougori settings", "Engine, storage, updates and help"),
                ("Exit", "Leave workloads running"),
            ],
        ) {
            Ok(i) => i,
            Err(e) if cancelled(&e) => break,
            Err(e) => return Err(e),
        };
        report(match choice {
            0 => launch().await,
            1 => sandboxes().await,
            2 => environments(false).await,
            3 => models().await,
            4 => setups().await,
            5 => command(&["top"]).await,
            6 => settings().await,
            _ => break,
        });
    }
    ui::take_interrupt();
    ui::outro("Menu closed. Your workloads keep running.");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_defaults_do_not_grant_host_or_network_access() {
        let form = Launch {
            cpu: "2".into(),
            memory: "4".into(),
            ..Default::default()
        };
        assert_eq!(
            form.request().unwrap(),
            json!({"action":"launch","cpu":2,"memoryGb":4.0})
        );
        assert!(!form.tree && !form.ask);
    }

    #[test]
    fn launch_rejects_bad_limits_and_bad_routes_before_any_mutation() {
        for (cpu, memory) in [
            ("0", "2"),
            ("256", "2"),
            ("1.5", "2"),
            ("1", "NaN"),
            ("1", "inf"),
            ("1", "0.1"),
        ] {
            assert!(Launch {
                cpu: cpu.into(),
                memory: memory.into(),
                ..Default::default()
            }
            .request()
            .is_err());
        }
        let folder = tempfile::tempdir().unwrap();
        let routes = folder.path().join("routes.json");
        std::fs::write(&routes, "{}").unwrap();
        let mut form = Launch {
            cpu: "1".into(),
            memory: "2".into(),
            routes: routes.to_string_lossy().into(),
            ..Default::default()
        };
        assert!(form.request().is_err());
        std::fs::write(&routes, "[]").unwrap();
        form.workspace = folder.path().to_string_lossy().into();
        assert_eq!(form.request().unwrap()["routes"], json!([]));
        form.workspace = folder.path().join("missing").to_string_lossy().into();
        assert!(form.request().is_err());
    }

    #[test]
    fn displayed_records_cannot_inject_terminal_controls() {
        assert_eq!(
            text(&json!({"name":"vm\u{1b}[2J\nfake"}), "name"),
            "vm[2Jfake"
        );
    }
}
