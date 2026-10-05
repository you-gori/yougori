//! Chat with a local model in the terminal. Startup phases show as steps, replies stream in as
//! they are written, and the footer shows the model's CPU, memory and GPU. Conversations are the
//! ones the desktop app shows.
use super::{api, call, clean, ui, Footer};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Map, Value};
use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};
use yougori_cli::{client, network, public};

const CODE: ui::Rgb = ui::Rgb(0xa5, 0xb4, 0xfc);

/// `model run MODEL` and `model chat ENV` on a terminal; scripts keep the JSON commands.
pub fn requested(args: &[String]) -> bool {
    args.len() >= 3
        && args[0] == "model"
        && matches!(args[1].as_str(), "run" | "chat")
        && !args.iter().any(|a| matches!(a.as_str(), "--dry-run" | "--help" | "-h"))
        && (args.iter().any(|a| a == "--neocloud") || !args.iter().any(|a| matches!(a.as_str(), "--api" | "--port")))
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
}

struct Options {
    resources: Map<String, Value>,
    fresh: bool,
    /// `--change`: choose the model's resources, even when it already exists or is running.
    change: bool,
    neocloud: bool,
    environment: Option<String>,
    api_port: Option<u16>,
    share_mode: Option<&'static str>,
    quant: Option<String>,
}

fn options(args: &[String]) -> Result<Options, String> {
    let run = args[1] == "run";
    let mut resources = Map::new();
    let mut fresh = false;
    let mut change = false;
    let mut neocloud = false;
    let mut environment = None;
    let mut api_port = None;
    let mut share_mode = None;
    let mut quant = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--now" | "--nowfree") if run => {
                if share_mode.is_some() { return Err("Use only one of --now or --nowfree".into()); }
                share_mode = network::mode(flag);
            }
            "--quant" if run => {
                i += 1;
                quant = Some(args.get(i).filter(|v| !v.starts_with('-')).ok_or("--quant needs a quantization such as Q4_K_M")?.clone());
            }
            flag @ ("--cpu" | "--memory" | "--storage") if run => {
                let number = args
                    .get(i + 1)
                    .and_then(|raw| raw.trim_end_matches("GB").parse::<f64>().ok())
                    .filter(|n| n.is_finite() && *n > 0.0)
                    .ok_or("Model resources must be positive numbers (memory/storage in GB)")?;
                let key = match flag {
                    "--cpu" => "cpu",
                    "--memory" => "memoryGb",
                    _ => "storageGb",
                };
                resources.insert(key.into(), json!(number));
                i += 1;
            }
            "--new" if !run => fresh = true,
            "--change" if run => change = true,
            "--neocloud" if run => neocloud = true,
            "--environment" if run => {
                i += 1;
                environment = Some(args.get(i).filter(|v| !v.starts_with('-')).ok_or("--environment needs a pod name or ID")?.clone());
            }
            "--api" if run => { api_port.get_or_insert(8000); }
            "--port" if run => {
                i += 1;
                api_port = Some(args.get(i).and_then(|v| v.parse::<u16>().ok()).filter(|p| *p > 0).ok_or("Invalid API port")?);
            }
            // `npm run yougori -- model run ...` habits: a bare separator changes nothing.
            "--" => {}
            _ => return Err("Unknown model option. Usage: yougori model run hf.co/OWNER/MODEL [--now | --nowfree] [--quant Q4_K_M] [--neocloud [--environment ENV]] [--change] [--cpu N] [--memory GB] [--storage GB] | model chat ENV [--new]".into()),
        }
        i += 1;
    }
    public::validate_model_neocloud(neocloud, environment.as_deref(), change || !resources.is_empty())?;
    if neocloud && quant.is_some() { return Err("GGUF quantization is not supported on Neocloud pods".into()); }
    Ok(Options {
        resources,
        fresh,
        change,
        neocloud,
        environment,
        api_port,
        share_mode,
        quant,
    })
}

/// What a model reserves after `changes`, e.g. `2 CPU · 4 GB memory · 20 GB storage`.
fn reserved(changes: &Map<String, Value>, env: &Value) -> String {
    let value = |key: &str, current: &Value| {
        changes.get(key).and_then(Value::as_f64).or(current.as_f64()).unwrap_or(0.0)
    };
    format!(
        "{} CPU · {} GB memory · {} GB storage",
        value("cpu", &env["resourcePolicy"]["cpu"]["max"]),
        value("memoryGb", &env["resourcePolicy"]["memoryGb"]["max"]),
        value("storageGb", &env["storageLimitGb"]),
    )
}

/// The model's own name: `hf.co/Owner/Name-7B` is shown as `Name-7B`.
pub fn short(model: &str) -> String {
    clean(
        model
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(model),
    )
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    let chat_only = args[1] == "chat";
    let mut options = options(args)?;
    // Keep Ctrl+C as input throughout startup and shutdown, including network waits.
    let _raw = ui::Raw::on()?;
    let target = &args[2];
    let _session = ui::Session::start("model", if options.neocloud { "open models, served from Neocloud" } else { "open models, chat and API" });
    super::releases::offer(false).await?;
    let engine = ui::task("Starting Yougori engine");
    client::start(None).await?;
    let mut engine = Some(engine);
    if !chat_only {
        ui::intro(&short(target), &clean(target));
        if let Some(engine) = engine.take() {
            engine.done("Engine ready");
        }
    }
    if options.share_mode.is_some() && !network::signed_in().await? {
        ui::step("Sign in to share this model on the Yougori Network");
        network::login(|code, address| {
            ui::step(&format!("Approve code {} in your browser", clean(code)));
            ui::line(&clean(address));
        }).await?;
        ui::step("Signed in; the desktop app shares this account");
    }
    let (id, name) = if chat_only {
        let id = public::resolve(target).await?;
        let state = call("get_platform_state", json!({})).await?;
        let env = state["environments"]
            .as_array()
            .and_then(|all| all.iter().find(|e| e["id"] == id))
            .cloned()
            .unwrap_or(Value::Null);
        let model = state["neocloudDeployments"][&id]["extra"]["yougoriModel"].as_str().map(short).or_else(|| env["description"]
            .as_str()
            .and_then(|d| d.strip_prefix("Hugging Face · "))
            .map(short))
            .unwrap_or_else(|| short(target));
        // The title names the model, which is only known once the environment is found.
        ui::intro(&model, &format!("chat · {}", clean(env["name"].as_str().unwrap_or(&id))));
        if let Some(engine) = engine.take() {
            engine.done("Engine ready");
        }
        if env["status"] != "running" || env["kind"] == "cloud" {
            let starting = ui::task(&format!("Starting {}", clean(env["name"].as_str().unwrap_or(&id))));
            call(
                "start_model",
                json!({"environmentId":id}),
            )
            .await?;
            starting.done(&format!("{} running", clean(env["name"].as_str().unwrap_or(&id))));
        }
        (id, model)
    } else if options.neocloud {
        let state = call("get_platform_state", json!({})).await?;
        let candidates = public::neocloud_model_targets(&state);
        let Some(env) = super::neocloud::target(&state, &candidates, options.environment.as_deref(), target).await? else {
            return Ok(0);
        };
        let starting = ui::task(&format!("Starting {} on {}", short(target), clean(env["name"].as_str().unwrap_or("RunPod"))));
        let mut result = call("run_neocloud_model", json!({"model":target,"environmentId":env["id"],"port":options.api_port})).await?;
        starting.done("Model started in Neocloud");
        if options.api_port.is_some() {
            if let Some(mode) = options.share_mode {
                let id = result["id"].as_str().ok_or("Model environment missing")?.to_owned();
                result["network"] = network::share(&id, mode).await?;
            }
            ui::outro("API configured; model weights may still be loading");
            // Keys are explicitly requested with --api, as with the scripted local runner.
            println!("{}", serde_json::to_string_pretty(&result).map_err(|e|e.to_string())?);
            return Ok(0);
        }
        (result["id"].as_str().ok_or("Model environment missing")?.to_owned(), short(target))
    } else if let Some(env) = public::find_model(target).await?.filter(|_| options.quant.is_none()) {
        // One environment per model: start the one that already has it.
        let name = clean(env["name"].as_str().unwrap_or(""));
        let running = env["status"] == "running";
        // A stopped model offers a change before it starts; `--change` also changes a running
        // one, whose container takes new CPU, memory and storage without a restart.
        if options.resources.is_empty() && (options.change || !running) {
            ui::step(&format!("{name} already has this model"));
            let host = call("get_platform_state", json!({})).await?["host"].take();
            if let Some(changes) = super::changed_model_resources(&host, &env, options.change)? {
                options.resources = changes;
            }
        }
        let changed = !options.resources.is_empty();
        let using = ui::task(&if running {
            format!("Using {name}")
        } else {
            format!("Starting {name}")
        });
        using.detail("it already has this model");
        let result = public::reuse_model(&env, &options.resources, None).await?;
        using.done(&format!("Using {name}, which already has this model"));
        if changed {
            ui::step(&format!("Resources changed · {}", reserved(&options.resources, &env)));
        }
        (
            result["id"].as_str().ok_or("Model environment missing")?.to_owned(),
            short(target),
        )
    } else {
        if options.resources.is_empty() {
            let host = call("get_platform_state", json!({})).await?["host"].take();
            let [cpu, memory, storage] = super::model_resources(&host, options.change)?;
            options.resources = Map::from_iter([
                ("cpu".into(), json!(cpu)),
                ("memoryGb".into(), json!(memory)),
                ("storageGb".into(), json!(storage)),
            ]);
        }
        let creating = ui::task("Creating the model environment");
        creating.detail("a GPU container with PyTorch; the first run downloads it");
        let result = call(
            "run_model",
            json!({"model":target,"resources":options.resources,"quant":options.quant}),
        )
        .await?;
        let id = result["id"]
            .as_str()
            .ok_or("Model environment missing")?
            .to_owned();
        creating.done(&format!("Created {}", clean(result["name"].as_str().unwrap_or(&id))));
        (id, short(target))
    };
    if let Some(mode) = options.share_mode {
        match network::share(&id, mode).await {
            Ok(share) => ui::step(&clean(&network::summary(&share))),
            Err(error) => ui::warn(&format!("Model is running; sharing needs attention: {}", clean(&error))),
        }
    }
    session(&id, &name, options.fresh).await?;
    Ok(0)
}

/// Waits for the model, then chats until the user leaves. The model keeps running.
pub async fn session(id: &str, name: &str, fresh: bool) -> Result<(), String> {
    let environment = call("get_platform_state", json!({}))
        .await
        .ok()
        .and_then(|state| {
            state["environments"]
                .as_array()?
                .iter()
                .find(|e| e["id"] == id)?["name"]
                .as_str()
                .map(clean)
        })
        .unwrap_or_else(|| id.to_owned());
    let _raw = ui::Raw::on()?;
    let footer = Footer::open(
        name,
        vec![("t", "Open terminal"), ("ctrl+c", "stop options"), ("d", "leave it running")],
        id,
        true,
    );
    let exit = match wait_ready(id, name).await? {
        Err(exit) => exit,
        Ok(status) => {
            match network::settled(id, Duration::from_secs(45)).await {
                Ok(Some(share)) => ui::step(&clean(&network::summary(&share))),
                Err(error) => ui::warn(&clean(&error)),
                _ => {}
            }
            ui::dash(|d| {
                d.status(ui::Tone::Good, "ready");
                d.keys(vec![
                    ("/terminal", "Open terminal"),
                    ("enter", "send"),
                    ("esc", "stop reply"),
                    ("/new", "new chat"),
                    ("/api", "API access"),
                    ("/detach", "leave running"),
                    ("ctrl+c", "stop options"),
                ]);
            });
            chat(id, name, fresh, &status).await?
        }
    };
    drop(footer);
    match exit {
        Exit::Detach => {
            ui::outro(&format!("{name} keeps running"));
            ui::line(&format!(
                "   {}",
                ui::muted(&format!(
                    "yougori model chat {environment} continues · yougori model stop {environment} stops it"
                ))
            ));
        }
        Exit::Stop => {
            stop_choice(id).await?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum StopAction { Stop, Delete }

fn stop_request(state: &Value, id: &str, action: StopAction) -> Result<(&'static str, Value), String> {
    let env = state["environments"].as_array().and_then(|all| all.iter().find(|e| e["id"] == id))
        .ok_or("Model environment not found")?;
    if env["kind"] == "cloud" {
        let pod = &state["neocloudDeployments"][id];
        let name = pod["name"].as_str().filter(|_| pod["provider"] == "runpod")
            .ok_or("This model has no RunPod pod to stop or delete")?;
        Ok(("neocloud_action", json!({"environmentId":id,"action":if action == StopAction::Delete {"delete"} else {"stop"},
            "confirmation":if action == StopAction::Delete {Some(name)} else {None}})))
    } else {
        Ok((if action == StopAction::Delete {"delete_environment"} else {"stop_model"}, json!({"environmentId":id})))
    }
}

/// One explicit choice, one operation. Raw input stays on until the operation finishes.
pub(super) async fn stop_choice(id: &str) -> Result<(), String> {
    let _raw = ui::Raw::on()?;
    let state = call("get_platform_state", json!({})).await?;
    // Validate the target before presenting a destructive choice.
    let (stop_method, _) = stop_request(&state, id, StopAction::Stop)?;
    let cloud = stop_method == "neocloud_action";
    let env = state["environments"].as_array().unwrap().iter().find(|e| e["id"] == id).unwrap();
    let name = clean(env["name"].as_str().unwrap_or(id));
    let choices = [
        ui::Choice::new("Stop", if cloud {"stop the RunPod pod; keep it for later"} else {"stop the model; keep its environment"}),
        ui::Choice::new("Stop and delete", if cloud {"permanently delete the RunPod pod and its local data"} else {"permanently delete the model environment and its managed data"}),
    ];
    let picked = ui::select_required("How do you want to stop?", &[name.clone()], &choices)?;
    let action = if picked == 0 { StopAction::Stop } else { StopAction::Delete };
    let (method, params) = stop_request(&state, id, action)?;
    let task = ui::task(&format!("{} {name}", if action == StopAction::Delete {"Stopping and deleting"} else {"Stopping"}));
    let result = async {
        if !cloud && action == StopAction::Delete {
            call("stop_model", json!({"environmentId":id})).await?;
        }
        let result = call(method, params).await?;
        if cloud {
            let status = result["neocloudDeployments"][id]["state"].as_str().unwrap_or("Unknown");
            let verified = if action == StopAction::Delete { status == "Deleted" }
                else { matches!(status.to_ascii_lowercase().as_str(), "stopped" | "exited" | "paused" | "shutoff" | "off" | "powered off") };
            if !verified {
                return Err(format!("RunPod reports {}. Check `yougori neocloud inspect {id}` before retrying; the action is not confirmed.", clean(status)));
            }
            if action == StopAction::Delete {
                call("delete_environment", json!({"environmentId":id})).await
                    .map_err(|e| format!("The RunPod pod was deleted, but its Yougori entry could not be removed: {e}"))?;
            }
        }
        Ok::<(),String>(())
    }.await;
    // Consume repeated presses made while the operation was in flight before restoring the terminal.
    while event::poll(Duration::ZERO).unwrap_or(false) {
        if event::read().is_err() { break; }
    }
    match result {
        Ok(()) => {
            task.done(&format!("{name} {}", if action == StopAction::Delete {"deleted"} else {"stopped"}));
            if cloud && action == StopAction::Stop { ui::info("The pod is stopped. RunPod storage charges may continue."); }
            ui::outro(if action == StopAction::Delete {"Stopped and deleted"} else {"Stopped"});
            Ok(())
        }
        Err(error) => { task.fail("Could not complete the selected action"); Err(error) }
    }
}

/// How the user left: stopping the model's container, or leaving it running.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Exit {
    Stop,
    Detach,
}

fn phase(phase: &str, name: &str) -> (String, String) {
    match phase {
        "installing" => (
            "Installing model dependencies".into(),
            "Model dependencies ready".into(),
        ),
        "downloading" => (format!("Downloading {name}"), format!("{name} files ready")),
        "loading" => ("Loading onto the GPU".into(), "Loaded onto the GPU".into()),
        _ => (
            "Starting the model server".into(),
            "Model server started".into(),
        ),
    }
}

/// Shows each startup phase as a step. `Err(exit)` when the user leaves before the model is ready.
async fn wait_ready(id: &str, name: &str) -> Result<Result<Value, Exit>, String> {
    let mut current = "starting".to_string();
    let mut task = ui::task(&phase(&current, name).0);
    ui::dash(|d| d.status(ui::Tone::Busy, "starting the model server"));
    let mut check_at = Instant::now();
    let mut logs_at = Instant::now();
    loop {
        let now = Instant::now();
        if now >= check_at {
            check_at = now + Duration::from_millis(800);
            let status = tokio::time::timeout(
                Duration::from_secs(5),
                call("model_status", json!({"environmentId":id})),
            )
            .await;
            match status {
                Ok(Ok(status)) => {
                    let next = status["status"].as_str().unwrap_or("starting").to_owned();
                    if next == "error" {
                        task.fail("The model could not load");
                        return Err(clean(
                            status["error"].as_str().unwrap_or("The model could not load"),
                        ));
                    }
                    if next == "ready" {
                        let gpu = status["gpu"]
                            .as_str()
                            .map(clean)
                            .unwrap_or_else(|| "the GPU".into());
                        if current == "loading" {
                            task.done(&format!("Loaded onto {gpu}"));
                        } else if task.elapsed() >= Duration::from_secs(1) {
                            task.done(&phase(&current, name).1);
                        } else {
                            task.clear();
                            ui::step(&format!("{name} is running on {gpu}"));
                        }
                        return Ok(Ok(status));
                    }
                    if next != current {
                        task.done(&phase(&current, name).1);
                        current = next;
                        let (text, _) = phase(&current, name);
                        task = ui::task(&text);
                        ui::dash(|d| d.status(ui::Tone::Busy, &text.to_lowercase()));
                    }
                }
                Ok(Err(error))
                    if error.contains("Start the model environment")
                        || error.contains("not found") =>
                {
                    task.fail("The model environment is not running");
                    return Err(error);
                }
                _ => {}
            }
        }
        if now >= logs_at {
            logs_at = now + Duration::from_secs(2);
            let logs = tokio::time::timeout(
                Duration::from_secs(3),
                call("get_environment_logs", json!({"environmentId":id})),
            )
            .await;
            if let Ok(Ok(logs)) = logs {
                if let Some(last) = logs
                    .as_str()
                    .and_then(|l| l.lines().rev().map(str::trim).find(|l| !l.is_empty()))
                {
                    task.detail(&clean(last));
                }
            }
        }
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                    let exit = match key.code {
                        KeyCode::Char('t') if !ctrl => { super::open_terminal(id, false, None); None }
                        KeyCode::Char('c' | 'd') if ctrl => Some(Exit::Stop),
                        KeyCode::Char('d') => Some(Exit::Detach),
                        _ => None,
                    };
                    if let Some(exit) = exit {
                        task.clear();
                        return Ok(Err(exit));
                    }
                }
                Event::Resize(..) => ui::refresh(),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The message being typed, with a cursor and the messages sent this session.
#[derive(Default)]
struct Editor {
    text: String,
    cursor: usize,
    sent: Vec<String>,
    recall: Option<usize>,
}

enum Input {
    Send(String),
    Leave,
    None,
}

impl Editor {
    fn key(&mut self, key: &KeyEvent) -> Input {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c' | 'd') if ctrl => return Input::Leave,
            KeyCode::Char('u') if ctrl => self.set(String::new()),
            KeyCode::Enter => {
                let text = self.text.trim().to_owned();
                if !text.is_empty() {
                    self.sent.push(text.clone());
                    self.recall = None;
                    self.set(String::new());
                    return Input::Send(text);
                }
            }
            KeyCode::Esc => self.set(String::new()),
            KeyCode::Backspace => {
                if let Some(c) = self.text[..self.cursor].chars().next_back() {
                    self.cursor -= c.len_utf8();
                    self.text.remove(self.cursor);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.text.len() {
                    self.text.remove(self.cursor);
                }
            }
            KeyCode::Left => {
                if let Some(c) = self.text[..self.cursor].chars().next_back() {
                    self.cursor -= c.len_utf8();
                }
            }
            KeyCode::Right => {
                if let Some(c) = self.text[self.cursor..].chars().next() {
                    self.cursor += c.len_utf8();
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Up if !self.sent.is_empty() => {
                let at = self.recall.map_or(self.sent.len() - 1, |i| i.saturating_sub(1));
                self.recall = Some(at);
                self.set(self.sent[at].clone());
            }
            KeyCode::Down => match self.recall {
                Some(i) if i + 1 < self.sent.len() => {
                    self.recall = Some(i + 1);
                    self.set(self.sent[i + 1].clone());
                }
                _ => {
                    self.recall = None;
                    self.set(String::new());
                }
            },
            KeyCode::Tab => self.insert(' '),
            KeyCode::Char(c) if !ctrl && !c.is_control() && self.text.len() < 30_000 => {
                self.insert(c)
            }
            _ => {}
        }
        Input::None
    }

    fn set(&mut self, text: String) {
        self.cursor = text.len();
        self.text = text;
    }

    fn insert(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// The message wrapped to the terminal, with the cursor shown as a highlighted cell.
    fn lines(&self, name: &str, columns: usize) -> Vec<String> {
        let prompt = ui::paint("›", ui::SKY);
        let caret = |c: &str| {
            if ui::color() {
                format!("\x1b[7m{c}\x1b[27m")
            } else {
                format!("[{c}]")
            }
        };
        if self.text.is_empty() {
            return vec![format!(
                "{prompt} {}{}",
                caret(" "),
                ui::muted(&format!("Message {name}"))
            )];
        }
        let mut lines = Vec::new();
        let mut start = 0;
        for (row, used) in ui::wrap(&format!("{} ", self.text), columns.saturating_sub(4)) {
            let end = start + row.len();
            let shown = if (start..end).contains(&self.cursor) {
                let at = self.cursor - start;
                let c = row[at..].chars().next().map_or(" ".into(), String::from);
                format!("{}{}{}", &row[..at], caret(&c), &row[at + c.len()..])
            } else if self.cursor >= end && self.cursor < start + used {
                format!("{row}{}", caret(" "))
            } else {
                row
            };
            lines.push(format!(
                "{} {shown}",
                if start == 0 { prompt.clone() } else { " ".into() }
            ));
            start += used;
        }
        // Long messages show their end, where the typing is.
        let keep = lines.len().saturating_sub(8);
        lines.split_off(keep)
    }
}

/// Model text as it streams: finished rows join the log, the row being written stays live.
#[derive(Default)]
struct Writer {
    text: String,
    done: usize,
    code: bool,
}

impl Writer {
    fn push(&mut self, piece: &str) {
        for c in piece.chars() {
            match c {
                c if self.text.is_empty() && c.is_whitespace() => {}
                '\t' => self.text.push_str("    "),
                '\n' => self.text.push('\n'),
                c if c.is_control() => {}
                c => self.text.push(c),
            }
        }
    }

    /// Commits the rows that can no longer change and returns the one still being written.
    fn flush(&mut self, finished: bool) -> Option<String> {
        let columns = crossterm::terminal::size()
            .map(|(c, _)| usize::from(c))
            .unwrap_or(80)
            .saturating_sub(4);
        loop {
            let rest = &self.text[self.done..];
            if let Some(end) = rest.find('\n') {
                let paragraph = rest[..end].to_owned();
                for (row, _) in ui::wrap(&paragraph, columns) {
                    self.commit(&row);
                }
                self.done += end + 1;
                continue;
            }
            if rest.is_empty() {
                return None;
            }
            let rows = ui::wrap(rest, columns);
            let count = rows.len() - usize::from(!finished);
            let mut used = 0;
            for (row, bytes) in &rows[..count] {
                used += bytes;
                self.commit(row);
            }
            self.done += used;
            return (!finished).then(|| format!("  {}", self.style(&rows[count].0, false)));
        }
    }

    fn commit(&mut self, row: &str) {
        let styled = self.style(row, true);
        ui::line(&format!("  {styled}"));
    }

    /// Code blocks and headings stand out; everything else is plain text.
    fn style(&mut self, row: &str, finished: bool) -> String {
        let trimmed = row.trim_start();
        if trimmed.starts_with("```") {
            if finished {
                self.code = !self.code;
            }
            return ui::muted(row);
        }
        if self.code {
            return ui::paint(row, CODE);
        }
        if trimmed.starts_with('#') {
            return ui::bold(trimmed.trim_start_matches('#').trim_start());
        }
        row.to_owned()
    }
}

const HINT: &str = "/terminal opens the environment shell · /api sets up API access · /new starts a new conversation · /help lists commands · ctrl+c opens stop options, /detach leaves it running";

async fn new_chat(id: &str, store: &mut Value) -> Result<(), String> {
    let mut next = store.clone();
    public::start_conversation(&mut next);
    call("save_model_chat_history", json!({"environmentId":id,"history":next})).await?;
    *store = next;
    Ok(())
}

async fn start_new_chat(id: &str, store: &mut Value, editor: &mut Editor) {
    match new_chat(id, store).await {
        Ok(()) => {
            *editor = Editor::default();
            ui::line("");
            ui::line(&ui::muted("  New chat · previous conversations saved"));
        }
        Err(error) => ui::warn(&format!("Could not start a new chat: {}", clean(&error))),
    }
}

async fn chat(id: &str, name: &str, fresh: bool, status: &Value) -> Result<Exit, String> {
    let mut store = call("model_chat_history", json!({"environmentId":id}))
        .await
        .unwrap_or(Value::Null);
    store = public::chat_history_or_default(store);
    let (max_tokens, temperature, system) = public::chat_settings(&store, status);
    let active = store["conversations"]
        .as_array()
        .and_then(|list| list.iter().position(|c| c["id"] == store["activeId"]));
    match active {
        Some(index) if !fresh => {
            let conversation = &store["conversations"][index];
            let messages = conversation["messages"].as_array().cloned().unwrap_or_default();
            ui::info(&format!(
                "Continuing \"{}\" · {} messages",
                clean(conversation["title"].as_str().unwrap_or("chat")),
                messages.len()
            ));
            ui::outro(&ui::muted(HINT));
            // A short reminder of the last exchange; the full conversation is in the app.
            let last_user = messages.iter().rposition(|m| m["role"] == "user");
            if let Some(at) = last_user {
                ui::line("");
                for message in &messages[at..] {
                    let user = message["role"] == "user";
                    let rows = recap(message["content"].as_str().unwrap_or(""), if user { 2 } else { 4 });
                    for (i, row) in rows.iter().enumerate() {
                        let lead = if user && i == 0 { ui::paint("›", ui::SKY) } else { " ".into() };
                        ui::line(&format!("{lead} {}", ui::muted(row)));
                    }
                }
                ui::line("");
            }
        }
        _ => {
            new_chat(id, &mut store).await?;
            ui::outro(&ui::muted(HINT));
        }
    }
    let block = ui::block();
    let mut editor = Editor::default();
    let mut streaming = true;
    loop {
        let Some(text) = read(&block, &mut editor, name).await? else {
            return Ok(Exit::Stop);
        };
        match text.as_str() {
            "/terminal" => {
                super::open_terminal(id, false, None);
                continue;
            }
            "/exit" | "/quit" | "/stop" => return Ok(Exit::Stop),
            "/detach" => return Ok(Exit::Detach),
            "/new" => {
                start_new_chat(id, &mut store, &mut editor).await;
                continue;
            }
            "/clear" => {
                ui::clear();
                continue;
            }
            "/api" => {
                ui::line("");
                ui::take_interrupt();
                match api::menu(id, status["stream"] == true).await {
                    Ok(api::MenuExit::NewChat) => start_new_chat(id, &mut store, &mut editor).await,
                    Ok(api::MenuExit::Done) => {},
                    Err(error) => ui::warn(&clean(&error)),
                }
                if ui::take_interrupt() { return Ok(Exit::Stop); }
                ui::line("");
                continue;
            }
            "/help" => {
                ui::line("");
                for (command, meaning) in [
                    ("/terminal", "open the environment shell in a new window"),
                    ("/api", "local and public API access, the key and code examples"),
                    ("/new", "start a new conversation"),
                    ("/clear", "clear the screen"),
                    ("/exit", "choose Stop or Stop and delete (ctrl+c too)"),
                    ("/detach", "leave; the model keeps running"),
                    ("esc", "stop a reply while it is being written"),
                    ("↑ ↓", "earlier messages"),
                ] {
                    ui::line(&format!("  {}  {}", ui::paint(&format!("{command:<7}"), ui::SKY), ui::muted(meaning)));
                }
                ui::line("");
                continue;
            }
            _ => {}
        }
        you(&text);
        let index = store["conversations"]
            .as_array()
            .and_then(|list| list.iter().position(|c| c["id"] == store["activeId"]))
            .unwrap_or(0);
        let conversation = &mut store["conversations"][index];
        if conversation["title"] == "New chat" {
            conversation["title"] = public::chat_title(&text).into();
        }
        let Some(messages) = conversation["messages"].as_array_mut() else {
            return Err("Saved conversation is invalid".into());
        };
        messages.push(json!({"id":public::new_id(),"role":"user","content":text}));
        let request = public::fit_messages(&system, messages);
        let started = Instant::now();
        let mut leave = false;
        match reply(&block, id, name, request, max_tokens, temperature, &mut streaming, &mut leave).await {
            Ok((reply, result)) => {
                let seconds = started.elapsed().as_secs_f64();
                let tokens = result["usage"]["completion_tokens"].as_u64();
                let finish = result["finishReason"].as_str().unwrap_or("stop").to_owned();
                let mut facts = Vec::new();
                if let Some(tokens) = tokens {
                    facts.push(format!("{tokens} tokens"));
                }
                facts.push(format!("{seconds:.1}s"));
                if let Some(tokens) = tokens.filter(|_| seconds > 0.0) {
                    facts.push(format!("{:.0} tokens/s", tokens as f64 / seconds));
                }
                match finish.as_str() {
                    "length" => facts.push("stopped at the reply length limit".into()),
                    "cancelled" => facts.push("stopped".into()),
                    _ => {}
                }
                ui::line(&format!("  {}", ui::muted(&facts.join(" · "))));
                ui::line("");
                if reply.is_empty() {
                    messages.pop();
                    if leave { return Ok(Exit::Stop); }
                    continue;
                }
                messages.push(json!({"id":public::new_id(),"role":"assistant","content":reply,
                    "stats":{"tokens":tokens,"seconds":seconds,"finish":if finish == "length" {"length"} else {"stop"}}}));
                conversation["updatedAt"] = public::now_millis().into();
                if let Err(error) = call(
                    "save_model_chat_history",
                    json!({"environmentId":id,"history":store}),
                )
                .await
                {
                    ui::warn(&format!("Reply not saved: {error}"));
                }
            }
            Err(error) => {
                messages.pop();
                ui::warn(&clean(&error));
            }
        }
        if leave { return Ok(Exit::Stop); }
    }
}

/// The first rows of a message, ending with … when it goes on.
fn recap(text: &str, rows: usize) -> Vec<String> {
    let columns = crossterm::terminal::size()
        .map(|(c, _)| usize::from(c))
        .unwrap_or(80)
        .saturating_sub(4);
    let mut out: Vec<String> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .flat_map(|line| ui::wrap(&clean(line.trim()), columns))
        .map(|(row, _)| row)
        .collect();
    if out.len() > rows {
        out.truncate(rows);
        if let Some(last) = out.last_mut() {
            last.push_str(" …");
        }
    }
    out
}

fn you(text: &str) {
    let columns = crossterm::terminal::size()
        .map(|(c, _)| usize::from(c))
        .unwrap_or(80)
        .saturating_sub(4);
    ui::line("");
    for (i, paragraph) in text.lines().enumerate() {
        for (j, (row, _)) in ui::wrap(paragraph, columns).into_iter().enumerate() {
            let lead = if i == 0 && j == 0 {
                ui::paint("›", ui::SKY)
            } else {
                " ".into()
            };
            ui::line(&format!("{lead} {}", ui::bold(&clean(&row))));
        }
    }
    ui::line("");
}

/// Reads keys until a message is sent. `None` when the user leaves.
async fn read(block: &ui::Block, editor: &mut Editor, name: &str) -> Result<Option<String>, String> {
    let mut shown = Vec::new();
    loop {
        let columns = crossterm::terminal::size()
            .map(|(c, _)| usize::from(c))
            .unwrap_or(80);
        let lines = editor.lines(name, columns);
        if lines != shown {
            block.set(lines.clone());
            shown = lines;
        }
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => match editor.key(&key) {
                    Input::Send(text) => {
                        block.set(Vec::new());
                        return Ok(Some(text));
                    }
                    Input::Leave => {
                        block.set(Vec::new());
                        return Ok(None);
                    }
                    Input::None => {}
                },
                Event::Paste(text) => {
                    for c in text.chars() {
                        editor.insert(if c.is_control() { ' ' } else { c });
                    }
                }
                Event::Resize(..) => ui::refresh(),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Esc stops the reply; Ctrl+C also opens the session's stop choices.
async fn reply(
    block: &ui::Block,
    id: &str,
    name: &str,
    request: Vec<Value>,
    max_tokens: u64,
    temperature: f64,
    streaming: &mut bool,
    leave: &mut bool,
) -> Result<(String, Value), String> {
    let params = json!({"environmentId":id,"messages":request,"maxTokens":max_tokens,"temperature":temperature});
    let writing = ui::task(&format!("{name} is writing"));
    writing.detail("esc stops");
    ui::dash(|d| d.status(ui::Tone::Busy, "writing"));
    let mut writer = Writer::default();
    let outcome = async {
        if *streaming {
            match call("model_chat_begin", params.clone()).await {
                Ok(begin) => {
                    let request = begin["requestId"]
                        .as_str()
                        .ok_or("The engine did not start the reply")?
                        .to_owned();
                    return stream(block, &request, &mut writer, leave).await;
                }
                // Engines from before streaming replies answer in one piece.
                Err(error) if error.contains("Unknown method") => *streaming = false,
                Err(error) => return Err(error),
            }
        }
        let answer = call("model_chat", params).await?;
        writer.push(
            answer["choices"][0]["message"]["content"]
                .as_str()
                .ok_or("Invalid model answer")?,
        );
        Ok(json!({
            "finishReason": if answer["choices"][0]["finish_reason"] == "length" { "length" } else { "stop" },
            "usage": answer["usage"],
        }))
    }
    .await;
    writing.clear();
    block.set(Vec::new());
    writer.flush(true);
    ui::dash(|d| d.status(ui::Tone::Good, "ready"));
    outcome.map(|result| (writer.text, result))
}

fn reply_interrupt(key: KeyEvent, stop: &mut bool, leave: &mut bool) {
    if key.kind == KeyEventKind::Release { return; }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        *leave = true;
        *stop = true;
    } else if key.code == KeyCode::Esc {
        *stop = true;
    }
}

async fn stream(block: &ui::Block, request: &str, writer: &mut Writer, leave: &mut bool) -> Result<Value, String> {
    let mut offset = 0u64;
    let mut stop = false;
    let mut asked = false;
    loop {
        let mut params = json!({"requestId":request,"offset":offset});
        if stop && !asked {
            params["stop"] = json!(true);
            asked = true;
        }
        let read = call("model_chat_read", params).await?;
        offset = read["offset"].as_u64().unwrap_or(offset);
        if let Some(text) = read["text"].as_str().filter(|t| !t.is_empty()) {
            writer.push(text);
            block.set(writer.flush(false).into_iter().collect());
        }
        if read["done"] == true {
            if let Some(error) = read["error"].as_str() {
                return Err(error.to_owned());
            }
            return Ok(read["result"].clone());
        }
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    reply_interrupt(key, &mut stop, leave);
                }
                Event::Resize(..) => ui::refresh(),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_choices_control_the_pod_for_neocloud_and_the_environment_for_local_models() {
        let state = json!({"environments":[
            {"id":"local","kind":"container","name":"Small model"},
            {"id":"cloud","kind":"cloud","name":"Display name"}
        ],"neocloudDeployments":{"cloud":{"provider":"runpod","name":"Exact provider name"}}});
        let (method, params) = stop_request(&state, "local", StopAction::Stop).unwrap();
        assert_eq!(method, "stop_model");
        assert_eq!(params, json!({"environmentId":"local"}));
        assert_eq!(stop_request(&state, "local", StopAction::Delete).unwrap().0, "delete_environment");
        let (method, params) = stop_request(&state, "cloud", StopAction::Stop).unwrap();
        assert_eq!(method, "neocloud_action");
        assert_eq!(params["action"], "stop");
        assert!(params["confirmation"].is_null());
        let (method, params) = stop_request(&state, "cloud", StopAction::Delete).unwrap();
        assert_eq!(method, "neocloud_action");
        assert_eq!(params["action"], "delete");
        assert_eq!(params["confirmation"], "Exact provider name");
        assert!(stop_request(&state, "missing", StopAction::Delete).is_err());
        let unknown = json!({"environments":[{"id":"cloud","kind":"cloud"}]});
        assert!(stop_request(&unknown, "cloud", StopAction::Delete).is_err());
    }

    #[test]
    fn repeated_ctrl_c_during_a_reply_keeps_the_stop_menu_request() {
        let (mut stop, mut leave) = (false, false);
        reply_interrupt(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &mut stop, &mut leave);
        assert!(stop);
        assert!(!leave);
        for _ in 0..10 {
            reply_interrupt(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL), &mut stop, &mut leave);
            assert!(stop && leave);
        }
        reply_interrupt(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &mut stop, &mut leave);
        assert!(leave);
    }

    fn press(editor: &mut Editor, code: KeyCode) -> Option<String> {
        match editor.key(&KeyEvent::new(code, KeyModifiers::NONE)) {
            Input::Send(text) => Some(text),
            _ => None,
        }
    }

    #[test]
    fn only_interactive_model_commands_open_the_chat_screen() {
        let args = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        // Tests run without a terminal, so even the right commands stay on the JSON path.
        assert!(!requested(&args("model run hf.co/a/b")));
        assert!(!requested(&args("model run hf.co/a/b --api")));
        let parsed = options(&args("model run hf.co/a/b --cpu 4 --memory 8GB")).unwrap();
        assert_eq!(parsed.resources["cpu"], 4.0);
        assert_eq!(parsed.resources["memoryGb"], 8.0);
        assert!(options(&args("model chat env-1 --new")).unwrap().fresh);
        assert!(options(&args("model run hf.co/a/b --new")).is_err());
        assert!(options(&args("model run hf.co/a/b --cpu -1")).is_err());
        assert!(options(&args("model run hf.co/a/b -- --change")).unwrap().change);
        assert!(options(&args("model chat env --change")).is_err());
        let cloud = options(&args("model run hf.co/a/b --neocloud --environment gpu-pod --api --port 8123")).unwrap();
        assert!(cloud.neocloud);
        assert_eq!(cloud.environment.as_deref(), Some("gpu-pod"));
        assert_eq!(cloud.api_port, Some(8123));
        assert!(options(&args("model run hf.co/a/b --neocloud --cpu 4")).is_err());
        assert!(options(&args("model run hf.co/a/b --neocloud --change")).is_err());
        assert!(options(&args("model run hf.co/a/b --environment gpu-pod")).is_err());
        assert!(options(&args("model run hf.co/a/b --neocloud --port 0")).is_err());
        assert!(options(&args("model chat env --neocloud")).is_err());
        let shared = options(&args("model run hf.co/a/b --nowfree --quant Q8_0")).unwrap();
        assert_eq!(shared.share_mode, Some("free"));
        assert_eq!(shared.quant.as_deref(), Some("Q8_0"));
        assert!(options(&args("model run hf.co/a/b --now --nowfree")).is_err());
        assert!(options(&args("model run hf.co/a/b --quant")).is_err());
        assert!(options(&args("model run hf.co/a/b --neocloud --quant Q8_0")).is_err());
        assert!(options(&args("model chat env --now")).is_err());
        assert_eq!(short("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0"), "TinyLlama-1.1B-Chat-v1.0");
        assert_eq!(short("model-env"), "model-env");
    }

    #[test]
    fn the_editor_moves_recalls_and_sends() {
        let mut editor = Editor::default();
        for c in "helo".chars() {
            press(&mut editor, KeyCode::Char(c));
        }
        press(&mut editor, KeyCode::Left);
        press(&mut editor, KeyCode::Char('l'));
        assert_eq!(editor.text, "hello");
        press(&mut editor, KeyCode::Home);
        press(&mut editor, KeyCode::Delete);
        press(&mut editor, KeyCode::Char('H'));
        assert_eq!(press(&mut editor, KeyCode::Enter).as_deref(), Some("Hello"));
        assert_eq!(press(&mut editor, KeyCode::Enter), None, "empty messages are not sent");
        press(&mut editor, KeyCode::Up);
        assert_eq!(editor.text, "Hello");
        press(&mut editor, KeyCode::Down);
        assert_eq!(editor.text, "");
        for c in "é日".chars() {
            press(&mut editor, KeyCode::Char(c));
        }
        press(&mut editor, KeyCode::Backspace);
        assert_eq!(editor.text, "é");
        let lines = editor.lines("Model", 40);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains('é'));
        assert!(editor.lines("Model", 12).len() == 1);
        editor.set("word ".repeat(30));
        assert!(editor.lines("Model", 30).len() > 1, "long messages wrap");
    }

    #[test]
    fn streamed_text_is_committed_only_when_rows_are_final() {
        let mut writer = Writer::default();
        writer.push("\n  Hello");
        assert_eq!(writer.text, "Hello", "leading blank space is dropped");
        writer.push(" world\n```\nlet x\x1b[2J = 1;\n```\nDone");
        // `flush` writes finished rows to the terminal; here only the bookkeeping is checked.
        let partial = writer.flush(false).unwrap();
        assert!(partial.contains("Done"));
        assert_eq!(&writer.text[writer.done..], "Done");
        assert!(!writer.text.contains('\x1b'), "control characters never reach the terminal");
        assert!(!writer.code, "the code block closed");
        assert!(writer.flush(true).is_none());
        assert_eq!(writer.done, writer.text.len());
    }

    #[test]
    fn a_resumed_conversation_shows_only_a_short_recap() {
        let long = "First line of the answer.

".to_owned() + &"More detail. ".repeat(200);
        let rows = recap(&long, 4);
        assert_eq!(rows.len(), 4);
        assert!(rows[3].ends_with(" …"));
        assert_eq!(recap("hi", 2), vec!["hi"]);
        assert_eq!(recap("a[2Jb", 2), vec!["a[2Jb"]);
    }

    #[test]
    fn wrapping_keeps_every_byte_accounted_for() {
        let text = "The quick brown fox jumps over the lazy dog and keeps running";
        let rows = ui::wrap(text, 16);
        assert!(rows.iter().all(|(row, _)| ui::width(row) <= 16));
        assert_eq!(rows.iter().map(|(_, used)| used).sum::<usize>(), text.len());
        let long = ui::wrap(&"x".repeat(40), 16);
        assert_eq!(long.len(), 3);
        assert_eq!(ui::wrap("", 16), vec![(String::new(), 0)]);
    }
}
