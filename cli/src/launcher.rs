//! Interactive compute launcher. Scripted commands keep their JSON contract.
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};
use serde_json::{json, Map, Value};
use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};
use yougori_cli::{
    client,
    public::{self, call},
};
mod api;
mod chat;
mod diagnose;
mod domains;
mod live;
mod menu;
mod neocloud;
mod package;
mod plan;
mod project;
mod releases;
mod scripts;
mod stream;
mod sync;
mod ui;

fn open_terminal(id: &str, project: bool, container: Option<&str>) {
    match yougori_cli::terminal::open(id, project, container) {
        Ok(()) => { ui::dash(|d| d.note("Terminal opened in a new window")); }
        Err(error) => ui::warn(&clean(&error)),
    }
}

/// Menu commands use the normal command dispatcher. Keep their progress alive
/// only during work, handing the screen back before it prints or prompts.
pub(crate) async fn command_progress<T>(
    args: &[String],
    work: impl std::future::Future<Output = T>,
) -> T {
    let _activity = ui::CommandActivity::start(menu::activity_label(args));
    work.await
}

fn hf(s: &str) -> bool {
    s.starts_with("hf.co/") || s.starts_with("https://huggingface.co/")
}
pub fn requested(args: &[String]) -> bool {
    if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
        return false;
    }
    args.first().is_some_and(|s| s == "launch" || s == "cli")
        || args == ["run"]
        || (io::stdin().is_terminal()
            && io::stdout().is_terminal()
            && args.len() == 2
            && args[0] == "run"
            && hf(&args[1]))
        || chat::requested(args)
}
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}
/// Options written as "Label — hint" show the hint beside the label.
fn options(items: &[String]) -> Vec<ui::Choice> {
    items
        .iter()
        .map(|item| match item.split_once(" — ") {
            Some((label, hint)) => ui::Choice::new(clean(label), clean(hint)),
            None => ui::Choice::new(clean(item), ""),
        })
        .collect()
}
fn choose(title: &str, items: &[String]) -> Result<usize, String> {
    choose_with_note(title, "", items)
}
fn choose_with_note(title: &str, note: &str, items: &[String]) -> Result<usize, String> {
    let note: Vec<String> = note
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(clean)
        .collect();
    ui::select(title, &note, &options(items), 0)
}
fn text(title: &str, default: &str, secret: bool) -> Result<String, String> {
    ui::input(title, default, secret, &|entry| {
        if entry.is_empty() {
            Err("Enter a value.".into())
        } else {
            Ok(entry.into())
        }
    })
}
fn valid_port(entry: &str) -> Result<u16, String> {
    entry
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0 && *p != 7443)
        .ok_or_else(|| "Enter a port from 1 to 65535 (7443 is reserved for Yougori).".into())
}
fn port(title: &str, default: u16) -> Result<u16, String> {
    valid_port(&ui::input(title, &default.to_string(), false, &|entry| {
        valid_port(entry).map(|p| p.to_string())
    })?)
}
fn local_port(default: u16) -> Result<u16, String> {
    let suggested = std::net::TcpListener::bind(("127.0.0.1", default))
        .or_else(|_| std::net::TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("Cannot reserve a local API port: {e}"))?
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();
    let entry = ui::input(
        "Port on this computer (localhost access stays enabled)",
        &suggested.to_string(),
        false,
        &|entry| {
            let port = valid_port(entry)?;
            std::net::TcpListener::bind(("127.0.0.1", port))
                .map_err(|_| format!("Port {port} is already in use. Choose another."))?;
            Ok(port.to_string())
        },
    )?;
    valid_port(&entry)
}
/// Defaults and slider limits for this host; `min_storage` is raised to an existing disk's size.
fn limits(host: &Value, model: bool, min_storage: u32) -> Result<([u32; 3], [(u32, u32); 3]), String> {
    let max_cpu = host["totalCpu"]
        .as_u64()
        .unwrap_or(2)
        .max(1)
        .min(u32::MAX as u64) as u32;
    let max_ram = host["totalMemoryGb"]
        .as_f64()
        .unwrap_or(4.0)
        .floor()
        .max(2.0) as u32;
    let max_storage = host["totalStorageGb"]
        .as_f64()
        .zip(host["usedStorageGb"].as_f64())
        .map(|(total, used)| ((total - used - 2.0).floor() as i64).clamp(0, 16380) as u32)
        .unwrap_or(16380);
    if max_storage < min_storage {
        return Err(format!("This drive needs at least {min_storage} GB free for this environment, plus 2 GB reserved for the computer."));
    }
    if model && (max_cpu < 2 || max_ram < 4) {
        return Err("Models require at least 2 CPU cores and 4 GB RAM".into());
    }
    // A model runs on the GPU, so it needs no more CPU or memory than a project.
    let defaults = [
        max_cpu.min(2),
        max_ram.min(4),
        max_storage.min(20).max(min_storage),
    ];
    let limits = [
        (if model { 2 } else { 1 }, max_cpu),
        (if model { 4 } else { 1 }, max_ram),
        (min_storage, max_storage),
    ];
    Ok((defaults, limits))
}
/// Arrow-key resources, starting from `initial` when settings are being changed.
fn resources(host: &Value, model: bool, initial: Option<[u32; 3]>) -> Result<[u32; 3], String> {
    sliders(host, model, if model { 12 } else { 1 }, initial)
}
fn sliders(host: &Value, model: bool, min_storage: u32, initial: Option<[u32; 3]>) -> Result<[u32; 3], String> {
    let (defaults, limits) = limits(host, model, min_storage)?;
    let start = initial.unwrap_or(defaults);
    let slider = |i: usize, label, unit| ui::Slider {
        label,
        unit,
        value: start[i].clamp(limits[i].0, limits[i].1.max(limits[i].0)),
        min: limits[i].0,
        max: limits[i].1,
        default: defaults[i],
    };
    let mut sliders = [
        slider(0, "CPU", "cores"),
        slider(1, "Memory", "GB"),
        slider(2, "Storage", "GB"),
    ];
    ui::sliders(
        "Resources",
        if model {
            "Reserved for this model. It runs on the GPU, so it needs little CPU or memory."
        } else {
            "Reserved for this environment. Free disk space is checked before creation."
        },
        &mut sliders,
    )?;
    Ok([sliders[0].value, sliders[1].value, sliders[2].value])
}
fn allocation_text(a: [u32; 3]) -> String {
    format!("{} CPU · {} GB memory · {} GB storage", a[0], a[1], a[2])
}
/// Resources for a new model: the recommended ones, or sliders to customize them.
/// `customize` goes straight to the sliders.
fn model_resources(host: &Value, customize: bool, min_storage: u32) -> Result<[u32; 3], String> {
    let (recommended, _) = limits(host, true, min_storage)?;
    let custom = customize || ui::select(
        "How much should this model reserve?",
        &[],
        &[
            ui::Choice::new("Recommended", allocation_text(recommended)),
            ui::Choice::new("Customize", "choose CPU, memory and storage"),
        ],
        0,
    )? == 1;
    if custom {
        sliders(host, true, min_storage, Some(recommended))
    } else {
        Ok(recommended)
    }
}
async fn model_storage(model: &str, quant: Option<&str>) -> Result<u32, String> {
    let preflight = call("model_preflight", json!({"model": model, "quant": quant})).await?;
    if preflight["supported"] != true {
        return Err(preflight["reason"].as_str().unwrap_or("This model needs a dedicated runner").into());
    }
    Ok(preflight["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.0).ceil().max(12.0) as u32)
}
/// Changes for an existing model's resources, or `None` to start it as before.
/// Its disk can grow but never shrink. `change` goes straight to the sliders.
fn changed_model_resources(host: &Value, env: &Value, change: bool) -> Result<Option<Map<String, Value>>, String> {
    let current = [
        env["resourcePolicy"]["cpu"]["max"].as_f64().unwrap_or(2.0).max(2.0).ceil() as u32,
        env["resourcePolicy"]["memoryGb"]["max"].as_f64().unwrap_or(4.0).max(4.0).ceil() as u32,
        env["storageLimitGb"].as_f64().unwrap_or(12.0).ceil() as u32,
    ];
    let change = change || ui::select(
        "How should it start?",
        &[],
        &[
            ui::Choice::new("As before", allocation_text(current)),
            ui::Choice::new("Change resources", "choose CPU and memory, or add storage"),
        ],
        0,
    )? == 1;
    if !change {
        return Ok(None);
    }
    let chosen = sliders(host, true, current[2].max(12), Some(current))?;
    let mut map = Map::new();
    if chosen[..2] != current[..2] {
        map.insert("cpu".into(), json!(chosen[0]));
        map.insert("memoryGb".into(), json!(chosen[1]));
    }
    if chosen[2] > current[2] {
        map.insert("storageGb".into(), json!(chosen[2]));
    }
    Ok(Some(map))
}

#[derive(Debug)]
enum Network {
    Computer,
    Lan,
    Quick,
    Domain(String),
    NewDomain {
        hostname: String,
        token: String,
        host_port: u16,
    },
}
fn tunnel_token(input: &str) -> Result<String, String> {
    input
        .split_whitespace()
        .map(|s| {
            s.strip_prefix("--token=")
                .unwrap_or(s)
                .trim_matches(['\'', '"', '`'])
        })
        .max_by_key(|s| s.len())
        .filter(|s| s.len() >= 32)
        .map(str::to_owned)
        .ok_or_else(|| "Paste a Cloudflare tunnel token or the complete install command".into())
}
fn new_domain() -> Result<(String, String, u16), String> {
    let hostname = text("Public domain", "", false)?;
    let host_port = port(
        "Tunnel origin port (Cloudflare routes to http://127.0.0.1:THIS_PORT)",
        45000,
    )?;
    ui::info("Cloudflare dashboard: https://dash.cloudflare.com/");
    ui::info("Go to Networking > Tunnels, select your tunnel, then Add a replica to copy its install command.");
    let token = tunnel_token(&text(
        "Cloudflare tunnel token (or the full install command)",
        "",
        true,
    )?)?;
    Ok((hostname, token, host_port))
}
async fn network(model: bool, current: Option<&str>, service_port: Option<u16>) -> Result<Network, String> {
    let saved = domains::available(current, service_port).await?;
    let mut options = vec![
        ui::Choice::new("This computer", "localhost only"),
        ui::Choice::new("Local network", "other devices on your Wi-Fi or LAN"),
        ui::Choice::new("Quick public link", "a temporary trycloudflare.com address"),
        ui::Choice::new("Your own domain", "set up and save a Cloudflare tunnel"),
    ];
    options.extend(saved.iter().map(|d| d.choice()));
    let initial = saved.iter().position(|d| d.connected).map_or(0, |i| i + 4);
    let selection = ui::select(
        if model {
            "Who can reach the model API?"
        } else {
            "Who can open your app?"
        },
        &[], &options, initial,
    )?;
    Ok(match selection {
        0 => Network::Computer,
        1 => Network::Lan,
        2 => Network::Quick,
        3 => {
            let (hostname, token, host_port) = new_domain()?;
            Network::NewDomain {
                hostname,
                token,
                host_port,
            }
        }
        i => {
            let domain = &saved[i - 4].domain;
            Network::Domain(domain["hostname"].as_str().ok_or("Missing domain")?.into())
        }
    })
}
fn publish_params(network: &Network, id: &str, port: u16) -> Option<Value> {
    let mut p = json!({"environmentId":id,"port":port});
    match network {
        Network::Computer => return None,
        Network::Lan => p["kind"] = json!("local"),
        Network::Quick => p["kind"] = json!("cloudflare"),
        Network::Domain(domain)
        | Network::NewDomain {
            hostname: domain, ..
        } => p["domain"] = json!(domain),
    }
    Some(p)
}

/// Usage of one environment from a metrics refresh, for the live footer.
fn usage(state: &Value, id: &str, gpu: bool) -> Option<ui::Sample> {
    let env = state["environments"]
        .as_array()?
        .iter()
        .find(|env| env["id"] == id)?;
    let policy = |name: &str| {
        let range = &env["resourcePolicy"][name];
        range["max"]
            .as_f64()
            .filter(|v| *v > 0.0)
            .or_else(|| range["current"].as_f64())
            .unwrap_or(0.0)
    };
    Some(ui::Sample {
        cpu_percent: env["cpuUsage"].as_f64()?,
        cores: policy("cpu").max(1.0),
        memory_gb: env["memoryUsageGb"].as_f64()?,
        memory_limit_gb: policy("memoryGb"),
        gpu_percent: (gpu || env["gpuAccess"] == true)
            .then(|| state["host"]["gpuUsagePercent"].as_f64())
            .flatten(),
        network_mbps: env["networkRxMbps"].as_f64(),
    })
}
async fn sample(id: &str, gpu: bool) -> Option<ui::Sample> {
    let state = tokio::time::timeout(
        Duration::from_secs(3),
        call("refresh_host_metrics", json!({})),
    )
    .await
    .ok()?
    .ok()?;
    usage(&state, id, gpu)
}
/// Samples an environment's usage into the footer until dropped, then closes the footer.
struct Footer(tokio::task::JoinHandle<()>);

impl Footer {
    fn open(name: &str, keys: Vec<(&'static str, &'static str)>, environment: &str, gpu: bool) -> Self {
        ui::dash_open(name, keys);
        let environment = environment.to_owned();
        Self(tokio::spawn(async move {
            loop {
                if let Some(sample) = sample(&environment, gpu).await {
                    ui::dash(|d| d.sample(sample));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }))
    }
}

impl Drop for Footer {
    fn drop(&mut self) {
        self.0.abort();
        ui::dash_close();
    }
}

/// The port of a local API address such as `http://127.0.0.1:8000/v1`.
fn url_port(url: &str) -> Option<u16> {
    url.strip_prefix("http://127.0.0.1:")?
        .split('/')
        .next()?
        .parse()
        .ok()
}

/// Index in `next` where lines not already shown begin.
fn fresh(previous: &[String], next: &[String]) -> usize {
    (0..=next.len().min(previous.len()))
        .rev()
        .find(|&j| next[..j] == previous[previous.len() - j..])
        .unwrap_or(0)
}
/// A view that must not stay in scrollback, such as credentials.
fn private_view(title: &str, body: &str) -> Result<(), String> {
    ui::pause(true);
    let shown = (|| -> io::Result<()> {
        let mut out = io::stdout();
        execute!(
            out,
            terminal::EnterAlternateScreen,
            cursor::Hide,
            cursor::MoveTo(0, 0),
            terminal::Clear(ClearType::All)
        )?;
        write!(
            out,
            "\r\n  {}\r\n\r\n{}\r\n\r\n  {}",
            ui::bold(title),
            body.replace('\n', "\r\n"),
            ui::muted("Any key returns")
        )?;
        out.flush()?;
        loop {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Release {
                    ui::note_interrupt(key);
                    break;
                }
            }
        }
        execute!(out, terminal::LeaveAlternateScreen)
    })();
    ui::pause(false);
    shown.map_err(|e| e.to_string())
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    let result = if args.first().is_some_and(|arg| arg == "cli") {
        menu::run(args).await
    } else if args.first().is_some_and(|arg| arg == "launch") || args == ["run"] {
        project::run(args).await
    } else if args.first().is_some_and(|arg| arg == "model") {
        chat::run(args).await
    } else {
        run_model(args).await
    };
    match result {
        // Leaving a prompt is not a failure; the prompt already shows it was cancelled.
        Err(error) if error == ui::CANCELLED => {
            ui::outro(&ui::muted(&error));
            Ok(130)
        }
        other => other,
    }
}

async fn run_model(args: &[String]) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("The launcher needs an interactive terminal. For scripts use yougori run -d IMAGE or yougori model run MODEL --api.".into());
    }
    let target = match args {
        [cmd, target] if cmd == "run" && hf(target) => target.clone(),
        _ => {
            return Err("Usage: yougori launch [--change] or yougori run hf.co/OWNER/MODEL".into())
        }
    };
    let _raw = ui::Raw::on()?;
    let session = ui::Session::start("run", "open models, served from this PC");
    releases::offer(false).await?;
    ui::intro(&clean(&target), "model");
    let engine = ui::task("Starting Yougori engine");
    client::start(None).await?;
    engine.done("Engine ready");
    let state = call("get_platform_state", json!({})).await?;
    // One environment per model: an existing one is started instead of creating another.
    let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
    let mut existing = public::existing_model(environments, &target).cloned();
    if let Some(env) = &mut existing {
        public::name_after_model(env, environments).await;
    }
    let existing_name = existing
        .as_ref()
        .map(|env| clean(env["name"].as_str().unwrap_or("")));
    let mut existing_api = None;
    if let (Some(env), Some(name)) = (&existing, &existing_name) {
        ui::step(&format!("{name} already has this model; it will be reused"));
        if env["status"] == "running" {
            existing_api = call("model_api_status", json!({"environmentId":env["id"]}))
                .await
                .ok()
                .and_then(|access| access["apiUrl"].as_str().and_then(url_port));
        }
    }
    let allocation = match existing {
        Some(_) => None,
        None => Some(model_resources(&state["host"], false, model_storage(&target, None).await?)?),
    };
    // A running model keeps its resources; a stopped one can change them before it starts.
    let changes = match &existing {
        Some(env) if env["status"] != "running" => changed_model_resources(&state["host"], env, false)?,
        _ => None,
    };
    let guest = 8000;
    let network = network(true, existing.as_ref().and_then(|e| e["id"].as_str()), Some(guest)).await?;
    let local = match existing_api {
        Some(port) => {
            ui::step(&format!("Keeping its local API on port {port}"));
            port
        }
        None => local_port(8000)?,
    };
    let finish = choose(
        "When the model is ready",
        &[
            "Chat here — replies stream into this terminal, plus the API".into(),
            "Python chat — run the generated yougori_chat.py, plus the API".into(),
            "API only — keep watching usage".into(),
        ],
    )?;
    let destination = match &network {
        Network::Computer => "This computer".into(),
        Network::Lan => "This computer and your local network".into(),
        Network::Quick => "This computer and a public quick link (anyone with the URL)".into(),
        Network::Domain(d) | Network::NewDomain { hostname: d, .. } => {
            format!("This computer and https://{}", clean(d))
        }
    };
    let review = [
        match (allocation, &existing_name) {
            (Some(a), _) => allocation_text(a),
            (None, Some(name)) if changes.as_ref().is_some_and(|c| !c.is_empty()) => {
                format!("Reuses {name} with new resources")
            }
            (None, Some(name)) => format!("Reuses {name}"),
            (None, None) => String::new(),
        },
        format!("Local port {local} → model port {guest}"),
        destination,
    ];
    let (question, go) = if existing.is_some() {
        ("Start this model?", "Start")
    } else {
        ("Create and run this model?", "Create and run")
    };
    if ui::select(
        question,
        &review,
        &[
            ui::Choice::new(go, ""),
            ui::Choice::new("Cancel", "nothing is changed"),
        ],
        0,
    )? != 0
    {
        ui::outro("Nothing was changed.");
        return Ok(0);
    }
    if let Network::NewDomain {
        hostname,
        token,
        host_port,
    } = &network
    {
        call(
            "add_saved_domain",
            json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest}),
        )
        .await?;
        ui::step(&format!("Saved {}", clean(hostname)));
    }
    let id = match (&existing, allocation) {
        (Some(env), _) => {
            let name = existing_name.clone().unwrap_or_default();
            let starting = ui::task(&format!("Starting {name}"));
            let result = public::reuse_model(env, &changes.clone().unwrap_or_default(), Some(local)).await?;
            starting.done(&format!("Using {name}"));
            result["id"]
                .as_str()
                .ok_or("Model environment missing")?
                .to_owned()
        }
        (None, allocation) => {
            let allocation = allocation.unwrap_or_default();
            let creating = ui::task("Creating model environment");
            creating.detail("image and model downloads can take several minutes");
            let result = call("run_model",json!({"model":target,"port":local,"resources":{"cpu":allocation[0],"memoryGb":allocation[1],"storageGb":allocation[2]}})).await?;
            let id = result["id"]
                .as_str()
                .ok_or("Created environment did not return an ID")?
                .to_owned();
            creating.done(&format!("Created {}", clean(result["name"].as_str().unwrap_or(&id))));
            id
        }
    };
    let id = id.as_str();
    if let Some(params) = publish_params(&network, id, guest) {
        let publishing = ui::task("Publishing");
        match domains::publish(params).await {
            Ok(_) => publishing.done("Published"),
            Err(e) => {
                publishing.fail("Publishing failed");
                return Err(format!("Environment {id} exists and localhost access is enabled, but publishing failed: {e}. Retry publishing on this environment; do not recreate it."));
            }
        }
    }
    let local_url = format!("http://127.0.0.1:{local}/v1");
    let script = write_chat(id)?;
    ui::info(&format!("API credentials: yougori model access {id}"));
    ui::info(&format!("Python chat: {}", script.display()));
    ui::gap();
    if finish == 0 {
        return chat::session(id, &chat::short(&target), true)
            .await
            .map(|()| 0);
    }
    let python = finish == 1;
    let ready = dashboard(id, &local_url, python).await?;
    if python && ready {
        ui::outro("Model ready. Starting the Python chat; the model keeps running after you leave it.");
        drop(session);
        drop(_raw);
        run_python(&script)?;
        println!("Environment {id} is managed by Yougori. Use yougori ps to check its state.");
    } else {
        ui::outro(&format!(
            "Environment {id} is managed by Yougori. Use yougori ps to check its state."
        ));
    }
    Ok(0)
}

async fn dashboard(id: &str, local: &str, chat: bool) -> Result<bool, String> {
    let _raw = ui::Raw::on()?;
    struct Close;
    impl Drop for Close {
        fn drop(&mut self) {
            ui::dash_close();
        }
    }
    ui::dash_open(
        "model",
        vec![("t", "Open terminal"), ("a", "API access"), ("q", "leave running"), ("ctrl+c", "stop options")],
    );
    let _close = Close;
    ui::dash(|d| {
        d.status(ui::Tone::Busy, "loading model");
        d.links(vec![("local".into(), local.into())]);
    });
    let mut state_at = Instant::now();
    let mut logs_at = Instant::now();
    let mut services_at = Instant::now();
    let mut shown: Vec<String> = Vec::new();
    let mut ready = false;
    loop {
        let now = Instant::now();
        if now >= state_at {
            state_at = now + Duration::from_secs(1);
            let state = tokio::time::timeout(
                Duration::from_secs(10),
                call("refresh_host_metrics", json!({})),
            )
            .await
            .map_err(|_| "Usage refresh timed out. The environment keeps running.")??;
            let env = state["environments"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["id"] == id))
                .ok_or("Environment no longer exists")?;
            if env["status"] == "error" {
                return Err(env["lastError"]
                    .as_str()
                    .unwrap_or("Environment failed")
                    .into());
            }
            if env["status"] != "running" {
                ui::warn("The environment is no longer running.");
                return Ok(false);
            }
            let name = clean(env["name"].as_str().unwrap_or(id));
            let sample = usage(&state, id, false);
            ui::dash(|d| {
                d.rename(&name);
                if let Some(sample) = sample {
                    d.sample(sample);
                }
            });
            let health = tokio::time::timeout(
                Duration::from_secs(3),
                call("model_status", json!({"environmentId":id})),
            )
            .await
            .ok()
            .and_then(Result::ok);
            if let Some(error) = health
                .as_ref()
                .and_then(|h| h["error"].as_str())
                .filter(|s| !s.is_empty())
            {
                return Err(error.into());
            }
            if health.as_ref().is_some_and(|h| h["status"] == "ready") && !ready {
                ready = true;
                ui::dash(|d| d.status(ui::Tone::Good, "ready"));
                ui::line(&format!(
                    "  {}  {}",
                    ui::paint("ready", ui::GREEN),
                    ui::muted(&format!("in {}", ui::clock(ui::since_start())))
                ));
                if chat {
                    return Ok(true);
                }
            }
        }
        if now >= services_at {
            services_at = now + Duration::from_secs(5);
            let services = tokio::time::timeout(
                Duration::from_secs(5),
                call("list_environment_services", json!({"environmentId":id})),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Value::Null);
            let mut links = vec![("local".to_string(), local.to_string())];
            for p in services["publications"].as_array().into_iter().flatten() {
                for url in p["urls"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if !links.iter().any(|(_, u)| u == url) {
                        links.push((clean(p["kind"].as_str().unwrap_or("link")), clean(url)));
                    }
                }
            }
            ui::dash(|d| d.links(links));
        }
        if now >= logs_at {
            logs_at = now + Duration::from_secs(2);
            let logs = tokio::time::timeout(
                Duration::from_secs(3),
                call("get_environment_logs", json!({"environmentId":id})),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Value::Null);
            let lines: Vec<String> = logs
                .as_str()
                .unwrap_or("")
                .lines()
                .rev()
                .take(200)
                .map(clean)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let start = fresh(&shown, &lines);
            for line in lines[start.max(lines.len().saturating_sub(40))..].iter() {
                ui::line(&format!("  {}", ui::muted(line)));
            }
            shown = lines;
        }
        let mut stop = false;
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Char('t' | 'T') => open_terminal(id, false, None),
                    KeyCode::Char('q' | 'Q') => return Ok(false),
                    KeyCode::Char('s' | 'S') => stop = true,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        stop = true
                    }
                    KeyCode::Char('a' | 'A') => {
                        ui::take_interrupt();
                        let access = call("model_api_status", json!({"environmentId":id})).await?;
                        private_view("Model API · private credentials",&format!("  Base URL       {}\n  Public URL     {}\n  Authorization  Bearer {}\n\n  POST /chat/completions\n  Content-Type: application/json\n  {{\"model\":{},\"messages\":[{{\"role\":\"user\",\"content\":\"Hello\"}}]}}",access["apiUrl"],access["publicUrl"],clean(access["apiKey"].as_str().unwrap_or("")),access["model"]))?;
                        if ui::take_interrupt() { stop = true; }
                    }
                    _ => {}
                },
                Event::Resize(..) => ui::refresh(),
                _ => {}
            }
        }
        if stop {
            drop(_close);
            chat::stop_choice(id).await?;
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn write_chat(id: &str) -> Result<std::path::PathBuf, String> {
    let profile = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or("Cannot locate your user profile")?;
    let directory = std::path::PathBuf::from(profile)
        .join(".yougori")
        .join("chat");
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let source = include_str!("model_chat.py").replace(
        "__CONFIG__",
        &serde_json::to_string(&json!({"environment":id,"cli":executable})).unwrap(),
    );
    // Atomic create, never overwrite the user's Python files.
    for i in 0..1000 {
        let path = directory.join(if i == 0 {
            "yougori_chat.py".into()
        } else {
            format!("yougori_chat_{i}.py")
        });
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(source.as_bytes())
                    .map_err(|e| e.to_string())?;
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Model {id} is running, but cannot create Python chat file: {e}"
                ))
            }
        }
    }
    Err("No unused Python chat filename; model remains running".into())
}
fn run_python(path: &std::path::Path) -> Result<(), String> {
    for (program, prefix) in [("python3", None), ("python", None), ("py", Some("-3"))] {
        let mut probe = std::process::Command::new(program);
        if let Some(p) = prefix {
            probe.arg(p);
        }
        if !probe
            .args([
                "-c",
                "import sys;sys.exit(0 if sys.version_info >= (3,8) else 1)",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            continue;
        }
        let mut command = std::process::Command::new(program);
        if let Some(p) = prefix {
            command.arg(p);
        }
        let status = command.arg(path).status().map_err(|e| e.to_string())?;
        return if status.success() {
            Ok(())
        } else {
            Err(format!(
                "Python chat exited with {status}. Your model remains available."
            ))
        };
    }
    Err(format!("Model is ready. Install Python 3.8 or newer, then run: python \"{}\". No pip packages are needed. You can chat now with yougori model chat ENV (use the environment ID printed above).",path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_tunnel_preserves_actual_model_port() {
        assert_eq!(
            publish_params(&Network::Domain("model.example.com".into()), "env-x", 8000).unwrap(),
            json!({"environmentId":"env-x","port":8000,"domain":"model.example.com"})
        );
        assert!(publish_params(&Network::Computer, "env-x", 80).is_none());
    }
    #[test]
    fn launch_is_explicit_and_safe_for_pipes() {
        assert!(requested(&["launch".into()]));
        assert!(requested(&["run".into()]));
        assert!(!requested(&["run".into(), "-d".into(), "nginx".into()]));
        assert!(!requested(&["launch".into(), "--help".into()]));
    }
    #[test]
    fn guest_text_cannot_control_terminal() {
        assert_eq!(clean("a\x1b[2J\nb\r"), "a[2Jb");
        let choices = options(&["Local network — Wi-Fi \x1b[2J".into(), "Plain".into()]);
        assert_eq!(choices[0].label, "Local network");
        assert_eq!(choices[0].hint, "Wi-Fi [2J");
        assert_eq!(choices[1].hint, "");
    }
    #[test]
    fn pasted_commands_extract_tokens_without_execution() {
        let token = "a".repeat(100);
        for command in [
            format!("sudo cloudflared service install {token}"),
            format!("cloudflared tunnel run --token='{token}'"),
            token.clone(),
        ] {
            assert_eq!(tunnel_token(&command).unwrap(), token);
        }
        assert!(tunnel_token("cloudflared").is_err());
    }
    #[test]
    fn ports_are_checked_before_use() {
        assert_eq!(valid_port("5173").unwrap(), 5173);
        assert!(valid_port("0").is_err());
        assert!(valid_port("7443").is_err());
        assert!(valid_port("70000").is_err());
        assert!(valid_port("abc").is_err());
    }
    #[test]
    fn models_default_to_little_cpu_and_memory_and_disks_never_shrink() {
        let host = json!({"totalCpu":16,"totalMemoryGb":31.8,"totalStorageGb":500.0,"usedStorageGb":100.0});
        assert_eq!(
            limits(&host, true, 12).unwrap(),
            ([2, 4, 20], [(2, 16), (4, 31), (12, 398)])
        );
        let grown = limits(&host, true, 40).unwrap();
        assert_eq!((grown.0[2], grown.1[2].0), (40, 40));
        let small = json!({"totalCpu":1,"totalMemoryGb":2.0,"totalStorageGb":20.0,"usedStorageGb":5.0});
        assert!(limits(&small, true, 12).is_err());
        assert!(limits(&small, true, 14).is_err());
    }
    #[test]
    fn usage_is_measured_against_the_environment_allocation() {
        let state = json!({"host":{"gpuUsagePercent":40.0},"environments":[{"id":"e","cpuUsage":150.0,"memoryUsageGb":1.5,"networkRxMbps":2.0,"gpuAccess":true,"resourcePolicy":{"cpu":{"max":4},"memoryGb":{"max":8}}}]});
        let sample = usage(&state, "e", false).unwrap();
        assert_eq!(sample.cores, 4.0);
        assert_eq!(sample.memory_limit_gb, 8.0);
        assert_eq!(sample.gpu_percent, Some(40.0));
        let plain = json!({"host":{"gpuUsagePercent":40.0},"environments":[{"id":"e","cpuUsage":1.0,"memoryUsageGb":0.1,"resourcePolicy":{"cpu":{"current":2},"memoryGb":{}}}]});
        let sample = usage(&plain, "e", false).unwrap();
        assert_eq!(sample.cores, 2.0);
        assert_eq!(sample.gpu_percent, None);
        assert!(usage(&plain, "missing", false).is_none());
    }
    #[test]
    fn local_api_ports_are_read_from_addresses() {
        assert_eq!(url_port("http://127.0.0.1:8000/v1"), Some(8000));
        assert_eq!(url_port("http://127.0.0.1:61234"), Some(61234));
        assert_eq!(url_port("https://x.trycloudflare.com/v1"), None);
    }
    #[test]
    fn only_new_log_lines_are_shown() {
        let lines = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(fresh(&[], &lines("a b")), 0);
        assert_eq!(fresh(&lines("a b c"), &lines("b c d e")), 2);
        assert_eq!(fresh(&lines("a b"), &lines("a b")), 2);
        assert_eq!(fresh(&lines("a b"), &lines("x y")), 0);
    }
}
